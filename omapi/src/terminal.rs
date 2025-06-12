// Copyright 2024, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module provides a [`Terminal`] type that wraps an [`ISecureElement`], which represents a
//! secure element reader (or "terminal").  The name "Terminal" is used instead of "Reader" to
//! allow distinction between this hardware interface and a higher-level interface that will be
//! used by applications.

#[cfg(test)]
mod test;

use crate::{
    sensitive,
    utils::{
        binder_exception, service_specific_exception, ServiceSpecificException::*, TraceResultExt,
    },
};
use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElement as HwSe;
use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElement::ISecureElement;
use binder::{
    ExceptionCode::{
        ILLEGAL_ARGUMENT, ILLEGAL_STATE, SECURITY, SERVICE_SPECIFIC, UNSUPPORTED_OPERATION,
    },
    Result, Status, Strong,
};
use log::{debug, error, trace, warn};
use std::{collections::HashMap, fmt::Display};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Newtype for `bool` that indicates whether the [`Terminal`] should re-select the default applet
/// when the basic channel is closed.
#[derive(Clone, Copy)]
pub struct SendSelectOnClose(pub bool);

const SELECT_DEFAULT_APDU: [u8; 4] = [0x00, 0xA4, 0x04, 0x00];
const WRONG_LE_SW1: StatusByte = StatusByte(0x6C);
const BYTES_TO_RECEIVE_SW1: StatusByte = StatusByte(0x61);
const SUCCESS_STATUS: [u8; 2] = [0x90, 0x00];

/// [`ChannelId`] is a newtype that identifies an SE channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId(pub i8);

impl Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ChannelId {
    /// ID of the "basic" channel.
    pub const BASIC: ChannelId = ChannelId(0);

    /// Returns `true` iff [`self`] references the basic, non-supplementary channel.
    pub fn is_basic(&self) -> bool {
        *self == Self::BASIC
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SelectResponse(pub Vec<u8>);

impl Display for SelectResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SelectResponse({})", hex::encode(&self.0))
    }
}

/// [`Terminal`] provides access to SE reader hardware, either an embedded SE or an SE reader
/// (e.g. SIM card slot) with an (optionally) inserted reader.
#[derive(Debug)]
pub struct Terminal {
    /// System name of this reader.
    name: String,

    /// Proxy of the underlying SE HAL instance, the binder service that communicates with the
    /// actual hardware.
    se_hal: Strong<dyn ISecureElement>,

    /// `true` if the SE HAL is connected to the SE.  May be false if the SE is a SIM which has been
    /// removed from the device or if the SE HAL is not yet initialized.
    is_connected: bool,

    /// True if the basic channel was opened without specifying an AID.  Not meaningful if the
    /// basic channel is not yet open.
    is_default_app_selected_on_basic_channel: bool,

    /// Open channels.
    channels: HashMap<ChannelId, SelectResponse>,
}

impl Terminal {
    /// Create a [`Terminal`] object that provides access to the SE reader referenced by `se_hal`.
    pub fn new(name: &str, se_hal: Strong<dyn ISecureElement>) -> Result<Terminal> {
        Ok(Terminal {
            name: name.to_owned(),
            se_hal,
            is_connected: false,
            is_default_app_selected_on_basic_channel: true,
            channels: HashMap::new(),
        })
    }

    /// Returns the name of the SE.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns true iff the SE is present in the terminal (i.e. the SIM is inserted).
    pub fn is_secure_element_present(&self) -> Result<bool> {
        self.se_hal.isCardPresent()
    }

    /// Reset the SE.
    pub fn reset(&self) -> bool {
        if let Err(e) = self.se_hal.reset() {
            error!("Got error {e} resetting SE {}.", self.name);
            // The Java implementation doesn't propagate the error, so we don't either.
            false
        } else {
            true
        }
    }

    /// Returns the answer to reset (ATR) message returned by the SE when it was last reset.
    pub fn answer_to_reset(&self) -> Result<Option<Vec<u8>>> {
        if !self.is_connected {
            return Ok(None);
        }

        let atr = self.se_hal.getAtr()?;
        debug!("ATR: [{}]", hex::encode(&atr));

        let have_atr = !atr.is_empty();
        Ok(have_atr.then_some(atr))
    }

    /// Open the basic channel, selecting the specified AID (may be empty) and P2 value.
    pub fn open_basic_channel(&mut self, aid: &[u8], p2: i8) -> Result<Option<ChannelId>> {
        trace!("open_basic_channel() {} P2 = 0x{p2:02x}", hex::encode(aid));

        if !self.channel_closed(ChannelId::BASIC) {
            error!("Basic channel in use");
            return Ok(None);
        }
        self.check_channel_open_requirements(p2, aid)?;

        if aid.is_empty() && !self.is_default_app_selected_on_basic_channel {
            error!("Default application is not selected, AID required");
            return Ok(None);
        }

        let select_response = match self.se_hal.openBasicChannel(aid, p2) {
            Ok(response) => SelectResponse(response),
            Err(status) => return convert_hw_exception(status),
        };

        if !aid.is_empty() {
            self.is_default_app_selected_on_basic_channel = false
        };

        self.channels.insert(ChannelId::BASIC, select_response);
        Ok(Some(ChannelId::BASIC))
    }

    /// Open a logical channel, selecting the specified AID (may be empty) and P2 value.
    pub fn open_logical_channel(&mut self, aid: &[u8], p2: i8) -> Result<Option<ChannelId>> {
        trace!("open_logical_channel() {} P2 = 0x{p2:02x}", hex::encode(aid));

        self.check_channel_open_requirements(p2, aid)?;

        let response = match self.se_hal.openLogicalChannel(aid, p2) {
            Ok(response) => response,
            Err(status) => return convert_hw_exception(status),
        };

        if response.channelNumber <= 0 {
            // This logic is odd, but it's what the Java implementation does.  If the SE for some
            // reason returns an invalid channel ID, we don't throw an exception we return None,
            // which translated to `null` in Java.
            //
            // TODO: See if this actually makes sense for some reason.
            error!("Invalid logical channel {} received from SE", response.channelNumber);
            return Ok(None);
        }

        let channel_id = ChannelId(response.channelNumber);
        self.channels.insert(channel_id, SelectResponse(response.selectResponse));
        Ok(Some(channel_id))
    }

    /// Get the response returned by the SELECT command sent when the specified channel was
    /// opened, if any.
    pub fn select_response(&self, channel_id: ChannelId) -> Option<&[u8]> {
        self.channels.get(&channel_id).map(|select_response| &select_response.0[..])
    }

    /// Close the specified channel, optionally selecting the default applet if channel is
    /// `ChannelId::BASIC`.
    pub fn close_channel(&mut self, id: ChannelId, send_select: SendSelectOnClose) -> Result<()> {
        if self.channels.remove(&id).is_none() {
            error!("Got request to close already-closed {id}");
            return Ok(());
        }
        self.close_channel_internal(id, send_select)
    }

    /// Returns true iff the specified channel is closed.
    pub fn channel_closed(&self, channel_id: ChannelId) -> bool {
        !self.channels.contains_key(&channel_id)
    }

    /// SECURITY NOTE: APDU and response contents may be sensitive, so any copies must be zeroized
    /// and the content must not be logged, except with [`sensitive!`], which is disabled except
    /// sometimes on local developer builds.
    ///
    /// This method needs to copy the APDU to modify the CLA byte, so it puts the copy into an
    /// [`Apdu`] instance, which zeroizes on drop and does not implement [`Clone`].  This method
    /// does not copy the response data, just passes it through.
    pub fn transmit(&self, id: ChannelId, apdu: &[u8], priv_caller: bool) -> Result<ApduResponse> {
        if self.channel_closed(id) {
            return binder_exception(ILLEGAL_STATE, &format!("Channel {id} is closed"));
        }

        let apdu = Apdu::new(apdu, Some(id))?;
        apdu.check_disallowed_iso_commands(priv_caller)?;

        self.transmit_and_get_response(apdu)
    }

    /// Change SE connection state
    pub fn set_connected(&mut self, connected: bool) {
        if connected == self.is_connected {
            // I don't think we can get here, but just in case we get duplicate connection
            // requests, don't do anything.
            warn!("Got informed of a successful SE connection, but the SE is already connected.");
            return;
        }

        self.close_channels(SendSelectOnClose(false));

        self.is_connected = connected;
        if connected {
            self.is_default_app_selected_on_basic_channel = true;
        }
    }

    /// SECURITY NOTE:  APDU and response contents may be sensitive, so any copies must be
    /// zeroized and the content must not be logged, except with [`trace!`], which is normaly
    /// disabled.
    ///
    /// This method does not copy APDU or response.
    fn transmit_and_get_response(&self, mut apdu: Apdu) -> Result<ApduResponse> {
        if !self.is_connected {
            return service_specific_exception(IoError, "Secure Element is not connected");
        }

        let mut response = self.send_apdu(&apdu)?;

        if response.incorrect_le() {
            sensitive!("Wrong Le field, re-sending with correct value {:?}", response.sw2());
            apdu.set_le(response.sw2());
            return self.transmit_and_get_response(apdu).trace("transmit (corrected Le)");
        }

        while response.get_data_required() {
            sensitive!("Response chaining requested, getting {:?}", response.sw2());
            let get_data_apdu = response.create_get_data_command(apdu.cla());
            response.extend(self.send_apdu(&get_data_apdu)?);
        }

        Ok(response)
    }

    /// SECURITY NOTE:  APDU and response contents may be sensitive, so any copies must be
    /// zeroized and the content must not be logged, except with [`trace!`], which is disabled.
    fn send_apdu(&self, apdu: &Apdu) -> Result<ApduResponse> {
        sensitive!("Transmitting: {apdu:?}");
        ApduResponse::new(self.se_hal.transmit(&apdu.0)?).sensitive("transmit")
    }

    /// Close all open channels on the [`Terminal`]
    pub fn close_channels(&mut self, send_select: SendSelectOnClose) {
        for channel_id in self.channels.drain().map(|(id, _)| id).collect::<Vec<_>>() {
            let _ = self.close_channel_internal(channel_id, send_select);
        }
    }

    fn close_channel_internal(
        &mut self,
        id: ChannelId,
        send_select: SendSelectOnClose,
    ) -> Result<()> {
        trace!("Closing {id}.");

        if !self.is_connected {
            debug!("Can't actually close {id}, reader isn't connected.");
            return Ok(());
        }

        if send_select.0 && id.is_basic() {
            let apdu = Apdu::create_select_default_on_basic();

            if let Err(e) = self.transmit_and_get_response(apdu) {
                error!("Error trying to select default applet on basic channel during close: {e}");
            } else {
                self.is_default_app_selected_on_basic_channel = true;
            }
        }

        if let Err(e) = self.se_hal.closeChannel(id.0) {
            // Don't return errors caused by closing the basic channel.
            //
            // TODO: Figure out why we don't return them (other than the Java implementation
            // doesn't).
            if !id.is_basic() {
                error!("Error closing channel {}: {e}.", id.0);
                return Err(e);
            }
        }

        trace!("Closed {id}");
        Ok(())
    }

    fn check_channel_open_requirements(&mut self, p2: i8, aid: &[u8]) -> Result<()> {
        self.check_connected()?;
        validate_p2(p2)?;
        validate_aid(aid)?;
        Ok(())
    }

    fn check_connected(&mut self) -> Result<()> {
        if !self.is_connected {
            return service_specific_exception(
                SecureElementNotConnected,
                "Secure Element is not connected",
            );
        };
        Ok(())
    }
}

/// [`StatusByte`] is a newtype for APDU response status bytes.  It exists so it can derive
/// [`ZeroizeOnDrop`].  It's unclear if there are any situations in which status bytes are
/// sensitive, but better safe than sorry.
///
/// SECURITY NOTE:  APDU and response contents may be sensitive, so any copies must be zeroized
/// and the content must not be logged, except with [`sensitive!`].  To help ensure this,
/// [`StatusByte`]'s implementation of [`std::fmt::Debug`] is a no-op when sensitive data logging
/// is not enabled, and [`std::fmt::Display`] is not implemented.
#[derive(Clone, ZeroizeOnDrop, PartialEq)]
pub(crate) struct StatusByte(u8);

impl std::fmt::Debug for StatusByte {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This conditional shouldn't be necessary, since code should always use [`sensitive`] to
        // trace APDU response data, but this helps protect against mistakes.
        if cfg!(any(feature = "log_sensitive_data", test)) {
            return write!(f, "{:#04X?}", self.0);
        }
        Ok(())
    }
}

/// [`ApduResponse`]is a newtype for APDU response contents.  It exists primarily so it can derive
/// [`ZeroizeOnDrop`].
///
/// SECURITY NOTE:  APDU and response contents may be sensitive, so any copies must be zeroized
/// and the content must not be logged, except with [`sensitive!`].  To help ensure this,
/// [`ApduResponse`]'s implementation of [`std::fmt::Debug`] is a no-op when sensitive data
/// logging is not enabled, and [`std::fmt::Display`] is not implemented.
#[derive(Clone, ZeroizeOnDrop, PartialEq)]
pub(crate) struct ApduResponse(Vec<u8>);

impl std::fmt::Debug for ApduResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This conditional shouldn't be necessary, since code should always use [`sensitive`] to
        // trace APDU response data, but this helps protect against mistakes.
        if cfg!(any(feature = "log_sensitive_data", test)) {
            return write!(f, "{}", hex::encode(&self.0));
        }
        Ok(())
    }
}

impl ApduResponse {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        if data.len() < 2 {
            return service_specific_exception(IoError, "Error in transmit(), too-short response");
        }
        Ok(Self(data))
    }

    /// Extend this response by appending the contents of `additional`.  The status word of `self`
    /// is discarded and the result has the status word from `additional`.
    ///
    /// SECURITY NOTE:  The implementation of this method is a little tricky, because we need to
    /// ensure we don't leave any copies of the data around in the heap.  So we can't use
    /// `self.0.resize()`, nor can we pass `additional.0` to `Vec::append`, since that would
    /// probably "move" the contents out of `additional.0` by copying them, leaving `additional.0`
    /// empty so [`ZeroizeOnDrop`] does nothing.
    pub fn extend(&mut self, additional: ApduResponse) {
        if self.0.capacity() >= self.data_len() + additional.0.len() {
            self.0.pop();
            self.0.pop();
            self.0.extend_from_slice(&additional.0);
        } else {
            let mut tmp = Vec::with_capacity(self.data_len() + additional.0.len());
            tmp.extend_from_slice(self.risky_data());
            tmp.extend_from_slice(&additional.0[..]);
            std::mem::swap(&mut tmp, &mut self.0);
            tmp.zeroize();
        }
    }

    pub fn data_len(&self) -> usize {
        self.0.len() - 2
    }

    pub fn successful(&self) -> bool {
        self.0[self.0.len() - 2..] == SUCCESS_STATUS
    }

    /// Get a reference to the data portion of the response, as a slice.  This is labeled "risky"
    /// because the caller must take care not to copy the slice content, unless the caller knows
    /// that the content is not sensitive, or takes care to zeroize any copies.
    pub fn risky_data(&self) -> &[u8] {
        &self.0[..self.0.len() - 2]
    }

    /// Get a copy of the status portion of the response, as an array.  The caller must take care
    /// zeroize the copy, unless the caller knows it is not sensitive.
    pub fn non_zeroizing_status(&self) -> [u8; 2] {
        self.0[self.0.len() - 2..].try_into().unwrap()
    }

    /// Get a copy of the whole response as a vector that will not zeroize itself.  The caller
    /// must arrange some other way for the output vector to be zeroized, unless the caller knows
    /// that the content is not sensitive.
    pub fn non_zeroizing_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn sw1(&self) -> StatusByte {
        StatusByte(self.0[self.0.len() - 2])
    }

    fn sw2(&self) -> StatusByte {
        StatusByte(self.0[self.0.len() - 1])
    }

    fn incorrect_le(&self) -> bool {
        self.sw1() == WRONG_LE_SW1
    }

    fn get_data_required(&self) -> bool {
        self.sw1() == BYTES_TO_RECEIVE_SW1
    }

    fn create_get_data_command(&self, cla: u8) -> Apdu {
        Apdu(vec![cla, 0xC0, 0x00, 0x00, self.sw2().0])
    }
}

/*
 *  APDU header structure constants
 */

/// CLA -- Class byte.  Indicates whether the APDU is a standard ISO command, whether and what
/// sort of secure messaging is used, and what logical channel is in use.
const OFFSET_CLA: usize = 0;

/// INS -- Instruction byte.  Indicates what operation is being requested.
const OFFSET_INS: usize = OFFSET_CLA + 1;

/// P1 -- First parameter byte.  0x00 if unused.
const OFFSET_P1: usize = OFFSET_INS + 1;

/// P2 -- Second parameter byte. 0x00 if unused.
const OFFSET_P2: usize = OFFSET_P1 + 1;

/// Length of APDU header
const APDU_HEADER_LEN: usize = OFFSET_P2 + 1;

/// [`Apdu`] is a newtype for APDU contents.  It exists primarily so it can derive
/// [`ZeroizeOnDrop`].
///
/// Apdu creation validates the structure of the APDU, including its length, which must be at
/// least 4-7 bytes (depending on their content).
///
/// SECURITY NOTE:  APDU and response contents may be sensitive, so any copies must be zeroized
/// and the content must not be logged, except with [`sensitive!`].  To help ensure this,
/// [`Apdu`]'s implementation of [`std::fmt::Debug`] is a no-op when sensitive data logging is not
/// enabled, and [`std::fmt::Display`] is not implemented.
#[derive(Clone, ZeroizeOnDrop)]
pub(crate) struct Apdu(pub(crate) Vec<u8>);

impl std::fmt::Debug for Apdu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This conditional shouldn't be necessary, since code should always use [`sensitive`] to
        // trace Apdus, but this helps protect against mistakes.
        if cfg!(any(feature = "log_sensitive_data", test)) {
            write!(f, "{}", hex::encode(&self.0))
        } else {
            write!(f, "APDU elided for security")
        }
    }
}

impl Apdu {
    /// Create a new [`Apdu`] from an APDU buffer, validating its structure and optionally
    /// updating it to use a specified channel.
    pub(crate) fn new(apdu: &[u8], channel_id_opt: Option<ChannelId>) -> Result<Self> {
        check_apdu_structure(apdu)?;

        if ApduClassType::new(apdu[OFFSET_CLA]) == ApduClassType::ReservedForProtocolSelection {
            // Perhaps we should also reject `ApduClassType::Reserved`, but the Java OMAPI
            // implementation doesn't.
            binder_exception(ILLEGAL_ARGUMENT, &format!("Invalid CLA ({:#04X})", apdu[OFFSET_CLA]))
        } else if (apdu[OFFSET_INS] & 0xF0) == 0x60 || (apdu[OFFSET_INS] & 0xF0) == 0x90 {
            // ISO 7816-4 says that odd-valued INS bytes and INS bytes of the form 0x6_ and 0x9_
            // are all invalid, but the Java OMAPI implementation doesn't reject odd-valued INS
            // bytes, so we don't either.
            binder_exception(ILLEGAL_ARGUMENT, &format!("Invalid INS {:#04X}", apdu[OFFSET_INS]))
        } else {
            let mut apdu = Self(apdu.to_vec());

            if let Some(channel) = channel_id_opt {
                apdu.set_channel(channel)?;
            }

            Ok(apdu)
        }
    }

    /// Create a SELECT APDU that selects the default AID on the BASIC channel.
    pub fn create_select_default_on_basic() -> Self {
        let mut apdu = Self(SELECT_DEFAULT_APDU.to_vec());
        apdu.set_channel(ChannelId::BASIC).expect("Can't fail");
        apdu
    }

    /// Returns true if this APDU uses secure messaging, as indicated by the class byte.
    fn uses_secure_messaging(&self) -> bool {
        SecureMessagingConfiguration::new(self.cla())
            != SecureMessagingConfiguration::NoneOrNonStandard
    }

    /// Returns true if this APDU uses Global Platform secure messaging, as indicated by the class
    /// byte.
    fn uses_gp_secure_messaging(&self) -> bool {
        SecureMessagingConfiguration::new(self.cla())
            == SecureMessagingConfiguration::GlobalPlatform
    }

    /// Update the CLA byte to specify the channel ID, with correct interindustry class byte
    /// coding.  See Global Platform Card Specification 2.3.1, 11.1.4.
    fn set_channel(&mut self, id: ChannelId) -> Result<()> {
        let mut new_cla = self.cla();
        match id.0 {
            0..4 => {
                // Clear bit 7 to indicate first interindustry class byte coding
                new_cla &= 0xBC;

                // Encode `id` into bits 0 and 1.
                new_cla |= id.0 as u8
            }
            4..20 => {
                // Set bit 7 to indicate further interindustry class byte coding
                new_cla |= 0x40;

                // Set bit 6 if using secure messaging
                let first_interindustry_coding = self.cla() & 0x40 == 0;
                if first_interindustry_coding && self.uses_secure_messaging() {
                    new_cla |= 0x20
                }

                // Encode to `id - 4` into low-order nibble.
                new_cla = (new_cla & 0xF0) | (id.0 as u8 - 4)
            }
            _ => return binder_exception(ILLEGAL_ARGUMENT, &format!("Invalid {id}")),
        };

        self.0[OFFSET_CLA] = new_cla;

        Ok(())
    }

    /// Update the last byte of the APDU.
    fn set_le(&mut self, value: StatusByte) {
        self.0.pop();
        self.0.push(value.0);
    }

    /// Get class byte
    fn cla(&self) -> u8 {
        self.0[OFFSET_CLA]
    }

    /// Get instruction byte.
    fn ins(&self) -> u8 {
        self.0[OFFSET_INS]
    }

    /// Get p1 byte.
    fn p1(&self) -> u8 {
        self.0[OFFSET_P1]
    }

    /// Get the APDU type indicated by the class byte.
    fn get_cla_type(&self) -> ApduClassType {
        ApduClassType::new(self.cla())
    }

    /// Returns true iff the APDU is an ISO command, as indicated by the class byte.
    fn is_iso_command_class(&self) -> bool {
        let cla_type = self.get_cla_type();

        // It seems like we should only consider ISO 7816 CLA types to be ISO commands, but the
        // Java OMAPI implementation also allows CLA values in the reserved space.  This is likely
        // a bug, but we do the same for compatibility.
        //
        // TODO: Research why this is.
        cla_type == ApduClassType::Iso7816Command || cla_type == ApduClassType::Reserved
    }

    /// Returns [`Err`] if this APDU is a disallowed command.  `privileged_caller` indicates
    /// whether the caller is allowed to perform some ISO commands.
    fn check_disallowed_iso_commands(&self, privileged_caller: bool) -> Result<()> {
        // TODO: Research why not disallow SM.
        if self.is_iso_command_class() && !self.uses_gp_secure_messaging() {
            match self.ins() {
                0x70 => binder_exception(SECURITY, "MANAGE CHANNEL command not allowed."),
                0xA4 => {
                    if self.p1() == 0x04 && !privileged_caller {
                        binder_exception(SECURITY, "SELECT by DF name command not allowed.")
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()),
            }
        } else {
            Ok(())
        }
    }
}

/// This function validates the structure of the passed-in APDU buffer.  Conceptually, the APDU
/// structure is very simple:
///
/// * Class byte, CLA
/// * Instruction byte, INS
/// * Parameter byte, P1
/// * Parameter byte, P2
/// * Command data length, Lc
/// * Command data bytes
/// * Length expected, Le
///
/// The first four bytes (CLA, INS, P1, P2) are called the "header".
///
/// However, either or both of the Lc and Le fields may be omitted, and they may be one byte
/// (called "short") or two bytes (called "extended").  The Lc and Le fields are omitted to
/// indicate they have the value zero, and MUST be omitted if their value is zero.
///
/// Validating the structure is mostly about checking that the command data length, Lc,
/// corresponds to the amount of command data present, but all of the optional and length-varying
/// fields make this a little complicated.
///
/// The IS0 7816 documentation categorizes APDUs into four cases, based on the presence/absence of
/// Lc and Le:
///
/// * Case 1: No Lc and no Le.
/// * Case 2: No Lc but Le is present (non-zero).
/// * Case 3: Lc is present (non-zero), but no Le.
/// * Case 4: Lc and Le are both present (and non-zero)
///
/// Cases 2, 3 and 4 are further subdivided into "short" and "extended" cases, 2S, 2E, 3S, 3E, 4S
/// and 4E, depending on whether Lc and Le are encoded in one byte or two.
fn check_apdu_structure(apdu_data: &[u8]) -> Result<()> {
    if apdu_data.len() < APDU_HEADER_LEN {
        return binder_exception(
            ILLEGAL_ARGUMENT,
            &format!("Too-short APDU (length: {}).", apdu_data.len()),
        );
    }

    // Skip header
    let data = &apdu_data[APDU_HEADER_LEN..];

    if data.is_empty() {
        // Case 1, No Lc, no Le.
        Ok(())
    } else if data.len() == 1 {
        // Case 2S, No Lc, Le present.
        Ok(())
    } else if data[0] != 0 {
        // B1 != 0 indicates short (one-byte) Lc/Le, i.e. case 3S or 4S.
        check_apdu_structure_short(data)
    } else {
        // B1 == 0 indicates extended (two-byte) Lc/Le, i.e. case 2E, 3E, or 4E

        // Skip B1; it's not used in Lc in the extended cases
        let data = &data[1..];
        check_apdu_structure_extended(data)
    }
}

/// Check APDU structure, cases 3S and 4S
fn check_apdu_structure_short(data: &[u8]) -> Result<()> {
    // The format of the data should be:
    //
    // 1 byte: Lc
    // Lc bytes: data
    // 0 or 1 byte: Le

    let lc = data[0] as usize;

    // Skip past Lc
    let data = &data[1..];

    if data.len() == lc {
        // Case 3S, Lc present, no Le
        Ok(())
    } else if data.len() == lc + 1 {
        // Case 4S, Lc and Le both present
        Ok(())
    } else {
        binder_exception(
            ILLEGAL_ARGUMENT,
            &format!("Invalid APDU: Lc is {lc} but is followed by {} byte(s).", data.len()),
        )
    }
}

// Check APDU structure, cases 2E, 3E and 4E.
fn check_apdu_structure_extended(data: &[u8]) -> Result<()> {
    // The format of the data should be:
    //
    //     2 bytes: Lc
    //     Lc bytes: command data
    //     0 or 2 bytes: Le

    if data.len() < size_of::<u16>() {
        return binder_exception(
            ILLEGAL_ARGUMENT,
            &format!("Invalid extended APDU: Need 2 bytes for Lc, found {}.", data.len()),
        );
    }

    if data.len() == size_of::<u16>() {
        // Case 2E, No Lc, two-byte Le present.
        return Ok(());
    }

    // Have command data, get length.
    let mut lc = u16::from_be_bytes(data[..size_of::<u16>()].try_into().unwrap()) as usize;
    if lc == 0 {
        lc = 65536;
    }

    // Skip past Lc
    let data = &data[size_of::<u16>()..];

    if data.len() == lc {
        // Case 3E, two-byte Lc present, No Le
        Ok(())
    } else if data.len() == (lc + size_of::<u16>()) {
        // Case 4E, two-byte Lc and two-byte Le both present.
        Ok(())
    } else {
        binder_exception(
            ILLEGAL_ARGUMENT,
            &format!(
                "Invalid extended APDU: Lc is {lc} but is followed by {} byte(s).",
                data.len()
            ),
        )
    }
}

/// This enum categorizes the CLA byte value, which categorizes the APDU command.
#[derive(Debug, PartialEq)]
enum ApduClassType {
    /// Command defined by ISO 7816.
    Iso7816Command,
    /// Reserved for future use by ISO committee.
    Reserved,
    /// Command defined by Global Platform
    GlobalPlatform,
    /// APDU command and response use proprietary structure and coding.
    ProprietaryStructureAndCoding,
    /// Class reserved for protocol selection.
    ReservedForProtocolSelection,
}

impl ApduClassType {
    fn new(cla: u8) -> Self {
        match cla {
            0x00..0x10 => Self::Iso7816Command,
            0x10..0x80 => Self::Reserved,
            0x80..0xD0 => Self::GlobalPlatform,
            0xD0..0xFF => Self::ProprietaryStructureAndCoding,
            0xFF => Self::ReservedForProtocolSelection,
        }
    }
}

/// This enum categorizes the secure messaging being used, as specified by the CLA byte.
#[derive(Debug, PartialEq)]
enum SecureMessagingConfiguration {
    /// No secure messaging or no indication.
    NoneOrNonStandard,
    /// Proprietary secure messaging used.
    GlobalPlatform,
    /// Header is included in standard secure messaging.
    HeaderNotAuthenticated,
    /// Header is not included in standard secure messaging.
    HeaderAuthenticated,
}

impl SecureMessagingConfiguration {
    fn new(cla: u8) -> Self {
        match ApduClassType::new(cla) {
            ApduClassType::Iso7816Command | ApduClassType::GlobalPlatform => {
                match (cla & 0x0F) >> 2 {
                    0 => Self::NoneOrNonStandard,
                    1 => Self::GlobalPlatform,
                    2 => Self::HeaderNotAuthenticated,
                    3 => Self::HeaderAuthenticated,
                    _ => unreachable!(),
                }
            }
            _ => Self::NoneOrNonStandard,
        }
    }
}

fn convert_hw_exception(status: Status) -> Result<Option<ChannelId>> {
    debug!("Got error {status:?} from SE");
    if status.exception_code() == SERVICE_SPECIFIC {
        match status.service_specific_error() {
            HwSe::CHANNEL_NOT_AVAILABLE => Ok(None),
            HwSe::UNSUPPORTED_OPERATION => binder_exception(
                UNSUPPORTED_OPERATION,
                "Unsupported operation when opening channel",
            ),
            HwSe::IOERROR => service_specific_exception(IoError, "I/O error when opening channel"),
            HwSe::NO_SUCH_ELEMENT_ERROR => {
                service_specific_exception(NoSuchElement, "No such element when opening channel")
            }
            other => {
                error!("Unknown service-specific error {other} when opening channel");
                Err(status)
            }
        }
    } else {
        error!("Unexpected binder error {:?}", status.exception_code());
        Err(status)
    }
}

fn validate_aid(aid: &[u8]) -> Result<()> {
    match aid.len() {
        0 | 5..=16 => Ok(()),
        _ => binder_exception(ILLEGAL_ARGUMENT, "AID out of range"),
    }
}

fn validate_p2(p2: i8) -> Result<()> {
    match p2 {
        0x00 | 0x04 | 0x08 | 0x0C => Ok(()),
        other => binder_exception(ILLEGAL_ARGUMENT, &format!("p2 not supported: 0x{other:02x}")),
    }
}
