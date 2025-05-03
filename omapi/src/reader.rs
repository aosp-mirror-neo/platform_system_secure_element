// Copyright 2025, The Android Open Source Project
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

//! [`Reader`] provides access to an underlying [`Terminal`], with session management and access
//! control enforcement.

use crate::{
    access_enforcer::AccessEnforcer,
    ara::ApduAccessRule,
    system_services::{SystemServices, WaitForReader},
    terminal::{ApduResponse, ChannelId, SendSelectOnClose, Terminal},
    utils::{binder_exception, service_specific_exception,
        ServiceSpecificException::{IoError, SecureElementNotPresent}
     },
};
use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElementCallback::{
    BnSecureElementCallback, ISecureElementCallback};
use binder::{BinderFeatures, ExceptionCode::{SERVICE_SPECIFIC, ILLEGAL_STATE}, Result, Status, Strong};
use log::{debug, error, info, trace};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[cfg(test)]
mod test;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

enum ChannelType {
    Basic,
    Logical,
}

/// Reader owns and provides access to an underlying SE [`Terminal`], and is responsible for
/// managing client sessions and checking access control rules for applications trying to use the
/// SE.
#[derive(Debug)]
pub struct Reader {
    terminal: Terminal,
    access_enforcer: AccessEnforcer,
    system_services: Arc<dyn SystemServices>,
    sessions: HashMap<SessionId, Vec<ChannelId>>,
    session_id_counter: u64,
}

impl Reader {
    pub fn new_arc(
        name: &str,
        wait: WaitForReader,
        system_services: Arc<dyn SystemServices>,
    ) -> Result<Arc<Mutex<Self>>> {
        let se_hal = system_services.get_se_hal(name, wait)?;
        let security_profile = system_services.get_security_profile();
        let platform_rules = system_services.get_platform_rules(name)?;

        let terminal = Terminal::new(name, se_hal.clone())?;
        let access_enforcer = AccessEnforcer::new(security_profile, platform_rules);

        let reader_arc = Arc::new(Mutex::new(Self {
            terminal,
            access_enforcer,
            system_services,
            sessions: HashMap::new(),
            session_id_counter: 0,
        }));

        // The call to [`ISecureElement::init()`] might invoke the callback synchronously (but
        // usually won't).  As such, the lock on `reader_arc` must not be held for the call, to
        // prevent deadlock/double-lock.
        debug!("Initializing SE {name}");
        let reader_arc_clone = reader_arc.clone();
        let se_callback = SeHalCallback::new_native_binder(move |state: bool, reason: &str| {
            reader_arc_clone.lock().unwrap().on_state_change(state, reason)
        });
        se_hal.init(&se_callback)?;
        debug!("SE {name} initialized, callback established");

        Ok(reader_arc)
    }

    pub fn is_nfc_event_allowed(
        &self,
        aid: Option<&[u8]>,
        package_names: &[String],
        user_id: i32,
    ) -> Result<Vec<bool>> {
        let client_ids =
            self.system_services.get_client_ids_for_packages(package_names, user_id)?;
        self.access_enforcer.is_nfc_event_allowed(aid, &client_ids)
    }

    pub fn is_secure_element_present(&self) -> Result<bool> {
        self.terminal.is_secure_element_present()
    }

    pub fn get_atr(&self) -> Result<Option<Vec<u8>>> {
        self.terminal.answer_to_reset()
    }

    pub fn open_session(&mut self) -> Result<SessionId> {
        if !self.terminal.is_secure_element_present()? {
            service_specific_exception(SecureElementNotPresent, "Secure Element is not present.")?
        }

        let session_id = SessionId(self.session_id_counter);
        self.sessions.insert(session_id, Vec::new());
        self.session_id_counter += 1;

        trace!("Opened {session_id:?}");
        Ok(session_id)
    }

    pub fn open_basic_channel(
        &mut self,
        session_id: SessionId,
        aid: &[u8],
        p2: i8,
    ) -> Result<(Option<ChannelId>, ApduAccessRule)> {
        self.open_channel_internal(ChannelType::Basic, session_id, aid, p2)
            .inspect_err(|err| self.close_on_ioerror(err))
    }

    pub fn open_logical_channel(
        &mut self,
        session_id: SessionId,
        aid: &[u8],
        p2: i8,
    ) -> Result<(Option<ChannelId>, ApduAccessRule)> {
        self.open_channel_internal(ChannelType::Logical, session_id, aid, p2)
            .inspect_err(|err| self.close_on_ioerror(err))
    }

    /// Get the response returned by the SELECT command sent when the specified channel was
    /// opened, if any.
    pub fn select_response(&self, channel_id: ChannelId) -> Option<&[u8]> {
        self.terminal.select_response(channel_id)
    }

    /// Transmit the specified `apdu` on the specified channel.  If `privileged_caller` is true,
    /// privileged APDUs will be allowed.
    pub fn transmit_on_channel(
        &mut self,
        channel_id: ChannelId,
        apdu: &[u8],
        privileged_caller: bool,
    ) -> Result<ApduResponse> {
        self.terminal
            .transmit(channel_id, apdu, privileged_caller)
            .inspect_err(|e| self.close_on_ioerror(e))
    }

    /// Close the specified channel, first selecting the default applet if the channel is
    /// [`ChannelId::BASIC`] and `send_select` is `true`.
    pub fn close_channel(
        &mut self,
        channel_id: ChannelId,
        send_select: SendSelectOnClose,
    ) -> Result<()> {
        self.sessions
            .iter_mut()
            .for_each(|(_, channel_ids)| channel_ids.retain(|id| *id != channel_id));
        self.terminal.close_channel(channel_id, send_select)
    }

    /// Close all open channels on the specified session.  If the [`ChannelId::BASIC`] channel is
    /// open and `send_select` is `true`, the default applet will be selected.
    pub fn close_session_channels(&mut self, id: SessionId, send_select: SendSelectOnClose) {
        let mut tmp = Vec::new();
        if let Some(channel_ids) = self.sessions.get_mut(&id) {
            std::mem::swap(channel_ids, &mut tmp);
            self.close_channel_ids(tmp, send_select);
        } else {
            error!("Attempted to close channels for closed {id:?}");
        }
    }

    /// Close the specified session, and implicitly close all of the open channels on that
    /// session, first selecting the default applet if the channel is [`ChannelId::BASIC`] and
    /// `send_select` is `true`.
    pub fn close_session(&mut self, id: SessionId, send_select: SendSelectOnClose) {
        trace!("Closing {id:?}");
        if let Some(channel_ids) = self.sessions.remove(&id) {
            self.close_channel_ids(channel_ids, send_select);
        } else {
            debug!("Attempted to close closed {id:?}");
        }
    }

    /// Close all sessions, and implicitly close all of the open channels, first selecting the
    /// default applet if the channel is [`ChannelId::BASIC`] and `send_select` is `true`.
    pub fn close_sessions(&mut self, send_select: SendSelectOnClose) {
        self.terminal.close_channels(send_select);
        self.sessions.drain().for_each(|(id, _)| trace!("Closed {id:?}"));
    }

    /// Return true iff the specified channel is closed.
    pub fn is_channel_closed(&mut self, channel_id: ChannelId) -> bool {
        self.terminal.channel_closed(channel_id)
    }

    /// Returns true iff the specified session has been closed.
    pub fn is_session_closed(&self, session_id: SessionId) -> bool {
        !self.sessions.contains_key(&session_id)
    }

    pub fn reset(&self) -> bool {
        // TODO: Find out whether this needs to clean up sessions/channels.
        self.terminal.reset()
    }

    fn open_channel_internal(
        &mut self,
        channel_type: ChannelType,
        session_id: SessionId,
        aid: &[u8],
        p2: i8,
    ) -> Result<(Option<ChannelId>, ApduAccessRule)> {
        let policy = self.get_access_policy(aid)?;
        let channel_id = match channel_type {
            ChannelType::Basic => self.terminal.open_basic_channel(aid, p2)?,
            ChannelType::Logical => self.terminal.open_logical_channel(aid, p2)?,
        };

        if let Some(channel_id) = channel_id {
            let Some(session) = self.sessions.get_mut(&session_id) else {
                return binder_exception(ILLEGAL_STATE, &format!("{session_id:?} is closed."));
            };
            session.push(channel_id);
        }

        Ok((channel_id, policy))
    }

    fn close_channel_ids(&mut self, channel_ids: Vec<ChannelId>, send_select: SendSelectOnClose) {
        // sorted()/rev() is used so we close the basic channel last.
        itertools::sorted(channel_ids).rev().for_each(|id| {
            let _ = self.terminal.close_channel(id, send_select);
        });
    }

    fn on_state_change(&mut self, connected: bool, debug_reason: &str) {
        info!("on_state_change: connected: {connected} reason: {debug_reason}");

        self.terminal.set_connected(connected);

        // The Java OMAPI service starts the process of initializing the access enforcer here,
        // reading rules from the ARA applet.  We instead defer reading of rules to the first app
        // that tries to talk to the SE which isn't authorized by platform rules.  This is because
        // the first apps that try to use the SE are probably authorized by platform rules and
        // there's no reason to make the SE busy and block them while the ARA rules are read.
        //
        // Note that the Java service doesn't even start running until the first app tries to use
        // it, meaning the first such app always has to wait for rules to be read so this
        // difference in strategy won't impose any surprising latency on existing clients.

        info!("Reader {} state change, resetting ACE", self.terminal.name());
        self.access_enforcer.reset();
    }

    fn get_access_policy(&mut self, aid: &[u8]) -> Result<ApduAccessRule> {
        let client_id = self.system_services.get_client_id()?;

        // Special case:  If we haven't read the applet rules yet but the platform rules allow
        // the access, use that result without waiting to read ARA rules.
        if !self.access_enforcer.have_applet_rules() {
            trace!("No applet rules, checking platform rules.");
            if let Ok(policy) = self.access_enforcer.get_policy(aid, &client_id) {
                trace!("Platform rules allowed");
                return Ok(policy.clone());
            }
            trace!("Platform rules didn't allow");
        }

        // Normal case: Update the rule cache before retrieving policy.
        self.update_rules()?;
        self.access_enforcer.get_policy(aid, &client_id)
    }

    /// Update the rule cache.    In most cases this is relatively quick, requiring one APDU
    /// exchange to check that the refresh tag has not changed.  If the rules have changed, it
    /// will take longer.
    fn update_rules(&mut self) -> Result<()> {
        // The AccessEnforcer copy is a workaround for the borrow checker's conservatism.  It
        // won't let us borrow both reader.terminal and reader.access_enforcer at the same time
        // because that would be two mutable borrows of (parts of) reader.  Instead, we clone
        // reader.access_enforcer, update the new copy, then move it into reader.  This isn't
        // terribly efficient.
        let mut access_enforcer = self.access_enforcer.clone();
        access_enforcer.update_rule_cache(&mut self.terminal)?;
        self.access_enforcer = access_enforcer;
        Ok(())
    }

    #[cfg(test)]
    pub fn get_open_sessions(&self) -> HashMap<SessionId, Vec<ChannelId>> {
        self.sessions.clone()
    }

    fn close_on_ioerror(&mut self, err: &Status) {
        if err.exception_code() == SERVICE_SPECIFIC
            && err.service_specific_error() == IoError as i32
        {
            error!("Got IOERROR from SE, closing all sessions.");
            self.close_sessions(SendSelectOnClose(false));
        }
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        trace!("Reader dropped, closing sessions");
        self.close_sessions(SendSelectOnClose(false));
    }
}

#[derive(Debug)]
struct SeHalCallback<F>
where
    F: Fn(bool, &str) + Send + Sync + 'static,
{
    callback: F,
}

impl<F> SeHalCallback<F>
where
    F: Fn(bool, &str) + Send + Sync + 'static,
{
    fn new_native_binder(callback: F) -> Strong<dyn ISecureElementCallback> {
        BnSecureElementCallback::new_binder(SeHalCallback { callback }, BinderFeatures::default())
    }
}

impl<F> binder::Interface for SeHalCallback<F> where F: Fn(bool, &str) + Send + Sync + 'static {}

impl<F> ISecureElementCallback for SeHalCallback<F>
where
    F: Fn(bool, &str) + Send + Sync + 'static,
{
    fn onStateChange(&self, connected: bool, debug_reason: &str) -> Result<()> {
        (self.callback)(connected, debug_reason);
        Ok(())
    }
}
