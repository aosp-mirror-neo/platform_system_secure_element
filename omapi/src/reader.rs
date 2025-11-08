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
    ara::{ApduAccessRule, ApduHeader},
    system_services::{SeSecurityProfile, SystemServices, WaitForReader},
    terminal::{ApduResponse, ChannelId, SendSelectOnClose, Terminal},
    utils::{binder_exception, service_specific_exception,
        ServiceSpecificException::{IoError, SecureElementNotPresent},
     },
};
use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElementCallback::{
    BnSecureElementCallback, ISecureElementCallback,
};
use binder::{
    BinderFeatures, ExceptionCode::{ILLEGAL_STATE, SECURITY, SERVICE_SPECIFIC}, Result, Status, Strong,
};
use log::{debug, error, info, trace};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[cfg(test)]
mod test;

/// [`AccessPolicy`] describes the access for a particular caller to a particular applet.
#[derive(Clone, Debug, PartialEq)]
pub enum AccessPolicy {
    /// [`AccessPolicy::Normal`] access is defined by ARA rules, and may include restrictions on
    /// the set of allowed APDUs, as indicated by the contained [`ApduAccessRule`].
    Normal(ApduAccessRule),
    /// [`AccessPolicy::PrivilegedCaller`] access is for clients with the
    /// "SECURE_ELEMENT_PRIVILEGED_OPERATION" permission.  They can access all applets and reset
    /// the SE.
    PrivilegedCaller,
}

impl AccessPolicy {
    /// Returns true iff the caller is allowed to send APDUs with the specified header.
    pub fn allow_apdu(&self, apdu_header: &ApduHeader) -> bool {
        match self {
            AccessPolicy::Normal(apdu_access_rule) => apdu_access_rule.allow_apdu(apdu_header),
            AccessPolicy::PrivilegedCaller => true,
        }
    }

    /// Returns true iff the caller has access to all applets and to reset the SE.
    pub fn privileged_caller(&self) -> bool {
        matches!(self, AccessPolicy::PrivilegedCaller)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

/// A non-repeating ID to track a single client's use of a channel.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientChannelId(pub u64);

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
    sessions: HashMap<SessionId, Vec<ClientChannelId>>,
    session_id_counter: u64,
    client_channel_id_counter: u64,
    client_channel_id_map: HashMap<ClientChannelId, ChannelId>,
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
            client_channel_id_counter: 0,
            client_channel_id_map: HashMap::new(),
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
        self.session_id_counter = self.session_id_counter.checked_add(1).ok_or_else(|| {
            Status::new_exception_str(
                ILLEGAL_STATE,
                Some("Too many sessions opened; counter overflow"),
            )
        })?;

        trace!("Opened {session_id:?}");
        Ok(session_id)
    }

    pub fn open_basic_channel(
        &mut self,
        session_id: SessionId,
        aid: &[u8],
        p2: i8,
    ) -> Result<(Option<ClientChannelId>, AccessPolicy)> {
        self.open_channel_internal(ChannelType::Basic, session_id, aid, p2)
            .inspect_err(|err| self.close_on_ioerror(err))
    }

    pub fn open_logical_channel(
        &mut self,
        session_id: SessionId,
        aid: &[u8],
        p2: i8,
    ) -> Result<(Option<ClientChannelId>, AccessPolicy)> {
        self.open_channel_internal(ChannelType::Logical, session_id, aid, p2)
            .inspect_err(|err| self.close_on_ioerror(err))
    }

    /// Get the response returned by the SELECT command sent when the specified channel was
    /// opened, if any.
    pub fn select_response(&self, client_channel_id: ClientChannelId) -> Option<&[u8]> {
        self.client_channel_id_map
            .get(&client_channel_id)
            .and_then(|channel_id| self.terminal.select_response(*channel_id))
    }

    /// Transmit the specified `apdu` on the specified channel.  If `privileged_caller` is true,
    /// privileged APDUs will be allowed.
    pub fn transmit_on_channel(
        &mut self,
        client_channel_id: ClientChannelId,
        apdu: &[u8],
        privileged_caller: bool,
    ) -> Result<ApduResponse> {
        let channel_id = self.client_channel_id_map.get(&client_channel_id);
        let Some(channel_id) = channel_id else {
            return binder_exception(ILLEGAL_STATE, &format!("{client_channel_id:?} is closed."));
        };
        self.terminal
            .transmit(*channel_id, apdu, privileged_caller)
            .inspect_err(|e| self.close_on_ioerror(e))
    }

    /// Close the specified channel, first selecting the default applet if the channel is
    /// [`ChannelId::BASIC`] and `send_select` is `true`.
    pub fn close_channel(
        &mut self,
        client_channel_id: ClientChannelId,
        send_select: SendSelectOnClose,
    ) -> Result<()> {
        self.sessions.iter_mut().for_each(|(_, client_channel_ids)| {
            client_channel_ids.retain(|id| *id != client_channel_id)
        });
        if let Some(channel_id) = self.client_channel_id_map.remove(&client_channel_id) {
            self.terminal.close_channel(channel_id, send_select)
        } else {
            Ok(())
        }
    }

    /// Close all open channels on the specified session.  If the [`ChannelId::BASIC`] channel is
    /// open and `send_select` is `true`, the default applet will be selected.
    pub fn close_session_channels(&mut self, id: SessionId, send_select: SendSelectOnClose) {
        let mut tmp = Vec::new();
        if let Some(client_channel_ids) = self.sessions.get_mut(&id) {
            std::mem::swap(client_channel_ids, &mut tmp);
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
    pub fn is_channel_closed(&mut self, client_channel_id: ClientChannelId) -> bool {
        !self.client_channel_id_map.contains_key(&client_channel_id)
    }

    /// Returns true iff the specified session has been closed.
    pub fn is_session_closed(&self, session_id: SessionId) -> bool {
        !self.sessions.contains_key(&session_id)
    }

    /// Returns true iff the specified channel is the basic channel.
    pub fn is_basic_channel(&self, client_channel_id: ClientChannelId) -> bool {
        self.client_channel_id_map
            .get(&client_channel_id)
            .is_some_and(|channel_id| channel_id.is_basic())
    }

    /// Reset (reboot, essentially) the SE.
    pub fn reset(&self) -> Result<bool> {
        if !self.system_services.is_caller_privileged()? {
            return binder_exception(SECURITY, "Caller is not authorized to reset SE");
        }
        // TODO: Find out whether this needs to clean up sessions/channels.
        Ok(self.terminal.reset())
    }

    fn open_channel_internal(
        &mut self,
        channel_type: ChannelType,
        session_id: SessionId,
        aid: &[u8],
        p2: i8,
    ) -> Result<(Option<ClientChannelId>, AccessPolicy)> {
        let policy = self.get_access_policy(aid)?;
        let channel_id = match channel_type {
            ChannelType::Basic => self.terminal.open_basic_channel(aid, p2)?,
            ChannelType::Logical => self.terminal.open_logical_channel(aid, p2)?,
        };

        if let Some(channel_id) = channel_id {
            let Some(session) = self.sessions.get_mut(&session_id) else {
                return binder_exception(ILLEGAL_STATE, &format!("{session_id:?} is closed."));
            };
            let client_channel_id = ClientChannelId(self.client_channel_id_counter);
            self.client_channel_id_map.insert(client_channel_id, channel_id);
            session.push(client_channel_id);
            self.client_channel_id_counter =
                self.client_channel_id_counter.checked_add(1).ok_or_else(|| {
                    Status::new_exception_str(
                        ILLEGAL_STATE,
                        Some("Too many channels opened; counter overflow"),
                    )
                })?;
            Ok((Some(client_channel_id), policy))
        } else {
            Ok((None, policy))
        }
    }

    fn close_channel_ids(
        &mut self,
        client_channel_ids: Vec<ClientChannelId>,
        send_select: SendSelectOnClose,
    ) {
        // sort() and rev() are used so we close the basic channel last.
        let mut channel_ids = client_channel_ids
            .iter()
            .filter_map(|client_channel_id| self.client_channel_id_map.remove(client_channel_id))
            .collect::<Vec<ChannelId>>();
        channel_ids.sort();
        for id in channel_ids.into_iter().rev() {
            let _ = self.terminal.close_channel(id, send_select);
        }
    }

    fn on_state_change(&mut self, connected: bool, debug_reason: &str) {
        info!("on_state_change: connected: {connected} reason: {debug_reason}");

        self.terminal.set_connected(connected);

        // The Java OMAPI service starts the process of initializing the access enforcer when
        // onStateChange() occurs, reading rules from the ARA applet.  We instead defer reading of
        // rules to the first app that tries to talk to the SE which isn't authorized by platform
        // rules.  This is because the first apps that try to use the SE are probably authorized
        // by platform rules and there's no reason to make them wait while SE rules are read.
        //
        // Note that the Java service doesn't even start running until the first app tries to use
        // it, meaning the first such app always has to wait for rules to be read so this
        // difference in strategy won't impose any surprising latency on existing clients.

        info!("Reader {} state change, resetting ACE", self.terminal.name());
        self.access_enforcer.reset();
    }

    fn get_access_policy(&mut self, aid: &[u8]) -> Result<AccessPolicy> {
        let client_id = self.system_services.get_client_id()?;
        if self.system_services.is_caller_privileged()? {
            trace!("Caller is privileged, allowing all APDUs, to all applets");
            return Ok(AccessPolicy::PrivilegedCaller);
        }

        // Special case:  If we haven't read the applet rules yet but the platform rules allow
        // the access, use that result without waiting to read ARA rules.
        if !self.access_enforcer.have_applet_rules() {
            trace!("No applet rules, checking platform rules.");
            if let Ok(apdu_policy) = self.access_enforcer.get_policy(aid, &client_id) {
                trace!("Platform rules allowed");
                return Ok(AccessPolicy::Normal(apdu_policy.clone()));
            }
            trace!("Platform rules didn't allow");
        }

        // Normal case: Update the rule cache before retrieving policy.
        self.update_rules()?;
        Ok(AccessPolicy::Normal(self.access_enforcer.get_policy(aid, &client_id)?))
    }

    /// Update the rule cache.    In most cases this is relatively quick, requiring one APDU
    /// exchange to check that the refresh tag has not changed.  If the rules have changed, it
    /// will take longer.
    fn update_rules(&mut self) -> Result<()> {
        // The AccessEnforcer swapping is a workaround for the borrow checker's conservatism.
        let mut tmp = AccessEnforcer::new(
            // Security profile values don't matter; this is just a placeholder.
            SeSecurityProfile { full_access: true, use_ara_applet: false },
            vec![],
        );
        std::mem::swap(&mut self.access_enforcer, &mut tmp);
        tmp.update_rule_cache(&mut self.terminal)?;
        std::mem::swap(&mut self.access_enforcer, &mut tmp);

        Ok(())
    }

    #[cfg(test)]
    pub fn get_open_sessions(&self) -> HashMap<SessionId, Vec<ClientChannelId>> {
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
