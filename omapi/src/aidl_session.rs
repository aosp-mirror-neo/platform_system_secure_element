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

//! This module implements the [`ISecureElementSession`] binder interface, delegating all actual
//! work to the contained [`Reader`].

use crate::{
    aidl_channel::AidlChannel,
    reader::{Reader, SessionId},
    terminal::SendSelectOnClose,
    utils::TraceResultExt,
};
use android_se_omapi::aidl::android::se::omapi::{
    ISecureElementChannel::ISecureElementChannel,
    ISecureElementListener::ISecureElementListener,
    ISecureElementSession::{BnSecureElementSession, ISecureElementSession},
};
use binder::{BinderFeatures, Result, Strong, ThreadState};
use log::trace;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct AidlSession {
    reader: Arc<Mutex<Reader>>,
    id: SessionId,
}

impl AidlSession {
    pub fn new_native_binder(
        reader: Arc<Mutex<Reader>>,
        id: SessionId,
    ) -> Strong<dyn ISecureElementSession> {
        BnSecureElementSession::new_binder(AidlSession { reader, id }, BinderFeatures::default())
    }

    fn trace_caller(&self, method: &str) {
        trace!(
            "ISecureElementSession::{} called by {}:{}",
            method,
            ThreadState::get_calling_uid(),
            ThreadState::get_calling_pid()
        );
    }
}

impl Drop for AidlSession {
    fn drop(&mut self) {
        if !self.isClosed().unwrap_or(false) {
            let _ = self.close();
        }
    }
}

impl binder::Interface for AidlSession {}

impl ISecureElementSession for AidlSession {
    fn getAtr(&self) -> Result<Option<Vec<u8>>> {
        self.trace_caller("getAtr");
        self.reader.lock().unwrap().get_atr().trace("getAtr")
    }

    fn close(&self) -> Result<()> {
        self.trace_caller("close");
        self.reader.lock().unwrap().close_session(self.id, SendSelectOnClose(true));
        Ok(()).trace("close")
    }

    fn closeChannels(&self) -> Result<()> {
        self.trace_caller("closeChannels");
        self.reader.lock().unwrap().close_session_channels(self.id, SendSelectOnClose(true));
        Ok(()).trace("closeChannels")
    }

    fn isClosed(&self) -> Result<bool> {
        self.trace_caller("isClosed");
        Ok(self.reader.lock().unwrap().is_session_closed(self.id)).trace("isClosed")
    }

    fn openBasicChannel(
        &self,
        aid: Option<&[u8]>,
        p2: i8,
        listener: &Strong<dyn ISecureElementListener>,
    ) -> Result<Option<Strong<dyn ISecureElementChannel>>> {
        self.trace_caller("openBasicChannel");
        let (channel_id, policy) = self
            .reader
            .lock()
            .unwrap()
            .open_basic_channel(self.id, aid.unwrap_or_default(), p2)
            .trace("openBasicChannel")?;
        Ok(channel_id
            .map(|id| AidlChannel::new_native_binder(self.reader.clone(), id, policy, listener)))
    }

    fn openLogicalChannel(
        &self,
        aid: Option<&[u8]>,
        p2: i8,
        listener: &Strong<dyn ISecureElementListener>,
    ) -> Result<Option<Strong<dyn ISecureElementChannel>>> {
        self.trace_caller("openLogicalChannel");
        let (channel_id, policy) = self
            .reader
            .lock()
            .unwrap()
            .open_logical_channel(self.id, aid.unwrap_or_default(), p2)
            .trace("openLogicalChannel")?;
        Ok(channel_id
            .map(|id| AidlChannel::new_native_binder(self.reader.clone(), id, policy, listener)))
    }
}
