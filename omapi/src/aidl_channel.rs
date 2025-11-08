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

//! This module implements the [`ISecureElementChannel`] binder interface, delegating all actual
//! work to the contained [`Reader`].

use crate::{
    ara::ApduHeader,
    reader::{AccessPolicy, ClientChannelId, Reader},
    terminal::SendSelectOnClose,
    utils::{binder_exception, create_exception_status, TraceResultExt},
};
use android_se_omapi::aidl::android::se::omapi::{
    ISecureElementChannel::{BnSecureElementChannel, ISecureElementChannel},
    ISecureElementListener::ISecureElementListener,
};
use binder::{
    BinderFeatures, DeathRecipient,
    ExceptionCode::{ILLEGAL_ARGUMENT, SECURITY, UNSUPPORTED_OPERATION},
    IBinder, Result, Strong, ThreadState,
};
use log::{error, trace};
use std::sync::{Arc, Mutex, Weak};

pub struct AidlChannel {
    reader: Arc<Mutex<Reader>>,
    id: ClientChannelId,
    policy: AccessPolicy,
    _death_recipient: DeathRecipient,
}

impl AidlChannel {
    pub fn new_native_binder(
        reader: Arc<Mutex<Reader>>,
        id: ClientChannelId,
        policy: AccessPolicy,
        listener: &Strong<dyn ISecureElementListener>,
    ) -> Strong<dyn ISecureElementChannel> {
        let mut death_recipient = build_death_recipient(Arc::downgrade(&reader), id);
        if let Err(e) = listener.as_binder().link_to_death(&mut death_recipient) {
            error!("Error setting up death listener for channel: {e}");
        }
        let channel = AidlChannel { reader, id, policy, _death_recipient: death_recipient };
        BnSecureElementChannel::new_binder(channel, BinderFeatures::default())
    }

    fn trace_caller(&self, method: &str) {
        trace!(
            "ISecureElementChannel::{} called by {}:{}",
            method,
            ThreadState::get_calling_uid(),
            ThreadState::get_calling_pid()
        );
    }
}

fn build_death_recipient(
    weak_reader_ref: Weak<Mutex<Reader>>,
    id: ClientChannelId,
) -> DeathRecipient {
    DeathRecipient::new(move || {
        if let Some(reader) = weak_reader_ref.upgrade() {
            let _ = reader.lock().unwrap().close_channel(id, SendSelectOnClose(true));
        }
    })
}

impl Drop for AidlChannel {
    fn drop(&mut self) {
        if !self.isClosed().unwrap_or(false) {
            let _ = self.close();
        }
    }
}

// Implement Debug for AidlChannel.  We can't use `#[derive(Debug)]` because it contains a
// `DeathRecipient` which does not implement `Debug`.
impl std::fmt::Debug for AidlChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AidlChannel")
            .field("reader", &self.reader)
            .field("id", &self.id)
            .field("policy", &self.policy)
            .finish()
    }
}

impl binder::Interface for AidlChannel {}

impl ISecureElementChannel for AidlChannel {
    fn close(&self) -> Result<()> {
        self.trace_caller("close");
        self.reader.lock().unwrap().close_channel(self.id, SendSelectOnClose(true))
    }

    fn isClosed(&self) -> Result<bool> {
        self.trace_caller("isClosed");
        Ok(self.reader.lock().unwrap().is_channel_closed(self.id)).trace("isClosed")
    }

    fn isBasicChannel(&self) -> Result<bool> {
        self.trace_caller("isBasicChannel");
        Ok(self.reader.lock().unwrap().is_basic_channel(self.id)).trace("isBasicChannel")
    }

    fn getSelectResponse(&self) -> Result<Option<Vec<u8>>> {
        self.trace_caller("getSelectResponse");
        Ok(self.reader.lock().unwrap().select_response(self.id))
            .map(|v: Option<&[u8]>| v.map(|v: &[u8]| v.to_vec()))
            .sensitive("getSelectResponse")
    }

    fn transmit(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        self.trace_caller(&format!("transmit({})", hex::encode(apdu)));
        if self.policy.allow_apdu(&get_apdu_header(apdu)?) {
            self.reader
                .lock()
                .unwrap()
                .transmit_on_channel(self.id, apdu, self.policy.privileged_caller())
                // The copied response vector should zeroized by the binder infrastructure
                .map(|response| response.non_zeroizing_vec())
                .trace("transmit")
        } else {
            binder_exception(SECURITY, "APDU blocked by ARA policy")
        }
    }

    fn selectNext(&self) -> Result<bool> {
        // TODO: Implement this.
        binder_exception(UNSUPPORTED_OPERATION, "TODO")
    }
}

fn get_apdu_header(apdu: &[u8]) -> Result<ApduHeader> {
    let header_bytes: [u8; 4] = apdu
        .get(0..4)
        .ok_or(create_exception_status(ILLEGAL_ARGUMENT, "Too-short APDU"))?
        .try_into()
        .expect("Can't fail");
    Ok(header_bytes.into())
}
