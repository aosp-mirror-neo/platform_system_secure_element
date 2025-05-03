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

//! This module implements the [`ISecureElementReader`] binder interface, implemented in the
//! [`AidlReader`] type which serves only as wrapper around a [`Reader`].
//!
//! [`Reader`] is the component that provides access to the SE and implements the access control
//! logic to determine which Android apps are allowed to communicate with which SE applets.  The
//! [`AidlSession`] and [`AidlChannel`] objects implement [`ISecureElementSession`] and
//! [`ISecureElementChannel`], respectively, using a [`Reader`] through the threadsafe
//! [`Arc<Mutex<Reader>`] they hold.

use crate::{
    aidl_session::AidlSession, reader::Reader, terminal::SendSelectOnClose, utils::TraceResultExt,
};
use android_se_omapi::aidl::android::se::omapi::{
    ISecureElementReader::{BnSecureElementReader, ISecureElementReader},
    ISecureElementSession::ISecureElementSession,
};
use binder::{BinderFeatures, Result, Strong, ThreadState};
use log::trace;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone)]
pub struct AidlReader {
    reader: Arc<Mutex<Reader>>,
}

impl AidlReader {
    pub fn new_native_binder(reader: Arc<Mutex<Reader>>) -> Strong<dyn ISecureElementReader> {
        BnSecureElementReader::new_binder(AidlReader { reader }, BinderFeatures::default())
    }

    fn reader(&self) -> MutexGuard<'_, Reader> {
        self.reader.lock().unwrap()
    }

    fn trace_caller(&self, method: &str) {
        trace!(
            "ISecureElementReader::{} called by {}:{}",
            method,
            ThreadState::get_calling_uid(),
            ThreadState::get_calling_pid(),
        );
    }
}

impl binder::Interface for AidlReader {}

impl ISecureElementReader for AidlReader {
    fn isSecureElementPresent(&self) -> Result<bool> {
        self.trace_caller("isSecureElementPresent");
        self.reader().is_secure_element_present().trace("isSecureElementPresent")
    }

    fn openSession(&self) -> Result<Strong<dyn ISecureElementSession>> {
        self.trace_caller("openSession");
        let session_id = self.reader().open_session()?;
        Ok(AidlSession::new_native_binder(self.reader.clone(), session_id))
    }

    fn closeSessions(&self) -> Result<()> {
        self.trace_caller("closeSessions");
        self.reader().close_sessions(SendSelectOnClose(true));
        Ok(())
    }

    fn reset(&self) -> Result<bool> {
        self.trace_caller("reset");
        Ok(self.reader().reset()).trace("reset")
    }
}
