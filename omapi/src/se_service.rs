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

use crate::{
    aidl_reader::AidlReader,
    reader::Reader,
    system_services::{SystemServices, WaitForReader},
    utils::{binder_exception, create_exception_status, TraceResultExt},
};
use android_se_omapi::aidl::android::se::omapi::{
    ISecureElementReader::ISecureElementReader,
    ISecureElementService::{BnSecureElementService, ISecureElementService},
};
use binder::{ExceptionCode::ILLEGAL_ARGUMENT, Result, Strong};
use log::{debug, info, trace};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

const ESE_PREFIX: &str = "eSE";
const SIM_PREFIX: &str = "SIM";

struct ReaderRefs {
    reader_arc: Arc<Mutex<Reader>>,
    binder_ref: Strong<dyn ISecureElementReader>,
}

#[derive(Debug, EnumIter)]
enum ReaderType {
    ExternalSe,
    Sim,
}

impl ReaderType {
    fn prefix(&self) -> &str {
        match self {
            ReaderType::ExternalSe => ESE_PREFIX,
            ReaderType::Sim => SIM_PREFIX,
        }
    }

    fn wait_for_first(&self) -> bool {
        match self {
            ReaderType::ExternalSe => !cfg!(feature = "sim_not_required"),
            ReaderType::Sim => !cfg!(feature = "ese_not_required"),
        }
    }
}

/// [`SecureElementService`]` implements the secure element service.  It allows clients to query
/// for the list of available [`Reader`]s and retrieve one, and to query whether a client should
/// be allowed to receive NFC events related to a reader and AID.  It's also responsible for
/// enumerating the available [`Reader`]s on startup.
pub struct SecureElementService {
    readers: HashMap<String, ReaderRefs>,
}

impl SecureElementService {
    /// Creates a new [`SecureElementService`] and enumerates all available Secure Element
    /// readers.
    pub fn new_native_binder(
        system_services: Arc<dyn SystemServices>,
    ) -> Strong<dyn ISecureElementService> {
        info!("Enumerating readers");

        let mut readers = HashMap::new();
        for reader_type in ReaderType::iter() {
            readers.extend(enumerate_readers(reader_type, &system_services));
        }
        debug!("Done enumerating readers, found: {:?}", readers.keys());

        BnSecureElementService::new_binder(
            SecureElementService { readers },
            binder::BinderFeatures::default(),
        )
    }
}

impl binder::Interface for SecureElementService {}

impl ISecureElementService for SecureElementService {
    fn getReaders(&self) -> Result<Vec<String>> {
        Ok(self.readers.keys().cloned().collect()).trace("getReaders")
    }

    fn getReader(&self, reader: &str) -> Result<Strong<dyn ISecureElementReader>> {
        self.readers
            .get(reader)
            .map(|se_binder| se_binder.binder_ref.clone())
            .ok_or_else(|| create_invalid_reader_exception(reader))
    }

    fn isNfcEventAllowed(
        &self,
        reader: &str,
        aid: Option<&[u8]>,
        package_names: Option<&[Option<String>]>,
        user_id: i32,
    ) -> Result<Option<Vec<bool>>> {
        let package_names = filter_out_none_or_empty(package_names.unwrap_or_default());
        if package_names.is_empty() {
            return binder_exception(ILLEGAL_ARGUMENT, "No package names specified");
        }

        let result = self
            .readers
            .get(reader)
            .ok_or_else(|| create_invalid_reader_exception(reader))?
            .reader_arc
            .lock()
            .unwrap()
            .is_nfc_event_allowed(aid, &package_names, user_id)
            .trace("isNfcEventAllowed")?;
        Ok(Some(result))
    }
}

fn enumerate_readers(
    reader_type: ReaderType,
    system_services: &Arc<dyn SystemServices>,
) -> HashMap<String, ReaderRefs> {
    let mut result = HashMap::new();
    let mut index = 1;

    loop {
        let name = build_reader_name(reader_type.prefix(), index);
        info!("Checking if terminal {name} is available (index: {index}).");

        let wait = if index == 1 && reader_type.wait_for_first() {
            info!("Reader of type {reader_type:?} is required");
            true
        } else {
            false
        };

        match Reader::new_arc(&name, WaitForReader(wait), system_services.clone()) {
            Ok(reader_arc) => {
                trace!("Added reader {name}");
                let binder_ref = AidlReader::new_native_binder(reader_arc.clone());
                result.insert(name, ReaderRefs { reader_arc, binder_ref });
                index += 1;
            }
            Err(e) => {
                // TODO: Distinguish between "doesn't exist" and "binder error".
                info!("Got error {e} checking terminal {name}");
                return result;
            }
        }
    }
}

fn build_reader_name(name_prefix: &str, index: usize) -> String {
    format!("{name_prefix}{index}")
}

fn filter_out_none_or_empty(package_names: &[Option<String>]) -> Vec<String> {
    package_names
        .iter()
        .filter_map(|name_opt| match name_opt {
            Some(name) if !name.is_empty() => Some(name.clone()),
            _ => None,
        })
        .collect()
}

fn create_invalid_reader_exception(reader: &str) -> binder::Status {
    create_exception_status(ILLEGAL_ARGUMENT, &format!("Reader: {reader} not supported."))
}
