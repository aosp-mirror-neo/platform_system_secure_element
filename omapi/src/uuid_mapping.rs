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

//! This module provides a simple parser for HAL UUID mapping files.
//!
//! There doesn't seem to be a formal schema for the files, but they serve to define how to
//! translate Android Linux uids to UUID values that can be matched against ARA rules.  They look
//! like this:
//!
//! ```xml
//! <ref_do>
//!   <uuid_ref_do>
//!     <uids>
//!       <uid>0</uid>
//!     </uids>
//!     <uuid>9f36407ead0639fc966f14dde7970f68</uuid>
//!   </uuid_ref_do>
//!
//!   <uuid_ref_do>
//!     <uids>
//!         <uid>2901</uid>
//!         <uid>2902</uid>
//!         <uid>2903</uid>
//!     </uids>
//!     <uuid>636F6D2E6E78702E7365637572697479</uuid>
//!   </uuid_ref_do>
//! </ref_do>
//! ```
//!
//! The UUIDs are 16 bytes, as per the UUID standard.  GP ARA rules require 20-byte UUIDs, so the
//! UUIDs in the file are prefixed with "ffffffff" to make them 20 bytes.
//!
//! If a uid is mapped to multiple UUIDs, all UUIDs will be used.

use hex::FromHexError;
use serde::Deserialize;
use serde_xml_rs::from_reader;
use std::{
    array::TryFromSliceError,
    io::{BufReader, Read},
};
use thiserror::Error;

#[cfg(test)]
mod test;

/// Error type for [`parse_uuid_mappings`].
#[derive(Error, Debug)]
pub enum UuidError {
    /// Errors found while parsing XML
    #[error("Error parsing XML: {0}")]
    XmlError(#[from] serde_xml_rs::Error),
    /// Errors found while converting from hex to binary bytes.
    #[error("Error parsing hexadecimal UUID: {0}")]
    HexError(#[from] FromHexError),
    /// Errors found while trying to convert variable length arrays to fixed-length arrays.
    #[error("UUID length invalid; must by 16 bytes, or 32 hex digits.")]
    InvalidUuidLength(#[from] TryFromSliceError),
}

/// Struct to hold UID to UUID mappings
#[derive(Debug)]
pub struct UuidMapping {
    /// The mapped UIDs
    pub uids: Vec<i32>,
    /// The UUID mapped to.
    pub uuid: [u8; 20],
}

/// Parse UID to UUID mappings from the provided reader (file or whatever).
pub fn parse_uuid_mappings<R: Read>(reader: R) -> Result<Vec<UuidMapping>, UuidError> {
    let readable = BufReader::new(reader);
    let ref_do: RefDo = from_reader(readable)?;

    ref_do
        .uuid_ref_do
        .into_iter()
        .map(|entry| {
            Ok(UuidMapping {
                uids: entry.uids.uid.iter().map(|uid| uid.0).collect(),
                uuid: string_to_uuid(entry.uuid.0)?,
            })
        })
        .collect()
}

fn string_to_uuid(uuid: String) -> Result<[u8; 20], UuidError> {
    let uuid_bytes = hex::decode("ffffffff".to_owned() + &uuid.replace(['-'], ""))?;
    Ok(uuid_bytes.as_slice().try_into()?)
}

#[derive(Debug, Deserialize)]
#[serde(rename = "ref_do")]
struct RefDo {
    uuid_ref_do: Vec<UuidRefDo>,
}

#[derive(Debug, Deserialize)]
struct UuidRefDo {
    uids: Uids,
    uuid: Uuid,
}

#[derive(Debug, Deserialize)]
struct Uids {
    uid: Vec<Uid>,
}

#[derive(Debug, Deserialize)]
struct Uid(i32);

#[derive(Debug, Deserialize)]
struct Uuid(String);
