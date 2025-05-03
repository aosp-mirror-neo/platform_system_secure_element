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

//! libse_service implements the core functionality of an OMAPI service for Android.

#![deny(missing_docs)]

mod access_enforcer;
mod aidl_channel;
mod aidl_reader;
mod aidl_session;
mod android_system_services;
mod ara;
mod reader;
mod se_service;
mod system_services;
mod terminal;
mod utils;
mod uuid_mapping;

pub use android_system_services::{is_debuggable_build, AndroidSystemServices};
pub use se_service::SecureElementService;

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_utils;
