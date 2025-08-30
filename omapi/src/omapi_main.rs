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

//! This module implements ISecureElementService, which provides GP OMAPI.

use log::{error, info};
use omapi::{initialize_logging, is_debuggable_build, AndroidSystemServices, SecureElementService};
use std::{panic, sync::Arc};

const VSTABLE_SECURE_ELEMENT_SERVICE: &str = "android.se.omapi.ISecureElementService/default";

fn main() -> binder::Result<()> {
    initialize_logging(/* tag */ "omapi", is_debuggable_build());

    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    info!("SecureElementService is starting.");

    binder::ProcessState::start_thread_pool();

    let se_service =
        SecureElementService::new_native_binder(Arc::new(AndroidSystemServices::new()?));
    binder::add_service(VSTABLE_SECURE_ELEMENT_SERVICE, se_service.as_binder())?;

    info!("Service added, joining threadpool");

    binder::ProcessState::join_thread_pool();
    Ok(())
}
