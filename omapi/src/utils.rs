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

//! Utility functions and types, notably tools for creating binder exceptions and easy tracing of
//! return values.

use crate::terminal::{Apdu, ApduResponse};
use binder::{self, ExceptionCode, Result};
use std::error::Error;

/// SE service errors
pub enum ServiceSpecificException {
    /// IO error communicating with SE.
    IoError = 1,
    /// No such Secure Element is configured.
    NoSuchElement = 2,
    /// Secure Element is not present (e.g. SIM is not inserted).
    _SecureElementNotPresent = 3,
    /// Secure Element is not connected.
    SecureElementNotConnected = 4,
}

/// Create a [`binder::Result`] containing a service-specific exception.
pub fn service_specific_exception<T>(error: ServiceSpecificException, message: &str) -> Result<T> {
    Err(binder::Status::new_service_specific_error_str(error as i32, Some(message)))
}

/// Create a [`binder::Result`]` containing an error with the specified [`ExceptionCode`] and
/// message.
pub fn binder_exception<T>(exception_code: ExceptionCode, message: &str) -> Result<T> {
    Err(create_exception_status(exception_code, message))
}

/// Create a [`binder::Status`] with the specified [`ExceptionCode`] and message. Wrap in [`Err`]
/// to create a [`binder::Result`] (or use [`binder_exception`]).
pub fn create_exception_status(exception_code: ExceptionCode, message: &str) -> binder::Status {
    binder::Status::new_exception_str(exception_code, Some(message))
}

/// The [`sensitive`] macro is used for logging sensitive data.  It logs at
/// [`log::LevelFilter::Trace`], but only if sensitive logging is allowed, either because the
/// "log_sensitive_data" feature is enabled or because we're building in a test configuration.
#[macro_export]
macro_rules! sensitive {
    ($fmt:expr $(, $args:expr)* ) => {
        #[cfg(any(feature = "log_sensitive_data", test))]
            trace!($fmt $(, $args)*);
        }
    }

/// An object that provides a string for tracing.
trait Traceable {
    fn trace_string(&self) -> String;
}

impl Traceable for Vec<u8> {
    fn trace_string(&self) -> String {
        hex::encode(self)
    }
}

macro_rules! trace_debug {
    ($t:ty) => {
        impl Traceable for $t {
            fn trace_string(&self) -> String {
                format!("{self:?}")
            }
        }
    };
}

trace_debug!(Apdu);
trace_debug!(ApduResponse);

/// Provide an easy way to trace [`Traceable`] values that are about to be returned.  That is,
/// supposing `result` is [`Traceable`] and is being returned from a function:
///
/// ```
/// result.trace("context")
/// ```
///
/// will output `result` in a trace message, then return it.  Likewise `sensitive()` can be used
/// to trace a sensitive value, but only if sensitive logging is allowed.
pub trait TraceResultExt {
    /// Trace self, adding context string, and returns self, for additional processing.
    fn trace(self, context: &str) -> Self;

    /// Trace self as above, but only if feature `log_sensitive_data` is enabled, or if this is a
    /// test build.  In other builds, do nothing.
    fn sensitive(self, context: &str) -> Self
    where
        Self: std::marker::Sized,
    {
        if cfg!(any(feature = "log_sensitive_data", test)) {
            Self::trace(self, context)
        } else {
            self
        }
    }
}

impl<T, E> TraceResultExt for std::result::Result<T, E>
where
    T: Traceable,
    E: Error,
{
    fn trace(self, context: &str) -> Self {
        log::trace!(
            "{context} result: {}",
            match self.as_ref() {
                Ok(v) => format!("Ok({})", v.trace_string()),
                Err(e) => format!("Err({e})"),
            }
        );
        self
    }
}
