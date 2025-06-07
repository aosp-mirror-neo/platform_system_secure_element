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

//! This module defines a trait that provides information from the system.

pub use crate::ara::{Rule, Sha1DigestOrUuid, Sha256Digest};
use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElement::ISecureElement;
use binder::{Result, Strong};
use bssl_crypto::digest::{InsecureSha1, Sha256};
use itertools::Itertools;
use std::fmt::Display;

/// Newtype to specify whether to wait for an SE HAL service to become available.
pub struct WaitForReader(pub bool);

/// Trait that provides access to system services needed by libse_service.
#[mockall::automock]
pub trait SystemServices: std::fmt::Debug + Send + Sync {
    /// Returns an SE HAL binder object for the specified SE name.  If `wait` is true, will wait
    /// until the SE HAL is available (potentially waiting forever).
    fn get_se_hal(&self, se_name: &str, wait: WaitForReader) -> Result<Strong<dyn ISecureElement>>;

    /// Returns the UUID(s) and certificate hash(es) of the calling device application.
    fn get_client_id(&self) -> Result<ClientId>;

    /// Returns [`ClientId`]s for teach of the provided set of package names, for the specified user ID.
    fn get_client_ids_for_packages(
        &self,
        package_names: &[String],
        user_id: i32,
    ) -> Result<Vec<ClientId>>;

    /// Returns the platform security configuration.
    fn get_security_profile(&self) -> SeSecurityProfile;

    /// Returns the platform security rules for the specified SE
    fn get_platform_rules(&self, se_name: &str) -> Result<Vec<Rule>>;
}

#[derive(Debug, Clone, Copy)]
/// [`SeSecurityProfile`] defines overall policy for access control to SE applets.  In general,
/// policy is default-deny.  That is, if there isn't some policy that allows an app to access an
/// applet, it may not.
pub struct SeSecurityProfile {
    /// If true, rules are read from the ARA applet and may provide access.
    pub use_ara_applet: bool,
    /// If true, all access is allowed.
    pub full_access: bool,
}

/// Android package information bundle, used to describe a caller.
pub struct PackageInfo {
    /// Package name.
    pub package_name: String,
    /// SHA1 hashes of APK signing certificates.
    pub sha1s: Vec<Sha1DigestOrUuid>,
    /// SHA256 hashes of APK signing certificates.
    pub sha256s: Vec<Sha256Digest>,
}

impl Display for PackageInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "package_name: {}, sha1s: [{}], sha256s: [{}]",
            self.package_name,
            self.sha1s.iter().map(hex::encode).join(", "),
            self.sha256s.iter().map(hex::encode).join(", ")
        )
    }
}

impl PackageInfo {
    /// Create package info by hashing a set of certificates.
    pub fn new<I>(package_name: String, cert_iter: I) -> Self
    where
        I: Iterator<Item = Vec<u8>>,
    {
        let (sha1s, sha256s) = cert_iter
            .map(|cert| ({ InsecureSha1::hash(&cert).into() }, { Sha256::hash(&cert).into() }))
            .unzip();
        PackageInfo { package_name, sha1s, sha256s }
    }
}

/// Enum that describes the way OMAPI callers may be identified for access control.
pub enum ClientId {
    /// Caller identity expressed as a set of Android package information bundles.
    PackageInfo(Vec<PackageInfo>),
    /// Caller identity expressed as UUIDs.
    Uuids(Vec<Sha1DigestOrUuid>),
}

impl Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientId::PackageInfo(package_infos) => {
                write!(
                    f,
                    "package_info:\n{}",
                    package_infos.iter().map(PackageInfo::to_string).join("\n"),
                )
            }
            ClientId::Uuids(uuids) => {
                write!(f, "system_uuid: [{}]", uuids.iter().map(hex::encode).join("\n"))
            }
        }
    }
}
