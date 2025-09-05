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

//! This module provides an Android-specific implementation of the [`SystemServices`] trait.

use crate::{
    ara::{parse_xml_rules, Rule, Sha1DigestOrUuid},
    system_services::{ClientId, PackageInfo, SeSecurityProfile, SystemServices, WaitForReader},
    utils::create_exception_status,
    uuid_mapping::{parse_uuid_mappings, UuidMapping},
};
use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElement::ISecureElement;
use binder::{binder_impl::IBinderInternal, ExceptionCode::ILLEGAL_ARGUMENT, Result, Strong};
use itertools::Itertools;
use log::{debug, error, info, trace, warn};
use packagemanager_aidl::aidl::android::content::pm::{
    IPackageManagerNative::IPackageManagerNative, PackageInfoNative::PackageInfoNative,
};
use rustutils::android::system_properties;
use std::{fs::File, sync::Mutex};

#[cfg(test)]
mod test;

const DEBUG_BUILD_PROPERTY: &str = "ro.debuggable";
const PACKAGE_MANAGER_NATIVE_SERVICE: &str = "package_native";
const PROP_PRODUCT_HARDWARE_SKU: &str = "ro.boot.product.hardware.sku";
const PROP_SE_PERSIST_SECURITY_PROFILE: &str = "persist.service.seek";
const PROP_SE_SECURITY_PROFILE: &str = "service.seek";
const PLATFORM_CONFIG_PATHS: [&str; 3] = ["/odm/etc/", "/vendor/etc/", "/etc/"];
const UUID_MAPPING_CONFIG_PREFIX: &str = "hal_uuid_map_";
const UUID_MAPPING_CONFIG_SUFFIX: &str = ".xml";
const PLATFORM_RULES_PREFIX: &str = "se_access_rules_";
const PLATFORM_RULES_SUFFIX: &str = ".xml";

/// Value returned from checkPermission if the specified package has the specified permission.
///
/// See `PackageManager#PERMISSION_GRANTED` in
/// `frameworks/base/core/java/android/content/pm/PackageManager.java`.
const PERMISSION_GRANTED: i32 = 0;

/// Range of uids allocated for an Android user.
///
/// See `UserHandle#PerUserRange` in `frameworks/base/core/java/android/os/UserHandle.java`.
const PER_USER_RANGE: i32 = 100_000;

#[derive(Debug)]
struct AndroidSystemServicesData {
    /// Cached [`IPackageManagerNative`] binder handle.  Mutex-protected because it may be
    /// accessed from many threads, and may potentially need interior mutability to update the
    /// cached reference.
    package_manager: Mutex<Option<Strong<dyn IPackageManagerNative>>>,

    /// UUID mappings, read during startup.  No Mutex required because it's immutable.
    uuid_mapping: Vec<UuidMapping>,
}

/// [`AndroidSystemServices`] implements [`SystemServices`] using Android system features.
#[derive(Debug)]
pub struct AndroidSystemServices(AndroidSystemServicesData);

impl AndroidSystemServices {
    /// Creates a new [`AndroidSystemServices`] instance.
    pub fn new() -> Result<Self> {
        Ok(AndroidSystemServices(AndroidSystemServicesData {
            package_manager: Mutex::new(None),
            uuid_mapping: read_uuid_mappings()?,
        }))
    }
}

impl AndroidSystemServicesData {
    fn get_package_manager(&self) -> binder::Result<Strong<dyn IPackageManagerNative>> {
        let mut pm_opt = self.package_manager.lock().unwrap();
        if pm_opt.is_none() || !pm_opt.as_ref().unwrap().as_binder().is_binder_alive() {
            trace!("Getting PackageManagerNative if available");
            // We use [`binder::check_interface`] because the PackageManager is not available
            // during early boot and blocking here would block all early usage of OMAPI.
            let pm: Strong<dyn IPackageManagerNative> =
                binder::check_interface(PACKAGE_MANAGER_NATIVE_SERVICE).inspect_err(|e| {
                    warn!("Couldn't get PackageManager because {e}. This is normal during boot.")
                })?;
            *pm_opt = Some(pm);
        }
        Ok(pm_opt.as_ref().unwrap().clone())
    }

    fn get_caller_package_info(&self, caller_uid: i32) -> Vec<PackageInfo> {
        self.get_package_manager()
            .map(|package_manager| -> Vec<PackageInfo> {
                trace!("Getting package info for {caller_uid}");
                package_manager
                    .getPackageInfoWithSigningInfoForUid(caller_uid)
                    .inspect(|pkg_info| trace!("Got package info: {pkg_info:?}"))
                    .inspect_err(|e| trace!("Got error {e}"))
                    .unwrap_or(None)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(convert_native_package_info)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn get_caller_uuids(&self, caller_uid: i32) -> Vec<Sha1DigestOrUuid> {
        self.uuid_mapping
            .iter()
            .filter_map(|entry| {
                entry.uids.contains(&caller_uid).then_some(Sha1DigestOrUuid(entry.uuid))
            })
            .sorted()
            .dedup()
            .collect()
    }

    fn is_uid_privileged(&self, caller_uid: i32) -> Result<bool> {
        let Ok(package_manager) = self.get_package_manager() else {
            // Assume unprivileged if PackageManager is unavailable.
            return Ok(false);
        };

        let package_names: Vec<String> = package_manager.getNamesForUids(&[caller_uid])?;

        if package_names.is_empty() {
            info!("No packages found for UID {caller_uid}");
            return Ok(false);
        }

        for package_name in package_names {
            match package_manager.checkPermission(
                "android.permission.SECURE_ELEMENT_PRIVILEGED_OPERATION",
                &package_name,
                caller_uid / PER_USER_RANGE,
            ) {
                Err(e) => {
                    error!("Error checking permission for package {package_name}: {e}");
                    return Err(e);
                }
                Ok(PERMISSION_GRANTED) => {
                    info!("Package {package_name} is privileged.");
                    return Ok(true);
                }
                _ => {}
            }
        }

        trace!("No privileged packages found for UID {caller_uid}");
        Ok(false)
    }
}

impl SystemServices for AndroidSystemServices {
    fn get_se_hal(
        &self,
        name: &str,
        wait: WaitForReader,
    ) -> binder::Result<Strong<dyn ISecureElement>> {
        let service_name = &format!("android.hardware.secure_element.ISecureElement/{name}");

        // Only wait if asked and if the service is declared in the manifest.
        let wait = wait.0 && binder::is_declared(service_name)?;

        if wait {
            debug!("Waiting for service {service_name}");
            Ok(binder::wait_for_interface(service_name)?)
        } else {
            debug!("Checking for service {service_name}");
            Ok(binder::check_interface(service_name)?)
        }
    }

    fn get_security_profile(&self) -> SeSecurityProfile {
        if is_debuggable_build() {
            // For eng and userdebug builds we potentially skip/avoid ARA, depending on some
            // system properties.
            let non_persist_profile = system_properties::read(PROP_SE_SECURITY_PROFILE)
                .unwrap_or(None)
                .unwrap_or("useara usearf".to_owned());
            let profile = system_properties::read(PROP_SE_PERSIST_SECURITY_PROFILE)
                .unwrap_or(None)
                .unwrap_or(non_persist_profile);

            let use_ara_applet = profile.contains("useara");
            let full_access = profile.contains("fullaccess");

            info!("This is a debug build.  Per system property configuration, use_ara={use_ara_applet}, full_access={full_access}.");
            SeSecurityProfile { use_ara_applet, full_access }
        } else {
            // Release builds must apply security rules.
            SeSecurityProfile { use_ara_applet: true, full_access: false }
        }
    }

    fn get_client_id(&self) -> binder::Result<ClientId> {
        let caller_uid = get_caller_uid_i32()?;

        let uuids = self.0.get_caller_uuids(caller_uid);
        if uuids.is_empty() {
            Ok(ClientId::PackageInfo(self.0.get_caller_package_info(caller_uid)))
        } else {
            Ok(ClientId::Uuids(uuids))
        }
    }

    fn get_client_ids_for_packages(
        &self,
        package_names: &[String],
        user_id: i32,
    ) -> Result<Vec<ClientId>> {
        let package_manager: Strong<dyn IPackageManagerNative> = self
            .0
            .get_package_manager()
            .inspect_err(|e| error!("Unable to get package manager because {e}."))?;

        package_names
            .iter()
            .map(|name| {
                let native_package_info = package_manager
                    .getPackageInfoWithSigningInfo(name, user_id)?
                    .ok_or(create_exception_status(ILLEGAL_ARGUMENT, "No package info"))?;
                let package_info = convert_native_package_info(native_package_info);
                Ok(ClientId::PackageInfo(vec![package_info]))
            })
            .collect()
    }

    fn get_platform_rules(&self, se_name: &str) -> Result<Vec<Rule>> {
        let rules_file_name = format!("{PLATFORM_RULES_PREFIX}{se_name}{PLATFORM_RULES_SUFFIX}");

        let mut result = Vec::new();
        for entry in config_files(&rules_file_name) {
            let Some((path, file)) = entry? else { continue };

            info!("Parsing platform rules file: {path}");

            match parse_xml_rules(file) {
                Ok(rule_set) => {
                    for xml_rule in rule_set.ref_ar_do {
                        match Rule::from_xml(xml_rule) {
                            Ok(ara_rule) => result.push(ara_rule),
                            Err(e) => error!("Error converting XML access rule in {path}: {e}"),
                        }
                    }
                }
                Err(e) => error!("Error parsing XML access rules in {path}: {e}"),
            }
        }
        Ok(result)
    }

    fn is_caller_privileged(&self) -> Result<bool> {
        self.0.is_uid_privileged(get_caller_uid_i32()?)
    }
}

/// Returns true if the current build is debuggable.
pub fn is_debuggable_build() -> bool {
    system_properties::read_bool(DEBUG_BUILD_PROPERTY, false).unwrap_or(false)
}

fn convert_native_package_info(info: PackageInfoNative) -> PackageInfo {
    let pkg_name = info.packageName;
    let cert_list = info.signingInfo.unwrap_or_default().apkContentSigners;
    PackageInfo::new(pkg_name, cert_list.into_iter().map(|cert| cert.signature))
}

fn read_uuid_mappings() -> Result<Vec<UuidMapping>> {
    let product_sku = system_properties::read(PROP_PRODUCT_HARDWARE_SKU)
        .unwrap_or(None)
        .unwrap_or("config".to_owned());
    let config_file_name =
        format!("{UUID_MAPPING_CONFIG_PREFIX}{product_sku}{UUID_MAPPING_CONFIG_SUFFIX}");

    let mut result = Vec::new();
    for entry in config_files(&config_file_name) {
        let Some((path, file)) = entry? else { continue };
        info!("Parsing UUID mapping file: {path}");
        match parse_uuid_mappings(file) {
            Ok(mappings) => result.extend(mappings),
            Err(e) => error!("Error parsing UUID mapping file {path}: {e}"),
        }
    }
    Ok(result)
}

fn config_files(file_name: &str) -> impl Iterator<Item = Result<Option<(String, File)>>> + use<'_> {
    PLATFORM_CONFIG_PATHS.iter().map(move |config_path| {
        let path = format!("{config_path}{file_name}");
        match File::open(&path) {
            Ok(file) => Ok(Some((path, file))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!("No config file found at {path}");
                Ok(None)
            }
            Err(e) => {
                error!("Error attempting to open config file {path}: {e}");
                Ok(None)
            }
        }
    })
}

fn get_caller_uid_i32() -> Result<i32> {
    binder::ThreadState::get_calling_uid().try_into().map_err(|uid| {
        // This can only happen if the UID cannot be represented in [`i32`].
        create_exception_status(ILLEGAL_ARGUMENT, &format!("Invalid UID {uid}"))
    })
}
