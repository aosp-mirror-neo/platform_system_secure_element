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

use super::*;
use crate::utils::binder_exception;
use binder::{BinderFeatures, ExceptionCode::ILLEGAL_STATE, Result};
use googletest::{prelude::*, test as gtest};
use mockall::{predicate as mp, Sequence};
use packagemanager_aidl::aidl::android::content::pm::IPackageManagerNative::{
    BnPackageManagerNative, MockIPackageManagerNative,
};

const PERMISSION_DENIED: i32 = -1;
const CALLER_UID: i32 = 1000;
const USER_ID: i32 = 0; // CALLER_UID / PER_USER_RANGE
const SECURE_ELEMENT_PERMISSION: &str = "android.permission.SECURE_ELEMENT_PRIVILEGED_OPERATION";

fn init() {
    crate::test_utils::init(module_path!());
}

#[gtest]
fn no_packages_for_uid() -> Result<()> {
    init();

    let services = mock_package_manager_and_services(|mock_pm, seq| {
        expect_get_names_for_uids(mock_pm, seq, Ok(vec![]));
        mock_pm.expect_checkPermission().times(0);
    });

    assert_that!(services.is_uid_privileged(CALLER_UID)?, eq(false));
    Ok(())
}

#[gtest]
fn one_package_privileged() -> Result<()> {
    init();

    let services = mock_package_manager_and_services(|mock_pm, seq| {
        expect_get_names_for_uids(mock_pm, seq, Ok(vec!["com.privileged.app"]));
        expect_check_permission(mock_pm, seq, "com.privileged.app", Ok(PERMISSION_GRANTED));
    });

    assert_that!(services.is_uid_privileged(CALLER_UID)?, eq(true));
    Ok(())
}

#[gtest]
fn one_package_not_privileged() -> Result<()> {
    init();

    let services = mock_package_manager_and_services(|mock_pm, seq| {
        expect_get_names_for_uids(mock_pm, seq, Ok(vec!["com.unprivileged.app"]));
        expect_check_permission(mock_pm, seq, "com.unprivileged.app", Ok(PERMISSION_DENIED));
    });

    assert_that!(services.is_uid_privileged(CALLER_UID)?, eq(false));
    Ok(())
}

#[gtest]
fn multiple_packages_one_is_privileged() -> Result<()> {
    init();

    let services = mock_package_manager_and_services(|mock_pm, seq| {
        let packages = vec!["com.unprivileged.app", "com.privileged.app"];
        expect_get_names_for_uids(mock_pm, seq, Ok(packages));
        expect_check_permission(mock_pm, seq, "com.unprivileged.app", Ok(PERMISSION_DENIED));
        expect_check_permission(mock_pm, seq, "com.privileged.app", Ok(PERMISSION_GRANTED));
    });

    assert_that!(services.is_uid_privileged(CALLER_UID)?, eq(true));
    Ok(())
}

#[gtest]
fn multiple_packages_none_privileged() -> Result<()> {
    init();

    let services = mock_package_manager_and_services(|mock_pm, seq| {
        expect_get_names_for_uids(mock_pm, seq, Ok(vec!["com.one.app", "com.two.app"]));
        expect_check_permission(mock_pm, seq, "com.one.app", Ok(PERMISSION_DENIED));
        expect_check_permission(mock_pm, seq, "com.two.app", Ok(PERMISSION_DENIED));
    });

    assert_that!(services.is_uid_privileged(CALLER_UID)?, eq(false));
    Ok(())
}

#[gtest]
fn check_permission_error() -> Result<()> {
    init();

    let services = mock_package_manager_and_services(|mock_pm, seq| {
        expect_get_names_for_uids(mock_pm, seq, Ok(vec!["com.one.app"]));
        let err = binder_exception(ILLEGAL_STATE, "test error");
        expect_check_permission(mock_pm, seq, "com.one.app", err);
    });

    let err = services.is_uid_privileged(CALLER_UID).unwrap_err();
    assert_that!(err.exception_code(), eq(ILLEGAL_STATE));
    assert_that!(err.get_description(), contains_substring("test error"));
    Ok(())
}

#[gtest]
fn get_names_for_uids_error() -> Result<()> {
    init();

    let services = mock_package_manager_and_services(|mock_pm, seq| {
        let err = binder_exception(ILLEGAL_ARGUMENT, "test error");
        expect_get_names_for_uids(mock_pm, seq, err);
        mock_pm.expect_checkPermission().times(0);
    });

    let err = services.is_uid_privileged(CALLER_UID).unwrap_err();
    assert_that!(err.exception_code(), eq(ILLEGAL_ARGUMENT));
    assert_that!(err.get_description(), contains_substring("test error"));
    Ok(())
}

fn mock_package_manager_and_services<F>(pm_expectations: F) -> AndroidSystemServicesData
where
    F: FnOnce(&mut MockIPackageManagerNative, &mut Sequence),
{
    let mut seq = Sequence::new();
    let mut mock_pm = MockIPackageManagerNative::new();
    pm_expectations(&mut mock_pm, &mut seq);
    let pm = BnPackageManagerNative::new_binder(mock_pm, BinderFeatures::default());
    AndroidSystemServicesData { package_manager: Mutex::new(Some(pm)), uuid_mapping: vec![] }
}

fn expect_get_names_for_uids(
    mock_pm: &mut MockIPackageManagerNative,
    seq: &mut Sequence,
    packages: Result<Vec<&str>>,
) {
    let packages = packages.map(|packages| packages.into_iter().map(String::from).collect());
    mock_pm
        .expect_getNamesForUids()
        .with(mp::eq(&[CALLER_UID][..]))
        .times(1)
        .in_sequence(seq)
        .return_once(move |_| packages);
}

fn expect_check_permission(
    mock_pm: &mut MockIPackageManagerNative,
    seq: &mut Sequence,
    package_name: &'static str,
    result: Result<i32>,
) {
    mock_pm
        .expect_checkPermission()
        .with(mp::eq(SECURE_ELEMENT_PERMISSION), mp::eq(package_name), mp::eq(USER_ID))
        .times(1)
        .in_sequence(seq)
        .return_once(move |_, _, _| result);
}
