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

//! Testing of [`Reader`] is minimal because nearly all of its functionality is provided by
//! sub-components which have their own tests.  Integration testing is provided at a higher level.

use super::*;
use crate::{
    ara::Rule,
    system_services::{ClientId, MockSystemServices, SeSecurityProfile},
    test_utils::init,
    utils::ServiceSpecificException,
};
use android_hardware_secure_element::aidl::android::hardware::secure_element::{
    ISecureElement::{BnSecureElement, ISecureElement, MockISecureElement},
    LogicalChannelResponse::LogicalChannelResponse,
};
use binder::ExceptionCode;
use googletest::{prelude::*, test as gtest, Result};

const DEFAULT_AID: &[u8] = &[];
const TEST_P2: i8 = 0x00;

#[gtest]
fn create_reader() -> Result<()> {
    init();

    let se_binder = mock_se(|_mock| {});
    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: true, full_access: false },
        /* platform_rules */ Ok(vec![]),
        |_mock| {},
    );
    let _reader = Reader::new_arc("se_name", WaitForReader(false), system_services)?;

    Ok(())
}

#[gtest]
fn open_and_close_sessions() -> Result<()> {
    init();

    let se_binder = mock_se(|mock| {
        mock.expect_isCardPresent().times(3).returning(|| Ok(true));
    });
    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: true, full_access: false },
        /* platform_rules */ Ok(vec![]),
        |_mock| {},
    );
    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
    let mut reader = reader_arc.lock().unwrap();
    let session1 = reader.open_session()?;
    let session2 = reader.open_session()?;
    let session3 = reader.open_session()?;

    assert_that!(reader.is_session_closed(session1), eq(false));
    assert_that!(reader.is_session_closed(session2), eq(false));
    assert_that!(reader.is_session_closed(session3), eq(false));
    assert_that!(reader.is_session_closed(session1), eq(false));

    reader.close_session(session1, SendSelectOnClose(true));

    assert_that!(reader.is_session_closed(session1), eq(true));
    assert_that!(reader.is_session_closed(session2), eq(false));

    reader.close_sessions(SendSelectOnClose(true));

    assert_that!(reader.is_session_closed(session1), eq(true));
    assert_that!(reader.is_session_closed(session2), eq(true));
    assert_that!(reader.is_session_closed(session3), eq(true));

    Ok(())
}

/// [`Reader`] should close all sessions if the ARA-M read returns an I/O error.
#[gtest]
fn close_on_ara_io_error() -> Result<()> {
    init();

    let se_binder = mock_se(|mock| {
        mock.expect_isCardPresent().times(2).returning(|| Ok(true));
        mock.expect_openLogicalChannel().times(1).returning(|_, _| {
            service_specific_exception(ServiceSpecificException::IoError, "I/O error")
        });
    });

    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: true, full_access: false },
        /* platform_rules */ Ok(vec![]),
        |mock| {
            mock.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
        },
    );

    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
    let mut reader = reader_arc.lock().unwrap();
    let session1 = reader.open_session()?;
    let session2 = reader.open_session()?;

    let err = reader.open_logical_channel(session1, DEFAULT_AID, TEST_P2).unwrap_err();
    assert_that!(err.exception_code(), eq(ExceptionCode::SERVICE_SPECIFIC));
    assert_that!(err.service_specific_error(), eq(ServiceSpecificException::IoError as i32));

    assert_that!(reader.is_session_closed(session1), eq(true));
    assert_that!(reader.is_session_closed(session2), eq(true));

    Ok(())
}

/// [`Reader`] should close all sessions if opening a session returns an I/O error.
#[gtest]
fn close_on_open_session_io_error() -> Result<()> {
    init();

    let se_binder = mock_se(|mock| {
        mock.expect_isCardPresent().times(2).returning(|| Ok(true));
        mock.expect_openLogicalChannel().times(1).returning(|_, _| {
            service_specific_exception(ServiceSpecificException::IoError, "I/O error")
        });
    });

    let system_services = mock_system_services(
        Ok(se_binder),
        // Full access security profile, to avoid triggering an ARA-M read.
        SeSecurityProfile { use_ara_applet: false, full_access: true },
        /* platform_rules */ Ok(vec![]),
        |mock| {
            mock.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
        },
    );

    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
    let mut reader = reader_arc.lock().unwrap();
    let session1 = reader.open_session()?;
    let session2 = reader.open_session()?;

    let err = reader.open_logical_channel(session1, DEFAULT_AID, TEST_P2).unwrap_err();
    assert_that!(err.exception_code(), eq(ExceptionCode::SERVICE_SPECIFIC));
    assert_that!(err.service_specific_error(), eq(ServiceSpecificException::IoError as i32));

    assert_that!(reader.is_session_closed(session1), eq(true));
    assert_that!(reader.is_session_closed(session2), eq(true));

    Ok(())
}

/// [`Reader`] should close all sessions if transmitting an APDU returns an IO error.
#[gtest]
fn close_on_transmit_io_error() -> Result<()> {
    init();

    let se_binder = mock_se(|mock| {
        mock.expect_isCardPresent().times(2).returning(|| Ok(true));
        mock.expect_openLogicalChannel().times(1).returning(|_, _| {
            Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] })
        });
        mock.expect_transmit().returning(|_| {
            service_specific_exception(ServiceSpecificException::IoError, "I/O error")
        });
        mock.expect_closeChannel().returning(|_| Ok(()));
    });

    let system_services = mock_system_services(
        Ok(se_binder),
        // Full access security profile, to avoid triggering an ARA-M read.
        SeSecurityProfile { use_ara_applet: false, full_access: true },
        /* platform_rules */ Ok(vec![]),
        |mock| {
            mock.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
        },
    );

    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
    let mut reader = reader_arc.lock().unwrap();
    let session1 = reader.open_session()?;
    let session2 = reader.open_session()?;

    let (Some(channel_id), _policy) =
        reader.open_logical_channel(session1, DEFAULT_AID, TEST_P2)?
    else {
        panic!("Should get a channel ID")
    };

    let privileged_caller = false;
    let err = reader
        .transmit_on_channel(channel_id, &[0x00, 0x00, 0x00, 0x00], privileged_caller)
        .unwrap_err();
    assert_that!(err.exception_code(), eq(ExceptionCode::SERVICE_SPECIFIC));
    assert_that!(err.service_specific_error(), eq(ServiceSpecificException::IoError as i32));

    assert_that!(reader.is_session_closed(session1), eq(true));
    assert_that!(reader.is_session_closed(session2), eq(true));

    Ok(())
}

fn mock_se(expectations: impl FnOnce(&mut MockISecureElement)) -> Strong<dyn ISecureElement> {
    let mut se_mock = MockISecureElement::new();
    se_mock.expect_init().returning(|callback| {
        callback.onStateChange(/* connected */ true, /* reason */ "connected")
    });

    expectations(&mut se_mock);

    BnSecureElement::new_binder(se_mock, BinderFeatures::default())
}

fn mock_system_services(
    se_hal: binder::Result<Strong<dyn ISecureElement>>,
    security_profile: SeSecurityProfile,
    platform_rules: binder::Result<Vec<Rule>>,
    expectations: impl FnOnce(&mut MockSystemServices),
) -> Arc<dyn SystemServices> {
    let mut mock_services = MockSystemServices::new();
    mock_services.expect_get_se_hal().return_once(move |_, _| se_hal);
    mock_services.expect_get_security_profile().return_once(move || security_profile);
    mock_services.expect_get_platform_rules().return_once(move |_| platform_rules);
    expectations(&mut mock_services);

    Arc::new(mock_services)
}
