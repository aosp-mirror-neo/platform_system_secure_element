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
    access_enforcer::{ARA_D_AID, ARA_M_AID, GET_ALL_APDU, GET_REFRESH_TAG_APDU},
    ara::{tlv, Rule},
    system_services::{ClientId, MockSystemServices, SeSecurityProfile},
    terminal::Apdu,
    utils::ServiceSpecificException,
};
use android_hardware_secure_element::aidl::android::hardware::secure_element::{
    ISecureElement::{BnSecureElement, ISecureElement, MockISecureElement},
    LogicalChannelResponse::LogicalChannelResponse,
};
use binder::ExceptionCode;
use googletest::{prelude::*, test as gtest, Result};
use mockall::predicate as mp;

const DEFAULT_AID: &[u8] = &[];
const TEST_P2: i8 = 0x00;

fn init() {
    crate::test_utils::init(module_path!());
}

#[gtest]
fn create_reader() -> Result<()> {
    init();

    let se_binder = mock_se(|_mock| {});
    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: true, full_access: false },
        /* platform_rules */ Ok(vec![]),
        /* is_caller_privileged_result */ Ok(false),
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
        /* is_caller_privileged_result */ Ok(false),
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

#[gtest]
fn is_secure_element_present() -> Result<()> {
    init();

    check_is_secure_element_present(true)?;
    check_is_secure_element_present(false)?;

    Ok(())
}

fn check_is_secure_element_present(present: bool) -> Result<()> {
    let se_binder = mock_se(|mock| {
        mock.expect_isCardPresent().returning(move || Ok(present));
    });
    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: false, full_access: true },
        /* platform_rules */ Ok(vec![]),
        /* is_caller_privileged_result */ Ok(true),
        |_mock| {},
    );

    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
    let reader = reader_arc.lock().unwrap();

    assert_that!(reader.is_secure_element_present()?, eq(present));

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
        /* is_caller_privileged_result */ Ok(false),
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
        /* is_caller_privileged_result */ Ok(false),
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
        /* is_caller_privileged_result */ Ok(false),
        |mock| {
            mock.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
        },
    );

    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
    let mut reader = reader_arc.lock().unwrap();
    let session1 = reader.open_session()?;
    let session2 = reader.open_session()?;

    let (Some(client_channel_id), _policy) =
        reader.open_logical_channel(session1, DEFAULT_AID, TEST_P2)?
    else {
        panic!("Should get a channel ID")
    };

    let privileged_caller = false;
    let err = reader
        .transmit_on_channel(client_channel_id, &[0x00, 0x00, 0x00, 0x00], privileged_caller)
        .unwrap_err();
    assert_that!(err.exception_code(), eq(ExceptionCode::SERVICE_SPECIFIC));
    assert_that!(err.service_specific_error(), eq(ServiceSpecificException::IoError as i32));

    assert_that!(reader.is_session_closed(session1), eq(true));
    assert_that!(reader.is_session_closed(session2), eq(true));

    Ok(())
}

#[gtest]
fn reset_privileged_caller() -> Result<()> {
    init();

    let se_binder = mock_se(|mock| {
        mock.expect_reset().times(1).returning(|| Ok(())); // HAL reset returns Ok(())
    });

    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: false, full_access: true },
        /* platform_rules */ Ok(vec![]),
        /* is_caller_privileged_result */ Ok(true),
        |_mock| {},
    );

    let reader_arc = Reader::new_arc("ESE0", WaitForReader(true), system_services)?;
    let reader = reader_arc.lock().unwrap();

    assert_that!(reader.reset(), ok(eq(&true)));

    Ok(())
}

#[gtest]
fn reset_non_privileged_caller() -> Result<()> {
    init();

    let se_binder = mock_se(|_mock| {
        // No reset expected, so no specific expectation for reset() here.
    });

    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: false, full_access: false },
        /* platform_rules */ Ok(vec![]),
        /* is_caller_privileged_result */ Ok(false),
        |_mock| {},
    );

    let reader_arc = Reader::new_arc("ESE0", WaitForReader(true), system_services)?;
    let reader = reader_arc.lock().unwrap();

    let result = reader.reset();
    assert_that!(result, err(anything()));
    assert_eq!(result.unwrap_err().exception_code(), ExceptionCode::SECURITY);

    Ok(())
}

#[gtest]
fn privileged_caller_can_access_any_applet() -> Result<()> {
    init();

    // Mock SE HAL: openLogicalChannel always succeeds.
    let se_binder = mock_se(|mock| {
        mock.expect_isCardPresent().returning(|| Ok(true));
        mock.expect_openLogicalChannel().times(1).returning(|aid, _p2| {
            Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: aid.to_vec() })
        });
        mock.expect_closeChannel().returning(|_| Ok(()));
    });

    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: true, full_access: false },
        Ok(vec![]), // No rules allow access
        Ok(true),   // Privileged caller
        |mock| {
            mock.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
        },
    );

    let reader_arc = Reader::new_arc("ESE0", WaitForReader(true), system_services)?;
    let mut reader = reader_arc.lock().unwrap();
    let session = reader.open_session()?;

    // Try to open a logical channel to a test AID.
    let test_aid = &[0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x01, 0x01];
    let (client_channel_id_opt, _policy) = reader.open_logical_channel(session, test_aid, 0x00)?;
    assert!(
        client_channel_id_opt.is_some(),
        "Privileged caller should be able to open channel even if rules disallow"
    );

    Ok(())
}

/// [`Reader`] should handle the case where the ARA-M apple is not present but the ARA-D applet is.
#[gtest]
fn missing_ara_m() -> Result<()> {
    init();
    let (client_channel_id, _policy) = check_missing_ara_applets(false, true)?;
    assert!(client_channel_id.is_some());
    Ok(())
}

/// [`Reader`] should handle the case where the ARA-D applet is not present but the ARA-M applet is.
#[gtest]
fn missing_ara_d() -> Result<()> {
    init();
    let (client_channel_id, _policy) = check_missing_ara_applets(true, false)?;
    assert!(client_channel_id.is_some());
    Ok(())
}

/// [`Reader`] should handle the case where both applets are missing, resulting in a denial.
#[gtest]
fn missing_both_ara_applets() -> Result<()> {
    init();
    let result = check_missing_ara_applets(false, false);
    assert_eq!(result.unwrap_err().exception_code(), ExceptionCode::SECURITY);
    Ok(())
}

fn check_missing_ara_applets(
    ara_m_present: bool,
    ara_d_present: bool,
) -> binder::Result<(Option<ClientChannelId>, AccessPolicy)> {
    let se_binder = mock_se(|mock| {
        mock.expect_isCardPresent().returning(|| Ok(true));
        expect_ara_m_request(mock, ara_m_present);
        expect_ara_d_request(mock, ara_d_present);
        mock.expect_openLogicalChannel().with(mp::eq(DEFAULT_AID), mp::eq(TEST_P2)).returning(
            move |_aid, _p2| {
                Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] })
            },
        );
    });
    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: true, full_access: false },
        /* platform_rules */ Ok(vec![]),
        /* is_caller_privileged_result */ Ok(false),
        |mock| {
            mock.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
        },
    );
    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
    let mut reader = reader_arc.lock().unwrap();
    let session = reader.open_session()?;

    reader.open_logical_channel(session, DEFAULT_AID, TEST_P2)
}

#[gtest]
fn use_closed_channel_fails() -> Result<()> {
    init();

    let se_binder = mock_se(|mock| {
        mock.expect_isCardPresent().times(1).returning(|| Ok(true));
        mock.expect_openLogicalChannel().times(1).returning(|_, _| {
            Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] })
        });
        mock.expect_closeChannel().returning(|_| Ok(()));
    });

    let system_services = mock_system_services(
        Ok(se_binder),
        // Full access security profile, to avoid triggering an ARA-M read.
        SeSecurityProfile { use_ara_applet: false, full_access: true },
        /* platform_rules */ Ok(vec![]),
        /* is_caller_privileged_result */ Ok(false),
        |mock| {
            mock.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
        },
    );

    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
    let mut reader = reader_arc.lock().unwrap();
    let session = reader.open_session()?;

    let (Some(client_channel_id), _policy) =
        reader.open_logical_channel(session, DEFAULT_AID, TEST_P2)?
    else {
        panic!("Should get a channel ID")
    };

    reader.close_channel(client_channel_id, SendSelectOnClose(true))?;

    let privileged_caller = false;
    let err = reader
        .transmit_on_channel(client_channel_id, &[0x00, 0x00, 0x00, 0x00], privileged_caller)
        .unwrap_err();
    assert_that!(err.exception_code(), eq(ExceptionCode::ILLEGAL_STATE));

    Ok(())
}

#[gtest]
fn channel_id_reuse_is_safe() -> Result<()> {
    init();

    let se_binder = mock_se(|mock| {
        mock.expect_isCardPresent().times(2).returning(|| Ok(true));
        mock.expect_openLogicalChannel().times(1).returning(|_, _| {
            Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] })
        });
        mock.expect_closeChannel().with(mp::eq(1)).times(1).returning(|_| Ok(()));
        mock.expect_openLogicalChannel().times(1).returning(|_, _| {
            Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] })
            // Reuse channel number 1
        });
        mock.expect_closeChannel().with(mp::eq(1)).times(1).returning(|_| Ok(()));
    });

    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: false, full_access: true },
        Ok(vec![]),
        Ok(false),
        |mock| {
            mock.expect_get_client_id().times(2).returning(|| Ok(ClientId::PackageInfo(vec![])));
        },
    );

    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
    let mut reader = reader_arc.lock().unwrap();
    let session1 = reader.open_session()?;

    // Client A opens a channel
    let (Some(channel_id_a), _policy) =
        reader.open_logical_channel(session1, DEFAULT_AID, TEST_P2)?
    else {
        panic!("Should get a channel ID")
    };

    // Client A closes the channel
    reader.close_channel(channel_id_a, SendSelectOnClose(true))?;

    // Client B opens a channel, underlying channel ID is reused
    let session2 = reader.open_session()?;
    let (Some(channel_id_b), _policy) =
        reader.open_logical_channel(session2, DEFAULT_AID, TEST_P2)?
    else {
        panic!("Should get a channel ID")
    };

    // Ensure channel_id_a is different from channel_id_b
    assert_ne!(channel_id_a, channel_id_b);

    // Client A trying to use its old, closed channel ID should fail
    let privileged_caller = false;
    let err = reader
        .transmit_on_channel(channel_id_a, &[0x00, 0x00, 0x00, 0x00], privileged_caller)
        .unwrap_err();
    assert_that!(err.exception_code(), eq(ExceptionCode::ILLEGAL_STATE));

    Ok(())
}

#[gtest]
fn closing_session_closes_channels() -> Result<()> {
    init();

    let se_binder = mock_se(|mock| {
        mock.expect_isCardPresent().times(1).returning(|| Ok(true));
        mock.expect_openLogicalChannel().times(2).returning(|_, _| {
            // Return different channel numbers
            use std::sync::atomic::{AtomicI8, Ordering};
            static CHANNEL_COUNTER: AtomicI8 = AtomicI8::new(1);
            let channel_number = CHANNEL_COUNTER.fetch_add(1, Ordering::SeqCst);
            Ok(LogicalChannelResponse { channelNumber: channel_number, selectResponse: vec![] })
        });
        // Expect close for channel 1 and 2. Order is not guaranteed.
        mock.expect_closeChannel().with(mp::in_iter([1, 2])).times(2).returning(|_| Ok(()));
    });

    let system_services = mock_system_services(
        Ok(se_binder),
        SeSecurityProfile { use_ara_applet: false, full_access: true },
        Ok(vec![]),
        Ok(false),
        |mock| {
            mock.expect_get_client_id().times(2).returning(|| Ok(ClientId::PackageInfo(vec![])));
        },
    );

    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
    let mut reader = reader_arc.lock().unwrap();
    let session = reader.open_session()?;

    let (Some(channel1), _) = reader.open_logical_channel(session, DEFAULT_AID, TEST_P2)? else {
        panic!("Should get a channel ID")
    };
    let (Some(channel2), _) = reader.open_logical_channel(session, DEFAULT_AID, TEST_P2)? else {
        panic!("Should get a channel ID")
    };

    assert!(!reader.is_channel_closed(channel1));
    assert!(!reader.is_channel_closed(channel2));

    reader.close_session(session, SendSelectOnClose(true));

    assert!(reader.is_channel_closed(channel1));
    assert!(reader.is_channel_closed(channel2));

    Ok(())
}

fn expect_ara_d_request(mock: &mut MockISecureElement, is_present: bool) {
    mock.expect_openLogicalChannel().with(mp::eq(ARA_D_AID), mp::eq(0)).returning(
        move |_aid, _p2| {
            if is_present {
                Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] })
            } else {
                service_specific_exception(
                    ServiceSpecificException::NoSuchElement,
                    "No such element",
                )
            }
        },
    );

    if !is_present {
        return;
    }

    // The open for the ARA-D applet succeeded, handle retrieval of an allow-all rule.
    expect_transmit(
        mock,
        GET_REFRESH_TAG_APDU,
        &tlv::Object::new(tlv::Tag::ResponseRefreshTagDo, tlv::Value::Primitive(&[0; 8])).to_ber(),
    );

    // ARA-D rule set containing a rule that allows all apps access to all applets.
    let permissive_rule_set = tlv::Object::new(
        tlv::Tag::ResponseAllRefArDo,
        tlv::Value::Constructed(vec![tlv::Object::new(
            tlv::Tag::RefArDo,
            tlv::Value::Constructed(vec![
                tlv::Object::new(
                    tlv::Tag::RefDo,
                    tlv::Value::Constructed(vec![tlv::Object::new(
                        tlv::Tag::DeviceAppIdRefDo,
                        tlv::Value::Primitive(&[/* all apps */]),
                    )]),
                ),
                tlv::Object::new(
                    tlv::Tag::ArDo,
                    tlv::Value::Constructed(vec![tlv::Object::new(
                        tlv::Tag::PermArDo,
                        tlv::Value::Primitive(&[0, 0, 0, 1, 0, 0, 0, 0 /* Always allow */]),
                    )]),
                ),
            ]),
        )]),
    )
    .to_ber();

    expect_transmit(mock, GET_ALL_APDU, &permissive_rule_set);
    mock.expect_closeChannel().returning(|_| Ok(()));
}

fn expect_ara_m_request(mock: &mut MockISecureElement, is_present: bool) {
    mock.expect_openLogicalChannel().with(mp::eq(ARA_M_AID), mp::eq(0)).returning(
        move |_aid, _p2| {
            if is_present {
                Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] })
            } else {
                service_specific_exception(
                    ServiceSpecificException::NoSuchElement,
                    "No such element",
                )
            }
        },
    );

    if !is_present {
        return;
    }

    // The open for the ARA-M applet succeeded, handle retrieval of an allow-all rule.
    expect_transmit(
        mock,
        GET_REFRESH_TAG_APDU,
        &tlv::Object::new(tlv::Tag::ResponseRefreshTagDo, tlv::Value::Primitive(&[0; 8])).to_ber(),
    );

    // ARA-M rule set containing a rule that allows all apps access to all applets.
    let permissive_rule_set = tlv::Object::new(
        tlv::Tag::ResponseAllRefArDo,
        tlv::Value::Constructed(vec![tlv::Object::new(
            tlv::Tag::RefArDo,
            tlv::Value::Constructed(vec![
                tlv::Object::new(
                    tlv::Tag::RefDo,
                    tlv::Value::Constructed(vec![
                        tlv::Object::new(
                            tlv::Tag::AidRefDoSpecificApplet,
                            tlv::Value::Primitive(&[/* all AIDs */]),
                        ),
                        tlv::Object::new(
                            tlv::Tag::DeviceAppIdRefDo,
                            tlv::Value::Primitive(&[/* all apps */]),
                        ),
                    ]),
                ),
                tlv::Object::new(
                    tlv::Tag::ArDo,
                    tlv::Value::Constructed(vec![tlv::Object::new(
                        tlv::Tag::ApduArDo,
                        tlv::Value::Primitive(&[1 /* Always allow */]),
                    )]),
                ),
            ]),
        )]),
    )
    .to_ber();

    expect_transmit(mock, GET_ALL_APDU, &permissive_rule_set);
    mock.expect_closeChannel().returning(|_| Ok(()));
}

fn expect_transmit(mock: &mut MockISecureElement, apdu: &[u8], response: &[u8]) {
    let response = [response, &[0x90, 0x00][..]].concat();
    mock.expect_transmit()
        .times(1)
        .with(mp::eq(set_channel(1, apdu)))
        .return_once(move |_| Ok(response));
}

fn set_channel(channel: i8, apdu: &[u8]) -> Vec<u8> {
    let apdu =
        Apdu::new(apdu, Some(ChannelId(channel))).expect("We shouldn't be using invalid APDUs");
    apdu.0.clone()
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
    is_caller_privileged_result: binder::Result<bool>,
    expectations: impl FnOnce(&mut MockSystemServices),
) -> Arc<dyn SystemServices> {
    let mut mock_services = MockSystemServices::new();
    mock_services.expect_get_se_hal().return_once(move |_, _| se_hal);
    mock_services.expect_get_security_profile().return_once(move || security_profile);
    mock_services.expect_get_platform_rules().return_once(move |_| platform_rules);
    mock_services.expect_is_caller_privileged().returning(
        move || match &is_caller_privileged_result {
            Ok(b) => Ok(*b),
            Err(s) => {
                let msg = s.get_description();
                if s.exception_code() == ExceptionCode::SERVICE_SPECIFIC {
                    Err(binder::Status::new_service_specific_error_str(
                        s.service_specific_error(),
                        Some(&msg),
                    ))
                } else {
                    Err(binder::Status::new_exception_str(s.exception_code(), Some(&msg)))
                }
            }
        },
    );
    expectations(&mut mock_services);

    Arc::new(mock_services)
}
