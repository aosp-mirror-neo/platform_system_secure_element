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
    reader::{Reader, SessionId},
    system_services::{
        ClientId, MockSystemServices, SeSecurityProfile, SystemServices, WaitForReader,
    },
    terminal::ChannelId,
    utils::ServiceSpecificException,
};
use android_hardware_secure_element::aidl::android::hardware::secure_element::{
    ISecureElement::{BnSecureElement, ISecureElement, MockISecureElement, IOERROR},
    LogicalChannelResponse::LogicalChannelResponse,
};
use android_se_omapi::aidl::android::se::omapi::ISecureElementListener::{
    BnSecureElementListener, ISecureElementListener,
};
use binder::{BinderFeatures, ExceptionCode, Result, Status, Strong};
use googletest::{prelude::*, test as gtest};
use mockall::{predicate as mp, *};
use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::Arc, thread};

fn init() {
    crate::test_utils::init(module_path!());
}

#[gtest]
fn open_session() -> Result<()> {
    init();

    let mut se_mock = MockISecureElement::new();
    let mut seq = Sequence::new();
    se_mock.expect_init().times(1).in_sequence(&mut seq).returning(|_| Ok(()));
    expect_is_card_present(&mut se_mock, &mut seq, true);
    let se = BnSecureElement::new_binder(se_mock, BinderFeatures::default());

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder = AidlReader::new_native_binder(reader_arc.clone());

    let session = binder.openSession()?;
    assert!(!session.isClosed()?);

    session.close()?;
    assert!(session.isClosed()?);

    Ok(())
}

#[gtest]
fn open_session_no_card() -> googletest::Result<()> {
    init();

    let mut seq = Sequence::new();
    let (se, _) = build_mock_se(|mock| {
        expect_is_card_present(mock, &mut seq, false);
    });

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder_ref = AidlReader::new_native_binder(reader_arc.clone());

    let err = binder_ref.openSession().unwrap_err();
    assert_that!(err.exception_code(), eq(ExceptionCode::SERVICE_SPECIFIC));
    assert_that!(
        err.service_specific_error(),
        eq(ServiceSpecificException::SecureElementNotPresent as i32)
    );
    assert_that!(err.get_description(), contains_substring("Secure Element is not present"));

    Ok(())
}

#[gtest]
fn no_atr_until_callback() -> Result<()> {
    init();

    let mut seq = Sequence::new();
    let (se, _) = build_mock_se(|mock| {
        expect_is_card_present(mock, &mut seq, true);
    });

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder_ref = AidlReader::new_native_binder(reader_arc.clone());

    let session = binder_ref.openSession()?;
    assert_eq!(session.getAtr()?, None);

    Ok(())
}

#[gtest]
fn get_atr() -> Result<()> {
    init();

    const ATR: &[u8] = "Hello".as_bytes();

    let mut seq = Sequence::new();
    let (se, on_state_change) = build_mock_se(|mock| {
        expect_is_card_present(mock, &mut seq, true);
        mock.expect_getAtr().times(1).in_sequence(&mut seq).returning(|| Ok(ATR.to_vec()));
    });

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder_ref = AidlReader::new_native_binder(reader_arc.clone());

    on_state_change(true, "connected")?;

    let session = binder_ref.openSession()?;
    assert!(!session.isClosed()?);

    assert_eq!(session.getAtr()?, Some(ATR.to_vec()));

    Ok(())
}

#[gtest]
fn no_channel_until_callback() -> Result<()> {
    init();

    let mut seq = Sequence::new();
    let (se, on_state_change) = build_mock_se(|mock| {
        expect_is_card_present(mock, &mut seq, true);
        mock.expect_openBasicChannel().times(1).in_sequence(&mut seq).returning(|_, _| Ok(vec![]));
        expect_select_default(mock, &mut seq);
        expect_close_channel(mock, &mut seq, 0);
    });

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder_ref = AidlReader::new_native_binder(reader_arc.clone());

    let session = binder_ref.openSession()?;

    // Try to get a channel.  Should fail because SE hasn't called back yet.  Also, shouldn't
    // fulfill the mock expectation of a call to ISecureElement::openBasicChannel().
    let death_listener = TestListener::new_binder();
    let channel = session.openBasicChannel(None, 0x00, &death_listener);

    let err = channel.expect_err("Should be an error");
    assert_eq!(err.exception_code(), ExceptionCode::SERVICE_SPECIFIC);
    assert!(err.get_description().contains("Secure Element is not connected"));

    // Simulate SE callback and availability, now opening the channel will work.
    on_state_change(true, "Hello")?;
    session.openBasicChannel(None, 0x00, &death_listener)?;

    Ok(())
}

#[gtest]
fn open_basic_channel() -> Result<()> {
    init();

    let mut seq = Sequence::new();
    let (se, on_state_change) = build_mock_se(|mock| {
        expect_is_card_present(mock, &mut seq, true);
        expect_open_basic_channel_success(mock, &mut seq, vec![]);
        mock.expect_transmit()
            .with(mp::eq([0x00, 0x00, 0x00, 0x00]))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(vec![0x90, 0x00]));
        expect_select_default(mock, &mut seq);
        expect_close_channel(mock, &mut seq, 0);
    });

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder_ref = AidlReader::new_native_binder(reader_arc.clone());

    on_state_change(true, "Hello")?;

    let session = binder_ref.openSession()?;
    let death_listener = TestListener::new_binder();
    let channel = session.openBasicChannel(None, 0x00, &death_listener)?.unwrap();

    assert!(channel.isBasicChannel()?);
    assert!(!channel.isClosed()?);

    let response = channel.transmit(&[0x00, 0x00, 0x00, 0x00])?;
    assert_eq!(response, vec![0x90, 0x00]);

    channel.close()?;

    assert!(channel.isClosed()?);

    Ok(())
}

#[gtest]
fn reopen_basic_channel() -> Result<()> {
    init();

    let mut seq = Sequence::new();
    let (se, on_state_change) = build_mock_se(|mock| {
        // Each openSession checks card presence.
        expect_is_card_present(mock, &mut seq, true);
        expect_is_card_present(mock, &mut seq, true);
        // SE only gets one openBasicChannel call.
        expect_open_basic_channel_success(mock, &mut seq, vec![]);
        expect_select_default(mock, &mut seq);
        expect_close_channel(mock, &mut seq, 0);
    });
    let death_listener = TestListener::new_binder();

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder_ref = AidlReader::new_native_binder(reader_arc.clone());

    on_state_change(true, "Hello")?;

    let session1 = binder_ref.openSession()?;
    let session2 = binder_ref.openSession()?;

    // First attempt returns a channel.
    let channel1 = session1.openBasicChannel(None, 0x00, &death_listener)?;
    assert!(channel1.is_some());

    // Second does not.
    let channel2 = session2.openBasicChannel(None, 0x00, &death_listener)?;
    assert!(channel2.is_none());

    Ok(())
}

#[gtest]
fn open_logical_channel_before_basic() -> Result<()> {
    init();

    let mut seq = Sequence::new();
    let (se, on_state_change) = build_mock_se(|mock| {
        expect_is_card_present(mock, &mut seq, true);
        expect_open_logical_channel_success(mock, &mut seq, 1, vec![]);
        expect_close_channel(mock, &mut seq, 1);
    });

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder_ref = AidlReader::new_native_binder(reader_arc.clone());

    on_state_change(true, "Hello")?;

    let session = binder_ref.openSession()?;
    let death_listener = TestListener::new_binder();
    let channel = session.openLogicalChannel(None, 0x00, &death_listener)?;
    assert!(channel.is_some());

    Ok(())
}

#[gtest]
fn open_logical_channel() -> Result<()> {
    init();

    let mut seq = Sequence::new();
    let (se, on_state_change) = build_mock_se(|mock| {
        expect_is_card_present(mock, &mut seq, true);
        expect_open_basic_channel_success(mock, &mut seq, vec![]);
        expect_open_logical_channel_success(mock, &mut seq, 1, vec![]);
        expect_close_channel(mock, &mut seq, 1);
        expect_select_default(mock, &mut seq);
        expect_close_channel(mock, &mut seq, 0);
    });

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder_ref = AidlReader::new_native_binder(reader_arc.clone());

    on_state_change(true, "Hello")?;

    let session = binder_ref.openSession()?;

    let death_listener = TestListener::new_binder();
    let channel1 = session.openBasicChannel(None, 0x00, &death_listener)?;
    assert!(channel1.is_some());
    let channel2 = session.openLogicalChannel(None, 0x00, &death_listener)?;
    assert!(channel2.is_some());

    Ok(())
}

#[gtest]
fn close_session_channels() -> Result<()> {
    init();

    let mut seq = Sequence::new();
    let (se, on_state_change) = build_mock_se(|mock| {
        expect_is_card_present(mock, &mut seq, true);
        expect_open_basic_channel_success(mock, &mut seq, vec![]);
        expect_open_logical_channel_success(mock, &mut seq, 1, vec![]);
        expect_close_channel(mock, &mut seq, 1);
        expect_select_default(mock, &mut seq);
        expect_close_channel(mock, &mut seq, 0);
    });

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder_ref = AidlReader::new_native_binder(reader_arc.clone());

    on_state_change(true, "Hello")?;

    let session = binder_ref.openSession()?;

    let death_listener = TestListener::new_binder();
    let basic_channel = session.openBasicChannel(None, 0x00, &death_listener)?.unwrap();
    let logical_channel = session.openLogicalChannel(None, 0x00, &death_listener)?.unwrap();

    assert!(!basic_channel.isClosed()?);
    assert!(!logical_channel.isClosed()?);

    session.closeChannels()?;

    assert!(basic_channel.isClosed()?);
    assert!(logical_channel.isClosed()?);

    assert!(!session.isClosed()?);
    session.close()?;
    assert!(session.isClosed()?);

    Ok(())
}

#[gtest]
fn io_error() -> Result<()> {
    init();

    let mut seq = Sequence::new();
    let (se, on_state_change) = build_mock_se(|mock_se| {
        // Each openSession call checks for card presence.
        expect_is_card_present(mock_se, &mut seq, true);
        expect_is_card_present(mock_se, &mut seq, true);
        // Note that the SE only gets one request to open the basic channel, even though two
        // sessions try to open it.
        expect_open_basic_channel_success(mock_se, &mut seq, vec![]);
        // Let the first logical channel succeed.
        expect_open_logical_channel_success(mock_se, &mut seq, 1, vec![]);
        // Fail on the second one.
        mock_se.expect_openLogicalChannel().times(1).in_sequence(&mut seq).returning(|_, _| {
            Err(Status::new_service_specific_error_str(IOERROR, Some("the frobber snizzled")))
        });
        // The reader will attempt to close the open channels after the error; and will likely get
        // more errors.
        mock_se.expect_closeChannel().times(2).returning(|_| {
            Err(Status::new_service_specific_error_str(IOERROR, Some("the frobber snizzled")))
        });
    });

    let reader_arc =
        Reader::new_arc(&reader_name("ESE0"), WaitForReader(true), mock_system_services(se))?;
    let binder_ref = AidlReader::new_native_binder(reader_arc.clone());

    on_state_change(true, "Hello")?;

    // Open multiple sessions, so we can verify that all of them get closed, not just the one that
    // triggers the IOERROR.
    let session1 = binder_ref.openSession()?;
    let session2 = binder_ref.openSession()?;

    let death_listener = TestListener::new_binder();
    let channel1 = session1.openBasicChannel(None, 0x00, &death_listener)?;
    assert!(channel1.is_some());
    let channel2 = session2.openBasicChannel(None, 0x00, &death_listener)?;
    assert!(channel2.is_none());
    let channel3 = session2.openLogicalChannel(None, 0x00, &death_listener)?;
    assert!(channel3.is_some());

    assert_eq!(
        reader_arc.lock().unwrap().get_open_sessions(),
        HashMap::from([(SessionId(0), vec![ChannelId(0)]), (SessionId(1), vec![ChannelId(1)])])
    );

    // Second open should fail.
    let err = session1.openLogicalChannel(None, 0x00, &death_listener).unwrap_err();
    assert_that!(err.to_string(), contains_substring("I/O error when opening channel"));

    assert!(reader_arc.lock().unwrap().get_open_sessions().is_empty());

    Ok(())
}

struct TestListener {}
impl TestListener {
    fn new_binder() -> Strong<dyn ISecureElementListener> {
        BnSecureElementListener::new_binder(TestListener {}, BinderFeatures::default())
    }
}
impl binder::Interface for TestListener {}
impl ISecureElementListener for TestListener {}

fn reader_name(prefix: &str) -> String {
    format!("{prefix}{:?}", thread::current().id())
}

fn mock_system_services(se: Strong<dyn ISecureElement>) -> Arc<dyn SystemServices> {
    let mut system_services = MockSystemServices::new();
    system_services
        .expect_get_security_profile()
        .returning(|| SeSecurityProfile { use_ara_applet: false, full_access: true });
    system_services.expect_get_platform_rules().returning(|_| Ok(vec![]));
    system_services.expect_get_se_hal().return_once(move |_, _| Ok(se));
    system_services.expect_is_caller_privileged().returning(|| Ok(false));
    system_services.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
    Arc::new(system_services)
}

/// Build a mock SE, with expectations.
///
/// This function builds a mock SE and returns a binder handle to it, and a callback that can be
/// used to simulate state changes.
///
/// An expectation for the call to ISecureElement::init is added, so the callback can be set up.
/// Additional expectations can be set up in the function passed to `additional_expectations`.
fn build_mock_se(
    additional_expectations: impl FnOnce(&mut MockISecureElement),
) -> (Strong<dyn ISecureElement>, impl Fn(bool, &'static str) -> Result<()>) {
    let cb = Rc::new(RefCell::new(None));
    let callback_ref_for_closure = cb.clone();

    let mut se_mock = MockISecureElement::new();
    se_mock.expect_init().times(1).returning_st(move |cb| {
        callback_ref_for_closure.borrow_mut().replace(cb.clone());
        Ok(())
    });
    additional_expectations(&mut se_mock);

    let se = BnSecureElement::new_binder(se_mock, BinderFeatures::default());
    let callback = move |connected, debug_reason: &'static str| {
        cb.borrow().as_ref().unwrap().onStateChange(connected, debug_reason)
    };

    (se, callback)
}

fn expect_is_card_present(mock: &mut MockISecureElement, seq: &mut Sequence, present: bool) {
    mock.expect_isCardPresent().times(1).in_sequence(seq).returning(move || Ok(present));
}

fn expect_open_basic_channel_success(
    mock: &mut MockISecureElement,
    seq: &mut Sequence,
    retval: Vec<u8>,
) {
    mock.expect_openBasicChannel()
        .times(1)
        .in_sequence(seq)
        .returning(move |_, _| Ok(retval.clone()));
}

fn expect_open_logical_channel_success(
    mock: &mut MockISecureElement,
    seq: &mut Sequence,
    channel_id: i8,
    select_response: Vec<u8>,
) {
    mock.expect_openLogicalChannel().times(1).in_sequence(seq).returning(move |_, _| {
        Ok(LogicalChannelResponse {
            channelNumber: channel_id,
            selectResponse: select_response.clone(),
        })
    });
}

fn expect_select_default(mock: &mut MockISecureElement, seq: &mut Sequence) {
    mock.expect_transmit()
        .with(mp::eq([0x00, 0xA4, 0x04, 0x00]))
        .times(1)
        .in_sequence(seq)
        .returning(|_| Ok(vec![0x90, 0x00]));
}

fn expect_close_channel(mock: &mut MockISecureElement, seq: &mut Sequence, channel_id: i8) {
    mock.expect_closeChannel()
        .with(mp::eq(channel_id))
        .times(1)
        .in_sequence(seq)
        .returning(|_| Ok(()));
}
