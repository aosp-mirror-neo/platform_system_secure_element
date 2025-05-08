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

//! This module defines the [`AccessEnforcer`] type, which implements a GlobalPlatform
//! AcesssControlEnforcer (ACE). It is responsible for enforcing applet access control,
//! restricting which device apps can communicate with which applets.
//!
//! The [`AccessEnforcer`] must communicate with the SE for which it enforces access, to retrieve
//! access rules.  For it to do that, the caller must provide a reference to a [`Terminal`].

use super::*;
use crate::{
    ara::{
        tlv::{Object, Value},
        Sha1DigestOrUuid,
    },
    terminal::Apdu,
};
use android_hardware_secure_element::aidl::android::hardware::secure_element::{
    ISecureElement::{BnSecureElement, ISecureElement, MockISecureElement},
    LogicalChannelResponse::LogicalChannelResponse,
};
use binder::{BinderFeatures, ExceptionCode, Strong};
use bssl_crypto::digest::Sha256;
use googletest::{prelude::*, test as gtest, Result};
use mockall::{predicate as mp, Sequence};

fn init() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("se_service_access_enforcer_test")
            .with_max_level(log::LevelFilter::Trace)
            .with_log_buffer(android_logger::LogId::System)
            .format(|buf, record| {
                writeln!(
                    buf,
                    "{}:{} - {}",
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.args()
                )
            }),
    );
}

#[gtest]
fn create() -> Result<()> {
    init();

    let security_profile = SeSecurityProfile { use_ara_applet: true, full_access: false };
    let platform_rules = vec![];
    let ae = AccessEnforcer::new(security_profile, platform_rules);

    assert_that!(ae.security_profile.use_ara_applet, eq(true));
    assert_that!(ae.security_profile.full_access, eq(false));

    Ok(())
}

#[gtest]
fn test_default_deny() -> Result<()> {
    init();

    let security_profile = SeSecurityProfile { use_ara_applet: true, full_access: false };
    let platform_rules = vec![];
    let ae = AccessEnforcer::new(security_profile, platform_rules);

    let aid = [0; 5];
    let client_id = ClientId::Uuids(vec![Sha1DigestOrUuid([0; 20])]);
    assert_that!(
        ae.get_policy(&aid, &client_id),
        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
    );

    Ok(())
}

#[gtest]
fn test_full_access() -> Result<()> {
    init();

    let security_profile = SeSecurityProfile { use_ara_applet: true, full_access: true };
    let platform_rules = vec![];
    let ae = AccessEnforcer::new(security_profile, platform_rules);

    // Any AID is accessible.
    let client_id = ClientId::Uuids(vec![Sha1DigestOrUuid([0; 20])]);
    assert_that!(ae.get_policy(&[0; 5], &client_id), ok(eq(&ApduAccessRule::Always)));
    assert_that!(ae.get_policy(&[1; 5], &client_id), ok(eq(&ApduAccessRule::Always)));
    assert_that!(ae.get_policy(&[2; 5], &client_id), ok(eq(&ApduAccessRule::Always)));
    assert_that!(ae.get_policy(&[3; 5], &client_id), ok(eq(&ApduAccessRule::Always)));

    Ok(())
}

/// The [`AccessEnforcer`] should use platform rules without attempting to retrieve rules from
/// ARA-M, if the platform rules satisfy the request.
#[gtest]
fn test_platform_rule() -> Result<()> {
    init();

    let aid1 = [0; 5];
    let aid2 = [1; 5];
    let uuid = [0; 20];
    let client_id = ClientId::Uuids(vec![Sha1DigestOrUuid([0; 20])]);

    let security_profile = SeSecurityProfile { use_ara_applet: true, full_access: false };
    let platform_rules = vec![Rule::from_tlv(build_allow_rule(&aid1, &uuid)).unwrap()];
    let mut ae = AccessEnforcer::new(security_profile, platform_rules);

    assert_that!(ae.get_policy(&aid1, &client_id), ok(eq(&ApduAccessRule::Always)));
    assert_that!(
        ae.get_policy(&aid2, &client_id),
        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
    );

    // Test that resetting the enforcer cache doesn't lose platform rules.
    ae.rule_cache.reset();
    assert_that!(ae.get_policy(&aid1, &client_id), ok(eq(&ApduAccessRule::Always)));
    assert_that!(
        ae.get_policy(&aid2, &client_id),
        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
    );

    Ok(())
}

#[gtest]
fn test_update_rule_cache() -> Result<()> {
    init();

    // Mock SE setup is extensive.  The SE has to respond to multiple requests to get the ARA-M
    // rule data, further complicated by the fact that we want to test the refresh tag
    // functionality, so we'll need to read rule data twice.
    //
    // We'll return two sets of rules, and two corresponding refresh tag values.  The first rule
    // set authorizes the all-zeros UUID, the second adds authorization for the all-ones UUID.
    // The client is the all-ones UUID.
    let se_hal = mock_se(|mock| {
        let mut seq = Sequence::new();

        let first_rule_set_data = build_rule_set(vec![build_allow_rule(
            /* aid */ &[0; 5], /* uuid */ &[0; 20],
        )])
        .to_ber();
        let first_refresh_tag = Object::new(
            Tag::ResponseRefreshTagDo,
            Value::Primitive(&Sha256::hash(&first_rule_set_data)[..8]),
        )
        .to_ber();

        let second_rule_set_data = build_rule_set(vec![
            build_allow_rule(/* aid */ &[0; 5], /* uuid */ &[1; 20]),
            build_allow_rule(/* aid */ &[0; 5], /* uuid */ &[1; 20]),
        ])
        .to_ber();
        let second_refresh_tag = Object::new(
            Tag::ResponseRefreshTagDo,
            Value::Primitive(&Sha256::hash(&second_rule_set_data)[..8]),
        )
        .to_ber();

        // First update request.  Since the AccessEnforcer has no rule data, this will include a
        // ruleset retrieval.  To test the chunk reassembly reature, break the data into chunks.
        let mut rule_chunks = first_rule_set_data.chunks(10);

        expect_open_channel(mock, &mut seq, ARA_M_AID);
        expect_transmit(mock, &mut seq, GET_REFRESH_TAG_APDU, &first_refresh_tag);
        expect_transmit(mock, &mut seq, GET_ALL_APDU, rule_chunks.next().unwrap());
        rule_chunks.for_each(|chunk| {
            expect_transmit(mock, &mut seq, GET_NEXT_APDU, chunk);
        });
        expect_close_channel(mock, &mut seq);

        // Another update request.  We return the same tag, which doesn't provoke ruleset retrieval.
        expect_open_channel(mock, &mut seq, ARA_M_AID);
        expect_transmit(mock, &mut seq, GET_REFRESH_TAG_APDU, &first_refresh_tag);
        expect_close_channel(mock, &mut seq);

        // A third update request, this time returning a different tag, provoking ruleset retrieval.
        // This time we'll return the whole ruleset in one response.
        expect_open_channel(mock, &mut seq, ARA_M_AID);
        expect_transmit(mock, &mut seq, GET_REFRESH_TAG_APDU, &second_refresh_tag);
        expect_transmit(mock, &mut seq, GET_ALL_APDU, &second_rule_set_data);
        expect_close_channel(mock, &mut seq);
    });

    let security_profile = SeSecurityProfile { use_ara_applet: true, full_access: false };
    let platform_rules = vec![];
    let mut ae = AccessEnforcer::new(security_profile, platform_rules);

    let mut terminal = Terminal::new("se_name", se_hal)?;
    terminal.set_connected(true);

    let client_id = ClientId::Uuids(vec![Sha1DigestOrUuid([1; 20])]);

    // We haven't yet read data from ARA-M, so access should be denied.
    let aid = [0; 5];
    assert_that!(
        ae.get_policy(&aid, &client_id),
        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
    );

    // Read from ARA-M.  The first rule set authorizes the all-zeros UUID but the client is the
    // all-ones UUID.
    ae.update_rule_cache(&mut terminal)?;
    assert_that!(
        ae.get_policy(&aid, &client_id),
        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
    );

    // The second update gets the same refresh tag, so no change in policy.
    ae.update_rule_cache(&mut terminal)?;
    assert_that!(
        ae.get_policy(&aid, &client_id),
        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
    );

    // The third update returns a different refresh tag, provoking a re-read of a new policy that
    // also authorizes the all-ones UUID.
    ae.update_rule_cache(&mut terminal)?;
    assert_that!(ae.get_policy(&aid, &client_id), ok(eq(&ApduAccessRule::Always)));

    // Resetting the enforcer cache should lose the ARA rules.
    ae.rule_cache.reset();
    assert_that!(
        ae.get_policy(&aid, &client_id),
        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
    );

    Ok(())
}

fn build_rule_set(objects: Vec<Object>) -> Object {
    Object::new(Tag::ResponseAllRefArDo, Value::Constructed(objects))
}

fn build_allow_rule<'a>(aid: &'a [u8], uuid: &'a [u8]) -> Object<'a> {
    Object::new(
        Tag::RefArDo,
        Value::Constructed(vec![
            Object::new(
                Tag::RefDo,
                Value::Constructed(vec![
                    // Match AID [0; 5].
                    Object::new(Tag::AidRefDoSpecificApplet, Value::Primitive(aid)),
                    // Match UUID [0; 20].
                    Object::new(Tag::DeviceAppIdRefDo, Value::Primitive(uuid)),
                ]),
            ),
            Object::new(
                Tag::ArDo,
                Value::Constructed(vec![
                    // Always allow APDUs
                    Object::new(Tag::ApduArDo, Value::Primitive(&[1])),
                ]),
            ),
        ]),
    )
}

fn expect_transmit(
    mock: &mut MockISecureElement,
    seq: &mut Sequence,
    apdu: &[u8],
    response: &[u8],
) {
    let response = [response, &[0x90, 0x00][..]].concat();
    mock.expect_transmit()
        .times(1)
        .in_sequence(seq)
        .with(mp::eq(set_channel(1, apdu)))
        .return_once(move |_| Ok(response));
}

fn expect_close_channel(mock: &mut MockISecureElement, seq: &mut Sequence) {
    // Close channel
    mock.expect_closeChannel().times(1).in_sequence(seq).with(mp::eq(1)).returning(|_| Ok(()));
}

fn expect_open_channel(mock: &mut MockISecureElement, seq: &mut Sequence, aid: &[u8]) {
    let aid = aid.to_vec();
    mock.expect_openLogicalChannel()
        .times(1)
        .in_sequence(seq)
        .with(mp::eq(aid), mp::eq(0))
        .returning(|_, _| Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] }));
}

fn mock_se(expectations: impl FnOnce(&mut MockISecureElement)) -> Strong<dyn ISecureElement> {
    let mut se_mock = MockISecureElement::new();
    expectations(&mut se_mock);

    BnSecureElement::new_binder(se_mock, BinderFeatures::default())
}

fn binder_status(
    code: ExceptionCode,
    description: &str,
) -> impl Fn(&'_ binder::Status) -> bool + use<'_> {
    let description = description.to_owned();
    move |s: &binder::Status| {
        s.exception_code() == code && s.get_description().contains(&description)
    }
}

fn set_channel(channel: i8, apdu: &[u8]) -> Vec<u8> {
    let apdu =
        Apdu::new(apdu, Some(ChannelId(channel))).expect("We shouldn't be using invalid APDUs");
    apdu.0.clone()
}
