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

use anyhow::Result;
use log::trace;

use super::tlv::{Object, Tag, Value};
use super::*;
use googletest::prelude::*;
use googletest::test as gtest;

#[cfg(not(feature = "notandroid"))]
fn init() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("se_ara_test")
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

#[cfg(feature = "notandroid")]
fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[gtest]
fn test_apdu_access_rule_merging() -> Result<()> {
    init();

    let values = [
        ApduAccessRule::Always,
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[0, 1, 2, 3, 4, 5, 6, 7])?),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[8, 9, 10, 11, 12, 13, 14, 15])?),
        ApduAccessRule::Never,
    ];

    fn is_at_least_as_restrictive(a: &ApduAccessRule, b: &ApduAccessRule) -> bool {
        match (a, b) {
            // Never is maximally-restrictive.
            (ApduAccessRule::Never, _) => true,
            // Always is as restrictive as Always
            (ApduAccessRule::Always, ApduAccessRule::Always) => true,
            // But always is less restrictive than anything else
            (ApduAccessRule::Always, _) => false,
            // PartialAllow is less restrictive than Never
            (ApduAccessRule::PartialAllow(_), ApduAccessRule::Never) => false,
            // PartialAllow is more restrictive than Always
            (ApduAccessRule::PartialAllow(_), ApduAccessRule::Always) => true,
            (ApduAccessRule::PartialAllow(a_set), ApduAccessRule::PartialAllow(b_set)) => {
                // If `b_set` is a subset of `a_set`, then `a_set` is more restrictive, so we
                // just test if all elements of `b_set` are in `a_set`.
                b_set.0.iter().all(|f| a_set.0.contains(f))
            }
        }
    }

    // For all combinations, check that merging produces rule that is at least as restrictive.
    for (a, b) in values.iter().cartesian_product(values.iter()) {
        let mut merged = a.clone();
        merged.merge(b.clone());

        assert!(is_at_least_as_restrictive(&merged, a), "A: {a:?}\nB: {b:?}\nM: {merged:?}\n");
        assert!(is_at_least_as_restrictive(&merged, b), "A: {a:?}\nB: {b:?}\nM: {merged:?}\n");
    }

    Ok(())
}

#[test]
fn test_apdu_access_rule_partial_allow_merging() -> Result<()> {
    init();

    // The merge of two distinct PartialAllows is different; it combines the filters.
    let mut rule =
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[0, 1, 2, 3, 4, 5, 6, 7])?);
    rule.merge(ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[7, 6, 5, 4, 3, 2, 1, 0])?));
    if let ApduAccessRule::PartialAllow(filter) = rule {
        assert!(
            filter == ApduFilterSet::from_data(&[7, 6, 5, 4, 3, 2, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7,])?
        )
    } else {
        panic!("Merger must be a PartialAllow");
    }

    Ok(())
}

#[test]
fn test_nfc_access_rule_merging() {
    init();

    let mut rule = NfcAccessRule::Always;
    rule.merge(NfcAccessRule::Never);
    assert_eq!(rule, NfcAccessRule::Never);

    let mut rule = NfcAccessRule::Never;
    rule.merge(NfcAccessRule::Always);
    assert!(rule == NfcAccessRule::Never);

    let mut rule = NfcAccessRule::Never;
    rule.merge(NfcAccessRule::Never);
    assert!(rule == NfcAccessRule::Never);

    let mut rule = NfcAccessRule::Always;
    rule.merge(NfcAccessRule::Always);
    assert!(rule == NfcAccessRule::Always);
}

#[test]
fn test_apdu_filter() -> Result<()> {
    init();

    let reject_filter = ApduFilter::from_data(&[
        0x01, 0x02, 0x03, 0x04, // Allowed
        0x00, 0x00, 0x00, 0x00, // Mask
    ]);
    let accept_filter = ApduFilter::from_data(&[
        0x01, 0x02, 0x03, 0x04, // Allowed
        0xFF, 0xFF, 0xFF, 0xFF, // Mask
    ]);
    let almost_accept_filter = ApduFilter::from_data(&[
        0x01, 0x02, 0x03, 0x04, // Allowed
        0xFF, 0xFF, 0x01, 0xFF, // Mask
    ]);

    let test_apdu = [0x01, 0x02, 0x03, 0x04].into();

    assert!(!reject_filter.allow_apdu(&test_apdu));
    assert!(accept_filter.allow_apdu(&test_apdu));
    assert!(!almost_accept_filter.allow_apdu(&test_apdu));

    Ok(())
}

#[test]
fn test_apdu_filter_set() -> Result<()> {
    init();

    let filter_set = ApduFilterSet::from_data(&[
        0x01, 0x02, 0x03, 0x04, // Allowed 1
        0x00, 0x00, 0x00, 0x00, // Mask 1
        0x01, 0x02, 0x03, 0x04, // Allowed 2
        0xFF, 0xFF, 0xFF, 0xFF, // Mask 2
    ])?;

    // This test APDU should be rejected by first, allowed by second, so allowed.
    let test_apdu = [0x01, 0x02, 0x03, 0x04].into();
    assert!(filter_set.allow(&test_apdu));

    // To confirm:
    assert!(!filter_set.0[0].allow_apdu(&test_apdu));
    assert!(filter_set.0[1].allow_apdu(&test_apdu));

    // This test APDU should be allowed by neither, so rejected.
    let test_apdu = [0x02, 0x02, 0x03, 0x04].into();
    assert!(!filter_set.allow(&test_apdu));

    Ok(())
}

#[gtest]
fn test_invalid_apdu_filter_set() -> Result<()> {
    init();

    assert_that!(
        ApduFilterSet::from_data(&[]).unwrap_err().to_string(),
        contains_substring("Invalid data in ApduFilterSet []")
    );

    assert_that!(
        ApduFilterSet::from_data(&[0x01]).unwrap_err().to_string(),
        contains_substring("Invalid data in ApduFilterSet [1]")
    );

    Ok(())
}

#[gtest]
fn test_invalid_access_rules() -> Result<()> {
    init();

    fn expect_fail(tlv: Object, want_err: &str) {
        let err = AccessRules::from_tlv(tlv).unwrap_err();
        assert!(err.to_string().contains(want_err));
    }

    // Invalid entry tag
    expect_fail(
        Object::new(
            Tag::ArDo,
            Value::Constructed(vec![Object::new(Tag::ArDo, Value::Primitive(&[0x01]))]),
        ),
        "Invalid tag",
    );

    // Invalid outer content
    expect_fail(Object::new(Tag::ArDo, Value::Empty), "Invalid content Empty");
    expect_fail(Object::new(Tag::ArDo, Value::Primitive(&[])), "Invalid content Primitive");
    expect_fail(Object::new(Tag::ArDo, Value::Constructed(Vec::new())), "Empty ArDo");

    expect_fail(
        Object::new(
            Tag::ArDo,
            Value::Constructed(vec![
                Object::new(Tag::ApduArDo, Value::Primitive(&[0x00])),
                Object::new(Tag::PkgRefDo, Value::Empty),
            ]),
        ),
        "Invalid tag PkgRefDo",
    );

    let contains_unknown = AccessRules::from_tlv(Object::new(
        Tag::ArDo,
        Value::Constructed(vec![
            Object::new(Tag::ApduArDo, Value::Primitive(&[0x00])),
            Object::new(Tag::new(&[0x00]), Value::Empty),
            Object::new(Tag::NfcArDo, Value::Primitive(&[0x00])),
        ]),
    ));

    if cfg!(feature = "disallow_unknown_ara_tags") {
        expect_that!(
            contains_unknown.unwrap_err().to_string(),
            contains_substring("Invalid tag Unknown")
        );
    } else {
        assert!(contains_unknown.is_ok(), "Got unexpected error {contains_unknown:?}");
    }

    Ok(())
}

#[test]
fn test_invalid_apdu_rule() -> Result<()> {
    init();

    // Wrong content types
    assert!(ApduAccessRule::from_tlv(Object::new(Tag::ApduArDo, Value::Empty))
        .unwrap_err()
        .to_string()
        .contains("Invalid content Empty"));
    assert!(ApduAccessRule::from_tlv(Object::new(Tag::ApduArDo, Value::Constructed(vec![])))
        .unwrap_err()
        .to_string()
        .contains("Invalid content Constructed"));

    // Can't be empty
    assert!(ApduAccessRule::from_tlv(Object::new(Tag::ApduArDo, Value::Primitive(&[])))
        .unwrap_err()
        .to_string()
        .contains("No data"));

    // Invalid single-byte value:
    assert!(ApduAccessRule::from_tlv(Object::new(Tag::ApduArDo, Value::Primitive(&[2])))
        .unwrap_err()
        .to_string()
        .contains("Invalid data byte"));

    // Invalid filter
    assert!(ApduAccessRule::from_tlv(Object::new(Tag::ApduArDo, Value::Primitive(&[2, 3])))
        .unwrap_err()
        .to_string()
        .contains("Invalid ApduFilters"));

    Ok(())
}

#[test]
fn test_invalid_nfc_rule() -> Result<()> {
    init();

    // Wrong content types
    assert!(NfcAccessRule::from_tlv(Object::new(Tag::NfcArDo, Value::Empty))
        .unwrap_err()
        .to_string()
        .contains("Invalid content Empty"));

    assert!(NfcAccessRule::from_tlv(Object::new(Tag::NfcArDo, Value::Constructed(vec![])))
        .unwrap_err()
        .to_string()
        .contains("Invalid content Constructed"));

    // Data must be a single byte
    assert!(NfcAccessRule::from_tlv(Object::new(Tag::NfcArDo, Value::Primitive(&[])))
        .unwrap_err()
        .to_string()
        .contains("Invalid data"));
    assert!(NfcAccessRule::from_tlv(Object::new(Tag::NfcArDo, Value::Primitive(&[1, 1])))
        .unwrap_err()
        .to_string()
        .contains("Invalid data"));

    // Invalid value (valid values are 0 and 1)
    assert!(NfcAccessRule::from_tlv(Object::new(Tag::NfcArDo, Value::Primitive(&[3])))
        .unwrap_err()
        .to_string()
        .contains("Invalid data"));

    Ok(())
}

#[test]
fn test_invalid_device_app_ref() -> Result<()> {
    init();

    // Invalid content type
    assert!(DeviceAppIdRef::from_tlv(Object::new(
        Tag::DeviceAppIdRefDo,
        Value::Constructed(vec![])
    ))
    .unwrap_err()
    .to_string()
    .contains("Invalid content Constructed"));

    // Invalid content data length (must be 20 or 32 bytes)
    assert!(DeviceAppIdRef::from_tlv(Object::new(Tag::DeviceAppIdRefDo, Value::Primitive(&[])))
        .unwrap_err()
        .to_string()
        .contains("Invalid DeviceAppId content length"));
    assert!(DeviceAppIdRef::from_tlv(Object::new(
        Tag::DeviceAppIdRefDo,
        Value::Primitive(&[1; 5])
    ))
    .unwrap_err()
    .to_string()
    .contains("Invalid DeviceAppId content length"));

    Ok(())
}

#[gtest]
fn test_invalid_match_criteria_structure() -> Result<()> {
    init();

    // Missing AID and app
    expect_that!(
        MatchCriteria::from_tlv(Object::new(Tag::RefDo, Value::Constructed(vec![])))
            .unwrap_err()
            .to_string(),
        contains_substring("Found empty REF-DO")
    );

    // Missing app
    expect_that!(
        MatchCriteria::from_tlv(Object::new(
            Tag::RefDo,
            Value::Constructed(vec![Object::new(Tag::AidRefDoImplicit, Value::Empty)]),
        ))
        .unwrap_err()
        .to_string(),
        contains_substring("No DeviceAppId-REF-DO")
    );

    // Extra entry
    expect_that!(
        MatchCriteria::from_tlv(Object::new(
            Tag::RefDo,
            Value::Constructed(vec![
                Object::new(Tag::AidRefDoImplicit, Value::Empty),
                Object::new(Tag::DeviceAppIdRefDo, Value::Empty),
                Object::new(Tag::DeviceAppIdRefDo, Value::Empty)
            ]),
        ))
        .unwrap_err()
        .to_string(),
        contains_substring("Found 3 components")
    );

    // AID and DeviceAppID out of order
    expect_that!(
        MatchCriteria::from_tlv(Object::new(
            Tag::RefDo,
            Value::Constructed(vec![
                Object::new(Tag::DeviceAppIdRefDo, Value::Empty),
                Object::new(Tag::AidRefDoImplicit, Value::Empty),
            ])
        ))
        .unwrap_err()
        .to_string(),
        contains_substring("AID-REF-DO found in position 1")
    );

    // AID and PKG-REF
    expect_that!(
        MatchCriteria::from_tlv(Object::new(
            Tag::RefDo,
            Value::Constructed(vec![
                Object::new(Tag::AidRefDoImplicit, Value::Empty),
                Object::new(Tag::PkgRefDo, Value::Empty),
            ])
        ))
        .unwrap_err()
        .to_string(),
        contains_substring("PKG-REF-DO not preceded by DeviceAppID")
    );

    // Invalid content type
    let e = MatchCriteria::from_tlv(Object::new(Tag::RefDo, Value::Primitive(&[])))
        .unwrap_err()
        .to_string();
    assert!(e.contains("Invalid RefDo content Primitive"), "{e}");
    expect_that!(
        MatchCriteria::from_tlv(Object::new(Tag::RefDo, Value::Empty)).unwrap_err().to_string(),
        contains_substring("Invalid RefDo content Empty")
    );

    let contains_unknown = MatchCriteria::from_tlv(Object::new(
        Tag::RefDo,
        Value::Constructed(vec![
            Object::new(Tag::AidRefDoImplicit, Value::Empty),
            Object::new(Tag::new(&[0x00]), Value::Empty),
            Object::new(Tag::DeviceAppIdRefDo, Value::Empty),
        ]),
    ));

    if cfg!(feature = "disallow_unknown_ara_tags") {
        expect_that!(
            contains_unknown.unwrap_err().to_string(),
            contains_substring("Invalid tag Unknown")
        )
    } else {
        assert!(contains_unknown.is_ok(), "Got unexpected error {contains_unknown:?}");
    }

    Ok(())
}

#[test]
fn test_invalid_applet_ref() -> Result<()> {
    init();

    // Default applet ref with invalid content
    assert_that!(
        AppletRef::from_tlv(Object::new(Tag::AidRefDoImplicit, Value::Primitive(&[])))
            .unwrap_err()
            .to_string(),
        contains_substring("Unexpected content Primitive")
    );
    assert_that!(
        AppletRef::from_tlv(Object::new(Tag::AidRefDoImplicit, Value::Constructed(vec![])))
            .unwrap_err()
            .to_string(),
        contains_substring("Unexpected content Constructed")
    );

    // AID ref with invalid content
    assert!(AppletRef::from_tlv(Object::new(
        Tag::AidRefDoSpecificApplet,
        Value::Constructed(vec![])
    ))
    .unwrap_err()
    .to_string()
    .contains("Found invalid content"));

    // Wrong tag
    assert_that!(
        AppletRef::from_tlv(Object::new(Tag::ArDo, Value::Empty)).unwrap_err().to_string(),
        contains_substring("Found unexpected ArDo")
    );

    Ok(())
}

#[test]
fn test_empty_rule_set() -> Result<()> {
    init();

    let tlv = Object::new(Tag::ResponseAllRefArDo, Value::Empty);

    let rule_set = RuleCache::from_tlv(tlv)?;
    assert!(rule_set.rules.is_empty());

    assert_eq!(
        *rule_set.get_apdu_rule(
            &DeviceAppId::new_apk(vec![[0; 32].into()], vec![], vec![]),
            &AppletId::new(&[])
        ),
        ApduAccessRule::Never
    );

    Ok(())
}

#[gtest]
fn test_unknown_in_rule_set() -> Result<()> {
    let tlv = rule_set(vec![Object::new(Tag::new(&[0x00]), Value::Empty)]);

    if cfg!(feature = "disallow_unknown_ara_tags") {
        expect_that!(
            RuleCache::from_tlv(tlv).unwrap_err().root_cause().to_string(),
            contains_substring("Unknown")
        );
    } else {
        expect_that!(RuleCache::from_tlv(tlv), ok(anything()));
    }

    Ok(())
}

#[test]
fn test_access_rule_translation_nfc_defaults() -> Result<()> {
    init();

    // APDU NEVER, no NFC -> NFC NEVER
    assert_eq!(
        AccessRules::from_tlv(access_rule(apdu_access_never(), no_rule()))?.nfc,
        NfcAccessRule::Never
    );

    // APDU ALWAYS, no NFC -> NFC ALWAYS
    assert_eq!(
        AccessRules::from_tlv(access_rule(apdu_access_always(), no_rule()))?.nfc,
        NfcAccessRule::Always
    );

    // APDU FILTER, no NFC -> NFC ALWAYS
    assert_eq!(
        AccessRules::from_tlv(access_rule(apdu_access_filtered(&[0; 8]), no_rule()))?.nfc,
        NfcAccessRule::Always
    );

    Ok(())
}

#[test]
fn test_access_rule_translation_apdu_defaults() -> Result<()> {
    init();

    // no APDU, NFC NEVER -> APDU NEVER
    assert_eq!(
        AccessRules::from_tlv(access_rule(no_rule(), nfc_access_never()))?.apdu,
        ApduAccessRule::Never
    );

    // no APDU, NFC ALWAYS -> APDU NEVER
    assert_eq!(
        AccessRules::from_tlv(access_rule(no_rule(), nfc_access_always()))?.apdu,
        ApduAccessRule::Never
    );

    Ok(())
}

#[test]
fn test_zen_rule_set() -> Result<()> {
    init();

    let app0 = &DeviceAppId::new_apk(vec![[0; 32].into()], vec![], vec![]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![[1; 20].into()], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
    let app3 = &DeviceAppId::new_apk(vec![[3; 32].into()], vec![], vec![]);
    let app4 = &DeviceAppId::new_apk(vec![[4; 32].into()], vec![], vec!["the_package".to_owned()]);
    let app5 = &DeviceAppId::new_system_component(vec![[5; 20].into()]);

    let applet0 = &AppletId::new(&[0; 5]);
    let applet1 = &AppletId::new(&[1; 5]);
    let applet2 = &AppletId::new(&[2; 5]);
    let applet3 = &AppletId::new(&[3; 5]);
    let applet4 = &AppletId::new(&[4; 5]);
    let applet5 = &AppletId::new(&[5; 5]);

    let tlv_rule_set = rule_set(vec![
        // Allow all apps to access applet0
        rule(
            matcher(match_aid(applet0), match_any_app()),
            access_rule(apdu_access_always(), nfc_access_always()),
        ),
        // Allow app0 to access default-selected app.
        rule(
            matcher(match_default_applet(), match_app_sha256(app0)),
            access_rule(apdu_access_always(), nfc_access_always()),
        ),
        // Allow app1 (specified with Sha1 hash) to get NFC events for applet1
        rule(
            matcher(match_aid(applet1), match_app_sha1(app1)),
            access_rule(apdu_access_never(), nfc_access_always()),
        ),
        // Allow app1 (specified with Sha256 hash) to send INS 0xA0 to applet2
        rule(
            matcher(match_aid(applet2), match_app_sha256(app1)),
            access_rule(
                apdu_access_filtered(&[
                    0x00, 0xA0, 0x00, 0x00, // allow
                    0x00, 0xFF, 0x00, 0x00, // mask
                ]),
                nfc_access_always(),
            ),
        ),
        // Another app1/applet2 rule, permissive on APDU and deny on NFC. This shouldn't change
        // the APDU filtering above (because filtering is stricter), but should change the NfC
        // always to never.
        rule(
            matcher(match_aid(applet2), match_app_sha256(app1)),
            access_rule(apdu_access_always(), nfc_access_never()),
        ),
        // Allow app3 APDU access to everything, no NFC rule.
        rule(
            matcher(match_any_aid(), match_app_sha256(app3)),
            access_rule(apdu_access_always(), no_rule()),
        ),
        // Allow all apps to access applet4
        rule(
            matcher(match_aid(applet4), match_any_app()),
            access_rule(apdu_access_always(), nfc_access_always()),
        ),
        // But also define a rule for app0 access to applet4.  This "shadows" the previous rule,
        // preventing any app other than app0 (and app4, due to carrier access rules, see below)
        // from using applet4.
        rule(
            matcher(match_aid(applet4), match_app_sha256(app0)),
            access_rule(apdu_access_always(), nfc_access_never()),
        ),
        // Allow app 4 carrier-privileged access, but only with right package name.  Note that
        // carrier rules do not participate in shadowing, so app4 also has access to applet4.
        rule(match_carrier(app4), access_rule(apdu_access_always(), nfc_access_always())),
        // Allow app 5, a system component, access to applet2, but APDU only, no NFC.
        rule(
            matcher(match_aid(applet2), match_uuid(app5)),
            access_rule(apdu_access_always(), nfc_access_never()),
        ),
    ]);

    let rules = RuleCache::from_tlv(tlv_rule_set)?;

    trace!("Zen RuleSet: {rules:#?}");

    // App0 has access to default-selected applet and applet4
    let test_app = &app0;
    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet0));
    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet1));
    assert_eq!(*rules.get_apdu_rule(test_app, applet2), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet2));
    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet3));
    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Always);
    assert!(!rules.check_nfc(test_app, applet4));
    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet5));
    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, &AppletId::DefaultApplet));

    // App1 can also get applet1 NFC events and send INS 0xA0 APDUs to applet2
    let test_app = &app1;
    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet0));
    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Never);
    assert!(rules.check_nfc(test_app, applet1));
    assert!(rules.check_apdu(test_app, applet2, &[0x00, 0xA0, 0x01, 0x05].into()));
    assert!(rules.check_apdu(test_app, applet2, &[0x0F, 0xA0, 0x02, 0x09].into()));
    assert!(!rules.check_apdu(test_app, applet2, &[0x00, 0xA1, 0x01, 0x05].into()));
    assert!(!rules.check_nfc(test_app, applet2));
    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet3));
    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet4));
    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet5));
    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, &AppletId::DefaultApplet));

    // App2 has no special access, should be denied everything except applet0 (which is
    // open-access).
    let test_app = &app2;
    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet0));
    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet1));
    assert_eq!(*rules.get_apdu_rule(test_app, applet2), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet2));
    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet3));
    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet4));
    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet5));
    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, &AppletId::DefaultApplet));

    // App3 has APDU access to everything; NFC access is default for the APDU ALWAYS case,
    // which per Annex G is ALWAYS.
    let test_app = &app3;
    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet0));
    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet1));
    assert_eq!(*rules.get_apdu_rule(test_app, applet2), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet2));
    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet3));
    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet4));
    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet5));
    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, &AppletId::DefaultApplet));

    // App4 has carrier access (meaning access to everything), with the correct package name.
    let test_app = &app4;
    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet0));
    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet1));
    assert_eq!(*rules.get_apdu_rule(test_app, applet2), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet2));
    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet3));
    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet4));
    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet5));
    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, &AppletId::DefaultApplet));

    // App5 has access to applet4, APDU only, and applet0, which is open access.
    let test_app = &app5;
    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
    assert!(rules.check_nfc(test_app, applet0));
    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet1));
    assert_eq!(*rules.get_apdu_rule(test_app, applet2), ApduAccessRule::Always);
    assert!(!rules.check_nfc(test_app, applet2));
    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet3));
    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet4));
    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, applet5));
    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Never);
    assert!(!rules.check_nfc(test_app, &AppletId::DefaultApplet));

    Ok(())
}

#[test]
fn test_highest_sha256_masks_sha1() -> Result<()> {
    init();

    let applet = AppletId::Aid(&[0; 5]);
    check_sha_256_masks_sha1(applet.clone(), match_aid(&applet))
}

#[test]
fn test_wildcard_aid_sha256_masks_sha1() -> Result<()> {
    init();

    let applet = AppletId::Aid(&[0; 5]);
    check_sha_256_masks_sha1(applet, match_any_aid())
}

fn check_sha_256_masks_sha1(
    applet: AppletId<'_>,
    applet_matcher: Object,
) -> std::result::Result<(), anyhow::Error> {
    let app = DeviceAppId::new_apk(vec![[0; 32].into()], vec![[1; 20].into()], vec![]);

    // Define a couple of APDU "filters".  We won't use these to filter APDUs, they're just
    // handy ways to identify matched rules by which filter the rule contains.
    let filter0 = [0; 8];
    let filter1 = [1; 8];

    let sha1_rule_w_filter_0 = rule(
        matcher(applet_matcher.clone(), match_app_sha1(&app)),
        access_rule(apdu_access_filtered(&filter0), nfc_access_always()),
    );

    let sha256_rule_w_filter_1 = rule(
        matcher(applet_matcher.clone(), match_app_sha256(&app)),
        access_rule(apdu_access_filtered(&filter1), nfc_access_never()),
    );

    // With only the sha1 rule, we should get filter0 & NFC allowed
    let rules = RuleCache::from_tlv(rule_set(vec![sha1_rule_w_filter_0.clone()]))?;
    assert_eq!(
        *rules.get_apdu_rule(&app, &applet),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter0)?)
    );
    assert!(rules.check_nfc(&app, &applet),);

    // With only the sha256 rule, we should get filter1 & NFC denied
    let rules = RuleCache::from_tlv(rule_set(vec![sha256_rule_w_filter_1.clone()]))?;
    assert_eq!(
        *rules.get_apdu_rule(&app, &applet),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter1)?)
    );
    assert!(!rules.check_nfc(&app, &applet),);

    // With both sha1 and sha256 rules, we should again get the sha256 rule content.
    let rules = RuleCache::from_tlv(rule_set(vec![
        sha256_rule_w_filter_1.clone(),
        sha1_rule_w_filter_0.clone(),
    ]))?;
    assert_eq!(
        *rules.get_apdu_rule(&app, &applet),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter1)?)
    );
    assert!(!rules.check_nfc(&app, &applet),);

    // Rule order shouldn't matter
    let rules = RuleCache::from_tlv(rule_set(vec![
        sha1_rule_w_filter_0.clone(),
        sha256_rule_w_filter_1.clone(),
    ]))?;
    assert_eq!(
        *rules.get_apdu_rule(&app, &applet),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter1)?)
    );
    assert!(!rules.check_nfc(&app, &applet),);

    Ok(())
}

#[test]
fn test_low_rules_mask_least_rules() -> Result<()> {
    init();

    let app1 = DeviceAppId::new_apk(vec![[0; 32].into()], vec![], vec![]);
    let app2 = DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    assert_ne!(app1, app2);

    // Define a couple of APDU "filters".  We won't use these to filter APDUs, they're just
    // handy ways to identify matched rules by which filter the rule contains.
    let filter0 = [0; 8];
    let filter1 = [1; 8];

    let low_rule = rule(
        matcher(match_any_aid(), match_app_sha256(&app1)),
        access_rule(apdu_access_filtered(&filter0), nfc_access_never()),
    );

    let least_rule = rule(
        matcher(match_any_aid(), match_any_app()),
        access_rule(apdu_access_filtered(&filter1), nfc_access_never()),
    );

    let applet = AppletId::Aid(&[0; 5]);

    // With only the low rule, we should get filter0 for app1 and NEVER for app2.
    let rules = RuleCache::from_tlv(rule_set(vec![low_rule.clone()]))?;
    assert_eq!(
        *rules.get_apdu_rule(&app1, &applet),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter0)?)
    );
    assert_eq!(*rules.get_apdu_rule(&app2, &applet), ApduAccessRule::Never,);

    // With only the least rule, we should get filter1 for both apps.
    let rules = RuleCache::from_tlv(rule_set(vec![least_rule.clone()]))?;
    assert_eq!(
        *rules.get_apdu_rule(&app1, &applet),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter1)?)
    );
    assert_eq!(
        *rules.get_apdu_rule(&app2, &applet),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter1)?)
    );

    // With both rules, we should get filter1 for app1, but NEVER for app2, because the low
    // rule masks the least rule, making it inapplicable.
    // With only the least rule, we should get filter1 for both apps.
    let rules = RuleCache::from_tlv(rule_set(vec![least_rule.clone(), low_rule.clone()]))?;
    assert_eq!(
        *rules.get_apdu_rule(&app1, &applet),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter0)?)
    );
    assert_eq!(*rules.get_apdu_rule(&app2, &applet), ApduAccessRule::Never);

    // Rule order doesn't matter.
    let rules = RuleCache::from_tlv(rule_set(vec![low_rule.clone(), least_rule.clone()]))?;
    assert_eq!(
        *rules.get_apdu_rule(&app1, &applet),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter0)?)
    );
    assert_eq!(*rules.get_apdu_rule(&app2, &applet), ApduAccessRule::Never);

    Ok(())
}

#[test]
fn test_invalid_rule_set() -> Result<()> {
    init();

    // Wrong tag
    assert_that!(
        RuleCache::from_tlv(Object::new(Tag::ArDo, Value::Empty))
            .unwrap_err()
            .root_cause()
            .to_string(),
        contains_substring("ArDo vs ResponseAllRefArDo")
    );

    // Wrong content type
    assert_that!(
        RuleCache::from_tlv(Object::new(Tag::ResponseAllRefArDo, Value::Primitive(&[])))
            .unwrap_err()
            .root_cause()
            .to_string(),
        contains_substring("Invalid RuleCache content Primitive")
    );

    Ok(())
}

#[gtest]
fn test_invalid_rule() -> Result<()> {
    init();

    // Wrong content type
    expect_that!(
        Rule::from_tlv(Object::new(Tag::RefArDo, Value::Empty)).unwrap_err().to_string(),
        contains_substring("Invalid RefArDo content Empty")
    );
    expect_that!(
        Rule::from_tlv(Object::new(Tag::RefArDo, Value::Primitive(&[]))).unwrap_err().to_string(),
        contains_substring("Invalid RefArDo content Primitive")
    );

    // Missing match criteria
    expect_that!(
        Rule::from_tlv(Object::new(Tag::RefArDo, Value::Constructed(vec![])))
            .unwrap_err()
            .root_cause()
            .to_string(),
        contains_substring("Missing RefDo")
    );

    // Missing access rules
    expect_that!(
        Rule::from_tlv(Object::new(
            Tag::RefArDo,
            Value::Constructed(vec![matcher(match_any_aid(), match_any_app())])
        ))
        .unwrap_err()
        .root_cause()
        .to_string(),
        contains_substring("Missing ArDo")
    );

    // Extra entry
    expect_that!(
        Rule::from_tlv(Object::new(
            Tag::RefArDo,
            Value::Constructed(vec![
                matcher(match_any_aid(), match_any_app()),
                access_rule(apdu_access_always(), nfc_access_always()),
                access_rule(apdu_access_always(), nfc_access_always()),
            ])
        ))
        .unwrap_err()
        .root_cause()
        .to_string(),
        contains_substring("Found multiple")
    );

    // Unknown tag
    let contains_unknown = Rule::from_tlv(Object::new(
        Tag::RefArDo,
        Value::Constructed(vec![
            matcher(match_any_aid(), match_any_app()),
            Object::new(Tag::new(&[0x00]), Value::Empty),
            access_rule(apdu_access_always(), nfc_access_always()),
        ]),
    ));

    if cfg!(feature = "disallow_unknown_ara_tags") {
        expect_that!(
            contains_unknown.unwrap_err().root_cause().to_string(),
            contains_substring("Invalid tag Unknown")
        );
    } else {
        assert!(contains_unknown.is_ok(), "Got unexpected error {contains_unknown:?}");
    }

    Ok(())
}

// Test case from page 106
#[test]
fn test_gp_doc_test_case_1() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![rule(
        matcher(match_aid(applet1), match_app_sha256(app1)),
        access_rule(apdu_access_always(), no_rule()),
    )]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    // Doc doesn't say what NFC access should be.

    assert!(rules.check_apdu(app1, applet1, &[0; 4].into()));
    assert!(!rules.check_apdu(app1, applet2, &[0; 4].into()));

    Ok(())
}

// Test case from page 106
#[test]
fn test_gp_doc_test_case_2() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_app_sha256(app2)),
            access_rule(apdu_access_always(), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 106
#[test]
fn test_gp_doc_test_case_3() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![rule(
        matcher(match_aid(applet1), match_app_sha256(app1)),
        access_rule(apdu_access_never(), no_rule()),
    )]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 106
#[test]
fn test_gp_doc_test_case_4() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_never(), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 106
#[test]
fn test_gp_doc_test_case_5() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![rule(
        matcher(match_aid(applet1), match_app_sha256(app1)),
        access_rule(apdu_access_filtered(&[1; 8]), no_rule()),
    )]))?;
    trace!("{rules:?}");

    assert_eq!(
        *rules.get_apdu_rule(app1, applet1),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[1; 8])?)
    );
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 106
#[test]
fn test_gp_doc_test_case_6() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let applet3 = &AppletId::Aid(&[3]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app2)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet2), match_app_sha256(app2)),
            access_rule(apdu_access_filtered(&[1; 8]), no_rule()),
        ),
        rule(
            matcher(match_any_aid(), match_app_sha256(app2)),
            access_rule(apdu_access_always(), no_rule()),
        ),
    ]))?;
    trace!("{rules:#?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(
        *rules.get_apdu_rule(app2, applet2),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[1; 8])?)
    );
    assert_eq!(*rules.get_apdu_rule(app1, applet3), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet3), ApduAccessRule::Always);

    Ok(())
}

// Test case on page 106
#[gtest]
fn test_gp_doc_test_case_7() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_app_sha256(app2)),
            access_rule(apdu_access_filtered(&[1; 8]), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
    assert_eq!(
        *rules.get_apdu_rule(app2, applet1),
        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[1; 8])?)
    );
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 107
#[gtest]
fn test_gp_doc_test_case_9() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_any_app()),
            access_rule(apdu_access_never(), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 107
#[gtest]
fn test_gp_doc_test_case_10() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_any_app()),
            access_rule(apdu_access_always(), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 107
#[gtest]
fn test_gp_doc_test_case_11() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_any_app()),
            access_rule(apdu_access_never(), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 107
#[test]
fn test_gp_doc_test_case_12() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_any_app()),
            access_rule(apdu_access_always(), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 107
#[gtest]
fn test_gp_doc_test_case_13() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![rule(
        matcher(match_any_aid(), match_any_app()),
        access_rule(apdu_access_always(), no_rule()),
    )]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Always);

    Ok(())
}

// Test case on page 107
#[gtest]
fn test_gp_doc_test_case_14() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_any_app()),
            access_rule(apdu_access_always(), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 108
#[test]
fn test_gp_doc_test_case_15() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let applet3 = &AppletId::Aid(&[3]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_any_app()),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet2), match_any_app()),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_any_aid(), match_any_app()),
            access_rule(apdu_access_never(), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app1, applet3), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet3), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 108
#[gtest]
fn test_gp_doc_test_case_16() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let applet3 = &AppletId::Aid(&[3]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_any_app()),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet2), match_app_sha256(app1)),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet2), match_any_app()),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_any_aid(), match_app_sha256(app1)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_any_aid(), match_any_app()),
            access_rule(apdu_access_always(), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app1, applet3), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet3), ApduAccessRule::Never);

    Ok(())
}

// Test case on page 108
#[gtest]
fn test_gp_doc_test_case_17() -> Result<()> {
    init();

    let applet1 = &AppletId::Aid(&[1]);
    let applet2 = &AppletId::Aid(&[2]);
    let applet3 = &AppletId::Aid(&[3]);
    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
    let app3 = &DeviceAppId::new_apk(vec![[3; 32].into()], vec![], vec![]);
    let app4 = &DeviceAppId::new_apk(vec![[4; 32].into()], vec![], vec![]);

    let rules = RuleCache::from_tlv(rule_set(vec![
        rule(
            matcher(match_aid(applet1), match_app_sha256(app1)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_app_sha256(app2)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_app_sha256(app3)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet1), match_any_app()),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet2), match_app_sha256(app1)),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet2), match_app_sha256(app2)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet2), match_app_sha256(app3)),
            access_rule(apdu_access_never(), no_rule()),
        ),
        rule(
            matcher(match_aid(applet2), match_any_app()),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_any_aid(), match_app_sha256(app1)),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_any_aid(), match_app_sha256(app2)),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_any_aid(), match_app_sha256(app3)),
            access_rule(apdu_access_always(), no_rule()),
        ),
        rule(
            matcher(match_any_aid(), match_any_app()),
            access_rule(apdu_access_never(), no_rule()),
        ),
    ]))?;
    trace!("{rules:?}");

    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app3, applet1), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app4, applet1), ApduAccessRule::Never);

    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app3, applet2), ApduAccessRule::Never);
    assert_eq!(*rules.get_apdu_rule(app4, applet2), ApduAccessRule::Never);

    assert_eq!(*rules.get_apdu_rule(app1, applet3), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app2, applet3), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app3, applet3), ApduAccessRule::Always);
    assert_eq!(*rules.get_apdu_rule(app4, applet3), ApduAccessRule::Never);

    Ok(())
}

#[gtest]
fn text_xml_rules() -> Result<()> {
    init();

    let text = r#"
    <rules>
      <ref_ar_do>
        <ref_do>
          <aid_ref_do>
            A00000015141434C00
          </aid_ref_do>
          <deviceappid_ref_do>
            00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
          </deviceappid_ref_do>
        </ref_do>
        <ar_do>
          <apdu_ar_do>
            01
          </apdu_ar_do>
        </ar_do>
      </ref_ar_do>
      <ref_ar_do>
        <ref_do>
          <aid_ref_do>
            A000000BCDEF
          </aid_ref_do>
          <deviceappid_ref_do/>
        </ref_do>
        <ar_do>
          <apdu_ar_do>
            00
          </apdu_ar_do>
        </ar_do>
      </ref_ar_do>
    </rules>"#;

    let _rules = RuleCache::xml_to_rules(xml::parse_xml_rules(text.as_bytes())?)?;

    Ok(())
}

pub fn match_any_aid() -> Object<'static> {
    Object::new(Tag::AidRefDoSpecificApplet, Value::Empty)
}

pub fn match_aid<'a>(applet: &'a AppletId) -> Object<'a> {
    match applet {
        AppletId::Aid(aid) => Object::new(Tag::AidRefDoSpecificApplet, Value::Primitive(aid)),
        AppletId::DefaultApplet => Object::new(Tag::AidRefDoImplicit, Value::Empty),
    }
}

pub fn match_default_applet() -> Object<'static> {
    Object::new(Tag::AidRefDoImplicit, Value::Empty)
}

pub fn match_any_app() -> Object<'static> {
    Object::new(Tag::DeviceAppIdRefDo, Value::Empty)
}

pub fn match_app_sha256(app: &DeviceAppId) -> Object<'_> {
    match app {
        DeviceAppId::Apk { sha256s, sha1s: _, package_names: _ } => {
            Object::new(Tag::DeviceAppIdRefDo, Value::Primitive(&sha256s[0].0))
        }
        DeviceAppId::SystemComponent { uuids: _ } => unreachable!(),
    }
}

pub fn match_package(pkg_name: &str) -> Object<'_> {
    Object::new(Tag::PkgRefDo, Value::Primitive(pkg_name.as_bytes()))
}

pub fn match_app_sha1(app: &DeviceAppId) -> Object {
    match app {
        DeviceAppId::Apk { sha256s: _, sha1s, package_names: _ } => {
            Object::new(Tag::DeviceAppIdRefDo, Value::Primitive(&sha1s[0].0))
        }
        DeviceAppId::SystemComponent { uuids: _ } => unreachable!(),
    }
}

pub fn match_uuid(app: &DeviceAppId) -> Object {
    match app {
        DeviceAppId::Apk { sha256s: _, sha1s: _, package_names: _ } => unreachable!(),
        DeviceAppId::SystemComponent { uuids } => {
            Object::new(Tag::DeviceAppIdRefDo, Value::Primitive(&uuids[0].0))
        }
    }
}

pub fn matcher<'a>(aid_ref: Object<'a>, app_ref: Object<'a>) -> Object<'a> {
    Object::new(Tag::RefDo, Value::Constructed(vec![aid_ref, app_ref]))
}

pub fn match_carrier(app: &DeviceAppId) -> Object<'_> {
    let mut vec = vec![match_app_sha256(app)];
    match app {
        DeviceAppId::Apk { sha256s: _, sha1s: _, package_names } => {
            vec.push(match_package(&package_names[0]))
        }
        DeviceAppId::SystemComponent { uuids: _ } => unreachable!(),
    }
    Object::new(Tag::RefDo, Value::Constructed(vec))
}

pub fn apdu_access_never() -> Option<Object<'static>> {
    Some(Object::new(Tag::ApduArDo, Value::Primitive(&[0x00])))
}

pub fn apdu_access_filtered(filters: &[u8]) -> Option<Object> {
    Some(Object::new(Tag::ApduArDo, Value::Primitive(filters)))
}

pub fn apdu_access_always() -> Option<Object<'static>> {
    Some(Object::new(Tag::ApduArDo, Value::Primitive(&[0x01])))
}

pub fn nfc_access_never() -> Option<Object<'static>> {
    Some(Object::new(Tag::NfcArDo, Value::Primitive(&[0x00])))
}

pub fn nfc_access_always() -> Option<Object<'static>> {
    Some(Object::new(Tag::NfcArDo, Value::Primitive(&[0x01])))
}

pub fn no_rule<'a>() -> Option<Object<'a>> {
    None
}

pub fn access_rule<'a>(apdu_rule: Option<Object<'a>>, nfc_rule: Option<Object<'a>>) -> Object<'a> {
    let mut vec = Vec::new();
    if let Some(apdu_rule) = apdu_rule {
        vec.push(apdu_rule);
    }
    if let Some(nfc_rule) = nfc_rule {
        vec.push(nfc_rule);
    }

    Object::new(Tag::ArDo, Value::Constructed(vec))
}

pub fn rule<'a>(matcher: Object<'a>, access_rule: Object<'a>) -> Object<'a> {
    Object::new(Tag::RefArDo, Value::Constructed(vec![matcher, access_rule]))
}

pub fn rule_set(rules: Vec<Object<'_>>) -> Object<'_> {
    match rules.len() {
        0 => Object::new(Tag::ResponseAllRefArDo, Value::Empty),
        _ => Object::new(Tag::ResponseAllRefArDo, Value::Constructed(rules)),
    }
}
