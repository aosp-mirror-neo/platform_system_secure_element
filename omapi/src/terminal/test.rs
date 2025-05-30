use super::*;
use crate::utils::create_exception_status;
use android_hardware_secure_element::aidl::android::hardware::secure_element::{
    ISecureElement::{BnSecureElement, MockISecureElement},
    LogicalChannelResponse::LogicalChannelResponse,
};
use binder::{BinderFeatures, ExceptionCode};
use googletest::prelude::*;
use googletest::test as gtest;
use googletest::Result;
use mockall::{predicate as mp, Sequence};

fn init() {
    crate::test_utils::init(module_path!());
}

#[gtest]
fn create_terminal() -> Result<()> {
    init();

    let se_binder = build_mock_se(|_mock_se| {});
    let terminal = Terminal::new("se_name", se_binder)?;

    assert_that!(terminal.name(), eq("se_name"));
    assert!(!terminal.is_connected);
    assert!(terminal.is_default_app_selected_on_basic_channel);
    assert!(terminal.channels.is_empty());

    Ok(())
}

#[gtest]
fn get_answer_to_reset() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        mock_se.expect_getAtr().times(1).return_once(|| Ok("Hello".as_bytes().to_vec()));
    });
    let mut terminal = Terminal::new("se_name", se_binder.clone())?;

    // Can't get ATR until connected.
    assert_that!(terminal.answer_to_reset()?, none());

    terminal.set_connected(true);

    assert_that!(terminal.answer_to_reset()?, some(eq("Hello".as_bytes())));

    Ok(())
}

#[gtest]
fn open_basic_channel() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        mock_se
            .expect_openBasicChannel()
            .with(mp::eq([]), mp::eq(0x00))
            .return_once(|_, _| Ok("ats".as_bytes().to_vec()));
        expect_default_select(mock_se);
        mock_se.expect_closeChannel().with(mp::eq(0)).returning(|_| Ok(()));
    });
    let mut terminal = Terminal::new("se_name", se_binder.clone())?;

    let err = terminal.open_basic_channel(&[], 0x00).unwrap_err();
    assert_eq!(err.exception_code(), ExceptionCode::SERVICE_SPECIFIC);
    assert!(err.get_description().contains("Secure Element is not connected"));

    terminal.set_connected(true);

    let channel_id = terminal.open_basic_channel(&[], 0x00)?.expect("Should not be None");
    assert!(channel_id.is_basic());
    assert_that!(terminal.select_response(channel_id).unwrap(), eq("ats".as_bytes()));
    assert!(!terminal.channel_closed(channel_id));

    terminal.close_channel(channel_id, SendSelectOnClose(false))?;
    assert!(terminal.channel_closed(channel_id));

    Ok(())
}

#[gtest]
fn open_basic_channel_invalid_p2() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        // openBasicChannel (and therefore closeChannel) is only called for the valid p2 values.
        mock_se.expect_openBasicChannel().times(4).returning(|_, _| Ok("ats".as_bytes().to_vec()));
        mock_se.expect_closeChannel().times(4).with(mp::eq(0)).returning(|_| Ok(()));
    });
    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);

    for p2 in 0x00_u8..=0xFF_u8 {
        let open_result = terminal.open_basic_channel(&[], p2 as i8);
        match p2 {
            0x00 | 0x04 | 0x08 | 0x0C => {
                let channel_id = open_result
                    .expect("No error expected for {p2}")
                    .expect("Some value expected for {p2}");
                assert!(channel_id.is_basic(), "Should be basic channel for {p2}");
                assert!(terminal.is_default_app_selected_on_basic_channel);
                terminal.close_channel(channel_id, SendSelectOnClose(false))?;
            }
            p2 => {
                assert_that!(
                    open_result
                        .expect_err(&format!("P2 value {p2} should not be supported."))
                        .to_string(),
                    contains_substring("p2 not supported")
                );
            }
        }
    }

    Ok(())
}

#[gtest]
fn open_basic_channel_invalid_aid() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        // openBasicChannel (and therefore closeChannel) is only called for the valid AIDs.
        mock_se.expect_openBasicChannel().times(13).returning(|_, _| Ok("ats".as_bytes().to_vec()));
        mock_se.expect_closeChannel().times(13).with(mp::eq(0)).returning(|_| Ok(()));
    });
    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);

    for aid_len in 0..20 {
        let aid = vec![0; aid_len];
        let open_result = terminal.open_basic_channel(&aid, 0x00);

        match aid_len {
            0x00 | 5..=16 => {
                let channel_id = open_result
                    .expect("No error expected for {aid_len}")
                    .expect("Some value expected for {aid_len}");
                assert!(channel_id.is_basic(), "Should be basic channel for {aid_len}",);
                assert!(
                    terminal.is_default_app_selected_on_basic_channel == (aid_len == 0),
                    "Default applet selection incorrect for {aid_len}"
                );
                terminal.close_channel(channel_id, SendSelectOnClose(false))?;
            }
            aid_len => {
                assert_that!(
                    open_result
                        .expect_err("AID length {aid_len} should not be supported.")
                        .to_string(),
                    contains_substring("AID out of range"),
                    "Wrong error for {aid_len}"
                );
            }
        }
    }

    Ok(())
}

#[gtest]
fn reopen_basic_channel() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        mock_se.expect_openBasicChannel().times(1).returning(|_, _| Ok("ats".as_bytes().to_vec()));
    });
    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);

    // First attempt works.
    let channel_id = terminal.open_basic_channel(&[], 0x00)?;
    assert!(channel_id.expect("Should not be None").is_basic());

    // Second time returns None because the channel is already open.
    let channel_id = terminal.open_basic_channel(&[], 0x00)?;
    assert!(channel_id.is_none());

    Ok(())
}

#[gtest]
fn open_logical_channel() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        mock_se.expect_openLogicalChannel().times(1).returning(|_, _| {
            Ok(LogicalChannelResponse {
                channelNumber: 1,
                selectResponse: "ats".as_bytes().to_vec(),
            })
        });
        mock_se.expect_closeChannel().with(mp::eq(1)).returning(|_| Ok(()));
    });
    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);

    let channel_id = terminal.open_logical_channel(&[], 0x00)?.expect("Should not be None");
    assert!(!channel_id.is_basic());
    assert_that!(channel_id, eq(ChannelId(1)));
    assert_that!(terminal.select_response(channel_id).unwrap(), eq("ats".as_bytes()));
    assert!(!terminal.channel_closed(channel_id));

    terminal.close_channel(channel_id, SendSelectOnClose(false))?;
    assert!(terminal.channel_closed(channel_id));

    Ok(())
}

#[gtest]
fn transmit_apdu() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        mock_se.expect_openLogicalChannel().times(1).returning(|_, _| {
            Ok(LogicalChannelResponse {
                channelNumber: 1,
                selectResponse: "ats".as_bytes().to_vec(),
            })
        });
        mock_se.expect_transmit().with(mp::eq([1, 0, 0, 0])).returning(|_| Ok(vec![0x90, 0x00]));
    });

    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);

    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();
    let response = terminal.transmit(channel_id, &[0x00, 0x00, 0x00, 0x00], false)?;
    assert_that!(response, eq(&ApduResponse(vec![0x90, 00])));

    Ok(())
}

#[gtest]
fn transmit_on_closed_channel() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        mock_se.expect_openLogicalChannel().times(1).returning(|_, _| {
            Ok(LogicalChannelResponse {
                channelNumber: 1,
                selectResponse: "ats".as_bytes().to_vec(),
            })
        });
        mock_se.expect_closeChannel().with(mp::eq(1)).returning(|_| Ok(()));
    });

    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);

    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();
    terminal.close_channel(channel_id, SendSelectOnClose(false))?;

    let err = terminal.transmit(channel_id, &[0x00, 0x00, 0x00, 0x00, 0x00], false).unwrap_err();
    assert_that!(err.to_string(), contains_substring("ChannelId(1) is closed"));

    Ok(())
}

#[gtest]
fn invalid_apdus() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        mock_se.expect_openLogicalChannel().times(1).returning(|_, _| {
            Ok(LogicalChannelResponse {
                channelNumber: 1,
                selectResponse: "ats".as_bytes().to_vec(),
            })
        });
        mock_se.expect_transmit().returning(|_| Ok(vec![0x90, 0x00]));
    });

    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);
    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();

    // Lambdas to reduce repetition.
    let expect_fail = |apdu: &[u8], expected_code: ExceptionCode, expected_err: &str| {
        expect_that!(
            terminal.transmit(channel_id, apdu, false),
            err(predicate(binder_status(expected_code, expected_err))),
            "APDU {} should have failed with {}",
            hex::encode(apdu),
            create_exception_status(expected_code, expected_err)
        );
    };
    let expect_success = |apdu: &[u8]| {
        expect_that!(
            terminal.transmit(channel_id, apdu, false),
            ok(eq(&ApduResponse(vec![0x90, 0x00]))),
            "APDU {} should have succeeded",
            hex::encode(apdu)
        );
    };

    expect_fail(&[0x00, 0x00, 0x00], ILLEGAL_ARGUMENT, "Too-short APDU");
    expect_fail(&[0xFF, 0x00, 0x00, 0x00], ILLEGAL_ARGUMENT, "Invalid CLA (0xFF)");

    // Invalid INS (with ISO CLA and P2 == 0x04)
    for ins in 0..0xFF_u8 {
        let apdu = &[0x00, ins, 0x04, 0x00];

        match ins {
            0xA4 => expect_fail(apdu, SECURITY, "SELECT by DF name command not allowed"),
            0x70 => expect_fail(apdu, SECURITY, "MANAGE CHANNEL command not allowed."),
            _ => match ins & 0xF0 {
                0x60 | 0x90 => {
                    expect_fail(apdu, ILLEGAL_ARGUMENT, &format!("Invalid INS {ins:#04X}"))
                }
                _ => expect_success(apdu),
            },
        }
    }

    // Verify that INS 0xA4 (SELECT DF) is allowed for non-privileged callers if P1 is not 0x04
    // (select by name)
    expect_success(&[0x00, 0xA4, 0x00, 0x00]);

    // Verify that INS 0xA4 with P1 0x04 is allowed for non-privileged callers with non-ISO CLA
    expect_success(&[0x80, 0xA4, 0x04, 0x00]);

    // Verify that privileged callers are allowed to use INS 0xA4 with P1 0x04
    expect_that!(
        terminal.transmit(channel_id, &[0x00, 0xA4, 0x04, 0x00], true),
        ok(eq(&ApduResponse(vec![0x90, 0x00])))
    );

    // Verify that INS 0x70 (manage channel) is allowed with non-ISO CLA
    expect_success(&[0x80, 0x70, 0x00, 0x00]);

    // Case 3S error; Not enough command bytes (Lc == 0x02, only one data byte).
    expect_fail(
        &[0x00, 0x00, 0x00, 0x00, 0x02, 0xFF],
        ILLEGAL_ARGUMENT,
        "Lc is 2 but is followed by 1 byte(s).",
    );

    // Case 3E error; Not enough command bytes (Lc == 0x02, only one data byte).
    expect_fail(
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF],
        ILLEGAL_ARGUMENT,
        "Lc is 2 but is followed by 1 byte(s).",
    );

    // Case 3S/4S error; Too many command bytes (Lc = 1, two data bytes)
    expect_fail(
        &[0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0x01],
        ILLEGAL_ARGUMENT,
        "Lc is 1 but is followed by 3 byte(s).",
    );

    // Case 3S/4E error; Too many command bytes (Lc = 1, two data bytes)
    expect_fail(
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0x00, 0x00],
        ILLEGAL_ARGUMENT,
        "Lc is 1 but is followed by 4 byte(s)",
    );

    // Verify that extended Lc goes up to 2^16 == 65536, not 2^16 - 1, as you'd usually expect.
    // 65536 is represented by 0x0000 in the Lc field.
    expect_success(
        &[
            &[0x00, 0x00, 0x00, 0x00, 0x00][..], // header w/B1 == 0 indicates extended
            &[0x00, 0x00][..],                   // 0x0000 means Lc = 65536
            &[0x00; 65536][..],                  // 65536 bytes of data.
        ]
        .concat(),
    );

    // One less byte of command data should fail
    expect_fail(
        &[
            &[0x00, 0x00, 0x00, 0x00, 0x00][..], // header w/B1 == 0 indicates extended
            &[0x00, 0x00][..],                   // 0x0000 means Lc = 65536
            &[0x00; 65535][..],                  // 65536 - 1 bytes of data.
        ]
        .concat(),
        ILLEGAL_ARGUMENT,
        "Lc is 65536 but is followed by 65535 byte(s)",
    );

    Ok(())
}

#[gtest]
fn handle_le_correction() -> Result<()> {
    init();

    let mut seq = Sequence::new();
    let se_binder = build_mock_se(|mock_se| {
        mock_se.expect_openLogicalChannel().times(1).in_sequence(&mut seq).returning(|_, _| {
            Ok(LogicalChannelResponse {
                channelNumber: 1,
                selectResponse: "ats".as_bytes().to_vec(),
            })
        });

        // First APDU has Le 0, but SE will respond saying it should be two.
        mock_se
            .expect_transmit()
            .with(mp::eq([0x01, 0x00, 0x00, 0x00, /* Le */ 0x00]))
            .times(1)
            .in_sequence(&mut seq)
            // Return SW1 0x6C, indicating Le should be corrected, and SW2 to indicate correct
            // value, in this case 2.
            .returning(|_| Ok(vec![0x6C, 0x02]));

        // Automatic resend should adjust the Le and return success with two bytes of data.
        mock_se
            .expect_transmit()
            .with(mp::eq([0x01, 0x00, 0x00, 0x00, /* Le */ 0x02]))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(vec![0x00, 0x00, 0x90, 0x00]));
    });

    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);

    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();
    // Although there will actually be two APDUs sent, the initial one and the corrected one, as
    // far as the client knows, there's just one successful APDU.
    let response =
        terminal.transmit(channel_id, &[0x00, 0x00, 0x00, 0x00, /* Le */ 0x00], false)?;
    assert_that!(response, eq(&ApduResponse(vec![0x00, 0x00, 0x90, 0x00])));

    Ok(())
}

#[gtest]
fn handle_response_chaining() -> Result<()> {
    init();

    let mut seq = Sequence::new();
    let se_binder = build_mock_se(|mock_se| {
        mock_se.expect_openLogicalChannel().times(1).in_sequence(&mut seq).returning(|_, _| {
            Ok(LogicalChannelResponse {
                channelNumber: 1,
                selectResponse: "ats".as_bytes().to_vec(),
            })
        });
        // First APDU has Le 0x10, but SE will respond with only the first four bytes and send
        // status words indicating that GET DATA should be used to get the rest.
        mock_se
            .expect_transmit()
            .with(mp::eq([0x01, 0x00, 0x00, 0x00, /* Le */ 0x10]))
            .times(1)
            .in_sequence(&mut seq)
            // Return SW1 0x61, indicating that not all data was returned and SW 0x0C, indicating
            // that 8 more bytes need to be retrieved
            .returning(|_| Ok(vec![0x01, 0x02, 0x03, 0x04, 0x61, 0x0C]));
        // Second APDU will be GET DATA, requesting 0x0C bytes.  Only return 4 and indicate
        // another GET DATA is needed.
        mock_se
            .expect_transmit()
            .with(mp::eq([0x01, 0xC0, 0x00, 0x00, /* Le */ 0x0C]))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(vec![0x05, 0x06, 0x07, 0x08, 0x61, 0x08]));
        // Third APDU will be GET DATA, requesting 0x08 bytes.  Only return 4 and indicate another
        // GET DATA is needed.
        mock_se
            .expect_transmit()
            .with(mp::eq([0x01, 0xC0, 0x00, 0x00, /* Le */ 0x08]))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(vec![0x09, 0x0A, 0x0B, 0x0C, 0x61, 0x04]));
        // Fourth and final APDU will be GET DATA, requesting 0x04 (12) bytes.  Return them and
        // indicate success.
        mock_se
            .expect_transmit()
            .with(mp::eq([0x01, 0xC0, 0x00, 0x00, /* Le */ 0x04]))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(vec![0x0D, 0x0E, 0x0F, 0x10, 0x90, 0x00]));
    });

    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);

    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();
    // Although four APDUs are exchanged, to the client it appears there was only one, and it
    // returned all 0x10 bytes of data.
    let response =
        terminal.transmit(channel_id, &[0x00, 0x00, 0x00, 0x00, /* Le */ 0x10], false)?;
    assert_that!(
        response,
        eq(&ApduResponse(vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x90, 0x00
        ]))
    );

    Ok(())
}

#[gtest]
fn transmit_disallowed_iso_commands_non_privileged() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        mock_se.expect_openLogicalChannel().times(1).returning(|_, _| {
            Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] })
        });
    });

    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);
    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();

    // SELECT by DF name (ISO CLA, INS 0xA4, P1 0x04)
    let err = terminal.transmit(channel_id, &[0x00, 0xA4, 0x04, 0x00], false).unwrap_err();
    assert_that!(err.to_string(), contains_substring("SELECT by DF name command not allowed"));

    // MANAGE CHANNEL (ISO CLA, INS 0x70)
    let err = terminal.transmit(channel_id, &[0x00, 0x70, 0x00, 0x00], false).unwrap_err();
    assert_that!(err.to_string(), contains_substring("MANAGE CHANNEL command not allowed"));

    Ok(())
}

#[gtest]
fn transmit_disallowed_iso_commands_privileged() -> Result<()> {
    init();

    let se_binder = build_mock_se(|mock_se| {
        mock_se.expect_openLogicalChannel().times(1).returning(|_, _| {
            Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] })
        });
        mock_se.expect_transmit().returning(|_| Ok(vec![0x90, 0x00]));
    });

    let mut terminal = Terminal::new("se_name", se_binder)?;
    terminal.set_connected(true);
    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();

    // SELECT by DF name (ISO CLA, INS 0xA4, P1 0x04) should be allowed for privileged
    let response = terminal.transmit(channel_id, &[0x00, 0xA4, 0x04, 0x00], true)?;
    assert_that!(response, eq(&ApduResponse(vec![0x90, 0x00])));

    // MANAGE CHANNEL (ISO CLA, INS 0x70) should also be allowed for privileged
    let response = terminal.transmit(channel_id, &[0x00, 0x70, 0x00, 0x00], true)?;
    assert_that!(response, eq(&ApduResponse(vec![0x90, 0x00])));

    // SELECT by DF name with GP secure messaging (CLA = 0x84, INS 0xA4, P1 0x04).  Note that a
    // real GP secure messaging implementation would require data to be encrypted and the header
    // and data to be authenticated, so a client can use a GP SM header to get by the
    // error-checking in `Terminal`, but the SE would reject the APDU if secure messaging has not
    // been set up or the APDU authentication is incorrect.
    let response = terminal.transmit(channel_id, &[0x84, 0xA4, 0x04, 0x00], false)?;
    assert_that!(response, eq(&ApduResponse(vec![0x90, 0x00])));

    // MANAGE CHANNEL with GP secure messaging (CLA = 0x84, INS 0x70)
    let response = terminal.transmit(channel_id, &[0x84, 0x70, 0x00, 0x00], false)?;
    assert_that!(response, eq(&ApduResponse(vec![0x90, 0x00])));

    Ok(())
}

fn build_mock_se(expectations: impl FnOnce(&mut MockISecureElement)) -> Strong<dyn ISecureElement> {
    let mut se_mock = MockISecureElement::new();
    expectations(&mut se_mock);

    BnSecureElement::new_binder(se_mock, BinderFeatures::default())
}

fn expect_default_select(mock_se: &mut MockISecureElement) {
    mock_se.expect_transmit().with(mp::eq(SELECT_DEFAULT_APDU)).returning(|_| Ok(vec![0x90, 0x00]));
}

fn binder_status(code: ExceptionCode, description: &str) -> impl Fn(&'_ binder::Status) -> bool {
    let description = description.to_owned();
    move |s: &binder::Status| {
        s.exception_code() == code && s.get_description().contains(&description)
    }
}
