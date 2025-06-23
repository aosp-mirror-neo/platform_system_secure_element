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

//! Unit tests for uuid_mapping.rs

use super::*;
use googletest::prelude::*;
use googletest::test as gtest;

fn init() {
    crate::test_utils::init(module_path!());
}

#[gtest]
fn test_parser() -> Result<()> {
    init();

    let text = r"
    <ref_do>
        <uuid_ref_do>
            <uids>
                <uid>0</uid>
            </uids>
            <uuid>9f36407ead0639fc966f14dde7970f68</uuid>
        </uuid_ref_do>
        <uuid_ref_do>
            <uids>
                <uid>1096</uid>
                <uid>1097</uid>
            </uids>
            <uuid>a9b7ba70-783b-317e-9998-dc4dd82eb3c5</uuid>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes())?;
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].uids, vec![0]);
    assert_eq!(
        result[0].uuid,
        [
            0xff, 0xff, 0xff, 0xff, 0x9f, 0x36, 0x40, 0x7e, 0xad, 0x06, 0x39, 0xfc, 0x96, 0x6f,
            0x14, 0xdd, 0xe7, 0x97, 0x0f, 0x68
        ]
    );
    assert_eq!(result[1].uids, vec![1096, 1097]);
    assert_eq!(
        result[1].uuid,
        [
            0xff, 0xff, 0xff, 0xff, 0xa9, 0xb7, 0xba, 0x70, 0x78, 0x3b, 0x31, 0x7e, 0x99, 0x98,
            0xdc, 0x4d, 0xd8, 0x2e, 0xb3, 0xc5
        ]
    );

    Ok(())
}

#[gtest]
fn test_comments() -> Result<()> {
    init();

    let text = r"
    <!-- Add an XML comment -->
    <ref_do>
        <uuid_ref_do>
            <uids>
                <uid>0<!-- Another one here --></uid>
            </uids>
            <uuid>9f36407e<!-- One in the middle of value -->ad0639fc966f14dde7970f68</uuid>
        </uuid_ref_do>
        <uuid_ref_do>
            <uids>
                <uid>1096</uid>
                <uid>1097</uid>
            </uids>
            <uuid>a9b7ba70-783b-317e-9998-dc4dd82eb3c5</uuid>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes())?;
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].uids, vec![0]);
    assert_eq!(
        result[0].uuid,
        [
            0xff, 0xff, 0xff, 0xff, 0x9f, 0x36, 0x40, 0x7e, 0xad, 0x06, 0x39, 0xfc, 0x96, 0x6f,
            0x14, 0xdd, 0xe7, 0x97, 0x0f, 0x68
        ]
    );
    assert_eq!(result[1].uids, vec![1096, 1097]);
    assert_eq!(
        result[1].uuid,
        [
            0xff, 0xff, 0xff, 0xff, 0xa9, 0xb7, 0xba, 0x70, 0x78, 0x3b, 0x31, 0x7e, 0x99, 0x98,
            0xdc, 0x4d, 0xd8, 0x2e, 0xb3, 0xc5
        ]
    );

    Ok(())
}

#[gtest]
fn test_no_entries() -> Result<()> {
    init();

    let text = r"
    <ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes());
    assert_that!(
        result.unwrap_err().to_string(),
        contains_substring("missing field `uuid_ref_do`")
    );

    Ok(())
}

#[gtest]
fn test_missing_uid() -> Result<()> {
    init();

    let text = r"
    <ref_do>
        <uuid_ref_do>
            <uids>
            </uids>
            <uuid>9f36407ead0639fc966f14dde7970f68</uuid>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes());
    assert_that!(result.unwrap_err().to_string(), contains_substring("missing field `uid`"));

    Ok(())
}

#[gtest]
fn test_missing_uids() -> Result<()> {
    init();

    let text = r"
    <ref_do>
        <uuid_ref_do>
            <uuid>9f36407ead0639fc966f14dde7970f68</uuid>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes());
    assert_that!(result.unwrap_err().to_string(), contains_substring("missing field `uids`"));

    Ok(())
}

#[gtest]
fn test_bad_uid() -> Result<()> {
    let text = r"
    <ref_do>
        <uuid_ref_do>
            <uids>
                <!-- UID that's too large to fit in i32 -->
                <uid>1000000000000</uid>
            </uids>
            <uuid>9f36407ead0639fc966f14dde7970f68</uuid>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes());
    assert_that!(
        result.unwrap_err().to_string(),
        contains_substring("Error parsing XML: ParseIntError: number too large")
    );

    Ok(())
}

#[gtest]
fn test_bad_uid_missing_uuid() -> Result<()> {
    let text = r"
    <ref_do>
        <uuid_ref_do>
            <uids>
                <uid>0</uid>
            </uids>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes());
    assert_that!(result.unwrap_err().to_string(), contains_substring("missing field `uuid`"));

    Ok(())
}

#[gtest]
fn test_uuid_too_long() -> Result<()> {
    let text = r"
    <ref_do>
        <uuid_ref_do>
            <uids>
                <uid>0</uid>
            </uids>
            <uuid>9f36407ead0639fc966f14dde7970f6800</uuid>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes());
    assert_that!(result.unwrap_err().to_string(), contains_substring("UUID length invalid"));

    Ok(())
}

/// This test verifies that the configuration cannot use a full 20-byte GP UUID, since that's
/// supposed to be constructed by taking a 16-byte UUID from the file and prepending
/// 0xffffffff.
#[gtest]
fn test_literal_gp_uuid() -> Result<()> {
    let text = r"
    <ref_do>
        <uuid_ref_do>
            <uids>
                <uid>1234</uid>
            </uids>
            <!-- 20 bytes (40 hex chars), starts with ffffffff -->
            <uuid>ffffffff9f36407ead0639fc966f14dde7970f68</uuid>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes());
    assert_that!(result.unwrap_err().to_string(), contains_substring("UUID length invalid"));

    Ok(())
}

#[gtest]
fn test_uuid_too_short() -> Result<()> {
    let text = r"
    <ref_do>
        <uuid_ref_do>
            <uids>
                <uid>0</uid>
            </uids>
            <uuid>9f36407ead0639fc966f14dde7970f</uuid>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes());
    assert_that!(result.unwrap_err().to_string(), contains_substring("UUID length invalid"));

    Ok(())
}

#[gtest]
fn test_uuid_odd_length() -> Result<()> {
    let text = r"
    <ref_do>
        <uuid_ref_do>
            <uids>
                <uid>0</uid>
            </uids>
            <uuid>9f36407ead0639fc966f14dde7970f6</uuid>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes());
    assert_that!(
        result.unwrap_err().to_string(),
        contains_substring("Error parsing hexadecimal UUID: Odd number of digits")
    );

    Ok(())
}

#[gtest]
fn test_uuid_invalid_chars() -> Result<()> {
    let text = r"
    <ref_do>
        <uuid_ref_do>
            <uids>
                <uid>0</uid>
            </uids>
            <uuid>9g36407ead0639fc966f14dde7970f68</uuid>
        </uuid_ref_do>
    </ref_do>
    ";

    let result = parse_uuid_mappings(text.as_bytes());
    assert_that!(
        result.unwrap_err().to_string(),
        contains_substring("Error parsing hexadecimal UUID: Invalid character 'g'")
    );

    Ok(())
}
