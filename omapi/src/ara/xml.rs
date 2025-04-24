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

//! This module extracts ARA rules from XML. No formal schema is defined, but the structure
//! mirrors the TLV structure and an example should make it clear. See the GP SE Access control
//! specification.
//!
//! Example:
//!
//! ```xml
//! <rules>
//!   <ref-ar-do>         <!-- Each ref-ar-do contains a single rule. -->
//!     <ref-do>          <!-- First part of a rule is the match criteria, ref-do -->
//!       <aid-ref-do>    <!-- Match an AID -->
//!         A00000015141434C00   <!-- AIDs are hex-encoded.  Empty means "all" -->
//!       </aid-ref-do>
//!       <deviceappid-ref-do>   <!-- Match a device app hash, 0, 20 or 32 bytes, in hex.
//!                                   0 bytes means "any app", 20 bytes is a SHA-1 hash or
//!                                   UUID, 32 bytes is a SHA-256 hash. -->
//!         00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
//!       </deviceappid-ref-do>
//!     </ref-do>
//!     <ar-do>           <!-- Second part of a rule is the access specification, ar-do -->
//!       <apdu-ar-do>    <!-- APDU access specification -->
//!         01            <!-- Content is hex-encoded 0, 1 or filter value. -->
//!       </apdu-ar-do>
//!     </ar-do>
//!   </ref-ar-do>
//! </rules>
//! ```

use std::io::{BufReader, Read};

use hex::FromHex;
use serde::{Deserialize, Deserializer};
use serde_xml_rs::from_reader;
use thiserror::Error;

use super::rules::{SHA1_OR_UUID_LEN, SHA256_LEN};

#[derive(Error, Debug)]
pub enum AraXmlError {
    #[error("Error parsing XML: {0}")]
    XmlError(#[from] serde_xml_rs::Error),

    #[error("Error decoding hex: {0}")]
    HexError(#[from] hex::FromHexError),

    #[error("Invalid AID: {0}")]
    InvalidAid(String),

    #[error("Invalid device app ID: {0}")]
    InvalidAppId(String),
}

/// Parse ARA rules from XML content in the provided [`Read`] object (e.g. a [`std::fs::File`]).
pub fn parse_xml_rules<R: Read>(reader: R) -> Result<Rules, serde_xml_rs::Error> {
    from_reader(BufReader::new(reader))
}

#[derive(Debug, Deserialize)]
pub struct Rules {
    #[serde(default)]
    pub ref_ar_do: Vec<RefArDo>,
}

#[derive(Debug, Deserialize)]
pub struct RefArDo {
    ref_do: RefDo,
    ar_do: ArDo,
}

impl RefArDo {
    pub fn get_match_criteria(&self) -> &RefDo {
        &self.ref_do
    }

    pub fn get_apdu_access(&self) -> &ArDo {
        &self.ar_do
    }
}

#[derive(Debug, Deserialize)]
pub struct RefDo {
    aid_ref_do: AidRefDo,
    deviceappid_ref_do: DeviceAppIdRefDo,
}

impl RefDo {
    pub fn get_aid_ref(&self) -> &AidRefDo {
        &self.aid_ref_do
    }

    pub fn get_app_id(&self) -> &DeviceAppIdRefDo {
        &self.deviceappid_ref_do
    }
}

#[derive(Debug, Deserialize)]
pub struct AidRefDo(#[serde(deserialize_with = "dehex_aid_ref_do")] Vec<u8>);

fn dehex_aid_ref_do<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let bytes = deserializer.deserialize_str(HexStrVisitor(" of len 0,5..=16"))?;
    match bytes.len() {
        0 | 5..=16 => Ok(bytes),
        _ => Err(serde::de::Error::custom(hex::FromHexError::InvalidStringLength)),
    }
}

impl AidRefDo {
    pub fn get_aid(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Deserialize)]
pub struct DeviceAppIdRefDo(#[serde(deserialize_with = "dehex_app_id_ref_do")] Vec<u8>);

fn dehex_app_id_ref_do<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let bytes = deserializer.deserialize_str(HexStrVisitor(" of len 0|20|32"))?;
    match bytes.len() {
        0 | SHA1_OR_UUID_LEN | SHA256_LEN => Ok(bytes),
        _ => Err(serde::de::Error::custom(hex::FromHexError::InvalidStringLength)),
    }
}

impl DeviceAppIdRefDo {
    pub fn get_app_id(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Deserialize)]
pub struct ArDo {
    apdu_ar_do: ApduArDo,
}

impl ArDo {
    pub(crate) fn get_apdu_access(&self) -> &[u8] {
        &self.apdu_ar_do.0
    }
}

#[derive(Debug, Deserialize)]
struct ApduArDo(#[serde(deserialize_with = "dehex_apdu_ar_do")] Vec<u8>);

fn dehex_apdu_ar_do<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    deserializer.deserialize_str(HexStrVisitor(""))
}

struct HexStrVisitor(&'static str);

impl serde::de::Visitor<'_> for HexStrVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "a hex encoded string{}", self.0)
    }

    fn visit_str<E: serde::de::Error>(self, data: &str) -> Result<Self::Value, E> {
        FromHex::from_hex(data).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use googletest::prelude::*;
    use googletest::test as gtest;

    #[cfg(not(feature = "notandroid"))]
    fn init() {
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("se_service_xml_rules_test")
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
    fn happy() -> Result<()> {
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

        let rules = parse_xml_rules(text.as_bytes())?.ref_ar_do;

        expect_eq!(rules.len(), 2);
        let ref_do = &rules[0].ref_do;
        expect_eq!(ref_do.aid_ref_do.0, [0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00]);
        expect_eq!(
            ref_do.deviceappid_ref_do.0,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
                0xCC, 0xDD, 0xEE, 0xFF
            ]
        );

        let ar_do = rules[0].get_apdu_access();
        expect_eq!(ar_do.get_apdu_access(), &[0x01]);

        let ref_do = &rules[1].ref_do;
        expect_eq!(ref_do.aid_ref_do.0, [0xA0, 0x00, 0x00, 0x0B, 0xCD, 0xEF]);
        expect_true!(ref_do.deviceappid_ref_do.0.is_empty());

        let ar_do = &rules[1].get_apdu_access();
        expect_eq!(ar_do.get_apdu_access(), &[0x00]);

        Ok(())
    }

    #[gtest]
    fn empty_rules() -> Result<()> {
        init();

        let text = r#"
        <rules>
        </rules>"#;

        let rules = parse_xml_rules(text.as_bytes())?;
        expect_eq!(rules.ref_ar_do.len(), 0);

        Ok(())
    }

    // This test exposes a misfeature in serde_xml_rs, that there is no way to specify that XML
    // objects must appear in the correct order.  It would be better to be strict about this, but
    // since we're not, at least we can test the incorrect behavior to be sure it doesn't change.
    #[gtest]
    fn out_of_order() -> Result<()> {
        init();

        let text = r#"
        <rules>
          <ref_ar_do>
            <ar_do>
              <apdu_ar_do>
                01
              </apdu_ar_do>
            </ar_do>
            <ref_do>
              <aid_ref_do>
                A00000015141434C00
              </aid_ref_do>
              <deviceappid_ref_do>
                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
              </deviceappid_ref_do>
            </ref_do>
          </ref_ar_do>
        </rules>"#;

        let rules = parse_xml_rules(text.as_bytes())?.ref_ar_do;

        expect_eq!(rules.len(), 1);
        let ref_do = &rules[0].ref_do;
        expect_eq!(ref_do.aid_ref_do.0, [0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00]);
        expect_eq!(
            ref_do.deviceappid_ref_do.0,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
                0xCC, 0xDD, 0xEE, 0xFF
            ]
        );

        let ar_do = &rules[0].ar_do;
        expect_eq!(ar_do.apdu_ar_do.0, [0x01]);

        Ok(())
    }

    // Similar to out of order fields, serde_xml_rs does not emit any diagnostics when parsing XML
    // that contains unknown XML objects.  This test ensures that this (mis)behavior isn't
    // inadvertently broken.
    #[gtest]
    fn unknown_tag() -> Result<()> {
        init();

        let text = r#"
        <rules>
        <unknown/>
        <ref_ar_do>
            <ref_do>
              <aid_ref_do>
                A00000015141434C00
              </aid_ref_do>
              <unknown/>
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
        </rules>"#;

        let rules = parse_xml_rules(text.as_bytes())?.ref_ar_do;

        expect_eq!(rules.len(), 1);
        let ref_do = &rules[0].ref_do;
        expect_eq!(ref_do.aid_ref_do.0, [0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00]);
        expect_eq!(
            ref_do.deviceappid_ref_do.0,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
                0xCC, 0xDD, 0xEE, 0xFF
            ]
        );

        let ar_do = &rules[0].ar_do;
        expect_eq!(ar_do.apdu_ar_do.0, [0x01]);

        Ok(())
    }

    #[gtest]
    fn invalid_hex_aid() -> Result<()> {
        init();

        let invalid_hex_aid = r#"
        <rules>
          <ref_ar_do>
            <ref_do>
              <aid_ref_do>
                INVALIDHEX
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
        </rules>"#;

        expect_that!(
            parse_xml_rules(invalid_hex_aid.as_bytes()).unwrap_err().to_string(),
            contains_substring("Invalid character 'I'")
        );

        Ok(())
    }

    #[gtest]
    fn invalid_hex_app_id() -> Result<()> {
        init();

        let invalid_hex_app_id = r#"
        <rules>
          <ref_ar_do>
            <ref_do>
              <aid_ref_do>
                A00000015141434C00
              </aid_ref_do>
              <deviceappid_ref_do>
                INVALIDHEX
              </deviceappid_ref_do>
            </ref_do>
            <ar_do>
              <apdu_ar_do>
                01
              </apdu_ar_do>
            </ar_do>
          </ref_ar_do>
        </rules>"#;

        expect_that!(
            parse_xml_rules(invalid_hex_app_id.as_bytes()).unwrap_err().to_string(),
            contains_substring("Invalid character 'I'")
        );

        Ok(())
    }

    #[gtest]
    fn odd_length_aid() -> Result<()> {
        init();

        let odd_length_aid = r#"
        <rules>
          <ref_ar_do>
            <ref_do>
              <aid_ref_do>
                A00000015141434C0
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
        </rules>"#;

        expect_that!(
            parse_xml_rules(odd_length_aid.as_bytes()).unwrap_err().to_string(),
            contains_substring("Odd number of digits")
        );

        Ok(())
    }

    #[gtest]
    fn odd_length_app_id() -> Result<()> {
        init();

        let odd_length_app_id = r#"
        <rules>
          <ref_ar_do>
            <ref_do>
              <aid_ref_do>
                A00000015141434C04
              </aid_ref_do>
              <deviceappid_ref_do>
                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEF
              </deviceappid_ref_do>
            </ref_do>
            <ar_do>
              <apdu_ar_do>
                01
              </apdu_ar_do>
            </ar_do>
          </ref_ar_do>
        </rules>"#;

        expect_that!(
            parse_xml_rules(odd_length_app_id.as_bytes()).unwrap_err().to_string(),
            contains_substring("Odd number of digits")
        );

        Ok(())
    }

    #[gtest]
    fn too_short_aid() -> Result<()> {
        let too_short_aid = r#"
        <rules>
          <ref_ar_do>
            <ref_do>
              <aid_ref_do>
                01020304
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
        </rules>"#;

        expect_that!(
            parse_xml_rules(too_short_aid.as_bytes()).unwrap_err().to_string(),
            contains_substring("Invalid string length")
        );

        Ok(())
    }

    #[gtest]
    fn too_long_aid() -> Result<()> {
        let too_long_aid = r#"
        <rules>
          <ref_ar_do>
            <ref_do>
              <aid_ref_do>
                000102030405060708090a0b0c0d0e0f10
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
        </rules>"#;

        expect_that!(
            parse_xml_rules(too_long_aid.as_bytes()).unwrap_err().to_string(),
            contains_substring("Invalid string length")
        );

        Ok(())
    }

    #[gtest]
    fn invalid_length_app_id() -> Result<()> {
        init();

        let prefix = r#"
        <rules>
          <ref_ar_do>
            <ref_do>
              <aid_ref_do>
                A00000015141434C0F
              </aid_ref_do>
              <deviceappid_ref_do>"#;

        let suffix = r#"
              </deviceappid_ref_do>
            </ref_do>
            <ar_do>
              <apdu_ar_do>
                01
              </apdu_ar_do>
            </ar_do>
          </ref_ar_do>
        </rules>"#;

        for aid_len in (0..40).step_by(2) {
            let aid = "FF".repeat(aid_len);
            let xml = format!("{prefix}{aid}{suffix}");

            match aid_len {
                0 | SHA1_OR_UUID_LEN | SHA256_LEN => {
                    let rules = parse_xml_rules(xml.as_bytes())
                        .unwrap_or_else(|e| panic!("Failed with {e} for aid_len {aid_len}"))
                        .ref_ar_do;
                    expect_that!(
                        rules[0].get_match_criteria().get_app_id().get_app_id(),
                        len(eq(aid_len)),
                        "{aid_len} should be valid",
                    );
                }
                _ => {
                    expect_that!(
                        parse_xml_rules(xml.as_bytes()).unwrap_err().to_string(),
                        contains_substring("Invalid string length"),
                        "Test failed for {aid_len}"
                    );
                }
            }
        }

        Ok(())
    }

    #[gtest]
    fn missing_aid_ref() -> Result<()> {
        init();

        let text = r#"
        <rules>
          <ref_ar_do>
            <ref_do>
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
        </rules>"#;

        expect_that!(
            parse_xml_rules(text.as_bytes()).unwrap_err(),
            matches_pattern!(serde_xml_rs::Error::Custom {
                field: contains_substring("missing field `aid_ref_do`")
            })
        );

        Ok(())
    }

    #[gtest]
    fn missing_device_app_ref() -> Result<()> {
        let text = r#"
        <rules>
          <ref_ar_do>
            <ref_do>
              <aid_ref_do>
                A00000015141434C00
              </aid_ref_do>
            </ref_do>
            <ar_do>
              <apdu_ar_do>
                01
              </apdu_ar_do>
            </ar_do>
          </ref_ar_do>
        </rules>"#;

        expect_that!(
            parse_xml_rules(text.as_bytes()).unwrap_err(),
            matches_pattern!(serde_xml_rs::Error::Custom {
                field: contains_substring("missing field `deviceappid_ref_do`")
            })
        );

        Ok(())
    }

    #[gtest]
    fn missing_ref_do() -> Result<()> {
        let text = r#"
        <rules>
          <ref_ar_do>
            <ar_do>
              <apdu_ar_do>
                01
              </apdu_ar_do>
            </ar_do>
          </ref_ar_do>
        </rules>"#;

        expect_that!(
            parse_xml_rules(text.as_bytes()).unwrap_err(),
            matches_pattern!(serde_xml_rs::Error::Custom {
                field: contains_substring("missing field `ref_do`")
            })
        );

        Ok(())
    }

    #[gtest]
    fn missing_apdu_ar_do() -> Result<()> {
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
            </ar_do>
          </ref_ar_do>
        </rules>"#;

        expect_that!(
            parse_xml_rules(text.as_bytes()).unwrap_err(),
            matches_pattern!(serde_xml_rs::Error::Custom {
                field: contains_substring("missing field `apdu_ar_do`")
            })
        );

        Ok(())
    }

    #[gtest]
    fn missing_ar_do() -> Result<()> {
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
          </ref_ar_do>
        </rules>"#;

        expect_that!(
            parse_xml_rules(text.as_bytes()).unwrap_err(),
            matches_pattern!(serde_xml_rs::Error::Custom {
                field: contains_substring("missing field `ar_do`")
            })
        );

        Ok(())
    }
}
