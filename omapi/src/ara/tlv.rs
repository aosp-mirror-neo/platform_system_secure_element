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

//! This module implements a simple TLV-BER parser, parsing a byte array and returning nested
//! [`Object`]s that represent the contents.  It does not define/implement standard ASN.1 types
//! (e.g. INTEGER, SEQUENCE, etc.) because they're not required by the ARA data structures.
//!
//! The reason this was written rather than using an existing crate is that the existing options
//! parse TLV-DER, and diagnose and report non-canonical encodings.  The ARA rule set is TLV-BER
//! encoded, not TLV-DER, because canonicalization is not required.

use strum_macros::{Display, EnumIter};
use thiserror::Error;

/// Trait that defines a common interface for parsing things from bytes.
trait Parseable<'a>: 'a + Sized {
    fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), TlvParseError>;
}

#[derive(Debug, Error, PartialEq)]
pub enum TlvParseError {
    #[error("Parse buffer exhausted; needed {need} bytes, found {found}")]
    BufferInsufficient { need: usize, found: usize },
    #[error("Can't get class of empty tag value")]
    EmptyTagValue,
    #[error("Invalid multi-byte tag")]
    InvalidMultiByteTag,
}

/// The parsed TLV data structure.
///
/// The content is simple: a [`Tag`] object that specifies the extracted tag, and a [`Value`] object
/// with the contained value.
#[derive(Debug, Clone, PartialEq)]
pub struct Object<'a> {
    tag: Tag,
    value: Value<'a>,
}

impl<'a> Object<'a> {
    #[cfg(test)]
    pub fn new(tag: Tag, value: Value<'a>) -> Self {
        Object { tag, value }
    }

    pub fn tag(&self) -> &Tag {
        &self.tag
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn get_content(self) -> Value<'a> {
        self.value
    }
}

impl<'a> Parseable<'a> for Object<'a> {
    fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), TlvParseError> {
        let (header, remainder) = Header::parse(input)?;

        if remainder.len() < header.length.0 {
            return Err(TlvParseError::BufferInsufficient {
                need: header.length.0,
                found: remainder.len(),
            });
        }

        let (tag, value, remainder) = Value::parse(header, remainder)?;
        Ok((Object { tag, value }, remainder))
    }
}

/// Value represents the content of a TLV object, whether [`Value::Empty`], meaning the TLV value
/// was empty, [`Value::Constructed`], meaning the value consists of a set of zero or more
/// contained TLV objects, or [`Value::Primitive`], meaning the value does not contain other TLV
/// objects, but only some primitive content.  Primitive content is provided only as a byte array.
#[derive(Display, Debug, Clone, PartialEq)]
pub enum Value<'a> {
    Empty,
    Primitive(&'a [u8]),
    Constructed(Vec<Object<'a>>),
}

impl<'a> Value<'a> {
    fn parse(header: Header, input: &'a [u8]) -> Result<(Tag, Value<'a>, &'a [u8]), TlvParseError> {
        let value_buf = &input[..header.length.0];

        let value = if header.length.0 == 0 {
            Value::Empty
        } else if header.tag.is_constructed()? {
            parse_constructed_content(value_buf)?
        } else {
            Value::Primitive(value_buf)
        };

        Ok((header.tag, value, &input[header.length.0..]))
    }
}

struct Header {
    tag: Tag,
    length: Asn1Length,
}

impl Parseable<'_> for Header {
    fn parse(input: &[u8]) -> Result<(Self, &[u8]), TlvParseError> {
        let (tag, remainder) = Tag::parse(input)?;
        let (length, remainder) = Asn1Length::parse(remainder)?;

        Ok((Header { tag, length }, remainder))
    }
}

struct Asn1Length(usize);

impl Parseable<'_> for Asn1Length {
    fn parse(input: &[u8]) -> Result<(Self, &[u8]), TlvParseError> {
        if input.is_empty() {
            return Err(TlvParseError::BufferInsufficient { need: 1, found: 0 });
        }

        if input[0] & 0x80 == 0x00 {
            Ok((Asn1Length((input[0] & 0x7F) as usize), &input[1..]))
        } else {
            parse_multi_byte_length(input)
        }
    }
}

/// The set of supported tags.  Additional tags can be added if needed, though unknown tags are
/// handled cleanly as [`Tag::Unknown`].
#[derive(Display, Debug, Clone, EnumIter, PartialEq)]
pub enum Tag {
    AidRefDoSpecificApplet,
    AidRefDoImplicit,
    DeviceAppIdRefDo,
    ApduArDo,
    NfcArDo,
    RefDo,
    RefArDo,
    ArDo,
    PkgRefDo,
    ResponseRefreshTagDo,
    ResponseAllRefArDo,
    Unknown(Vec<u8>),
}

impl Tag {
    pub fn new(tag_val: &[u8]) -> Self {
        match tag_val {
            [0x4F] => Self::AidRefDoSpecificApplet,
            [0xC0] => Self::AidRefDoImplicit,
            [0xC1] => Self::DeviceAppIdRefDo,
            [0xCA] => Self::PkgRefDo,
            [0xD0] => Self::ApduArDo,
            [0xD1] => Self::NfcArDo,
            [0xE1] => Self::RefDo,
            [0xE2] => Self::RefArDo,
            [0xE3] => Self::ArDo,
            [0xDF, 0x20] => Self::ResponseRefreshTagDo,
            [0xFF, 0x40] => Self::ResponseAllRefArDo,
            tag_val => Self::Unknown(tag_val.to_vec()),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Tag::AidRefDoImplicit => &[0xC0],
            Tag::AidRefDoSpecificApplet => &[0x4F],
            Tag::ApduArDo => &[0xD0],
            Tag::ArDo => &[0xE3],
            Tag::DeviceAppIdRefDo => &[0xC1],
            Tag::NfcArDo => &[0xD1],
            Tag::PkgRefDo => &[0xCA],
            Tag::RefArDo => &[0xE2],
            Tag::RefDo => &[0xE1],
            Tag::ResponseRefreshTagDo => &[0xDF, 0x20],
            Tag::ResponseAllRefArDo => &[0xFF, 0x40],
            Tag::Unknown(vec) => vec,
        }
    }

    fn is_constructed(&self) -> Result<bool, TlvParseError> {
        Ok(self.first_byte()? & 0x20 == 0x20)
    }

    fn first_byte(&self) -> Result<&u8, TlvParseError> {
        self.bytes().first().ok_or(TlvParseError::EmptyTagValue)
    }
}

impl Parseable<'_> for Tag {
    fn parse(input: &[u8]) -> Result<(Self, &[u8]), TlvParseError> {
        let Some(first) = input.first() else {
            return Err(TlvParseError::BufferInsufficient { need: 1, found: 0 });
        };

        let (tag, remainder) = {
            // Single-byte tags use the five low order bits to encode the tag values 0-30.  If those
            // bits contain 31 (0x1F), it's a multi-byte tag.
            if first & 0x1F != 0x1F {
                (Tag::new(&input[..1]), &input[1..])
            } else {
                parse_multi_byte_tag(input)?
            }
        };

        Ok((tag, remainder))
    }
}

/// Parse the provided buffer, returning an [`Object`] representing the parsed data and a slice
/// that references the unused portion of the buffer (if any; callers should probably assume that
/// a non-empty unused buffer means the input data was malformed).
pub fn parse(input: &[u8]) -> Result<(Object, &[u8]), TlvParseError> {
    Object::parse(input)
}

fn parse_multi_byte_tag(input: &[u8]) -> Result<(Tag, &[u8]), TlvParseError> {
    assert!(!input.is_empty());

    let Some(first_len_byte) = input.get(1) else {
        return Err(TlvParseError::InvalidMultiByteTag);
    };

    if first_len_byte & 0x7F == 0 {
        return Err(TlvParseError::InvalidMultiByteTag);
    }

    // A multi-byte tag consists of a header byte followed by a sequence of bytes with high-order
    // bit 1, followed by a byte with high-order bit 0.
    let tag_size = 1 + count_bytes_with_high_order_bit_set(&input[1..]) + 1;
    if input.len() < tag_size {
        return Err(TlvParseError::InvalidMultiByteTag);
    }
    Ok((Tag::new(&input[..tag_size]), &input[tag_size..]))
}

fn count_bytes_with_high_order_bit_set(input: &[u8]) -> usize {
    input.iter().take_while(|b| *b & 0x80 == 0x80).count()
}

fn parse_multi_byte_length(input: &[u8]) -> Result<(Asn1Length, &[u8]), TlvParseError> {
    let field_len = (input[0] & 0x7F) as usize;
    if input.len() < field_len + 1 {
        return Err(TlvParseError::BufferInsufficient { need: field_len + 1, found: input.len() });
    }

    let mut len: usize = 0;
    for b in &input[1..=field_len] {
        len = len * 256 + *b as usize;
    }
    Ok((Asn1Length(len), &input[1 + field_len..]))
}

fn parse_constructed_content(mut input: &[u8]) -> Result<Value, TlvParseError> {
    let mut objects = Vec::new();
    while !input.is_empty() {
        let (object, remaining_buf) = Object::parse(input)?;
        input = remaining_buf;
        objects.push(object);
    }
    Ok(Value::Constructed(objects))
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use googletest::test as gtest;

    use strum::IntoEnumIterator;

    #[gtest]
    fn parse_empty_tag() -> Result<()> {
        let data = [];
        let result = Tag::parse(&data);
        assert_that!(
            result.unwrap_err(),
            eq(&TlvParseError::BufferInsufficient { need: 1, found: 0 })
        );

        Ok(())
    }

    #[gtest]
    fn unknown_tag() -> Result<()> {
        let data = [
            0x00, // Tag
            0x00, // Length
        ];

        let (tag, _rest) = Tag::parse(&data)?;
        assert_eq!(tag, Tag::Unknown(vec![0x00]));

        let data = [
            0x1F, 0x01, // Two-byte tag
            0x00, // Length
        ];

        let (tag, _rest) = Tag::parse(&data)?;
        assert_eq!(tag, Tag::Unknown(vec![0x1F, 0x01]));

        let data = [
            0x1F, 0x81, 0x01, // Three-byte tag
            0x00, // Length
        ];

        let (tag, _rest) = Tag::parse(&data)?;
        assert_eq!(tag, Tag::Unknown(vec![0x1F, 0x81, 0x01]));

        Ok(())
    }

    #[gtest]
    fn parse_empty_len() -> Result<()> {
        let data = [];
        let result = Asn1Length::parse(&data);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn parse_short_buf() -> Result<()> {
        let data = [
            0x00, // Tag
            0x02, // Length - need two bytes
        ];

        let result = parse(&data);
        assert!(result.is_err());
        Ok(())
    }

    #[gtest]
    fn parse_rule_set_with_nop_rule() -> Result<()> {
        let data = [
            0xFF, 0x40, // Response-ALL-REF-AR-DO
            0x0D, // 13 bytes long
            0xE2, // REF-AR-DO tag
            0x0B, // 11 bytes long (6 REF-DO, 5 AR-DO)
            0xE1, // REF-DO tag
            0x04, // 4 bytes long
            0x4F, // AID-REF-DO tag
            0x00, // 0 bytes (empty AID)
            0xC1, // DeviceAppId-REF-DO tag
            0x00, // 0 bytes (empty device ID)
            0xE3, // AR-DO tag
            0x03, // 3 bytes long
            0xD0, // APDU-AR-DO tag
            0x01, // 1 byte long
            0x01, // 0x01 means ALWAYS allow.
        ];

        let (obj, rest) = parse(&data)?;
        assert!(rest.is_empty());
        assert_eq!(
            obj,
            Object::new(
                Tag::ResponseAllRefArDo,
                Value::Constructed(vec![Object::new(
                    Tag::RefArDo,
                    Value::Constructed(vec![
                        Object::new(
                            Tag::RefDo,
                            Value::Constructed(vec![
                                Object::new(Tag::AidRefDoSpecificApplet, Value::Empty),
                                Object::new(Tag::DeviceAppIdRefDo, Value::Empty)
                            ])
                        ),
                        Object::new(
                            Tag::ArDo,
                            Value::Constructed(vec![Object::new(
                                Tag::ApduArDo,
                                Value::Primitive(&[0x01])
                            )])
                        )
                    ])
                )])
            )
        );

        Ok(())
    }

    #[gtest]
    fn parse_invalid_multi_byte_tag() -> Result<()> {
        // A multi-byte tag must be more than one byte.
        assert_eq!(Tag::parse(&[0x1F]).unwrap_err(), TlvParseError::InvalidMultiByteTag);
        // The last byte of a multi-byte tag must have the high order bit clear
        assert_eq!(Tag::parse(&[0x1F, 0x81]).unwrap_err(), TlvParseError::InvalidMultiByteTag);
        // bit 7-0 may not be zero
        assert_eq!(Tag::parse(&[0x1F, 0x00]).unwrap_err(), TlvParseError::InvalidMultiByteTag);
        // bit 7-0 may not be zero
        assert_eq!(Tag::parse(&[0x1F, 0x80]).unwrap_err(), TlvParseError::InvalidMultiByteTag);
        Ok(())
    }

    #[gtest]
    fn test_tag_mappings() -> Result<()> {
        for tag in Tag::iter() {
            assert_eq!(Tag::new(tag.bytes()), tag);
            if matches!(tag, Tag::Unknown(_)) {
                continue;
            }
            expect_that!(tag.is_constructed()?, eq(tag.first_byte()? & 0x20 == 0x20), "{tag}");
        }
        Ok(())
    }

    #[gtest]
    fn test_incomplete_multi_byte_len() -> Result<()> {
        let data = [
            0x00, 0x82, // Length; should be followed by two bytes.
        ];

        let result = Header::parse(&data);
        assert!(result.is_err());
        Ok(())
    }

    #[gtest]
    fn test_multi_byte_len() -> Result<()> {
        let data = [
            0x82, // Length field, two-byte value
            0x01, // Byte 1: 1 * 256
            0x01, // Byte 2: 1
            0xFF, // Extra byte; shouldn't be used.
        ];

        let (val, remaining_buf) = Asn1Length::parse(&data)?;
        assert_eq!(val.0, 257);
        assert_eq!(remaining_buf, [0xFF]);

        Ok(())
    }

    #[gtest]
    fn test_error_in_constructed_object() -> Result<()> {
        let data = [
            0xE1, // RefDo tag
            0x02, // Length
            0x4F, // AidRefDo tag,
            0x82, // Invalid length
        ];

        let result = parse(&data);
        assert!(result.is_err());
        Ok(())
    }
}
