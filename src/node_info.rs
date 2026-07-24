//! Node identity records reconstructed from controlled client-stream captures.
//!
//! The official user-configuration documentation names long and short device
//! names. Black-box captures then locate those values in the protobuf stream:
//! changing only the long name changes path `4.2.2`, and changing only the
//! short name changes path `4.2.3`. The adjacent user ID and numeric node
//! number agree byte-for-byte as hexadecimal and are retained as the lookup
//! key needed to attach names to packet endpoints.

use std::collections::BTreeMap;

use crate::protobuf::{Reader, Value};

const FROM_RADIO_NODE_INFO_FIELD: u32 = 4;
const NODE_NUMBER_FIELD: u32 = 1;
const NODE_USER_FIELD: u32 = 2;
const USER_ID_FIELD: u32 = 1;
const USER_LONG_NAME_FIELD: u32 = 2;
const USER_SHORT_NAME_FIELD: u32 = 3;

/// The user-facing identity carried by one node-info record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct User<'a> {
    pub id: &'a str,
    pub long_name: &'a str,
    pub short_name: &'a str,
}

/// A numeric node lookup key and its user-facing identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeInfo<'a> {
    pub number: u32,
    pub user: User<'a>,
}

/// An owned identity retained by a long-lived client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedUser {
    pub id: String,
    pub long_name: String,
    pub short_name: String,
}

/// The latest observed identity for each numeric node key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeDirectory {
    nodes: BTreeMap<u32, OwnedUser>,
}

impl NodeDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one client-stream payload.
    ///
    /// Returns `true` when the payload was a node-info record. A later record
    /// for the same number replaces the earlier names.
    pub fn ingest_from_radio(&mut self, bytes: &[u8]) -> Result<bool, NodeInfoError> {
        let Some(info) = NodeInfo::decode_from_radio(bytes)? else {
            return Ok(false);
        };
        self.nodes.insert(
            info.number,
            OwnedUser {
                id: info.user.id.to_owned(),
                long_name: info.user.long_name.to_owned(),
                short_name: info.user.short_name.to_owned(),
            },
        );
        Ok(true)
    }

    pub fn get(&self, number: u32) -> Option<&OwnedUser> {
        self.nodes.get(&number)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl<'a> NodeInfo<'a> {
    /// Decode one client-stream `FromRadio` payload when it is the observed
    /// node-info variant.
    ///
    /// `Ok(None)` means the payload carries another top-level variant.
    /// Additional, still-unnamed node-info and user fields are ignored.
    pub fn decode_from_radio(bytes: &'a [u8]) -> Result<Option<Self>, NodeInfoError> {
        let mut reader = Reader::new(bytes);
        let Some(field) = reader.next() else {
            return Err(NodeInfoError::MalformedMessage("FromRadio"));
        };
        if reader.next().is_some() || !reader.is_complete() {
            return Err(NodeInfoError::MalformedMessage("FromRadio"));
        }
        if field.number != FROM_RADIO_NODE_INFO_FIELD {
            return Ok(None);
        }
        let Value::Len(node_info) = field.value else {
            return Err(NodeInfoError::WrongWireType("FromRadio.node_info"));
        };
        Self::decode(node_info).map(Some)
    }

    fn decode(bytes: &'a [u8]) -> Result<Self, NodeInfoError> {
        let mut reader = Reader::new(bytes);
        let mut number = None;
        let mut user = None;

        for field in reader.by_ref() {
            match (field.number, field.value) {
                (NODE_NUMBER_FIELD, Value::Varint(value)) => {
                    set_once(&mut number, "NodeInfo.number", || {
                        u32::try_from(value).map_err(|_| NodeInfoError::NumberOutOfRange(value))
                    })?;
                }
                (NODE_NUMBER_FIELD, _) => {
                    return Err(NodeInfoError::WrongWireType("NodeInfo.number"));
                }
                (NODE_USER_FIELD, Value::Len(value)) => {
                    set_once(&mut user, "NodeInfo.user", || decode_user(value))?;
                }
                (NODE_USER_FIELD, _) => {
                    return Err(NodeInfoError::WrongWireType("NodeInfo.user"));
                }
                _ => {}
            }
        }

        if !reader.is_complete() {
            return Err(NodeInfoError::MalformedMessage("NodeInfo"));
        }
        Ok(Self {
            number: number.ok_or(NodeInfoError::MissingField("NodeInfo.number"))?,
            user: user.ok_or(NodeInfoError::MissingField("NodeInfo.user"))?,
        })
    }
}

fn decode_user(bytes: &[u8]) -> Result<User<'_>, NodeInfoError> {
    let mut reader = Reader::new(bytes);
    let mut id = None;
    let mut long_name = None;
    let mut short_name = None;

    for field in reader.by_ref() {
        match (field.number, field.value) {
            (USER_ID_FIELD, Value::Len(value)) => {
                set_once(&mut id, "User.id", || utf8(value, "User.id"))?;
            }
            (USER_ID_FIELD, _) => return Err(NodeInfoError::WrongWireType("User.id")),
            (USER_LONG_NAME_FIELD, Value::Len(value)) => {
                set_once(&mut long_name, "User.long_name", || {
                    utf8(value, "User.long_name")
                })?;
            }
            (USER_LONG_NAME_FIELD, _) => {
                return Err(NodeInfoError::WrongWireType("User.long_name"));
            }
            (USER_SHORT_NAME_FIELD, Value::Len(value)) => {
                set_once(&mut short_name, "User.short_name", || {
                    utf8(value, "User.short_name")
                })?;
            }
            (USER_SHORT_NAME_FIELD, _) => {
                return Err(NodeInfoError::WrongWireType("User.short_name"));
            }
            _ => {}
        }
    }

    if !reader.is_complete() {
        return Err(NodeInfoError::MalformedMessage("User"));
    }
    Ok(User {
        id: id.ok_or(NodeInfoError::MissingField("User.id"))?,
        long_name: long_name.ok_or(NodeInfoError::MissingField("User.long_name"))?,
        short_name: short_name.ok_or(NodeInfoError::MissingField("User.short_name"))?,
    })
}

fn utf8<'a>(bytes: &'a [u8], field: &'static str) -> Result<&'a str, NodeInfoError> {
    core::str::from_utf8(bytes).map_err(|_| NodeInfoError::InvalidUtf8(field))
}

fn set_once<T>(
    slot: &mut Option<T>,
    field: &'static str,
    value: impl FnOnce() -> Result<T, NodeInfoError>,
) -> Result<(), NodeInfoError> {
    if slot.is_some() {
        return Err(NodeInfoError::DuplicateField(field));
    }
    *slot = Some(value()?);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeInfoError {
    MalformedMessage(&'static str),
    MissingField(&'static str),
    DuplicateField(&'static str),
    WrongWireType(&'static str),
    NumberOutOfRange(u64),
    InvalidUtf8(&'static str),
}

impl core::fmt::Display for NodeInfoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedMessage(message) => write!(f, "malformed {message} message"),
            Self::MissingField(field) => write!(f, "missing {field}"),
            Self::DuplicateField(field) => write!(f, "duplicate {field}"),
            Self::WrongWireType(field) => write!(f, "wrong wire type for {field}"),
            Self::NumberOutOfRange(value) => {
                write!(f, "node number is out of range: {value}")
            }
            Self::InvalidUtf8(field) => write!(f, "{field} is not valid UTF-8"),
        }
    }
}

impl std::error::Error for NodeInfoError {}

#[cfg(test)]
mod tests {
    use super::*;

    const BASELINE: &[u8] = &[
        0x22, 0x2a, 0x08, 0xe4, 0xf4, 0xab, 0xb3, 0x0f, 0x12, 0x22, 0x0a, 0x09, b'!', b'f', b'6',
        b'6', b'a', b'f', b'a', b'6', b'4', 0x12, 0x0f, b'M', b'e', b's', b'h', b't', b'a', b's',
        b't', b'i', b'c', b' ', b'f', b'a', b'6', b'4', 0x1a, 0x04, b'f', b'a', b'6', b'4',
    ];

    #[test]
    fn decodes_the_observed_identity_fields() {
        let node = NodeInfo::decode_from_radio(BASELINE).unwrap().unwrap();
        assert_eq!(node.number, 0xf66a_fa64);
        assert_eq!(node.user.id, "!f66afa64");
        assert_eq!(node.user.long_name, "Meshtastic fa64");
        assert_eq!(node.user.short_name, "fa64");
    }

    #[test]
    fn other_from_radio_variants_are_ignored() {
        assert_eq!(NodeInfo::decode_from_radio(b"\x68\x01").unwrap(), None);
    }

    #[test]
    fn malformed_and_ambiguous_records_are_rejected() {
        assert_eq!(
            NodeInfo::decode_from_radio(b"\x22\x02\x08\x01"),
            Err(NodeInfoError::MissingField("NodeInfo.user"))
        );
        assert_eq!(
            NodeInfo::decode_from_radio(b"\x22\x04\x08\x01\x08\x02"),
            Err(NodeInfoError::DuplicateField("NodeInfo.number"))
        );
        assert_eq!(
            NodeInfo::decode_from_radio(b"\x22\x08\x08\x01\x12\x04\x0a\x02\xff\xff"),
            Err(NodeInfoError::InvalidUtf8("User.id"))
        );
    }

    #[test]
    fn directory_retains_owned_names() {
        let mut directory = NodeDirectory::new();
        assert!(directory.ingest_from_radio(BASELINE).unwrap());
        assert_eq!(directory.len(), 1);
        assert_eq!(
            directory.get(0xf66a_fa64).unwrap().long_name,
            "Meshtastic fa64"
        );
        assert!(!directory.ingest_from_radio(b"\x68\x01").unwrap());
        assert_eq!(directory.len(), 1);
    }
}
