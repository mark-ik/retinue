//! Sennet: an independent, permissively licensed mesh radio protocol
//! implementation in the retinue family.
//!
//! Sennet targets interoperability with existing LoRa messaging meshes as a
//! sibling of [retinue](https://github.com/mark-ik/retinue) on the shared
//! tulle radio layer. It is an independent implementation, developed from
//! wire observation and public documentation, and is not affiliated with or
//! endorsed by any existing mesh project.
//!
//! A sennet is a ceremonial fanfare for a procession.
//!
//! # Provenance
//!
//! Sennet is a clean-room implementation. Every byte format here comes from one of three
//! sources only: publicly documented wire and frame layouts, Google's public protobuf wire
//! standard, or direct observation of bytes a device emits. No third-party protocol source,
//! schema definition, or client library was consulted. See `PROVENANCE.md`.

pub mod application;
pub mod flood;
pub mod node;
pub mod node_info;
pub mod packet_id;
pub mod protobuf;
pub mod stream;
pub mod transport;
