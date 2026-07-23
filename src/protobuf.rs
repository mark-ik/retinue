//! A minimal reader for Google's protobuf wire format.
//!
//! This decodes the *structure* of a protobuf message — its field numbers and wire types —
//! without any knowledge of what the fields mean. The wire format is Google's public standard
//! (protobuf.dev, "Encoding"); nothing here is derived from any particular schema. It is the
//! tool for observing, structurally, what a device emits: a message is a sequence of
//! `(field_number, value)` pairs, and length-delimited values may themselves be nested
//! messages, strings, or bytes, which the caller decides by trying to descend.
//!
//! On the wire each field is a varint tag `(field_number << 3) | wire_type`, then the value:
//!
//! | wire type | name | value |
//! |---|---|---|
//! | 0 | VARINT | a varint (ints, bools, enums) |
//! | 1 | I64 | 8 fixed bytes (fixed64, double) |
//! | 2 | LEN | a varint length, then that many bytes (string, bytes, message, packed) |
//! | 5 | I32 | 4 fixed bytes (fixed32, float) |

/// A decoded field value, tagged by its wire type but not its meaning.
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    /// Wire type 0: a variable-length integer.
    Varint(u64),
    /// Wire type 1: eight fixed bytes.
    I64([u8; 8]),
    /// Wire type 2: a length-delimited byte run (bytes, string, or nested message).
    Len(&'a [u8]),
    /// Wire type 5: four fixed bytes.
    I32([u8; 4]),
}

/// One field: its number and value.
#[derive(Debug, Clone, PartialEq)]
pub struct Field<'a> {
    pub number: u32,
    pub value: Value<'a>,
}

/// An iterator over the fields of a protobuf message. Stops at the first malformed field
/// (the message is truncated or not protobuf), yielding what parsed cleanly before it.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    failed: bool,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader {
            buf,
            pos: 0,
            failed: false,
        }
    }

    /// Whether the reader consumed the complete message without encountering a
    /// truncated field or unsupported wire type.
    ///
    /// Call this after iterating when malformed input must be distinguished
    /// from an ordinary end of message.
    pub fn is_complete(&self) -> bool {
        !self.failed && self.pos == self.buf.len()
    }

    fn read_varint(&mut self) -> Option<u64> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            if shift >= 64 {
                return None; // varint too long to be valid
            }
            let byte = *self.buf.get(self.pos)?;
            self.pos += 1;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
        }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let slice = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(slice)
    }

    fn read_field(&mut self) -> Option<Field<'a>> {
        let tag = self.read_varint()?;
        let number = u32::try_from(tag >> 3).ok()?;
        if number == 0 {
            return None;
        }
        let wire_type = (tag & 0x7) as u8;
        let value = match wire_type {
            0 => Value::Varint(self.read_varint()?),
            1 => Value::I64(self.take(8)?.try_into().ok()?),
            2 => {
                let len = usize::try_from(self.read_varint()?).ok()?;
                Value::Len(self.take(len)?)
            }
            5 => Value::I32(self.take(4)?.try_into().ok()?),
            _ => return None,
        };
        Some(Field { number, value })
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Field<'a>> {
        if self.failed || self.pos >= self.buf.len() {
            return None;
        }
        let field = self.read_field();
        if field.is_none() {
            self.failed = true;
        }
        field
    }
}

/// Encode `value` as a varint (for building requests structurally).
pub fn write_varint(value: u64, out: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// Encode a `(field_number, wire_type)` tag.
pub fn write_tag(number: u32, wire_type: u8, out: &mut Vec<u8>) {
    write_varint((u64::from(number) << 3) | u64::from(wire_type), out);
}

/// A structural summary of a message: each field's number and wire type, in order. Useful for
/// describing what a device emits without interpreting it.
pub fn structure(buf: &[u8]) -> Vec<(u32, u8)> {
    Reader::new(buf)
        .map(|f| {
            let wt = match f.value {
                Value::Varint(_) => 0,
                Value::I64(_) => 1,
                Value::Len(_) => 2,
                Value::I32(_) => 5,
            };
            (f.number, wt)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_varint_field() {
        // field 1, varint, value 150: tag 0x08, value 0x96 0x01.
        let msg = [0x08, 0x96, 0x01];
        let fields: Vec<_> = Reader::new(&msg).collect();
        assert_eq!(
            fields,
            vec![Field {
                number: 1,
                value: Value::Varint(150)
            }]
        );
    }

    #[test]
    fn reads_a_length_delimited_field() {
        // field 2, LEN, "testing": tag 0x12, len 0x07, bytes.
        let mut msg = vec![0x12, 0x07];
        msg.extend_from_slice(b"testing");
        let fields: Vec<_> = Reader::new(&msg).collect();
        assert_eq!(
            fields,
            vec![Field {
                number: 2,
                value: Value::Len(b"testing")
            }]
        );
    }

    #[test]
    fn reads_fixed_width_fields() {
        // field 3 I32 = 0x01020304, field 4 I64.
        let msg = [
            (3 << 3) | 5,
            0x04,
            0x03,
            0x02,
            0x01,
            (4 << 3) | 1,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let fields: Vec<_> = Reader::new(&msg).collect();
        assert_eq!(
            fields[0],
            Field {
                number: 3,
                value: Value::I32([4, 3, 2, 1])
            }
        );
        assert_eq!(
            fields[1],
            Field {
                number: 4,
                value: Value::I64([1, 0, 0, 0, 0, 0, 0, 0])
            }
        );
    }

    #[test]
    fn descends_into_a_nested_message() {
        // Outer field 1 LEN wraps an inner message {field 1 varint = 42}.
        let inner = [0x08, 42];
        let mut outer = vec![0x0a, inner.len() as u8];
        outer.extend_from_slice(&inner);
        let outer_fields: Vec<_> = Reader::new(&outer).collect();
        let Value::Len(nested) = outer_fields[0].value else {
            panic!("expected LEN");
        };
        let inner_fields: Vec<_> = Reader::new(nested).collect();
        assert_eq!(
            inner_fields,
            vec![Field {
                number: 1,
                value: Value::Varint(42)
            }]
        );
    }

    #[test]
    fn structure_summarizes_field_numbers_and_types() {
        let mut msg = vec![0x08, 0x01]; // field 1 varint
        msg.extend_from_slice(&[0x12, 0x02, b'h', b'i']); // field 2 LEN
        assert_eq!(structure(&msg), vec![(1, 0), (2, 2)]);
    }

    #[test]
    fn stops_cleanly_at_truncation() {
        // A LEN field claiming 9 bytes but only 3 present: yields nothing, does not panic.
        let msg = [0x12, 0x09, b'a', b'b', b'c'];
        let mut reader = Reader::new(&msg);
        assert!(reader.next().is_none());
        assert!(!reader.is_complete());
    }

    #[test]
    fn reports_a_complete_message() {
        let msg = [0x08, 0x01, 0x12, 0x02, b'h', b'i'];
        let mut reader = Reader::new(&msg);
        assert_eq!(reader.by_ref().count(), 2);
        assert!(reader.is_complete());
    }

    #[test]
    fn rejects_field_zero_and_unsupported_wire_types() {
        for msg in [[0x00], [0x0b]] {
            let mut reader = Reader::new(&msg);
            assert!(reader.next().is_none());
            assert!(!reader.is_complete());
        }
    }

    #[test]
    fn varint_round_trips() {
        for v in [0u64, 1, 127, 128, 300, 16384, u64::MAX] {
            let mut out = Vec::new();
            write_varint(v, &mut out);
            assert_eq!(
                Reader {
                    buf: &out,
                    pos: 0,
                    failed: false,
                }
                .read_varint(),
                Some(v)
            );
        }
    }
}
