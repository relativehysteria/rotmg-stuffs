//! Utilities for decoding game packets.
//!
//! Provides [`PacketReader`] for reading length-prefixed values and big-endian
//! integers from a byte slice.

use std::fmt;

/// Decodes a value from the packet wire format.
///
/// Implementations consume bytes from the [`PacketReadaer`] and reconstruct
/// a value from them.
pub trait PacketDecode: Sized {
    fn decode_packet(reader: &mut PacketReader) -> Result<Self, DecodeError>;
}

/// An error encountered while decoding a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The packet ended before enough bytes could be read.
    UnexpectedEof {
        pos: usize,
        needed: usize,
        remaining: usize,
    },

    /// A byte sequence was not valid UTF-8.
    InvalidUtf8 {
        pos: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof {
                pos,
                needed,
                remaining,
            } => write!(
                f,
                "unexpected end of packet at byte {pos}: \
                 needed {needed} bytes, but only {remaining} remain"
            ),
            Self::InvalidUtf8 { pos } => {
                write!(f, "invalid UTF-8 string at byte {pos}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Reads values sequentially from a byte slice.
pub struct PacketReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PacketReader<'a> {
    /// Creates a reader positioned at the start of the packet payload.
    ///
    /// `data` must be the raw decrypted payload.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns the current byte position.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the number of unread bytes.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Returns `true` if all bytes have been consumed.
    pub fn is_finished(&self) -> bool {
        self.data.len() == self.pos
    }

    /// Consumes and returns the next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(
            DecodeError::UnexpectedEof {
                pos: self.pos,
                needed: n,
                remaining: self.remaining(),
            },
        )?;

        if end > self.data.len() {
            return Err(DecodeError::UnexpectedEof {
                pos: self.pos,
                needed: n,
                remaining: self.remaining(),
            });
        }

        let result = &self.data[self.pos..end];
        self.pos = end;
        Ok(result)
    }

    /// Reads a length-prefixed byte arra.
    pub fn read_byte_array(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.read_u16()? as usize;
        self.take(len)
    }

    /// Reads a length-prefixed UTF-8 string.
    pub fn read_string(&mut self) -> Result<String, DecodeError> {
        let pos = self.pos;
        let bytes = self.read_byte_array()?;

        String::from_utf8(bytes.to_vec())
            .map_err(|_| DecodeError::InvalidUtf8 { pos })
    }
}

impl PacketDecode for String {
    fn decode_packet(reader: &mut PacketReader) -> Result<Self, DecodeError> {
        reader.read_string()
    }
}

impl PacketDecode for Vec<u8> {
    fn decode_packet(reader: &mut PacketReader) -> Result<Self, DecodeError> {
        reader.read_byte_array().map(|arr| arr.to_vec())
    }
}

macro_rules! impl_read_int {
    ($($ty:ty => $name:ident),* $(,)?) => {
        impl<'a> PacketReader<'a> {
            $(
                #[doc = concat!(
                    "Reads and returns `", stringify!($ty), "` from the packet."
                )]
                pub fn $name(&mut self) -> Result<$ty, DecodeError> {
                    let bytes = self.take(std::mem::size_of::<$ty>())?;

                    Ok(<$ty>::from_be_bytes(
                        bytes.try_into().unwrap()
                    ))
                }
            )*
        }

        $(
            impl PacketDecode for $ty {
                fn decode_packet(reader: &mut PacketReader)
                    -> Result<Self, DecodeError>
                {
                    reader.$name()
                }
            }
        )*
    };
}

impl_read_int! {
    u8   => read_u8,
    u16  => read_u16,
    u32  => read_u32,
    u64  => read_u64,
    u128 => read_u128,
    i8   => read_i8,
    i16  => read_i16,
    i32  => read_i32,
    i64  => read_i64,
    i128 => read_i128,
}
