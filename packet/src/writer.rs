//! Utilities for encoding game packets.
//!
//! Provides [`PacketWriter`] for writing length-prefixed values and big-endian
//! integers into a byte slice.

use std::fmt;
use crate::Rc4;

/// Encodes a value into the packet wire format.
pub trait PacketEncode {
    fn encode_packet(&self, writer: &mut PacketWriter)
        -> Result<(), EncodeError>;
}

/// An error encountered while encoding a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// Attempted to write byte array with size larger than [`u16::MAX`].
    LengthOverflow {
        pos: usize,
        len: usize,
        max: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow { pos, len, max } => write!(
                f,
                "cannot encode byte array at byte {pos}: \
                 length {len} exceeds maximum length {max}"
            ),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Writes values sequentially into a byte vector.
pub struct PacketWriter<'rc4> {
    data: Vec<u8>,
    rc4: &'rc4 mut Rc4,
}

impl<'rc4> PacketWriter<'rc4> {
    /// Creates a writer for a packet payload.
    pub const fn new(rc4: &'rc4 mut Rc4) -> Self {
        Self { rc4, data: Vec::new() }
    }

    /// Creates a writer for a packet payload with pre-allocated `capacity`.
    pub fn with_capacity(capacity: usize, rc4: &'rc4 mut Rc4) -> Self {
        Self {
            rc4,
            data: Vec::with_capacity(capacity),
        }
    }

    /// Returns the current byte position.
    pub fn pos(&self) -> usize {
        self.data.len()
    }

    /// Returns the inner vector as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the owned inner vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Encrypts and appends bytes to the payload.
    fn write_encrypted(&mut self, bytes: &[u8]) {
        self.data.reserve(bytes.len());
        for &byte in bytes {
            self.data.push(self.rc4.process_byte(byte));
        }
    }

    /// Writes a byte array into the payload.
    pub fn write_byte_array(&mut self, bytes: &[u8]) -> Result<(), EncodeError>
    {
        let len = u16::try_from(bytes.len()).map_err(|_| {
            EncodeError::LengthOverflow {
                pos: self.pos(),
                len: bytes.len(),
                max: u16::MAX as usize,
            }
        })?;

        self.write_u16(len);
        self.write_encrypted(bytes);

        Ok(())
    }

    /// Writes a string into the payload.
    pub fn write_string(&mut self, value: &str) -> Result<(), EncodeError> {
        self.write_byte_array(value.as_bytes())
    }
}

impl PacketEncode for &str {
    fn encode_packet(&self, writer: &mut PacketWriter)
        -> Result<(), EncodeError>
    {
        writer.write_string(self)
    }
}

impl PacketEncode for String {
    fn encode_packet(&self, writer: &mut PacketWriter)
        -> Result<(), EncodeError>
    {
        writer.write_string(self)
    }
}

impl PacketEncode for &[u8] {
    fn encode_packet(&self, writer: &mut PacketWriter)
        -> Result<(), EncodeError>
    {
        writer.write_byte_array(self)
    }
}

impl PacketEncode for Vec<u8> {
    fn encode_packet(&self, writer: &mut PacketWriter)
        -> Result<(), EncodeError>
    {
        writer.write_byte_array(self)
    }
}

macro_rules! impl_write_int {
    ($($ty:ty => $name:ident),* $(,)?) => {
        impl<'rc4> PacketWriter<'rc4> {
            $(
                #[doc = concat!(
                    "Writes `", stringify!($ty), "` into the payload."
                )]
                pub fn $name(&mut self, value: $ty) {
                    self.write_encrypted(&value.to_be_bytes());
                }
            )*
        }

        $(
            impl PacketEncode for $ty {
                fn encode_packet(&self, writer: &mut PacketWriter)
                    -> Result<(), EncodeError>
                {
                    // Primitive integer types never fail.
                    Ok(writer.$name(*self))
                }
            }
        )*
    };
}

impl_write_int! {
    u8   => write_u8,
    u16  => write_u16,
    u32  => write_u32,
    u64  => write_u64,
    u128 => write_u128,
    i8   => write_i8,
    i16  => write_i16,
    i32  => write_i32,
    i64  => write_i64,
    i128 => write_i128,
}
