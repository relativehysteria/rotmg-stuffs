//! Utilities for encoding game packets.
//!
//! Provides [`PacketWriter`] for writing length-prefixed values and big-endian
//! integers into a byte slice.

use std::fmt;

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
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PacketWriter {
    data: Vec<u8>,
}

impl PacketWriter {
    /// Creates a writer for a packet payload.
    pub const fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Creates a writer for a packet payload with pre-allocated `capacity`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
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
        self.data.extend_from_slice(bytes);

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
        impl PacketWriter {
            $(
                #[doc = concat!(
                    "Writes `", stringify!($ty), "` into the payload."
                )]
                pub fn $name(&mut self, value: $ty) {
                    self.data.extend_from_slice(&value.to_be_bytes());
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
