//! Implementation of the [RC4](https://en.wikipedia.org/wiki/RC4) cipher used
//! by the game to encrypt network packets.

/// Key used for outgoing packets.
pub const OUTGOING_KEY: &str = "5a4d2016bc16dc64883194ffd9";

/// Key used for incoming packets.
pub const INCOMING_KEY: &str = "c91d9eec420160730d825604e0";

/// RC4 stream cipher.
///
/// The cipher maintains state between calls to [`Rc4::process`], so multiple
/// calls continue consuming the same keystream.
#[derive(Debug, Clone)]
pub struct Rc4 {
    /// The RC4 permutation (S-box).
    s_box: [u8; 256],

    /// First RC4 state index.
    i: u8,

    /// Second RC4 state index.
    j: u8,
}

impl Rc4 {
    /// Creates an RC4 cipher using [`INCOMING_KEY`] as the key.
    pub fn new_incoming() -> Self {
        Self::from_hex(INCOMING_KEY)
    }

    /// Creates an RC4 cipher using [`OUTGOING_KEY`] as the key.
    pub fn new_outgoing() -> Self {
        Self::from_hex(OUTGOING_KEY)
    }

    /// Creates an RC4 cipher from a hexadecimal key.
    ///
    /// Will panic if `hex_key` is not a valid string of hex encoded bytes.
    pub fn from_hex(hex_key: &str) -> Self {
        let key = decode_hex(hex_key).expect("Couldn't decode hex key string");
        Self::new(&key)
    }

    /// Creates an RC4 cipher from a raw key.
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 key must not be empty");

        let mut s_box = [0u8; 256];

        for (value, slot) in s_box.iter_mut().enumerate() {
            *slot = value as u8;
        }

        let mut j = 0u8;

        for i in 0..256 {
            j = j
                .wrapping_add(s_box[i])
                .wrapping_add(key[i % key.len()]);

            s_box.swap(i, j as usize);
        }

        Self {
            s_box,
            i: 0,
            j: 0,
        }
    }

    /// Encrypts or decrypts `data` in place.
    ///
    /// RC4 is symmetric, so applying `process_mut()` with the same cipher state
    /// performs the corresponding encryption/decryption operation.
    pub fn process_mut(&mut self, data: &mut [u8]) {
        data.iter_mut().for_each(|b| { *b ^= self.next_byte(); });
    }

    /// Encrypts or decrypts `data` into a new buffer.
    ///
    /// RC4 is symmetric, so applying `process()` with the same cipher state
    /// performs the corresponding encryption/decryption operation.
    #[must_use]
    pub fn process(&mut self, data: &[u8]) -> Vec<u8> {
        let mut data = data.to_vec();
        self.process_mut(&mut data);
        data
    }

    /// Advances the cipher state by `n` bytes without producint output.
    pub fn discard(&mut self, n: usize) {
        (0..n).for_each(|_| { self.next_byte(); });
    }

    /// Calculates the next byte which should be used for encrypting (i.e.
    /// xoring with) a byte.
    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s_box[self.i as usize]);

        self.s_box.swap(self.i as usize, self.j as usize);

        let t = self.s_box[self.i as usize]
            .wrapping_add(self.s_box[self.j as usize]);

        self.s_box[t as usize]
    }

    /// Encrypts or decrypts a `byte`.
    pub fn process_byte(&mut self, byte: u8) -> u8 {
        byte ^ self.next_byte()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HexError {
    Empty,
    OddLength,
    InvalidCharacter(u8),
}

// Using `from_str_radix` would be rough here, so a lookup table it is.
fn decode_hex(input: &str) -> Result<Vec<u8>, HexError> {
    let bytes = input.as_bytes();

    if bytes.is_empty() {
        return Err(HexError::Empty);
    }

    if bytes.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }

    let hex_digit = |byte| {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    };

    bytes.chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])
                .ok_or(HexError::InvalidCharacter(pair[0]))?;
            let low = hex_digit(pair[1])
                .ok_or(HexError::InvalidCharacter(pair[1]))?;
            Ok((high << 4) | low)
        })
        .collect()
}
