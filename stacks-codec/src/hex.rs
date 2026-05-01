// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::fmt::Write;
use std::{error, fmt};

use crate::pair::Pairable;

/// Hex deserialization error
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HexError {
    /// Length was not 64 characters
    BadLength(usize),
    /// Non-hex character in string
    BadCharacter(char),
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HexError::BadLength(n) => write!(f, "bad length {n} for hex string"),
            HexError::BadCharacter(c) => write!(f, "bad character {c} for hex string"),
        }
    }
}

impl error::Error for HexError {
    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
    fn description(&self) -> &str {
        match *self {
            HexError::BadLength(_) => "hex string non-64 length",
            HexError::BadCharacter(_) => "bad hex character",
        }
    }
}

pub trait HexDeser: Sized {
    fn try_from_hex(hex: &str) -> Result<Self, HexError>;
}

// borrowed from Andrew Poelstra's rust-bitcoin library
/// Convert a hexadecimal-encoded string to its corresponding bytes
pub fn hex_bytes(s: &str) -> Result<Vec<u8>, HexError> {
    let mut v = Vec::with_capacity(s.len() / 2);
    let mut iter = s.chars().pair();
    // Do the parsing
    iter.by_ref()
        .try_fold((), |_, (f, s)| match (f.to_digit(16), s.to_digit(16)) {
            (None, _) => Err(HexError::BadCharacter(f)),
            (_, None) => Err(HexError::BadCharacter(s)),
            (Some(f), Some(s)) => {
                v.push((f * 0x10 + s) as u8);
                Ok(())
            }
        })?;
    // Check that there was no remainder
    match iter.remainder() {
        Some(_) => Err(HexError::BadLength(s.len())),
        None => Ok(v),
    }
}

/// Convert a binary-encoded string to its corresponding bytes
pub fn bin_bytes(s: &str) -> Result<Vec<u8>, HexError> {
    let mut v = Vec::with_capacity(s.len() / 8 + 1);
    let mut next = 0u8;
    for (i, c) in s.chars().rev().enumerate() {
        if c != '0' && c != '1' {
            return Err(HexError::BadCharacter(c));
        }
        if c == '1' {
            next |= 1 << (i % 8);
        }
        if i % 8 == 7 {
            v.push(next);
            next = 0;
        }
    }
    if !s.len().is_multiple_of(8) {
        v.push(next);
    }
    v.reverse();
    Ok(v)
}

/// Precomputed hex characters for optimized conversion
const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";

/// Convert a slice of u8 to a hex string, with optional "0x" prefix
pub fn to_hex_prefixed(s: &[u8], prefix: bool) -> String {
    let prefix_len = if prefix { 2 } else { 0 };
    let mut bytes = Vec::with_capacity(s.len() * 2 + prefix_len);

    if prefix {
        bytes.push(b'0');
        bytes.push(b'x');
    }

    for &b in s.iter() {
        // get the first hex digit by shifting right 4 bits
        bytes.push(HEX_CHARS[(b >> 4) as usize]);

        // get the second hex digit by masking the lower 4 bits
        bytes.push(HEX_CHARS[(b & 0x0f) as usize]);
    }

    // SAFETY: HEX_CHARS only contains valid ASCII characters, so this expect is safe
    #[allow(clippy::expect_used)]
    String::from_utf8(bytes).expect("Only valid UTF-8 characters (ASCII hex) should be present")
}

/// Convert a slice of u8 to a hex string
pub fn to_hex(s: &[u8]) -> String {
    to_hex_prefixed(s, false)
}

/// Convert a slice of u8 into a binary string
pub fn to_bin(s: &[u8]) -> String {
    let mut r = String::with_capacity(s.len() * 8);
    for b in s.iter() {
        write!(r, "{b:08b}").unwrap();
    }
    r
}

/// Convert a vec of u8 to a hex string
pub fn bytes_to_hex(s: &[u8]) -> String {
    to_hex(s)
}
