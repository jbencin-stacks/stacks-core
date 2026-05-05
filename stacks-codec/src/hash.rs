// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use ripemd::Ripemd160;
use serde::de::Error as de_Error;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512_256};

use crate::hex::{hex_bytes, to_hex};

macro_rules! impl_serde_json_hex_string {
    ($name:ident, $len:expr) => {
        pub struct $name {}
        impl $name {
            pub fn json_serialize<S: serde::Serializer>(
                inst: &[u8; $len],
                s: S,
            ) -> Result<S::Ok, S::Error> {
                let hex_inst = to_hex(inst);
                s.serialize_str(&hex_inst.as_str())
            }

            pub fn json_deserialize<'de, D: serde::Deserializer<'de>>(
                d: D,
            ) -> Result<[u8; $len], D::Error> {
                let hex_inst = String::deserialize(d)?;
                let inst_bytes = hex_bytes(&hex_inst).map_err(de_Error::custom)?;

                match inst_bytes.len() {
                    $len => {
                        let mut byte_slice = [0u8; $len];
                        byte_slice.copy_from_slice(&inst_bytes);
                        Ok(byte_slice)
                    }
                    _ => Err(de_Error::custom(format!(
                        "Invalid hex string -- not {} bytes",
                        $len
                    ))),
                }
            }
        }
    };
}

impl_serde_json_hex_string!(Hash20, 20);
impl_serde_json_hex_string!(Hash32, 32);
impl_serde_json_hex_string!(Hash64, 64);

#[derive(Serialize, Deserialize)]
pub struct Hash160(
    #[serde(
        serialize_with = "Hash20::json_serialize",
        deserialize_with = "Hash20::json_deserialize"
    )]
    pub [u8; 20],
);
crate::impl_array_newtype!(Hash160, u8, 20);
crate::impl_array_hexstring_fmt!(Hash160);
crate::impl_byte_array_newtype!(Hash160, u8, 20);
crate::impl_byte_array_message_codec!(Hash160, 20);
#[cfg(feature = "rusqlite")]
crate::impl_byte_array_rusqlite_only!(Hash160);
pub const HASH160_ENCODED_SIZE: u32 = 20;

#[derive(Serialize, Deserialize)]
pub struct Sha512Trunc256Sum(
    #[serde(
        serialize_with = "Hash32::json_serialize",
        deserialize_with = "Hash32::json_deserialize"
    )]
    pub [u8; 32],
);
crate::impl_array_newtype!(Sha512Trunc256Sum, u8, 32);
crate::impl_array_hexstring_fmt!(Sha512Trunc256Sum);
crate::impl_byte_array_newtype!(Sha512Trunc256Sum, u8, 32);
crate::impl_byte_array_message_codec!(Sha512Trunc256Sum, 32);
#[cfg(feature = "rusqlite")]
crate::impl_byte_array_rusqlite_only!(Sha512Trunc256Sum);

impl Hash160 {
    pub fn from_sha256(sha256_hash: &[u8; 32]) -> Hash160 {
        let mut rmd = Ripemd160::new();
        rmd.update(sha256_hash);
        let ret = rmd.finalize().into();
        Hash160(ret)
    }

    /// Create a hash by hashing some data
    // (borrowed from Andrew Poelstra)
    pub fn from_data(data: &[u8]) -> Hash160 {
        let sha2_result = Sha256::digest(data);
        let ripe_160_result = Ripemd160::digest(sha2_result);
        Hash160(ripe_160_result.into())
    }
}

impl Sha512Trunc256Sum {
    pub fn from_data(data: &[u8]) -> Sha512Trunc256Sum {
        Sha512Trunc256Sum(Sha512_256::digest(data).into())
    }
    pub fn from_hasher(hasher: Sha512_256) -> Sha512Trunc256Sum {
        Sha512Trunc256Sum(hasher.finalize().into())
    }
}
