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

use std::mem;

// Re-export the hash types and Merkle tree machinery from `stacks-codec` so
// existing call sites (`stacks_common::util::hash::{Hash160, Sha256Sum, ...}`)
// keep working.
pub use stacks_codec::hash::{
    DoubleSha256, Hash160, Hash20, Hash32, Hash64, Keccak256Hash, MerkleHashFunc, MerklePath,
    MerklePathOrder, MerklePathPoint, MerkleTree, Sha256Sum, Sha512Sum, Sha512Trunc256Sum,
    DOUBLE_SHA256_ENCODED_SIZE, HASH160_ENCODED_SIZE,
};
// Re-export the hex helpers from `stacks-codec` so existing call sites
// (`stacks_common::util::hash::{hex_bytes, to_hex, ...}`) keep working.
pub use stacks_codec::hex::{bin_bytes, bytes_to_hex, hex_bytes, to_bin, to_hex, to_hex_prefixed};

use crate::types::StacksPublicKeyBuffer;
use crate::util::secp256k1::Secp256k1PublicKey;
use crate::util::uint::Uint256;

/// Methods on `Hash160` that depend on stacks-common-defined key types and
/// therefore can't live in `stacks-codec` (which intentionally has no
/// `stacks-common` dep). Bring this trait into scope to call
/// `Hash160::from_node_public_key(...)` / `Hash160::from_node_public_key_buffer(...)`.
pub trait Hash160PubKeyExt {
    fn from_node_public_key(pubkey: &Secp256k1PublicKey) -> Hash160;
    fn from_node_public_key_buffer(pubkey_buf: &StacksPublicKeyBuffer) -> Hash160;
}

impl Hash160PubKeyExt for Hash160 {
    fn from_node_public_key(pubkey: &Secp256k1PublicKey) -> Hash160 {
        Hash160::from_data(&pubkey.to_bytes_compressed())
    }

    fn from_node_public_key_buffer(pubkey_buf: &StacksPublicKeyBuffer) -> Hash160 {
        Hash160::from_data(pubkey_buf.as_bytes())
    }
}

/// Methods on `DoubleSha256` that depend on `Uint256` (stacks-common). Same
/// pattern as `Hash160PubKeyExt`.
pub trait DoubleSha256Uint256Ext {
    fn into_le(self) -> Uint256;
    fn into_be(self) -> Uint256;
}

impl DoubleSha256Uint256Ext for DoubleSha256 {
    /// Converts a hash to a little-endian Uint256
    #[inline]
    fn into_le(self) -> Uint256 {
        let DoubleSha256(data) = self;
        let mut ret: [u64; 4] = unsafe { mem::transmute(data) };
        for x in ret.iter_mut() {
            *x = x.to_le();
        }
        Uint256(ret)
    }

    /// Converts a hash to a big-endian Uint256
    #[inline]
    fn into_be(self) -> Uint256 {
        let DoubleSha256(mut data) = self;
        data.reverse();
        let mut ret: [u64; 4] = unsafe { mem::transmute(data) };
        for x in ret.iter_mut() {
            *x = x.to_be();
        }
        Uint256(ret)
    }
}
