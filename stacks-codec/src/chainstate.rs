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

use sha2::{Digest, Sha512_256};

use crate::hash::{Hash160, Sha512Trunc256Sum};
use crate::Error as CodecError;
use crate::StacksMessageCodec;

pub struct Txid(pub [u8; 32]);
crate::impl_array_newtype!(Txid, u8, 32);
crate::impl_array_hexstring_fmt!(Txid);
crate::impl_byte_array_newtype!(Txid, u8, 32);
crate::impl_byte_array_message_codec!(Txid, 32);
crate::impl_byte_array_serde!(Txid);
#[cfg(feature = "rusqlite")]
crate::impl_byte_array_rusqlite_only!(Txid);
pub const TXID_ENCODED_SIZE: u32 = 32;

impl Txid {
    /// A Stacks transaction ID is a sha512/256 hash (not a double-sha256 hash)
    pub fn from_stacks_tx(txdata: &[u8]) -> Txid {
        let h = Sha512Trunc256Sum::from_data(txdata);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(h.as_bytes());
        Txid(bytes)
    }

    /// A sighash is calculated the same way as a txid
    pub fn from_sighash_bytes(txdata: &[u8]) -> Txid {
        Txid::from_stacks_tx(txdata)
    }
}

pub struct BlockHeaderHash(pub [u8; 32]);
crate::impl_array_newtype!(BlockHeaderHash, u8, 32);
crate::impl_array_hexstring_fmt!(BlockHeaderHash);
crate::impl_byte_array_newtype!(BlockHeaderHash, u8, 32);
crate::impl_byte_array_serde!(BlockHeaderHash);
crate::impl_byte_array_message_codec!(BlockHeaderHash, 32);
#[cfg(feature = "rusqlite")]
crate::impl_byte_array_rusqlite_only!(BlockHeaderHash);
pub const BLOCK_HEADER_HASH_ENCODED_SIZE: usize = 32;

pub struct StacksBlockId(pub [u8; 32]);
crate::impl_array_newtype!(StacksBlockId, u8, 32);
crate::impl_array_hexstring_fmt!(StacksBlockId);
crate::impl_byte_array_newtype!(StacksBlockId, u8, 32);
crate::impl_byte_array_serde!(StacksBlockId);
crate::impl_byte_array_message_codec!(StacksBlockId, 32);
#[cfg(feature = "rusqlite")]
crate::impl_byte_array_rusqlite_only!(StacksBlockId);

pub struct ConsensusHash(pub [u8; 20]);
crate::impl_array_newtype!(ConsensusHash, u8, 20);
crate::impl_array_hexstring_fmt!(ConsensusHash);
crate::impl_byte_array_newtype!(ConsensusHash, u8, 20);
crate::impl_byte_array_serde!(ConsensusHash);
crate::impl_byte_array_message_codec!(ConsensusHash, 20);
#[cfg(feature = "rusqlite")]
crate::impl_byte_array_rusqlite_only!(ConsensusHash);
pub const CONSENSUS_HASH_ENCODED_SIZE: u32 = 20;

impl StacksBlockId {
    pub fn new(
        sortition_consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> StacksBlockId {
        let mut hasher = Sha512_256::new();
        hasher.update(block_hash);
        hasher.update(sortition_consensus_hash);

        let h = Sha512Trunc256Sum::from_hasher(hasher);
        StacksBlockId(h.0)
    }

    pub fn first_mined() -> StacksBlockId {
        // Inlined from `stacks_common::consts::{FIRST_BURNCHAIN_CONSENSUS_HASH,
        // FIRST_STACKS_BLOCK_HASH}` to avoid pulling in stacks-common.
        StacksBlockId::new(&ConsensusHash([0u8; 20]), &BlockHeaderHash([0u8; 32]))
    }
}

impl BlockHeaderHash {
    pub fn to_hash160(&self) -> Hash160 {
        Hash160::from_sha256(&self.0)
    }

    pub fn from_serializer<C: StacksMessageCodec>(
        serializer: &C,
    ) -> Result<BlockHeaderHash, CodecError> {
        let mut hasher = Sha512_256::new();
        serializer.consensus_serialize(&mut hasher)?;
        let hash = Sha512Trunc256Sum::from_hasher(hasher);
        Ok(BlockHeaderHash(hash.0))
    }

    pub fn from_serialized_header(buf: &[u8]) -> BlockHeaderHash {
        let h = Sha512Trunc256Sum::from_data(buf);
        BlockHeaderHash(h.to_bytes())
    }
}
