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

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512_256};

use crate::hash::{Hash160, Sha512Trunc256Sum};
use crate::signatures::MessageSignature;
use crate::{read_next, write_next, Error as CodecError, StacksMessageCodec};

pub struct Txid(pub [u8; 32]);
crate::impl_array_newtype!(Txid, u8, 32);
crate::impl_array_hexstring_fmt!(Txid);
crate::impl_byte_array_newtype!(Txid, u8, 32);
crate::impl_byte_array_message_codec!(Txid, 32);
crate::impl_byte_array_serde!(Txid);
#[cfg(feature = "rusqlite")]
crate::impl_byte_array_rusqlite_only!(Txid);
pub const TXID_ENCODED_SIZE: u32 = 32;

/// Memo blob attached to a `TransactionPayload::TokenTransfer`. Same length
/// (34 bytes) as in stacks v1.
pub struct TokenTransferMemo(pub [u8; 34]);
crate::impl_byte_array_message_codec!(TokenTransferMemo, 34);
crate::impl_array_newtype!(TokenTransferMemo, u8, 34);
crate::impl_array_hexstring_fmt!(TokenTransferMemo);
crate::impl_byte_array_newtype!(TokenTransferMemo, u8, 34);
crate::impl_byte_array_serde!(TokenTransferMemo);

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

/// Header structure for a microblock. Lives here because
/// `TransactionPayload::PoisonMicroblock(StacksMicroblockHeader,
/// StacksMicroblockHeader)` is part of the StacksTransaction tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StacksMicroblockHeader {
    pub version: u8,
    pub sequence: u16,
    pub prev_block: BlockHeaderHash,
    pub tx_merkle_root: Sha512Trunc256Sum,
    pub signature: MessageSignature,
}

impl StacksMessageCodec for StacksMicroblockHeader {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        self.serialize(fd, false)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksMicroblockHeader, CodecError> {
        let version: u8 = read_next(fd)?;
        let sequence: u16 = read_next(fd)?;
        let prev_block: BlockHeaderHash = read_next(fd)?;
        let tx_merkle_root: Sha512Trunc256Sum = read_next(fd)?;
        let signature: MessageSignature = read_next(fd)?;

        // The original `stackslib` impl had a `cfg(not(any(test, feature =
        // "testing")))`-gated `to_secp256k1_recoverable()` call here as a
        // fail-fast on malformed sigs. Dropped during the move to stacks-codec
        // — `MessageSignature::is_recoverable()` is available for callers
        // that want the same eager check, and signature verification at
        // `verify` time still catches malformed sigs unconditionally.

        Ok(StacksMicroblockHeader {
            version,
            sequence,
            prev_block,
            tx_merkle_root,
            signature,
        })
    }
}

impl StacksMicroblockHeader {
    /// Internal serialization helper. With `empty_sig=true`, writes a
    /// zeroed-out signature placeholder (used by signing / verify paths).
    pub fn serialize<W: Write>(&self, fd: &mut W, empty_sig: bool) -> Result<(), CodecError> {
        write_next(fd, &self.version)?;
        write_next(fd, &self.sequence)?;
        write_next(fd, &self.prev_block)?;
        write_next(fd, &self.tx_merkle_root)?;
        if empty_sig {
            write_next(fd, &MessageSignature::empty())?;
        } else {
            write_next(fd, &self.signature)?;
        }
        Ok(())
    }

    pub fn block_hash(&self) -> BlockHeaderHash {
        let mut bytes = vec![];
        self.consensus_serialize(&mut bytes)
            .expect("BUG: failed to serialize to a vec");
        BlockHeaderHash::from_serialized_header(&bytes[..])
    }

    /// Create the first microblock header in a microblock stream.
    /// The header will not be signed
    pub fn first_unsigned(
        parent_block_hash: &BlockHeaderHash,
        tx_merkle_root: &Sha512Trunc256Sum,
    ) -> StacksMicroblockHeader {
        StacksMicroblockHeader {
            version: 0,
            sequence: 0,
            prev_block: parent_block_hash.clone(),
            tx_merkle_root: tx_merkle_root.clone(),
            signature: MessageSignature::empty(),
        }
    }

    /// Create the first microblock header in a microblock stream for an empty microblock stream.
    /// The header will not be signed
    pub fn first_empty_unsigned(parent_block_hash: &BlockHeaderHash) -> StacksMicroblockHeader {
        StacksMicroblockHeader::first_unsigned(parent_block_hash, &Sha512Trunc256Sum([0u8; 32]))
    }

    /// Create an unsigned microblock header from its parent
    /// Return an error on overflow
    pub fn from_parent_unsigned(
        parent_header: &StacksMicroblockHeader,
        tx_merkle_root: &Sha512Trunc256Sum,
    ) -> Option<StacksMicroblockHeader> {
        let next_sequence = parent_header.sequence.checked_add(1)?;

        Some(StacksMicroblockHeader {
            version: 0,
            sequence: next_sequence,
            prev_block: parent_header.block_hash(),
            tx_merkle_root: tx_merkle_root.clone(),
            signature: MessageSignature::empty(),
        })
    }
}
