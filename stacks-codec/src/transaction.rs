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

//! Auth-tree types for the `StacksTransaction` codec.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::address::AddressHashMode;
use crate::secp256k1::Secp256k1PublicKey;
use crate::signatures::{MessageSignature, StacksPublicKeyBuffer};
use crate::{read_next, write_next, Error as CodecError, StacksMessageCodec};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionAnchorMode {
    OnChainOnly = 1,  // must be included in a StacksBlock
    OffChainOnly = 2, // must be included in a StacksMicroBlock
    Any = 3,          // either
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionAuthFlags {
    // types of auth
    AuthStandard = 0x04,
    AuthSponsored = 0x05,
}

/// Transaction signatures are validated by calculating the public key from the signature, and
/// verifying that all public keys hash to the signing account's hash.  To do so, we must preserve
/// enough information in the auth structure to recover each public key's bytes.
///
/// An auth field can be a public key or a signature.  In both cases, the public key (either given
/// in-the-raw or embedded in a signature) may be encoded as compressed or uncompressed.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionAuthFieldID {
    // types of auth fields
    PublicKeyCompressed = 0x00,
    PublicKeyUncompressed = 0x01,
    SignatureCompressed = 0x02,
    SignatureUncompressed = 0x03,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum TransactionPublicKeyEncoding {
    // ways we can encode a public key
    Compressed = 0x00,
    Uncompressed = 0x01,
}

impl TransactionPublicKeyEncoding {
    pub fn from_u8(n: u8) -> Option<TransactionPublicKeyEncoding> {
        match n {
            x if x == TransactionPublicKeyEncoding::Compressed as u8 => {
                Some(TransactionPublicKeyEncoding::Compressed)
            }
            x if x == TransactionPublicKeyEncoding::Uncompressed as u8 => {
                Some(TransactionPublicKeyEncoding::Uncompressed)
            }
            _ => None,
        }
    }
}

// tag address hash modes as "singlesig" or "multisig" so we can't accidentally construct an
// invalid spending condition
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SinglesigHashMode {
    P2PKH = 0x00,
    P2WPKH = 0x02,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MultisigHashMode {
    P2SH = 0x01,
    P2WSH = 0x03,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OrderIndependentMultisigHashMode {
    P2SH = 0x05,
    P2WSH = 0x07,
}

impl SinglesigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            SinglesigHashMode::P2PKH => AddressHashMode::SerializeP2PKH,
            SinglesigHashMode::P2WPKH => AddressHashMode::SerializeP2WPKH,
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<SinglesigHashMode> {
        match hm {
            AddressHashMode::SerializeP2PKH => Some(SinglesigHashMode::P2PKH),
            AddressHashMode::SerializeP2WPKH => Some(SinglesigHashMode::P2WPKH),
            _ => None,
        }
    }

    pub fn from_u8(n: u8) -> Option<SinglesigHashMode> {
        match n {
            x if x == SinglesigHashMode::P2PKH as u8 => Some(SinglesigHashMode::P2PKH),
            x if x == SinglesigHashMode::P2WPKH as u8 => Some(SinglesigHashMode::P2WPKH),
            _ => None,
        }
    }
}

impl MultisigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            MultisigHashMode::P2SH => AddressHashMode::SerializeP2SH,
            MultisigHashMode::P2WSH => AddressHashMode::SerializeP2WSH,
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<MultisigHashMode> {
        match hm {
            AddressHashMode::SerializeP2SH => Some(MultisigHashMode::P2SH),
            AddressHashMode::SerializeP2WSH => Some(MultisigHashMode::P2WSH),
            _ => None,
        }
    }

    pub fn from_u8(n: u8) -> Option<MultisigHashMode> {
        match n {
            x if x == MultisigHashMode::P2SH as u8 => Some(MultisigHashMode::P2SH),
            x if x == MultisigHashMode::P2WSH as u8 => Some(MultisigHashMode::P2WSH),
            _ => None,
        }
    }
}

impl OrderIndependentMultisigHashMode {
    pub fn to_address_hash_mode(&self) -> AddressHashMode {
        match *self {
            OrderIndependentMultisigHashMode::P2SH => AddressHashMode::SerializeP2SH,
            OrderIndependentMultisigHashMode::P2WSH => AddressHashMode::SerializeP2WSH,
        }
    }

    pub fn from_address_hash_mode(hm: AddressHashMode) -> Option<OrderIndependentMultisigHashMode> {
        match hm {
            AddressHashMode::SerializeP2SH => Some(OrderIndependentMultisigHashMode::P2SH),
            AddressHashMode::SerializeP2WSH => Some(OrderIndependentMultisigHashMode::P2WSH),
            _ => None,
        }
    }

    pub fn from_u8(n: u8) -> Option<OrderIndependentMultisigHashMode> {
        match n {
            x if x == OrderIndependentMultisigHashMode::P2SH as u8 => {
                Some(OrderIndependentMultisigHashMode::P2SH)
            }
            x if x == OrderIndependentMultisigHashMode::P2WSH as u8 => {
                Some(OrderIndependentMultisigHashMode::P2WSH)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionAuthField {
    PublicKey(Secp256k1PublicKey),
    Signature(TransactionPublicKeyEncoding, MessageSignature),
}

impl TransactionAuthField {
    pub fn is_public_key(&self) -> bool {
        matches!(self, TransactionAuthField::PublicKey(_))
    }

    pub fn is_signature(&self) -> bool {
        matches!(self, TransactionAuthField::Signature(..))
    }

    pub fn as_public_key(&self) -> Option<Secp256k1PublicKey> {
        match *self {
            TransactionAuthField::PublicKey(ref pubk) => Some(pubk.clone()),
            _ => None,
        }
    }

    pub fn as_signature(&self) -> Option<(TransactionPublicKeyEncoding, MessageSignature)> {
        match *self {
            TransactionAuthField::Signature(ref key_fmt, ref sig) => Some((*key_fmt, sig.clone())),
            _ => None,
        }
    }
}

impl StacksMessageCodec for TransactionAuthField {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        match *self {
            TransactionAuthField::PublicKey(ref pubk) => {
                let field_id = if pubk.compressed() {
                    TransactionAuthFieldID::PublicKeyCompressed
                } else {
                    TransactionAuthFieldID::PublicKeyUncompressed
                };

                let pubkey_buf = StacksPublicKeyBuffer::from_public_key(pubk);

                write_next(fd, &(field_id as u8))?;
                write_next(fd, &pubkey_buf)?;
            }
            TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                let field_id = if *key_encoding == TransactionPublicKeyEncoding::Compressed {
                    TransactionAuthFieldID::SignatureCompressed
                } else {
                    TransactionAuthFieldID::SignatureUncompressed
                };

                write_next(fd, &(field_id as u8))?;
                write_next(fd, sig)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionAuthField, CodecError> {
        let field_id: u8 = read_next(fd)?;
        let field = match field_id {
            x if x == TransactionAuthFieldID::PublicKeyCompressed as u8 => {
                let pubkey_buf: StacksPublicKeyBuffer = read_next(fd)?;
                let mut pubkey = pubkey_buf
                    .to_public_key()
                    .map_err(|e| CodecError::DeserializeError(e.into()))?;
                pubkey.set_compressed(true);

                TransactionAuthField::PublicKey(pubkey)
            }
            x if x == TransactionAuthFieldID::PublicKeyUncompressed as u8 => {
                let pubkey_buf: StacksPublicKeyBuffer = read_next(fd)?;
                let mut pubkey = pubkey_buf
                    .to_public_key()
                    .map_err(|e| CodecError::DeserializeError(e.into()))?;
                pubkey.set_compressed(false);

                TransactionAuthField::PublicKey(pubkey)
            }
            x if x == TransactionAuthFieldID::SignatureCompressed as u8 => {
                let sig: MessageSignature = read_next(fd)?;
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, sig)
            }
            x if x == TransactionAuthFieldID::SignatureUncompressed as u8 => {
                let sig: MessageSignature = read_next(fd)?;
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, sig)
            }
            _ => {
                return Err(CodecError::DeserializeError(format!(
                    "Failed to parse auth field: unkonwn auth field ID {}",
                    field_id
                )));
            }
        };
        Ok(field)
    }
}
