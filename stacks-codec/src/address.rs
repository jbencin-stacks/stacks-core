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

use std::io::{Read, Write};
use std::{error, fmt};

use serde::{Deserialize, Serialize};

use crate::c32::{c32_address, Error as C32Error};
use crate::hash::{Hash160, HASH160_ENCODED_SIZE};
use crate::{read_next, write_next, Error as CodecError, StacksMessageCodec};

pub const C32_ADDRESS_VERSION_MAINNET_SINGLESIG: u8 = 22; // P
pub const C32_ADDRESS_VERSION_MAINNET_MULTISIG: u8 = 20; // M
pub const C32_ADDRESS_VERSION_TESTNET_SINGLESIG: u8 = 26; // T
pub const C32_ADDRESS_VERSION_TESTNET_MULTISIG: u8 = 21; // N

/// Serialization modes for public keys to addresses.  These apply to Stacks addresses, which
/// correspond to legacy Bitcoin addresses -- legacy Bitcoin address can be converted directly
/// into a Stacks address, permitting a Bitcoin address to be represented directly on Stacks.
/// These *do not apply* to Bitcoin segwit addresses.
#[repr(u8)]
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Hash, Eq, Copy, Serialize, Deserialize)]
pub enum AddressHashMode {
    // We support four different modes due to legacy compatibility with Stacks v1 addresses:
    SerializeP2PKH = 0x00,  // hash160(public-key), same as bitcoin's p2pkh
    SerializeP2SH = 0x01,   // hash160(multisig-redeem-script), same as bitcoin's multisig p2sh
    SerializeP2WPKH = 0x02, // hash160(segwit-program-00(p2pkh)), same as bitcoin's p2sh-p2wpkh
    SerializeP2WSH = 0x03,  // hash160(segwit-program-00(public-keys)), same as bitcoin's p2sh-p2wsh
}

impl AddressHashMode {
    pub fn to_version_mainnet(&self) -> u8 {
        match *self {
            AddressHashMode::SerializeP2PKH => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            _ => C32_ADDRESS_VERSION_MAINNET_MULTISIG,
        }
    }

    pub fn to_version_testnet(&self) -> u8 {
        match *self {
            AddressHashMode::SerializeP2PKH => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            _ => C32_ADDRESS_VERSION_TESTNET_MULTISIG,
        }
    }

    /// WARNING: this does not support segwit-p2sh!
    pub fn from_version(version: u8) -> AddressHashMode {
        match version {
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG | C32_ADDRESS_VERSION_MAINNET_SINGLESIG => {
                AddressHashMode::SerializeP2PKH
            }
            _ => AddressHashMode::SerializeP2SH,
        }
    }
}

/// Given the u8 of an AddressHashMode, deduce the AddressHashNode. Returns
/// `Err(InvalidStacksAddressVersion(value))` for an out-of-range byte. The
/// upstream version returned `stacks_common::address::Error` which carries
/// many c32 variants; stacks-common provides
/// `From<InvalidStacksAddressVersion> for address::Error` so existing `?`
/// propagation keeps working.
impl TryFrom<u8> for AddressHashMode {
    type Error = InvalidStacksAddressVersion;

    fn try_from(value: u8) -> Result<AddressHashMode, Self::Error> {
        match value {
            x if x == AddressHashMode::SerializeP2PKH as u8 => Ok(AddressHashMode::SerializeP2PKH),
            x if x == AddressHashMode::SerializeP2SH as u8 => Ok(AddressHashMode::SerializeP2SH),
            x if x == AddressHashMode::SerializeP2WPKH as u8 => {
                Ok(AddressHashMode::SerializeP2WPKH)
            }
            x if x == AddressHashMode::SerializeP2WSH as u8 => Ok(AddressHashMode::SerializeP2WSH),
            _ => Err(InvalidStacksAddressVersion(value)),
        }
    }
}

/// Error type for `StacksAddress::new` and `AddressHashMode::try_from`. The
/// original `TryFrom` returned `stacks_common::address::Error`, which has
/// many c32-specific variants; this enum carries only what's relevant for
/// the constructor. Stacks-common provides
/// `From<InvalidStacksAddressVersion> for address::Error` so existing `?`
/// propagation through `address::Error` keeps working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidStacksAddressVersion(pub u8);

impl fmt::Display for InvalidStacksAddressVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid version {}", self.0)
    }
}

impl error::Error for InvalidStacksAddressVersion {}

/// Stacks address: a 5-bit `version` byte plus a 20-byte `Hash160`.
///
/// Originally `stacks_common::types::chainstate::StacksAddress`. Convenience
/// constructors that depend on stacks-common-only types
/// (`AddressHashMode`, `Secp256k1PublicKey`) live in stacks-common as the
/// `StacksAddressExt` trait — bring it into scope at call sites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct StacksAddress {
    version: u8,
    bytes: Hash160,
}

impl StacksAddress {
    /// Construct a [`StacksAddress`] from raw components. Returns
    /// `Err(InvalidStacksAddressVersion(version))` if `version >= 32`
    /// (c32 only encodes 5-bit version bytes).
    pub fn new(version: u8, hash: Hash160) -> Result<StacksAddress, InvalidStacksAddressVersion> {
        if version >= 32 {
            return Err(InvalidStacksAddressVersion(version));
        }
        Ok(StacksAddress {
            version,
            bytes: hash,
        })
    }

    /// Construct without validation. Caller must ensure `version < 32`;
    /// formatting / encoding will panic otherwise. Intended for tests and
    /// fixtures.
    pub fn new_unsafe(version: u8, bytes: Hash160) -> Self {
        Self { version, bytes }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn bytes(&self) -> &Hash160 {
        &self.bytes
    }

    pub fn destruct(self) -> (u8, Hash160) {
        (self.version, self.bytes)
    }

    /// Because addresses are crockford-32 encoded, the version must be a 5-bit
    /// number. Historically, it was possible to construct invalid addresses
    /// given that we use a u8 to represent the version. This function is used
    /// to validate addresses before relying on their version.
    pub fn has_valid_version(&self) -> bool {
        self.version < 32
    }
}

impl StacksMessageCodec for StacksAddress {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.version)?;
        fd.write_all(self.bytes.as_bytes())
            .map_err(CodecError::WriteError)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksAddress, CodecError> {
        let version: u8 = read_next(fd)?;
        if version >= 32 {
            return Err(CodecError::DeserializeError(
                "Address version byte must be in range 0 to 31".into(),
            ));
        }
        let bytes: Hash160 = read_next(fd)?;
        Ok(StacksAddress { version, bytes })
    }
}

impl fmt::Display for StacksAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The .expect() should be unreachable since `has_valid_version` is
        // checked at construction; the only way to bypass is `new_unsafe`,
        // which is documented as test-only.
        c32_address(self.version, self.bytes.as_bytes())
            .expect("Stacks version is not C32-encodable")
            .fmt(f)
    }
}

pub const STACKS_ADDRESS_ENCODED_SIZE: u32 = 1 + HASH160_ENCODED_SIZE;

#[cfg(feature = "rusqlite")]
mod rusqlite_impls {
    use super::StacksAddress;

    impl rusqlite::types::ToSql for StacksAddress {
        fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
            let addr_str = self.to_string();
            Ok(addr_str.into())
        }
    }
}

/// Decode a c32-encoded address string into its raw components.
/// Convenience wrapper that exposes [`crate::c32::c32_address_decode`] as
/// `From<&str>` semantics for `StacksAddress`. Returns `Err` if the string
/// is malformed or has an out-of-range version. (`Address::from_string` in
/// stacks-common wraps this with c32-specific behavior.)
pub fn parse_c32(s: &str) -> Result<StacksAddress, C32Error> {
    let (version, bytes) = crate::c32::c32_address_decode(s)?;
    if bytes.len() != 20 {
        return Err(C32Error::InvalidCrockford32);
    }
    let mut hash_bytes = [0u8; 20];
    hash_bytes.copy_from_slice(&bytes[..]);
    StacksAddress::new(version, Hash160(hash_bytes))
        .map_err(|InvalidStacksAddressVersion(v)| C32Error::InvalidVersion(v))
}
