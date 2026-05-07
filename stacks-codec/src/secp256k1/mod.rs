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

#[cfg(not(target_family = "wasm"))]
mod native;
#[cfg(target_family = "wasm")]
mod wasm;

#[cfg(not(target_family = "wasm"))]
pub use self::native::*;
#[cfg(target_family = "wasm")]
pub use self::wasm::*;
use crate::signatures::StacksPublicKeyBuffer;

/// Conversions between the wire-format `StacksPublicKeyBuffer` (33 raw bytes)
/// and the in-memory `Secp256k1PublicKey`. Previously the
/// `StacksPublicKeyBufferExt` trait in stacks-common (orphan rule workaround
/// when the buffer type lived in a different crate); inherent now that both
/// types live in stacks-codec.
impl StacksPublicKeyBuffer {
    pub fn from_public_key(pubkey: &Secp256k1PublicKey) -> StacksPublicKeyBuffer {
        let pubkey_bytes_vec = pubkey.to_bytes_compressed();
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&pubkey_bytes_vec[..]);
        StacksPublicKeyBuffer(pubkey_bytes)
    }

    pub fn to_public_key(&self) -> Result<Secp256k1PublicKey, &'static str> {
        Secp256k1PublicKey::from_slice(&self.0)
            .map_err(|_e_str| "Failed to decode Stacks public key")
    }
}

pub struct SchnorrSignature(pub [u8; 65]);
crate::impl_array_newtype!(SchnorrSignature, u8, 65);
crate::impl_array_hexstring_fmt!(SchnorrSignature);
crate::impl_byte_array_newtype!(SchnorrSignature, u8, 65);
crate::impl_byte_array_serde!(SchnorrSignature);
pub const SCHNORR_SIGNATURE_ENCODED_SIZE: u32 = 65;

impl Default for SchnorrSignature {
    /// Creates a default Schnorr Signature. Note this is not a valid signature.
    fn default() -> Self {
        Self([0u8; 65])
    }
}
