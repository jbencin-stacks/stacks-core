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

pub const MESSAGE_SIGNATURE_ENCODED_SIZE: u32 = 65;

/// A container for compressed secp256k1 public keys (the wire-format pubkey:
/// always 33 bytes). Conversions to/from the in-memory `Secp256k1PublicKey`
/// type live in stacks-common as `StacksPublicKeyBufferExt` (those depend on
/// the active secp256k1 crate, which stacks-codec doesn't dictate).
pub struct StacksPublicKeyBuffer(pub [u8; 33]);
crate::impl_array_newtype!(StacksPublicKeyBuffer, u8, 33);
crate::impl_array_hexstring_fmt!(StacksPublicKeyBuffer);
crate::impl_byte_array_newtype!(StacksPublicKeyBuffer, u8, 33);
crate::impl_byte_array_message_codec!(StacksPublicKeyBuffer, 33);
crate::impl_byte_array_serde!(StacksPublicKeyBuffer);
#[cfg(feature = "rusqlite")]
crate::impl_byte_array_rusqlite_only!(StacksPublicKeyBuffer);

pub struct MessageSignature(pub [u8; 65]);
crate::impl_array_newtype!(MessageSignature, u8, 65);
crate::impl_array_hexstring_fmt!(MessageSignature);
crate::impl_byte_array_newtype!(MessageSignature, u8, 65);
crate::impl_byte_array_serde!(MessageSignature);
crate::impl_byte_array_message_codec!(MessageSignature, 65);
#[cfg(feature = "rusqlite")]
crate::impl_byte_array_rusqlite_only!(MessageSignature);

impl MessageSignature {
    pub fn empty() -> MessageSignature {
        // NOTE: this cannot be a valid signature
        MessageSignature([0u8; 65])
    }

    /// Build a `MessageSignature` directly from raw bytes (no validation).
    /// Intended for tests / fixtures; the original was `cfg(test, testing)`-gated
    /// in stacks-common, but moving it across the crate boundary made that
    /// gating impractical (the parent crate's `cfg(test)` doesn't propagate).
    pub fn from_raw(sig: &[u8]) -> MessageSignature {
        let mut buf = [0u8; 65];
        if sig.len() < 65 {
            buf.copy_from_slice(sig);
        } else {
            buf.copy_from_slice(&sig[..65]);
        }
        MessageSignature(buf)
    }

    /// Convert from VRS to RSV
    pub fn to_rsv(&self) -> Vec<u8> {
        [&self.0[1..], &self.0[0..1]].concat()
    }

    /// Returns true if these 65 bytes parse as a recoverable secp256k1 signature
    /// (1-byte recovery id followed by a 64-byte compact signature). Cheaper
    /// equivalent of `MessageSignatureSecpExt::to_secp256k1_recoverable(...).is_some()`
    /// used by codec deserializers to fail-fast on malformed sigs.
    #[cfg(not(target_family = "wasm"))]
    pub fn is_recoverable(&self) -> bool {
        let recid = match secp256k1::ecdsa::RecoveryId::from_i32(self.0[0] as i32) {
            Ok(rid) => rid,
            Err(_) => return false,
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..64].copy_from_slice(&self.0[1..=64]);
        secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes, recid).is_ok()
    }

    /// Same check as the native variant; uses `libsecp256k1` on wasm.
    #[cfg(target_family = "wasm")]
    pub fn is_recoverable(&self) -> bool {
        if libsecp256k1::RecoveryId::parse(self.0[0]).is_err() {
            return false;
        }
        libsecp256k1::Signature::parse_standard_slice(&self.0[1..65]).is_ok()
    }
}
