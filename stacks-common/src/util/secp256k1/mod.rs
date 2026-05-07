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

// `Secp256k1PublicKey`, `Secp256k1PrivateKey`, `MessageSignature` (with the
// `from_secp256k1_recoverable` / `to_secp256k1_recoverable` conversion
// methods, previously the `MessageSignatureSecpExt` trait), and the
// `secp256k1_recover` / `secp256k1_verify` helpers all live in stacks-codec.
// Re-exported here so existing call sites
// (`stacks_common::util::secp256k1::*`) keep working.
#[cfg(all(target_family = "wasm", not(feature = "wasm-deterministic")))]
pub use stacks_codec::secp256k1::{secp256k1_recover, secp256k1_verify};
#[cfg(not(target_family = "wasm"))]
pub use stacks_codec::secp256k1::{secp256k1_recover, secp256k1_verify, Error};
#[cfg(target_family = "wasm")]
pub use stacks_codec::secp256k1::{Error, PUBLIC_KEY_SIZE};
pub use stacks_codec::secp256k1::{
    SchnorrSignature, Secp256k1PrivateKey, Secp256k1PublicKey, SCHNORR_SIGNATURE_ENCODED_SIZE,
};
pub use stacks_codec::signatures::{MessageSignature, MESSAGE_SIGNATURE_ENCODED_SIZE};
