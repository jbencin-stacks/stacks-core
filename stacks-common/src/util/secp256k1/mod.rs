#[cfg(not(target_family = "wasm"))]
mod native;

#[cfg(not(target_family = "wasm"))]
pub use self::native::*;

#[cfg(target_family = "wasm")]
mod wasm;

#[cfg(target_family = "wasm")]
pub use self::wasm::*;

// `MessageSignature` lives in `stacks-codec` (it appears in the
// `StacksTransaction` type tree). Re-export so existing call sites
// (`stacks_common::util::secp256k1::MessageSignature`) keep working.
//
// Conversion to/from the underlying secp256k1 recoverable signature type
// (different between native and wasm targets) is provided by the
// `MessageSignatureSecpExt` trait defined in `native.rs` / `wasm.rs`.
// Bring it into scope at call sites via
// `use stacks_common::util::secp256k1::MessageSignatureSecpExt;`.
pub use stacks_codec::signatures::{MessageSignature, MESSAGE_SIGNATURE_ENCODED_SIZE};

pub struct SchnorrSignature(pub [u8; 65]);
impl_array_newtype!(SchnorrSignature, u8, 65);
impl_array_hexstring_fmt!(SchnorrSignature);
impl_byte_array_newtype!(SchnorrSignature, u8, 65);
impl_byte_array_serde!(SchnorrSignature);
pub const SCHNORR_SIGNATURE_ENCODED_SIZE: u32 = 65;

impl Default for SchnorrSignature {
    /// Creates a default Schnorr Signature. Note this is not a valid signature.
    fn default() -> Self {
        Self([0u8; 65])
    }
}
