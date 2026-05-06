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

// `Gamma` follows the variable naming in the ECVRF RFC; allow non-snake-case here.
#![allow(non_snake_case)]

use std::fmt::{self, Debug};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar as ed25519_Scalar;

use crate::hex::{hex_bytes, to_hex};
use crate::{Error as CodecError, StacksMessageCodec};

pub const VRF_PROOF_ENCODED_SIZE: u32 = 80;

#[derive(Clone, PartialEq, Eq)]
pub struct VRFProof {
    // force private so we don't accidentally expose
    // an invalid c point
    Gamma: EdwardsPoint,
    c: ed25519_Scalar,
    s: ed25519_Scalar,
}

impl Debug for VRFProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex())
    }
}

impl Hash for VRFProof {
    fn hash<H: Hasher>(&self, h: &mut H) {
        let bytes = self.to_bytes();
        bytes.hash(h);
    }
}

impl VRFProof {
    pub fn Gamma(&self) -> &EdwardsPoint {
        &self.Gamma
    }

    pub fn s(&self) -> &ed25519_Scalar {
        &self.s
    }

    pub fn c(&self) -> &ed25519_Scalar {
        &self.c
    }

    #[allow(clippy::needless_range_loop)]
    pub fn check_c(c: &ed25519_Scalar) -> bool {
        let c_bytes = c.to_bytes();

        // upper 16 bytes of c must be 0's
        for c_byte in c_bytes[16..32].iter() {
            if *c_byte != 0 {
                return false;
            }
        }
        true
    }

    pub fn empty() -> VRFProof {
        // can't be all 0's, since an all-0 string decodes to a low-order point
        VRFProof::from_slice(&[1u8; 80]).unwrap()
    }

    /// Returns `None` if `c` doesn't satisfy `check_c`.
    /// (Originally returned `Result<_, vrf::Error>` before the move; the
    /// only caller — `VRF::prove` in stacks-common — was updated.)
    pub fn new(
        Gamma: EdwardsPoint,
        c: ed25519_Scalar,
        s: ed25519_Scalar,
    ) -> Option<VRFProof> {
        if !VRFProof::check_c(&c) {
            return None;
        }

        Some(VRFProof { Gamma, c, s })
    }

    pub fn from_slice(bytes: &[u8]) -> Option<VRFProof> {
        match bytes.len() {
            80 => {
                // format:
                // 0                            32         48                         80
                // |----------------------------|----------|---------------------------|
                //      Gamma point               c scalar   s scalar
                let gamma_opt = CompressedEdwardsY::from_slice(&bytes[0..32])
                    .ok()
                    .and_then(|y| y.decompress());
                let gamma = gamma_opt?;
                if gamma.is_small_order() {
                    return None;
                }

                let mut c_buf = [0u8; 32];
                let mut s_buf = [0u8; 32];

                c_buf[..16].copy_from_slice(&bytes[32..(16 + 32)]);
                s_buf[..32].copy_from_slice(&bytes[48..(32 + 48)]);
                let c: Option<ed25519_Scalar> = ed25519_Scalar::from_canonical_bytes(c_buf).into();
                let s: Option<ed25519_Scalar> = ed25519_Scalar::from_canonical_bytes(s_buf).into();

                Some(VRFProof {
                    Gamma: gamma,
                    c: c?,
                    s: s?,
                })
            }
            _ => None,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<VRFProof> {
        VRFProof::from_slice(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Option<VRFProof> {
        match hex_bytes(hex_str) {
            Ok(b) => VRFProof::from_slice(&b[..]),
            Err(_) => None,
        }
    }

    pub fn to_bytes(&self) -> [u8; 80] {
        let mut c_bytes_16 = [0u8; 16];
        assert!(
            VRFProof::check_c(&self.c),
            "FATAL ERROR: somehow constructed an invalid ECVRF proof"
        );

        let c_bytes = self.c.to_bytes();
        c_bytes_16[0..16].copy_from_slice(&c_bytes[0..16]);

        let gamma_bytes = self.Gamma.compress().to_bytes();
        let s_bytes = self.s.to_bytes();

        let mut ret: Vec<u8> = Vec::with_capacity(80);
        ret.extend_from_slice(&gamma_bytes);
        ret.extend_from_slice(&c_bytes_16);
        ret.extend_from_slice(&s_bytes);

        let mut proof_bytes = [0u8; 80];
        proof_bytes.copy_from_slice(&ret[..]);
        proof_bytes
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }
}

impl serde::Serialize for VRFProof {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let inst = self.to_hex();
        s.serialize_str(&inst)
    }
}

impl<'de> serde::Deserialize<'de> for VRFProof {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<VRFProof, D::Error> {
        let inst_str = String::deserialize(d)?;
        VRFProof::from_hex(&inst_str)
            .ok_or_else(|| serde::de::Error::custom("Invalid VRF proof"))
    }
}

impl StacksMessageCodec for VRFProof {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        fd.write_all(&self.to_bytes()).map_err(CodecError::WriteError)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<VRFProof, CodecError> {
        let mut bytes = [0u8; VRF_PROOF_ENCODED_SIZE as usize];
        fd.read_exact(&mut bytes).map_err(CodecError::ReadError)?;
        VRFProof::from_slice(&bytes).ok_or(CodecError::DeserializeError(
            "Failed to parse VRF proof".to_string(),
        ))
    }
}

#[cfg(feature = "rusqlite")]
mod rusqlite_impls {
    use super::VRFProof;
    use crate::hex::hex_bytes;

    impl rusqlite::types::FromSql for VRFProof {
        fn column_result(
            value: rusqlite::types::ValueRef,
        ) -> rusqlite::types::FromSqlResult<Self> {
            let hex_str = value.as_str()?;
            let byte_str = hex_bytes(hex_str)
                .map_err(|_e| rusqlite::types::FromSqlError::InvalidType)?;
            let inst = VRFProof::from_bytes(&byte_str)
                .ok_or(rusqlite::types::FromSqlError::InvalidType)?;
            Ok(inst)
        }
    }

    impl rusqlite::types::ToSql for VRFProof {
        fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
            let hex_str = self.to_hex();
            Ok(hex_str.into())
        }
    }
}
