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

//! C32 (Crockford base-32) encoding helpers. The implementation lives in
//! `stacks_codec::c32`; this module re-exports its public surface and adapts
//! the local `super::Error` type. Tests still live here since they
//! cross-validate against `c32_old`.

use super::Error;

pub fn c32_address_decode(s: &str) -> Result<(u8, Vec<u8>), Error> {
    Ok(stacks_codec::c32::c32_address_decode(s)?)
}

pub fn c32_address(version: u8, data: &[u8]) -> Result<String, Error> {
    Ok(stacks_codec::c32::c32_address(version, data)?)
}

// Re-export low-level encoders for cross-validation tests below.
#[cfg(test)]
use stacks_codec::c32::{c32_decode, c32_encode};

#[cfg(test)]
mod test {
    use rand::Rng;

    use super::super::c32_old::{
        c32_address as c32_address_old, c32_address_decode as c32_address_decode_old,
    };
    use super::*;
    use crate::util::hash::hex_bytes;

    #[test]
    fn old_c32_validation() {
        for n in 0..5000 {
            // random version
            let random_version: u8 = rand::thread_rng().gen_range(0..31);

            // random 20 bytes
            let random_bytes = rand::thread_rng().gen::<[u8; 20]>();

            let addr_new = c32_address(random_version, &random_bytes).unwrap();
            let addr_old = c32_address_old(random_version, &random_bytes).unwrap();

            assert_eq!(&addr_new, &addr_old);

            let decoded_addrs = vec![
                c32_address_decode(&addr_new).unwrap(),
                c32_address_decode(&addr_old).unwrap(),
                c32_address_decode_old(&addr_new).unwrap(),
                c32_address_decode_old(&addr_new).unwrap(),
            ];

            for decoded_addr in decoded_addrs {
                assert_eq!(decoded_addr.0, random_version);
                assert_eq!(decoded_addr.1, random_bytes);
            }
        }
    }

    #[test]
    fn test_addresses() {
        let hex_strs = [
            "a46ff88886c2ef9762d970b4d2c63678835bd39d",
            "0000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000001",
            "1000000000000000000000000000000000000001",
            "1000000000000000000000000000000000000000",
        ];

        let versions = [22, 0, 31, 20, 26, 21];

        let c32_addrs = [
            [
                "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7",
                "SP000000000000000000002Q6VF78",
                "SP00000000000000000005JA84HQ",
                "SP80000000000000000000000000000004R0CMNV",
                "SP800000000000000000000000000000033H8YKK",
            ],
            [
                "S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
                "S0000000000000000000002AA028H",
                "S000000000000000000006EKBDDS",
                "S080000000000000000000000000000007R1QC00",
                "S080000000000000000000000000000003ENTGCQ",
            ],
            [
                "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR",
                "SZ000000000000000000002ZE1VMN",
                "SZ00000000000000000005HZ3DVN",
                "SZ80000000000000000000000000000004XBV6MS",
                "SZ800000000000000000000000000000007VF5G0",
            ],
            [
                "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G",
                "SM0000000000000000000062QV6X",
                "SM00000000000000000005VR75B2",
                "SM80000000000000000000000000000004WBEWKC",
                "SM80000000000000000000000000000000JGSYGV",
            ],
            [
                "ST2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQYAC0RQ",
                "ST000000000000000000002AMW42H",
                "ST000000000000000000042DB08Y",
                "ST80000000000000000000000000000006BYJ4R4",
                "ST80000000000000000000000000000002YBNPV3",
            ],
            [
                "SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9",
                "SN000000000000000000003YDHWKJ",
                "SN00000000000000000005341MC8",
                "SN800000000000000000000000000000066KZWY0",
                "SN800000000000000000000000000000006H75AK",
            ],
        ];

        for (i, h) in hex_strs.iter().enumerate() {
            for (j, v) in versions.iter().enumerate() {
                let b = hex_bytes(h).unwrap();
                let z = c32_address(*v, &b).unwrap();

                assert_eq!(z, c32_addrs[j][i]);

                let (decoded_version, decoded_bytes) = c32_address_decode(&z).unwrap();
                assert_eq!(decoded_version, *v);
                assert_eq!(decoded_bytes, b);
            }
        }
    }

    #[test]
    fn test_simple() {
        let hex_strings = &[
            "a46ff88886c2ef9762d970b4d2c63678835bd39d",
            "",
            "0000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000001",
            "1000000000000000000000000000000000000001",
            "1000000000000000000000000000000000000000",
            "01",
            "22",
            "0001",
            "000001",
            "00000001",
            "10",
            "0100",
            "1000",
            "010000",
            "100000",
            "01000000",
            "10000000",
            "0100000000",
        ];
        let c32_strs = [
            "MHQZH246RBQSERPSE2TD5HHPF21NQMWX",
            "",
            "00000000000000000000",
            "00000000000000000001",
            "20000000000000000000000000000001",
            "20000000000000000000000000000000",
            "1",
            "12",
            "01",
            "001",
            "0001",
            "G",
            "80",
            "400",
            "2000",
            "10000",
            "G0000",
            "800000",
            "4000000",
        ];

        let results: Vec<_> = hex_strings
            .iter()
            .zip(c32_strs.iter())
            .map(|(hex_str, expected)| {
                let bytes = hex_bytes(hex_str).unwrap();
                let c32_encoded = c32_encode(&bytes);
                let decoded_bytes = c32_decode(&c32_encoded).unwrap();
                let result = (bytes, c32_encoded, decoded_bytes, expected);
                println!("{result:?}");
                result
            })
            .collect();
        for (bytes, c32_encoded, decoded_bytes, expected_c32) in results.iter() {
            assert_eq!(bytes, decoded_bytes);
            assert_eq!(c32_encoded, *expected_c32);
        }
    }

    #[test]
    fn test_normalize() {
        let addrs = [
            "S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "SO2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "S02J6ZY48GVLEZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "SO2J6ZY48GVLEZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "s02j6zy48gv1ez5v2v5rb9mp66sw86pykkpvkg2ce",
            "sO2j6zy48gv1ez5v2v5rb9mp66sw86pykkpvkg2ce",
            "s02j6zy48gvlez5v2v5rb9mp66sw86pykkpvkg2ce",
            "sO2j6zy48gvlez5v2v5rb9mp66sw86pykkpvkg2ce",
        ];

        let expected_bytes = hex_bytes("a46ff88886c2ef9762d970b4d2c63678835bd39d").unwrap();
        let expected_version = 0;

        for addr in addrs.iter() {
            let (decoded_version, decoded_bytes) = c32_address_decode(addr).unwrap();
            assert_eq!(decoded_version, expected_version);
            assert_eq!(decoded_bytes, expected_bytes);
        }
    }

    #[test]
    fn test_ascii_only() {
        assert!(matches!(
            c32_address_decode("S\u{1D7D8}2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE"),
            Err(Error::InvalidCrockford32)
        ));

        assert!(matches!(
            c32_address_decode("\u{cd}\u{85}\x6a\x6a\x6a\x19\x00"),
            Err(Error::InvalidCrockford32)
        ));
    }
}
