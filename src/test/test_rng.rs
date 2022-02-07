/*
 * $Id$
 *
 * Copyright (c) 2021, Purushottam A. Kulkarni.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and
 * or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE
 *
 */

#[cfg(test)]
mod tests {
    const RNG_GET_BYTECOUNT: usize = 1024;
    #[test]
    fn test_rng_continuous() {
        let mut out_last = match crate::rng::get_bytes(RNG_GET_BYTECOUNT) {
            Ok(buf) => buf,
            Err(e) => panic!("{}", e),
        };

        for _i in 0..RNG_GET_BYTECOUNT {
            let out = match crate::rng::get_bytes(RNG_GET_BYTECOUNT) {
                Ok(buf) => buf,
                Err(e) => {
                    panic!("{}", e);
                }
            };
            assert_eq!(out.len(), RNG_GET_BYTECOUNT);
            assert_ne!(out, out_last);

            out_last = out;
        }
    }

    #[test]
    fn test_rng_generate() {
        let rng = match crate::rng::KcapiRNG::new("drbg_nopr_hmac_sha512") {
            Ok(rng) => rng,
            Err(e) => panic!("{}", e),
        };

        match rng.seed(vec![0u8; 16]) {
            Ok(()) => {}
            Err(e) => panic!("{}", e),
        };

        let mut out_last = match rng.generate(RNG_GET_BYTECOUNT) {
            Ok(buf) => buf,
            Err(e) => panic!("{}", e),
        };
        for _i in 0..RNG_GET_BYTECOUNT {
            let out = match rng.generate(RNG_GET_BYTECOUNT) {
                Ok(buf) => buf,
                Err(e) => panic!("{}", e),
            };
            assert_eq!(out.len(), RNG_GET_BYTECOUNT);
            assert_ne!(out, out_last);

            out_last = out;
        }
    }

    #[test]
    fn test_rng_generate_unseeded() {
        let rng = match crate::rng::KcapiRNG::new("drbg_nopr_hmac_sha512") {
            Ok(rng) => rng,
            Err(e) => panic!("{}", e),
        };

        let _out = match rng.generate(RNG_GET_BYTECOUNT) {
            Ok(_buf) => {
                panic!("[BUG] RNG generated randomness without being seeded.")
            }
            Err(_e) => {}
        };
    }

    #[test]
    fn test_rng_seedsize() {
        let rng = match crate::rng::KcapiRNG::new("drbg_nopr_hmac_sha512") {
            Ok(rng) => rng,
            Err(e) => panic!("{}", e),
        };

        let seedsize = rng.seedsize;
        println!("\nseedsize = {}", seedsize);
    }

    #[test]
    #[ignore]
    fn test_rng_setentropy() {
        let rng = match crate::rng::KcapiRNG::new("drbg_nopr_sha1") {
            Ok(rng) => rng,
            Err(e) => panic!("{}", e),
        };

        let ent = vec![0x41u8; 16];
        rng.setentropy(ent).expect("Failed to set entropy for RNG");
    }

    #[test]
    #[ignore]
    fn test_rng_kat() {
        let rng = match crate::rng::KcapiRNG::new("drbg_nopr_sha1") {
            Ok(rng) => rng,
            Err(e) => panic!("{}", e),
        };

        let ent = vec![0x41u8; 16];
        rng.setentropy(ent).expect("Failed to set entropy for RNG");

        let inp = vec![0x41u8; 16];
        rng.seed(inp).expect("Failed to seed RNG");

        let out_exp = vec![
            0xbd, 0x3a, 0xbb, 0xfe, 0x98, 0x85, 0x69, 0xbf, 0x64, 0x2f, 0xe9, 0xb3, 0x55, 0xc1,
            0xc0, 0x35,
        ];
        let out = rng.generate(16).expect("Failed to generate randomness");
        assert_eq!(out.len(), 16);
        assert_eq!(out, out_exp);
    }

    #[test]
    #[ignore]
    fn test_rng_cavp() {
        let rng = match crate::rng::KcapiRNG::new("drbg_pr_hmac_sha256") {
            Ok(rng) => rng,
            Err(e) => panic!("{}", e),
        };

        let ent = vec![
            0xa1, 0x27, 0xc0, 0xde, 0xf, 0x23, 0xc0, 0xfb, 0xf8, 0x20, 0xfd, 0xd5, 0x27, 0xc9,
            0x11, 0x92, 0x37, 0xd8, 0x88, 0xaa, 0x75, 0xae, 0xb3, 0xd6, 0x27, 0x48, 0x9d, 0xaf,
            0x3d, 0xa6, 0xc0, 0xce, 0x3a, 0xc8, 0xbd, 0x9a, 0x90, 0xf2, 0xf4, 0x99, 0x2a, 0xba,
            0xcf, 0xf0, 0x92, 0xce, 0x99, 0x2e,
        ];
        let perso_str = vec![0xd1, 0x7c, 0xe3, 0x55, 0x50, 0xe9, 0xdc, 0x56];

        let enta = vec![
            0x6e, 0x3c, 0x12, 0x19, 0x87, 0x83, 0xe2, 0x6b, 0xe8, 0x24, 0x96, 0x42, 0x14, 0xb0,
            0xde, 0x19, 0xe2, 0x5b, 0xe8, 0x8, 0xe1, 0xb7, 0x81, 0xdc, 0x35, 0x68, 0x4b, 0x4d,
            0x77, 0x7f, 0x78, 0x33,
        ];
        let addtla = vec![0x9e, 0xcf, 0x2c, 0x25, 0x95, 0xae];

        let entb = vec![
            0x2f, 0xc2, 0x73, 0x32, 0x48, 0x44, 0xc9, 0x1b, 0xe1, 0xc7, 0x6a, 0xc, 0x97, 0x53,
            0x9d, 0xea, 0x39, 0xc0, 0x89, 0x3b, 0xf2, 0x3e, 0xe6, 0x33, 0x2d, 0x41, 0x64, 0xc7,
            0xf1, 0x9, 0x91, 0x7b,
        ];
        let addtlb = vec![0x51, 0xb, 0x1f, 0x62, 0x7b, 0x13];

        rng.setentropy(ent).expect("Failed to set entropy for RNG");
        rng.seed(perso_str).expect("Failed to seed rng");

        rng.setentropy(enta).expect("Failed to set ent 1 for DRBG");
        rng.setaddtl(addtla)
            .expect("Failed to set additional data 1 for DRBG");
        let data = rng.generate(128).expect("Failed to generate 1st round");
        assert_eq!(data.len(), 128);

        rng.setentropy(entb)
            .expect("Failed to set entropy 2 for RNG");
        rng.setaddtl(addtlb)
            .expect("Failed to set additional data 2 for RNG");
        let data = rng.generate(128).expect("Failed to generate 2nd round");

        let exp = [
            0x25, 0x20, 0xc9, 0x7e, 0xf2, 0x35, 0xb0, 0xbb, 0x5, 0x39, 0x72, 0xb6, 0x66, 0x41,
            0x92, 0x1, 0xd4, 0x3, 0x9e, 0x2f, 0x93, 0x34, 0xb3, 0xa7, 0xfa, 0xf1, 0xae, 0xed, 0xf3,
            0x28, 0x11, 0x39, 0x4c, 0xc, 0xfa, 0x6c, 0xfc, 0x6c, 0xb8, 0xa9, 0x96, 0xbb, 0xff,
            0xdc, 0x3d, 0xbf, 0x9a, 0x7a, 0x9d, 0xfe, 0x3a, 0x3, 0xc4, 0xd, 0xc4, 0x6e, 0x9a, 0xd6,
            0x55, 0x5f, 0x93, 0xaa, 0xcd, 0xd0, 0x2c, 0x1c, 0x95, 0x8e, 0x66, 0x35, 0x83, 0xf3,
            0x91, 0xc3, 0x53, 0xac, 0x6d, 0x95, 0x44, 0xf1, 0x48, 0xc3, 0x4a, 0x0, 0xfc, 0xd5,
            0xfa, 0x9a, 0x98, 0xbe, 0xf0, 0x87, 0x68, 0xee, 0x6e, 0xe5, 0xbe, 0xec, 0x50, 0x87,
            0x5c, 0x86, 0x85, 0xc4, 0xd1, 0x27, 0x80, 0x74, 0xd1, 0x78, 0x52, 0x1a, 0x1, 0xf6,
            0xff, 0x40, 0x73, 0x7, 0x8c, 0x86, 0x53, 0x15, 0x1, 0x54, 0xae, 0x12, 0xe9, 0xe5,
        ];

        assert_eq!(data.len(), 128);
        assert_eq!(data, exp);
    }
}
