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
    use crate::md::{
        SHA1_DIGESTSIZE, SHA224_DIGESTSIZE, SHA256_DIGESTSIZE, SHA384_DIGESTSIZE, SHA512_DIGESTSIZE,
    };

    #[test]
    fn test_md_digest_oneshot() {
        let inp = vec![0x41u8; 16];
        const DIGEST_EXP: [u8; SHA1_DIGESTSIZE] = [
            0x19, 0xb1, 0x92, 0x8d, 0x58, 0xa2, 0x3, 0xd, 0x8, 0x2, 0x3f, 0x3d, 0x70, 0x54, 0x51,
            0x6d, 0xbc, 0x18, 0x6f, 0x20,
        ];

        let digest = match crate::md::digest("sha1", inp, 0) {
            Ok(digest) => digest,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(digest, DIGEST_EXP);
    }

    #[test]
    fn test_md_keyed_digest_oneshot() {
        let inp = vec![0x41u8; 16];
        let key = vec![0x0u8; SHA1_DIGESTSIZE];
        const HMAC_EXP: [u8; SHA1_DIGESTSIZE] = [
            0x41, 0x85, 0xf6, 0xa4, 0xc3, 0xab, 0x30, 0xf9, 0xa8, 0x5, 0x96, 0x45, 0x6f, 0x5d,
            0x61, 0x18, 0xd4, 0xfe, 0xe0, 0xd6,
        ];

        let hmac = match crate::md::keyed_digest("hmac(sha1)", key, inp, 0) {
            Ok(hmac) => hmac,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(hmac, HMAC_EXP);
    }

    #[test]
    fn test_md_digest() {
        let inp = vec![0x41u8; 16];
        const DIGEST_EXP: [u8; SHA1_DIGESTSIZE] = [
            0x19, 0xb1, 0x92, 0x8d, 0x58, 0xa2, 0x3, 0xd, 0x8, 0x2, 0x3f, 0x3d, 0x70, 0x54, 0x51,
            0x6d, 0xbc, 0x18, 0x6f, 0x20,
        ];

        let hash = match crate::md::KcapiHash::new("sha1", 0) {
            Ok(hash) => hash,
            Err(e) => panic!("{}", e),
        };

        match hash.update(inp) {
            Ok(()) => {}
            Err(e) => {
                panic!("{}", e);
            }
        };

        let digest = match hash.finalize() {
            Ok(digest) => digest,
            Err(e) => {
                panic!("{}", e)
            }
        };
        assert_eq!(digest, DIGEST_EXP)
    }

    #[test]
    fn test_md_keyed_digest() {
        let inp = vec![0x41u8; 16];
        let key = vec![0x0u8; SHA1_DIGESTSIZE];
        const HMAC_EXP: [u8; SHA1_DIGESTSIZE] = [
            0x41, 0x85, 0xf6, 0xa4, 0xc3, 0xab, 0x30, 0xf9, 0xa8, 0x5, 0x96, 0x45, 0x6f, 0x5d,
            0x61, 0x18, 0xd4, 0xfe, 0xe0, 0xd6,
        ];

        let mut hmac = match crate::md::KcapiHash::new("hmac(sha1)", 0) {
            Ok(hmac) => hmac,
            Err(e) => {
                panic!("{}", e);
            }
        };

        match hmac.setkey(key) {
            Ok(()) => {}
            Err(e) => {
                panic!("{}", e);
            }
        }

        match hmac.update(inp) {
            Ok(()) => {}
            Err(e) => {
                panic!("{}", e);
            }
        };

        let digest = match hmac.finalize() {
            Ok(digest) => digest,
            Err(e) => {
                panic!("{}", e)
            }
        };
        assert_eq!(digest, HMAC_EXP);
    }

    #[test]
    fn test_md_sha1() {
        let inp = vec![0x41u8; 16];
        const DIGEST_EXP: [u8; SHA1_DIGESTSIZE] = [
            0x19, 0xb1, 0x92, 0x8d, 0x58, 0xa2, 0x3, 0xd, 0x8, 0x2, 0x3f, 0x3d, 0x70, 0x54, 0x51,
            0x6d, 0xbc, 0x18, 0x6f, 0x20,
        ];

        let digest = match crate::md::sha1(inp) {
            Ok(digest) => digest,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(digest, DIGEST_EXP);
    }

    #[test]
    fn test_md_sha224() {
        let inp = vec![0x41u8; 16];
        const DIGEST_EXP: [u8; SHA224_DIGESTSIZE] = [
            0xcb, 0xa2, 0x25, 0xbd, 0x2d, 0xed, 0x28, 0xf5, 0xb9, 0xb3, 0xfa, 0xee, 0x8e, 0xca,
            0xed, 0x82, 0xba, 0x8, 0xd2, 0xbb, 0x5a, 0xee, 0x2c, 0x37, 0x40, 0xe7, 0xff, 0x8a,
        ];

        let digest = match crate::md::sha224(inp) {
            Ok(digest) => digest,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(digest, DIGEST_EXP);
    }

    #[test]
    fn test_md_sha256() {
        let inp = vec![0x41u8; 16];
        const DIGEST_EXP: [u8; SHA256_DIGESTSIZE] = [
            0x99, 0x12, 0x4, 0xfb, 0xa2, 0xb6, 0x21, 0x6d, 0x47, 0x62, 0x82, 0xd3, 0x75, 0xab,
            0x88, 0xd2, 0xe, 0x61, 0x8, 0xd1, 0x9, 0xae, 0xcd, 0xed, 0x97, 0xef, 0x42, 0x4d, 0xdd,
            0x11, 0x47, 0x6,
        ];

        let digest = match crate::md::sha256(inp) {
            Ok(digest) => digest,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(digest, DIGEST_EXP);
    }

    #[test]
    fn test_md_sha384() {
        let inp = vec![0x41u8; 16];
        const DIGEST_EXP: [u8; SHA384_DIGESTSIZE] = [
            0x62, 0x5e, 0x92, 0x3, 0x4, 0x7c, 0x52, 0xa1, 0xe2, 0x90, 0x18, 0x9b, 0xd1, 0x5a, 0xbf,
            0x17, 0xe, 0xd8, 0x86, 0xa3, 0x31, 0x90, 0x80, 0x3e, 0x4, 0x40, 0x2f, 0x4d, 0x48, 0xb1,
            0xf, 0xe0, 0x5a, 0xb1, 0x21, 0x97, 0xf9, 0xca, 0xc2, 0x53, 0x74, 0x9a, 0x5f, 0xde, 0x8,
            0x22, 0xc7, 0x34,
        ];

        let digest = match crate::md::sha384(inp) {
            Ok(digest) => digest,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(digest, DIGEST_EXP);
    }

    #[test]
    fn test_md_sha512() {
        let inp = vec![0x41u8; 16];
        const DIGEST_EXP: [u8; SHA512_DIGESTSIZE] = [
            0x67, 0x3a, 0x88, 0x7f, 0xe1, 0x68, 0xc, 0x26, 0xd8, 0x1d, 0x46, 0xd2, 0x76, 0xe6, 0xb,
            0x4d, 0xfd, 0x9c, 0x16, 0x60, 0x34, 0xe7, 0x2f, 0x69, 0xd6, 0x8a, 0x77, 0xf4, 0xb0,
            0xf7, 0x41, 0x21, 0xd4, 0x4b, 0x79, 0x68, 0xde, 0x8f, 0x55, 0xba, 0x26, 0x15, 0xf6,
            0xe7, 0x20, 0xa2, 0xc7, 0x43, 0x99, 0x9c, 0xbc, 0xc0, 0x7a, 0x4, 0x36, 0x6d, 0x9f,
            0x36, 0x46, 0xbc, 0xbc, 0x11, 0x98, 0xce,
        ];

        let digest = match crate::md::sha512(inp) {
            Ok(digest) => digest,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(digest, DIGEST_EXP);
    }

    #[test]
    fn test_md_hmac_sha1() {
        let inp = vec![0x41u8; 16];
        let key = vec![0x0u8; SHA1_DIGESTSIZE];
        const HMAC_EXP: [u8; SHA1_DIGESTSIZE] = [
            0x41, 0x85, 0xf6, 0xa4, 0xc3, 0xab, 0x30, 0xf9, 0xa8, 0x5, 0x96, 0x45, 0x6f, 0x5d,
            0x61, 0x18, 0xd4, 0xfe, 0xe0, 0xd6,
        ];

        let hmac = match crate::md::hmac_sha1(inp, key) {
            Ok(hmac) => hmac,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(hmac, HMAC_EXP);
    }

    #[test]
    fn test_md_hmac_sha224() {
        let inp = vec![0x41u8; 16];
        let key = vec![0x0u8; SHA224_DIGESTSIZE];
        const HMAC_EXP: [u8; SHA224_DIGESTSIZE] = [
            0x5d, 0x8c, 0x6c, 0x1f, 0xf2, 0x97, 0xbf, 0x59, 0x3f, 0x59, 0x1c, 0xf3, 0x4d, 0x3c,
            0x96, 0x36, 0xde, 0x33, 0x11, 0x5f, 0xb1, 0x3e, 0xa5, 0x75, 0x8c, 0xfc, 0xdc, 0x6,
        ];

        let hmac = match crate::md::hmac_sha224(inp, key) {
            Ok(hmac) => hmac,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(hmac, HMAC_EXP);
    }

    #[test]
    fn test_md_hmac_sha256() {
        let inp = vec![0x41u8; 16];
        let key = vec![0x0u8; SHA256_DIGESTSIZE];
        const HMAC_EXP: [u8; SHA256_DIGESTSIZE] = [
            0x4a, 0x81, 0xd6, 0x13, 0xb0, 0xe, 0x91, 0x9e, 0x8a, 0xd9, 0x63, 0x78, 0x88, 0xe6,
            0xa4, 0xfe, 0x8, 0x22, 0x4a, 0xb6, 0x48, 0x4b, 0xa, 0x37, 0x47, 0xa6, 0xa6, 0x62, 0xb6,
            0xa2, 0x99, 0xd,
        ];

        let hmac = match crate::md::hmac_sha256(inp, key) {
            Ok(hmac) => hmac,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(hmac, HMAC_EXP);
    }

    #[test]
    fn test_md_hmac_sha384() {
        let inp = vec![0x41u8; 16];
        let key = vec![0x0u8; SHA384_DIGESTSIZE];
        const HMAC_EXP: [u8; SHA384_DIGESTSIZE] = [
            0x1b, 0xcc, 0x5, 0x6f, 0x74, 0xc9, 0x34, 0xce, 0x5f, 0xe, 0xc4, 0xf5, 0x45, 0x3d, 0x1c,
            0xef, 0x7c, 0x1b, 0x8d, 0xae, 0xa7, 0x6d, 0xe7, 0xc7, 0x9e, 0x7e, 0xe, 0x68, 0x4e,
            0x95, 0x6d, 0xd8, 0x52, 0x11, 0x20, 0xd, 0x99, 0x93, 0x63, 0x89, 0x4f, 0xfd, 0x37, 0xc,
            0xdd, 0x27, 0x75, 0xc8,
        ];

        let hmac = match crate::md::hmac_sha384(inp, key) {
            Ok(hmac) => hmac,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(hmac, HMAC_EXP);
    }

    #[test]
    fn test_md_hmac_sha512() {
        let inp = vec![0x41u8; 16];
        let key = vec![0x0u8; SHA512_DIGESTSIZE];
        const HMAC_EXP: [u8; SHA512_DIGESTSIZE] = [
            0x44, 0xdb, 0xf1, 0xae, 0x7d, 0xcd, 0xc0, 0x5f, 0xa6, 0x9b, 0x30, 0x44, 0x99, 0xfa,
            0x19, 0x82, 0x40, 0xb, 0x94, 0xc0, 0xe9, 0x9, 0xcb, 0xc5, 0xf5, 0x74, 0x66, 0x84, 0x45,
            0x5b, 0x31, 0xf8, 0x8e, 0x94, 0x14, 0x8c, 0xe2, 0xa4, 0x7, 0xa7, 0x58, 0xd2, 0x14,
            0x11, 0x85, 0x8b, 0xa4, 0x50, 0x4c, 0xaa, 0x2e, 0xa1, 0x70, 0xa3, 0x1b, 0xec, 0x87,
            0xab, 0xb6, 0x54, 0xf4, 0xe9, 0xd, 0x48,
        ];

        let hmac = match crate::md::hmac_sha512(inp, key) {
            Ok(hmac) => hmac,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(hmac, HMAC_EXP);
    }
}
