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
    use crate::skcipher::{
        KcapiSKCipher, AES128_KEYSIZE, AES192_KEYSIZE, AES256_KEYSIZE, AES_BLOCKSIZE,
    };

    #[test]
    fn test_enc_aes128_cbc() {
        let pt = vec![0x41u8; AES_BLOCKSIZE];
        let key = vec![0u8; AES128_KEYSIZE];
        let iv = [0u8; AES_BLOCKSIZE];

        const CT_EXP: [u8; AES_BLOCKSIZE] = [
            0xb4, 0x9c, 0xbf, 0x19, 0xd3, 0x57, 0xe6, 0xe1, 0xf6, 0x84, 0x5c, 0x30, 0xfd, 0x5b,
            0x63, 0xe3,
        ];

        let ct = match crate::skcipher::enc_aes_cbc(key, pt, iv) {
            Ok(ct) => ct,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(ct, CT_EXP);
    }

    #[test]
    fn test_dec_aes128_cbc() {
        let ct = vec![
            0xb4, 0x9c, 0xbf, 0x19, 0xd3, 0x57, 0xe6, 0xe1, 0xf6, 0x84, 0x5c, 0x30, 0xfd, 0x5b,
            0x63, 0xe3,
        ];
        let key = vec![0u8; AES128_KEYSIZE];
        let iv = [0u8; AES_BLOCKSIZE];

        const PT_EXP: [u8; AES_BLOCKSIZE] = [0x41u8; AES_BLOCKSIZE];

        let pt = match crate::skcipher::dec_aes_cbc(key, ct, iv) {
            Ok(pt) => pt,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(pt, PT_EXP);
    }

    #[test]
    fn test_enc_aes192_cbc() {
        let pt = vec![0x41u8; AES_BLOCKSIZE];
        let key = vec![0u8; AES192_KEYSIZE];
        let iv = [0u8; AES_BLOCKSIZE];

        const CT_EXP: [u8; AES_BLOCKSIZE] = [
            0x48, 0x5e, 0x40, 0x47, 0x1, 0xda, 0x67, 0x88, 0x74, 0x72, 0x4d, 0x32, 0xda, 0x51,
            0xd1, 0x24,
        ];

        let ct = match crate::skcipher::enc_aes_cbc(key, pt, iv) {
            Ok(ct) => ct,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(ct, CT_EXP);
    }

    #[test]
    fn test_dec_aes192_cbc() {
        let ct = vec![
            0x48, 0x5e, 0x40, 0x47, 0x1, 0xda, 0x67, 0x88, 0x74, 0x72, 0x4d, 0x32, 0xda, 0x51,
            0xd1, 0x24,
        ];
        let key = vec![0u8; AES192_KEYSIZE];
        let iv = [0u8; AES_BLOCKSIZE];

        const PT_EXP: [u8; AES_BLOCKSIZE] = [0x41u8; AES_BLOCKSIZE];

        let pt = match crate::skcipher::dec_aes_cbc(key, ct, iv) {
            Ok(pt) => pt,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(pt, PT_EXP);
    }

    #[test]
    fn test_enc_aes256_cbc() {
        let pt = vec![0x41u8; AES_BLOCKSIZE];
        let key = vec![0u8; AES256_KEYSIZE];
        let iv = [0u8; AES_BLOCKSIZE];

        const CT_EXP: [u8; AES_BLOCKSIZE] = [
            0x7e, 0xe, 0x75, 0x77, 0xef, 0x9c, 0x30, 0xa6, 0xbf, 0xb, 0x25, 0xe0, 0x62, 0x1e, 0x82,
            0x7e,
        ];

        let ct = match crate::skcipher::enc_aes_cbc(key, pt, iv) {
            Ok(ct) => ct,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(ct, CT_EXP);
    }

    #[test]
    fn test_dec_aes256_cbc() {
        let ct = vec![
            0x7e, 0xe, 0x75, 0x77, 0xef, 0x9c, 0x30, 0xa6, 0xbf, 0xb, 0x25, 0xe0, 0x62, 0x1e, 0x82,
            0x7e,
        ];
        let key = vec![0u8; AES256_KEYSIZE];
        let iv = [0u8; AES_BLOCKSIZE];

        const PT_EXP: [u8; AES_BLOCKSIZE] = [0x41u8; AES_BLOCKSIZE];

        let pt = match crate::skcipher::dec_aes_cbc(key, ct, iv) {
            Ok(pt) => pt,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(pt, PT_EXP);
    }

    #[test]
    fn test_enc_aes128_ctr() {
        let pt = vec![0x41u8; AES_BLOCKSIZE * 2];
        let key = vec![0u8; AES128_KEYSIZE];
        let ctr = [0u8; AES_BLOCKSIZE];

        const CT_EXP: [u8; AES_BLOCKSIZE * 2] = [
            0x27, 0xa8, 0xa, 0x95, 0xae, 0xcb, 0x6d, 0x7a, 0xc9, 0xd, 0xbb, 0x18, 0x8b, 0x75, 0x6a,
            0x6f, 0x19, 0xa3, 0xbd, 0x8f, 0xbb, 0x3f, 0x71, 0x20, 0x77, 0x3e, 0x5c, 0x16, 0xe5,
            0xa6, 0x4, 0x1b,
        ];

        let ct = match crate::skcipher::enc_aes_ctr(key, pt, ctr) {
            Ok(ct) => ct,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(ct, CT_EXP);
    }

    #[test]
    fn test_dec_aes128_ctr() {
        let ct = vec![
            0x27, 0xa8, 0xa, 0x95, 0xae, 0xcb, 0x6d, 0x7a, 0xc9, 0xd, 0xbb, 0x18, 0x8b, 0x75, 0x6a,
            0x6f, 0x19, 0xa3, 0xbd, 0x8f, 0xbb, 0x3f, 0x71, 0x20, 0x77, 0x3e, 0x5c, 0x16, 0xe5,
            0xa6, 0x4, 0x1b,
        ];
        let key = vec![0u8; AES128_KEYSIZE];
        let ctr = [0u8; AES_BLOCKSIZE];

        const PT_EXP: [u8; AES_BLOCKSIZE * 2] = [0x41u8; AES_BLOCKSIZE * 2];

        let pt = match crate::skcipher::dec_aes_ctr(key, ct, ctr) {
            Ok(pt) => pt,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(pt, PT_EXP);
    }

    #[test]
    fn test_enc_aes192_ctr() {
        let pt = vec![0x41u8; AES_BLOCKSIZE * 2];
        let key = vec![0u8; AES192_KEYSIZE];
        let ctr = [0u8; AES_BLOCKSIZE];

        const CT_EXP: [u8; AES_BLOCKSIZE * 2] = [
            0xeb, 0xa1, 0x28, 0xd3, 0xed, 0xfe, 0x13, 0xe2, 0xa9, 0xb5, 0xe8, 0x2f, 0x88, 0x71,
            0x4a, 0x96, 0x8c, 0x72, 0xf3, 0xcb, 0x86, 0x32, 0xb6, 0xa, 0xe1, 0x4f, 0x90, 0xb2,
            0x53, 0x16, 0x65, 0x74,
        ];

        let ct = match crate::skcipher::enc_aes_ctr(key, pt, ctr) {
            Ok(ct) => ct,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(ct, CT_EXP);
    }

    #[test]
    fn test_dec_aes192_ctr() {
        let ct = vec![
            0xeb, 0xa1, 0x28, 0xd3, 0xed, 0xfe, 0x13, 0xe2, 0xa9, 0xb5, 0xe8, 0x2f, 0x88, 0x71,
            0x4a, 0x96, 0x8c, 0x72, 0xf3, 0xcb, 0x86, 0x32, 0xb6, 0xa, 0xe1, 0x4f, 0x90, 0xb2,
            0x53, 0x16, 0x65, 0x74,
        ];
        let key = vec![0u8; AES192_KEYSIZE];
        let ctr = [0u8; AES_BLOCKSIZE];

        const PT_EXP: [u8; AES_BLOCKSIZE * 2] = [0x41u8; AES_BLOCKSIZE * 2];

        let pt = match crate::skcipher::dec_aes_ctr(key, ct, ctr) {
            Ok(pt) => pt,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(pt, PT_EXP);
    }

    #[test]
    fn test_enc_aes256_ctr() {
        let pt = vec![0x41u8; AES_BLOCKSIZE * 2];
        let key = vec![0u8; AES256_KEYSIZE];
        let ctr = [0u8; AES_BLOCKSIZE];

        const CT_EXP: [u8; AES_BLOCKSIZE * 2] = [
            0x9d, 0xd4, 0x81, 0x39, 0xe3, 0x1, 0xc8, 0xc8, 0xec, 0x9, 0xe3, 0x55, 0xd3, 0xc5, 0x61,
            0xc6, 0x12, 0x4e, 0xcb, 0xba, 0x86, 0x4, 0x77, 0xf8, 0xe8, 0x22, 0xf5, 0xb0, 0x85,
            0x8a, 0x32, 0xca,
        ];

        let ct = match crate::skcipher::enc_aes_ctr(key, pt, ctr) {
            Ok(ct) => ct,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(ct, CT_EXP);
    }

    #[test]
    fn test_dec_aes256_ctr() {
        let ct = vec![
            0x9d, 0xd4, 0x81, 0x39, 0xe3, 0x1, 0xc8, 0xc8, 0xec, 0x9, 0xe3, 0x55, 0xd3, 0xc5, 0x61,
            0xc6, 0x12, 0x4e, 0xcb, 0xba, 0x86, 0x4, 0x77, 0xf8, 0xe8, 0x22, 0xf5, 0xb0, 0x85,
            0x8a, 0x32, 0xca,
        ];
        let key = vec![0u8; AES256_KEYSIZE];
        let ctr = [0u8; AES_BLOCKSIZE];

        const PT_EXP: [u8; AES_BLOCKSIZE * 2] = [0x41u8; AES_BLOCKSIZE * 2];

        let pt = match crate::skcipher::dec_aes_ctr(key, ct, ctr) {
            Ok(pt) => pt,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(pt, PT_EXP);
    }

    #[test]
    fn test_aes_cbc_invalid_key() {
        let pt = vec![0x41u8; AES_BLOCKSIZE];
        let key = vec![0u8; AES128_KEYSIZE + 1];
        let iv = [0u8; AES_BLOCKSIZE];

        let _ct = match crate::skcipher::enc_aes_cbc(key, pt, iv) {
            Ok(_ct) => {
                panic!(
                    "(BUG) AES-CBC Encryption passed with invalid keysize of {}",
                    AES128_KEYSIZE + 1
                );
            }
            Err(_e) => {}
        };
    }

    #[test]
    fn test_aes_ctr_invalid_key() {
        let pt = vec![0x41u8; AES_BLOCKSIZE];
        let key = vec![0u8; AES128_KEYSIZE + 1];
        let ctr = [0u8; AES_BLOCKSIZE];

        let _ct = match crate::skcipher::enc_aes_ctr(key, pt, ctr) {
            Ok(_ct) => {
                panic!(
                    "(BUG) AES-CTR Encryption passed with invalid keysize of {}",
                    AES128_KEYSIZE + 1
                );
            }
            Err(_e) => {}
        };
    }

    #[test]
    fn test_enc_aes_cbc_invalid_pt() {
        let pt = vec![0x41u8; AES_BLOCKSIZE + 1];
        let key = vec![0u8; AES128_KEYSIZE];
        let iv = [0u8; AES_BLOCKSIZE];

        let _ct = match crate::skcipher::enc_aes_cbc(key, pt, iv) {
            Ok(_ct) => {
                panic!(
                    "(BUG) AES CBC Encryption passed with invalid blocksize of {}",
                    AES128_KEYSIZE + 1
                );
            }
            Err(_e) => {}
        };
    }

    #[test]
    fn test_dec_aes_cbc_invalid_ct() {
        let ct = vec![0x41u8; AES_BLOCKSIZE + 1];
        let key = vec![0u8; AES128_KEYSIZE];
        let iv = [0u8; AES_BLOCKSIZE];

        let _pt = match crate::skcipher::dec_aes_cbc(key, ct, iv) {
            Ok(_pt) => {
                panic!(
                    "(BUG) AES CBC Decryption passed with invalid blocksize of {}",
                    AES_BLOCKSIZE + 1
                );
            }
            Err(_e) => {}
        };
    }

    #[test]
    fn test_enc_aes_ctr_invalid_pt() {
        let pt = vec![0x41u8; AES_BLOCKSIZE + 1];
        let key = vec![0u8; AES128_KEYSIZE];
        let ctr = [0u8; AES_BLOCKSIZE];

        let _ct = match crate::skcipher::enc_aes_ctr(key, pt, ctr) {
            Ok(_ct) => {
                panic!(
                    "(BUG) AES CTR Encryption passed with invalid blocksize of {}",
                    AES128_KEYSIZE + 1
                );
            }
            Err(_e) => {}
        };
    }

    #[test]
    fn test_dec_aes_ctr_invalid_ct() {
        let ct = vec![0x41u8; AES_BLOCKSIZE + 1];
        let key = vec![0u8; AES128_KEYSIZE];
        let ctr = [0u8; AES_BLOCKSIZE];

        let _pt = match crate::skcipher::dec_aes_ctr(key, ct, ctr) {
            Ok(_pt) => {
                panic!(
                    "(BUG) AES CTR Decryption passed with invalid blocksize of {}",
                    AES_BLOCKSIZE + 1
                );
            }
            Err(_e) => {}
        };
    }

    const XTS_AES128_KEYSIZE: usize = 32;
    const XTS_AES256_KEYSIZE: usize = 64;

    #[test]
    fn test_alg_encrypt() {
        let pt = vec![0x41u8; AES_BLOCKSIZE];
        let key = vec![0u8; XTS_AES128_KEYSIZE];
        let iv = vec![0u8; AES_BLOCKSIZE];

        const CT_EXP: [u8; AES_BLOCKSIZE] = [
            0x7e, 0xce, 0x9a, 0xad, 0x4c, 0x56, 0xc1, 0x9, 0xca, 0xfa, 0xeb, 0xb8, 0x1d, 0x31,
            0x8f, 0x65,
        ];

        let ct = match crate::skcipher::encrypt("xts(aes)", key, pt, iv) {
            Ok(ct) => ct,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(ct, CT_EXP);
    }

    #[test]
    fn test_alg_decrypt() {
        let ct = vec![
            0x7e, 0xce, 0x9a, 0xad, 0x4c, 0x56, 0xc1, 0x9, 0xca, 0xfa, 0xeb, 0xb8, 0x1d, 0x31,
            0x8f, 0x65,
        ];
        let key = vec![0u8; XTS_AES128_KEYSIZE];
        let iv = vec![0u8; AES_BLOCKSIZE];

        const PT_EXP: [u8; AES_BLOCKSIZE] = [0x41u8; AES_BLOCKSIZE];

        let pt = match crate::skcipher::decrypt("xts(aes)", key, ct, iv) {
            Ok(pt) => pt,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(pt, PT_EXP);
    }

    #[test]
    fn test_alg_encrypt_xts256() {
        let pt = vec![0x41u8; AES_BLOCKSIZE];
        let key = vec![0u8; XTS_AES256_KEYSIZE];
        let iv = vec![0u8; AES_BLOCKSIZE];

        const CT_EXP: [u8; AES_BLOCKSIZE] = [
            0x3d, 0x12, 0xff, 0x26, 0xa5, 0xa2, 0x5b, 0xbf, 0x6e, 0x93, 0x99, 0xf0, 0xcd, 0xf3,
            0xea, 0x52,
        ];

        let ct = match crate::skcipher::encrypt("xts(aes)", key, pt, iv) {
            Ok(ct) => ct,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(ct, CT_EXP);
    }

    #[test]
    fn test_alg_decrypt_xts256() {
        let ct = vec![
            0x3d, 0x12, 0xff, 0x26, 0xa5, 0xa2, 0x5b, 0xbf, 0x6e, 0x93, 0x99, 0xf0, 0xcd, 0xf3,
            0xea, 0x52,
        ];
        let key = vec![0u8; XTS_AES256_KEYSIZE];
        let iv = vec![0u8; AES_BLOCKSIZE];

        const PT_EXP: [u8; AES_BLOCKSIZE] = [0x41u8; AES_BLOCKSIZE];

        let pt = match crate::skcipher::decrypt("xts(aes)", key, ct, iv) {
            Ok(pt) => pt,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(pt, PT_EXP);
    }

    #[test]
    fn test_encrypt_aio() {
        let inp = vec![vec![0x41u8; 16]; 16];
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];

        let out_exp = vec![
            vec![
                0xb4, 0x9c, 0xbf, 0x19, 0xd3, 0x57, 0xe6, 0xe1, 0xf6, 0x84, 0x5c, 0x30, 0xfd, 0x5b,
                0x63, 0xe3,
            ],
            vec![
                0x6f, 0x9f, 0x76, 0x9a, 0x9c, 0xaa, 0x3, 0x13, 0xba, 0x17, 0x8c, 0x1c, 0x2e, 0xf,
                0x60, 0x76,
            ],
            vec![
                0xa, 0x31, 0x16, 0x35, 0xb5, 0x3f, 0x4, 0x68, 0xa8, 0xd, 0x3e, 0x6b, 0xdb, 0x4b,
                0xbc, 0x34,
            ],
            vec![
                0x5a, 0xf8, 0x51, 0x49, 0xff, 0xeb, 0xc6, 0x5e, 0x51, 0xcd, 0x69, 0x7b, 0x70, 0x3f,
                0x61, 0xca,
            ],
            vec![
                0x1, 0x65, 0x5a, 0x92, 0xcb, 0x8e, 0x13, 0x2e, 0x24, 0x3d, 0xf, 0x81, 0xa6, 0x22,
                0x6c, 0x11,
            ],
            vec![
                0x6c, 0x35, 0xa, 0xc0, 0x2b, 0xf2, 0x3d, 0x69, 0x66, 0x73, 0x63, 0x1a, 0x8b, 0x89,
                0x2, 0xf1,
            ],
            vec![
                0xc4, 0xc8, 0x84, 0x50, 0x69, 0x14, 0x0, 0xdd, 0xb, 0xa0, 0xbe, 0x3, 0x74, 0xc9,
                0x51, 0xc0,
            ],
            vec![
                0xb7, 0xa8, 0xd8, 0xe, 0x2, 0x39, 0xa, 0x49, 0x11, 0x95, 0xb3, 0x3b, 0xc2, 0x32,
                0xd8, 0xd3,
            ],
            vec![
                0xf, 0x16, 0xa1, 0xfd, 0xc4, 0x30, 0xa7, 0x54, 0x21, 0xcf, 0xea, 0x94, 0xba, 0x93,
                0x57, 0x44,
            ],
            vec![
                0x31, 0x81, 0x3e, 0xde, 0xa2, 0x85, 0xa, 0x88, 0x3d, 0x25, 0xb7, 0xdc, 0x94, 0x7d,
                0xe9, 0xd5,
            ],
            vec![
                0xfb, 0x99, 0x80, 0x55, 0xb9, 0xc3, 0x85, 0x1, 0x29, 0x3c, 0x3b, 0xc0, 0x65, 0x36,
                0x64, 0x20,
            ],
            vec![
                0x17, 0xed, 0xfd, 0xf9, 0x1d, 0xb9, 0x6d, 0xea, 0x99, 0x91, 0x8b, 0x1d, 0xb3, 0xa6,
                0x2d, 0x2f,
            ],
            vec![
                0x41, 0xd2, 0xd6, 0x42, 0x60, 0xd, 0x70, 0xdb, 0x74, 0xbd, 0xd0, 0xed, 0xd5, 0xca,
                0x9c, 0xc4,
            ],
            vec![
                0xd8, 0x20, 0x54, 0xd1, 0xa5, 0xcd, 0x15, 0xf8, 0xe0, 0x13, 0x93, 0x5f, 0x2a, 0xe8,
                0xc0, 0xd6,
            ],
            vec![
                0x85, 0x8b, 0xeb, 0x72, 0x47, 0xdb, 0xf, 0x66, 0x2f, 0xf2, 0x75, 0xc5, 0x8f, 0x61,
                0x1c, 0xa8,
            ],
            vec![
                0x6, 0x68, 0xd, 0x14, 0x18, 0x76, 0x17, 0xc5, 0x48, 0xd3, 0xb3, 0xb, 0x12, 0x21,
                0x44, 0xec,
            ],
        ];

        let out = match crate::skcipher::encrypt_aio("cbc(aes)", key, inp, iv) {
            Ok(ct) => ct,
            Err(e) => panic!("{}", e),
        };
        assert_eq!(out, out_exp);
    }

    #[test]
    fn test_decrypt_aio() {
        let inp = vec![
            vec![
                0xb4, 0x9c, 0xbf, 0x19, 0xd3, 0x57, 0xe6, 0xe1, 0xf6, 0x84, 0x5c, 0x30, 0xfd, 0x5b,
                0x63, 0xe3,
            ],
            vec![
                0x6f, 0x9f, 0x76, 0x9a, 0x9c, 0xaa, 0x3, 0x13, 0xba, 0x17, 0x8c, 0x1c, 0x2e, 0xf,
                0x60, 0x76,
            ],
            vec![
                0xa, 0x31, 0x16, 0x35, 0xb5, 0x3f, 0x4, 0x68, 0xa8, 0xd, 0x3e, 0x6b, 0xdb, 0x4b,
                0xbc, 0x34,
            ],
            vec![
                0x5a, 0xf8, 0x51, 0x49, 0xff, 0xeb, 0xc6, 0x5e, 0x51, 0xcd, 0x69, 0x7b, 0x70, 0x3f,
                0x61, 0xca,
            ],
            vec![
                0x1, 0x65, 0x5a, 0x92, 0xcb, 0x8e, 0x13, 0x2e, 0x24, 0x3d, 0xf, 0x81, 0xa6, 0x22,
                0x6c, 0x11,
            ],
            vec![
                0x6c, 0x35, 0xa, 0xc0, 0x2b, 0xf2, 0x3d, 0x69, 0x66, 0x73, 0x63, 0x1a, 0x8b, 0x89,
                0x2, 0xf1,
            ],
            vec![
                0xc4, 0xc8, 0x84, 0x50, 0x69, 0x14, 0x0, 0xdd, 0xb, 0xa0, 0xbe, 0x3, 0x74, 0xc9,
                0x51, 0xc0,
            ],
            vec![
                0xb7, 0xa8, 0xd8, 0xe, 0x2, 0x39, 0xa, 0x49, 0x11, 0x95, 0xb3, 0x3b, 0xc2, 0x32,
                0xd8, 0xd3,
            ],
            vec![
                0xf, 0x16, 0xa1, 0xfd, 0xc4, 0x30, 0xa7, 0x54, 0x21, 0xcf, 0xea, 0x94, 0xba, 0x93,
                0x57, 0x44,
            ],
            vec![
                0x31, 0x81, 0x3e, 0xde, 0xa2, 0x85, 0xa, 0x88, 0x3d, 0x25, 0xb7, 0xdc, 0x94, 0x7d,
                0xe9, 0xd5,
            ],
            vec![
                0xfb, 0x99, 0x80, 0x55, 0xb9, 0xc3, 0x85, 0x1, 0x29, 0x3c, 0x3b, 0xc0, 0x65, 0x36,
                0x64, 0x20,
            ],
            vec![
                0x17, 0xed, 0xfd, 0xf9, 0x1d, 0xb9, 0x6d, 0xea, 0x99, 0x91, 0x8b, 0x1d, 0xb3, 0xa6,
                0x2d, 0x2f,
            ],
            vec![
                0x41, 0xd2, 0xd6, 0x42, 0x60, 0xd, 0x70, 0xdb, 0x74, 0xbd, 0xd0, 0xed, 0xd5, 0xca,
                0x9c, 0xc4,
            ],
            vec![
                0xd8, 0x20, 0x54, 0xd1, 0xa5, 0xcd, 0x15, 0xf8, 0xe0, 0x13, 0x93, 0x5f, 0x2a, 0xe8,
                0xc0, 0xd6,
            ],
            vec![
                0x85, 0x8b, 0xeb, 0x72, 0x47, 0xdb, 0xf, 0x66, 0x2f, 0xf2, 0x75, 0xc5, 0x8f, 0x61,
                0x1c, 0xa8,
            ],
            vec![
                0x6, 0x68, 0xd, 0x14, 0x18, 0x76, 0x17, 0xc5, 0x48, 0xd3, 0xb3, 0xb, 0x12, 0x21,
                0x44, 0xec,
            ],
        ];
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];

        let out_exp = vec![vec![0x41u8; 16]; 16];

        let out = match crate::skcipher::decrypt_aio("cbc(aes)", key, inp, iv) {
            Ok(pt) => pt,
            Err(e) => panic!("{}", e),
        };
        assert_eq!(out, out_exp);
    }

    #[test]
    fn test_stream_enc() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];
        let inp = vec![vec![0x41u8; 16]; 1];
        let loops = 15;

        let out_exp = vec![
            vec![
                0x27, 0xa8, 0xa, 0x95, 0xae, 0xcb, 0x6d, 0x7a, 0xc9, 0xd, 0xbb, 0x18, 0x8b, 0x75,
                0x6a, 0x6f,
            ],
            vec![
                0x19, 0xa3, 0xbd, 0x8f, 0xbb, 0x3f, 0x71, 0x20, 0x77, 0x3e, 0x5c, 0x16, 0xe5, 0xa6,
                0x4, 0x1b,
            ],
            vec![
                0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
                0xbf, 0x39,
            ],
            vec![
                0xb6, 0xd4, 0xeb, 0xea, 0x8, 0xa, 0x18, 0x62, 0xb6, 0xbc, 0xc8, 0xbe, 0xd5, 0xca,
                0x80, 0xa1,
            ],
            vec![
                0x61, 0x43, 0x50, 0x60, 0xf, 0x32, 0xd5, 0x9b, 0x61, 0xc8, 0xf7, 0xed, 0x91, 0xd2,
                0xea, 0xa1,
            ],
            vec![
                0x88, 0xc, 0xe3, 0x58, 0x50, 0xcf, 0x68, 0x3c, 0x3a, 0x3f, 0xfd, 0xfd, 0x88, 0x82,
                0xc9, 0xb3,
            ],
            vec![
                0xcb, 0x9f, 0x3c, 0xc4, 0xe9, 0xaf, 0x74, 0x20, 0x2e, 0x30, 0x65, 0xe8, 0x94, 0x66,
                0x43, 0xd0,
            ],
            vec![
                0xd4, 0xf9, 0xc, 0x5a, 0xd7, 0x87, 0xd1, 0xbe, 0x6e, 0x6c, 0xa2, 0x4a, 0xb3, 0xad,
                0xc8, 0xa1,
            ],
            vec![
                0x43, 0x12, 0x39, 0x2f, 0x53, 0x24, 0x45, 0xb1, 0x9b, 0xf8, 0x4d, 0x9, 0xe2, 0x42,
                0x60, 0x9f,
            ],
            vec![
                0x72, 0x4, 0xa7, 0xf1, 0x7, 0x5f, 0x3d, 0xdf, 0x2d, 0x2a, 0x3b, 0xbf, 0x9c, 0xa9,
                0x7e, 0x1,
            ],
            vec![
                0x9f, 0xf2, 0xbb, 0x26, 0xd5, 0xb9, 0xbc, 0xce, 0x14, 0xe9, 0xcc, 0x8a, 0x9b, 0xdc,
                0x29, 0xb3,
            ],
            vec![
                0x52, 0x3d, 0x88, 0x89, 0x75, 0x61, 0x46, 0x3f, 0x3d, 0xb3, 0xcb, 0xf3, 0x28, 0x2a,
                0x4c, 0xb1,
            ],
            vec![
                0x1c, 0x50, 0x4, 0x6a, 0x19, 0xed, 0x11, 0xeb, 0x6f, 0xf2, 0xe0, 0xd4, 0xf7, 0x5a,
                0xc6, 0xa4,
            ],
            vec![
                0x87, 0x1b, 0x2c, 0x94, 0x96, 0xb6, 0xe9, 0x1, 0x24, 0x94, 0xe0, 0x3e, 0xb5, 0x23,
                0x32, 0x49,
            ],
            vec![
                0x21, 0x43, 0x8, 0x2c, 0xf7, 0x7e, 0xe5, 0xf8, 0x5a, 0xaf, 0x79, 0x3e, 0xe2, 0x42,
                0x4d, 0xd4,
            ],
        ];

        let mut cipher = match KcapiSKCipher::new_enc_stream("ctr(aes)", key, iv, inp.clone()) {
            Ok(handle) => handle,
            Err(e) => panic!("{}", e),
        };

        let mut i = 0;
        while i < loops {
            if i == (loops - 1) {
                match cipher.stream_update_last(inp.clone()) {
                    Ok(()) => {}
                    Err(e) => panic!("{}", e),
                }
            } else {
                match cipher.stream_update(inp.clone()) {
                    Ok(()) => {}
                    Err(e) => panic!("{}", e),
                }
            }

            let out = match cipher.stream_op() {
                Ok(out) => out,
                Err(e) => panic!("{}", e),
            };
            for o in out {
                assert_eq!(o, out_exp[i]);
                i += 1;
            }
        }
    }

    #[test]
    fn test_stream_dec() {
        let key = vec![0u8; 16];
        let iv = vec![0u8; 16];

        let inp = vec![
            vec![
                0x27, 0xa8, 0xa, 0x95, 0xae, 0xcb, 0x6d, 0x7a, 0xc9, 0xd, 0xbb, 0x18, 0x8b, 0x75,
                0x6a, 0x6f,
            ],
            vec![
                0x19, 0xa3, 0xbd, 0x8f, 0xbb, 0x3f, 0x71, 0x20, 0x77, 0x3e, 0x5c, 0x16, 0xe5, 0xa6,
                0x4, 0x1b,
            ],
            vec![
                0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
                0xbf, 0x39,
            ],
            vec![
                0xb6, 0xd4, 0xeb, 0xea, 0x8, 0xa, 0x18, 0x62, 0xb6, 0xbc, 0xc8, 0xbe, 0xd5, 0xca,
                0x80, 0xa1,
            ],
            vec![
                0x61, 0x43, 0x50, 0x60, 0xf, 0x32, 0xd5, 0x9b, 0x61, 0xc8, 0xf7, 0xed, 0x91, 0xd2,
                0xea, 0xa1,
            ],
            vec![
                0x88, 0xc, 0xe3, 0x58, 0x50, 0xcf, 0x68, 0x3c, 0x3a, 0x3f, 0xfd, 0xfd, 0x88, 0x82,
                0xc9, 0xb3,
            ],
            vec![
                0xcb, 0x9f, 0x3c, 0xc4, 0xe9, 0xaf, 0x74, 0x20, 0x2e, 0x30, 0x65, 0xe8, 0x94, 0x66,
                0x43, 0xd0,
            ],
            vec![
                0xd4, 0xf9, 0xc, 0x5a, 0xd7, 0x87, 0xd1, 0xbe, 0x6e, 0x6c, 0xa2, 0x4a, 0xb3, 0xad,
                0xc8, 0xa1,
            ],
            vec![
                0x43, 0x12, 0x39, 0x2f, 0x53, 0x24, 0x45, 0xb1, 0x9b, 0xf8, 0x4d, 0x9, 0xe2, 0x42,
                0x60, 0x9f,
            ],
            vec![
                0x72, 0x4, 0xa7, 0xf1, 0x7, 0x5f, 0x3d, 0xdf, 0x2d, 0x2a, 0x3b, 0xbf, 0x9c, 0xa9,
                0x7e, 0x1,
            ],
            vec![
                0x9f, 0xf2, 0xbb, 0x26, 0xd5, 0xb9, 0xbc, 0xce, 0x14, 0xe9, 0xcc, 0x8a, 0x9b, 0xdc,
                0x29, 0xb3,
            ],
            vec![
                0x52, 0x3d, 0x88, 0x89, 0x75, 0x61, 0x46, 0x3f, 0x3d, 0xb3, 0xcb, 0xf3, 0x28, 0x2a,
                0x4c, 0xb1,
            ],
            vec![
                0x1c, 0x50, 0x4, 0x6a, 0x19, 0xed, 0x11, 0xeb, 0x6f, 0xf2, 0xe0, 0xd4, 0xf7, 0x5a,
                0xc6, 0xa4,
            ],
            vec![
                0x87, 0x1b, 0x2c, 0x94, 0x96, 0xb6, 0xe9, 0x1, 0x24, 0x94, 0xe0, 0x3e, 0xb5, 0x23,
                0x32, 0x49,
            ],
            vec![
                0x21, 0x43, 0x8, 0x2c, 0xf7, 0x7e, 0xe5, 0xf8, 0x5a, 0xaf, 0x79, 0x3e, 0xe2, 0x42,
                0x4d, 0xd4,
            ],
            vec![
                0xe6, 0x7e, 0xcc, 0x45, 0x76, 0xa1, 0xd0, 0x1e, 0xfd, 0xa4, 0x96, 0xe7, 0x6c, 0xcc,
                0xea, 0x4b,
            ],
        ];
        let out_exp = vec![0x41u8; 16];

        for j in 0..inp.len() {
            let mut cipher = match KcapiSKCipher::new_dec_stream(
                "ctr(aes)",
                key.clone(),
                iv.clone(),
                vec![inp[j].clone()],
            ) {
                Ok(handle) => handle,
                Err(e) => panic!("{}", e),
            };

            for i in 1..(j + 1) {
                if i == j {
                    match cipher.stream_update_last(vec![inp[j].clone()]) {
                        Ok(()) => {}
                        Err(e) => panic!("{}", e),
                    }
                } else {
                    match cipher.stream_update(vec![inp[j].clone()]) {
                        Ok(()) => {}
                        Err(e) => panic!("{}", e),
                    }
                }
                let mut out = match cipher.stream_op() {
                    Ok(out) => out,
                    Err(e) => panic!("{}", e),
                };
                if i == j {
                    let o = out.pop().expect("(BUG) Empty output from stream_op");
                    assert_eq!(o, out_exp);
                }
            }
        }
    }
}
