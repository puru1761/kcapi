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
    use crate::{
        skcipher::{AES128_KEYSIZE, AES192_KEYSIZE, AES256_KEYSIZE, AES_BLOCKSIZE},
        KCAPI_ACCESS_HEURISTIC,
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

        let ct = match crate::skcipher::encrypt("xts(aes)", key, pt, iv, KCAPI_ACCESS_HEURISTIC) {
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

        let pt = match crate::skcipher::decrypt("xts(aes)", key, ct, iv, KCAPI_ACCESS_HEURISTIC)
        {
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

        let ct = match crate::skcipher::encrypt("xts(aes)", key, pt, iv, KCAPI_ACCESS_HEURISTIC) {
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

        let pt = match crate::skcipher::decrypt("xts(aes)", key, ct, iv, KCAPI_ACCESS_HEURISTIC)
        {
            Ok(pt) => pt,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(pt, PT_EXP);
    }
}
