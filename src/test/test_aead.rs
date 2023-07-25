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
    use crate::aead::KcapiAEADData;

    #[test]
    fn test_encrypt() {
        let pt = vec![
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41,
        ];
        let assocdata = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let taglen: usize = 16;

        let key = vec![0u8; 16];
        let iv = vec![0u8; 12];
        let data = KcapiAEADData::new_enc(pt, assocdata, taglen);

        let mut out_exp = KcapiAEADData::new();
        out_exp.set_data(vec![
            0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
            0xbf, 0x39, 0xb6, 0xd4, 0xeb,
        ]);
        out_exp.set_tag(vec![
            0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
            0x70,
        ]);
        out_exp.set_assocdata(vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);

        let out = match crate::aead::encrypt("gcm(aes)", data, key, iv) {
            Ok(ct) => ct,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(out.get_data(), out_exp.get_data());
        assert_eq!(out.get_tag(), out_exp.get_tag());
    }

    #[test]
    fn test_decrypt() {
        let ct = vec![
            0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
            0xbf, 0x39, 0xb6, 0xd4, 0xeb,
        ];
        let assocdata = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let tag = vec![
            0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
            0x70,
        ];

        let key = vec![0u8; 16];
        let iv = vec![0u8; 12];
        let data = KcapiAEADData::new_dec(ct, assocdata, tag);

        let mut out_exp = KcapiAEADData::new();
        out_exp.set_data(vec![
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41,
        ]);
        out_exp.set_tag(vec![
            0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
            0x70,
        ]);
        out_exp.set_assocdata(vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);

        let out = match crate::aead::decrypt("gcm(aes)", data, key, iv) {
            Ok(ct) => ct,
            Err(e) => {
                panic!("{}", e);
            }
        };
        assert_eq!(out.get_data(), out_exp.get_data());
        assert_eq!(out.get_tag(), out_exp.get_tag());
    }

    #[test]
    fn test_encrypt_fail_small_iv() {
        let pt = vec![
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41,
        ];
        let key = vec![0u8; 16];
        let assocdata = vec![0u8; 16];
        let taglen: usize = 16;
        let iv = vec![0u8; 4];
        let data = KcapiAEADData::new_enc(pt, assocdata, taglen);

        match crate::aead::encrypt("gcm(aes)", data, key, iv) {
            Ok(_output) => panic!("(BUG) cipher operation succeeded with invalid IV size"),
            Err(_e) => {}
        };
    }

    #[test]
    fn test_decrypt_fail_small_iv() {
        let ct = vec![
            0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
            0xbf, 0x39, 0xb6, 0xd4, 0xeb,
        ];
        let tag = vec![
            0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
            0x70,
        ];
        let key = vec![0u8; 16];
        let assocdata = vec![0u8; 16];
        let iv = vec![0u8; 4];
        let data = KcapiAEADData::new_dec(ct, assocdata, tag);

        match crate::aead::decrypt("gcm(aes)", data, key, iv) {
            Ok(_output) => panic!("(BUG) cipher operation succeeded with invalid IV size"),
            Err(_e) => {}
        };
    }

    #[test]
    fn test_encrypt_fail_invalid_taglen() {
        let pt = vec![
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41,
        ];
        let key = vec![0u8; 16];
        let assocdata = vec![0u8; 16];
        let taglen: usize = 17;
        let iv = vec![0u8; 12];
        let data = KcapiAEADData::new_enc(pt, assocdata, taglen);

        match crate::aead::encrypt("gcm(aes)", data, key, iv) {
            Ok(_output) => panic!("(BUG) cipher operation succeeded with invalid tag size"),
            Err(_e) => {}
        };
    }

    #[test]
    fn test_decrypt_fail_invalid_taglen() {
        let ct = vec![
            0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
            0xbf, 0x39, 0xb6, 0xd4, 0xeb,
        ];
        let tag = vec![
            0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
            0x70, 0x01,
        ];
        let key = vec![0u8; 16];
        let assocdata = vec![0u8; 16];
        let iv = vec![0u8; 12];
        let data = KcapiAEADData::new_dec(ct, assocdata, tag);

        match crate::aead::decrypt("gcm(aes)", data, key, iv) {
            Ok(_output) => panic!("(BUG) cipher operation succeeded with invalid tag size"),
            Err(_e) => {}
        };
    }

    #[test]
    fn test_decrypt_fail_invalid_tag() {
        let ct = vec![
            0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
            0xbf, 0x39, 0xb6, 0xd4, 0xeb,
        ];
        let tag = vec![
            0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
            0x71,
        ];
        let key = vec![0u8; 16];
        let assocdata = vec![0u8; 16];
        let iv = vec![0u8; 12];
        let data = KcapiAEADData::new_dec(ct, assocdata, tag);

        match crate::aead::decrypt("gcm(aes)", data, key, iv) {
            Ok(_output) => panic!("(BUG) cipher operation succeeded with invalid tag"),
            Err(e) => {
                assert_eq!(e.code, -libc::EBADMSG);
            }
        };
    }

    #[test]
    fn test_decrypt_fail_invalid_ct() {
        let ct = vec![
            0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
            0xbf, 0x39, 0xb6, 0xd4, 0xec,
        ];
        let tag = vec![
            0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
            0x70,
        ];
        let key = vec![0u8; 16];
        let assocdata = vec![0u8; 16];
        let iv = vec![0u8; 12];
        let data = KcapiAEADData::new_dec(ct, assocdata, tag);

        match crate::aead::decrypt("gcm(aes)", data, key, iv) {
            Ok(_output) => panic!("(BUG) cipher operation succeeded with invalid tag"),
            Err(e) => {
                assert_eq!(e.code, -libc::EBADMSG);
            }
        };
    }

    #[test]
    fn test_decrypt_fail_invalid_key() {
        let ct = vec![
            0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
            0xbf, 0x39, 0xb6, 0xd4, 0xeb,
        ];
        let tag = vec![
            0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
            0x70,
        ];
        let key = vec![0x01u8; 16];
        let assocdata = vec![0u8; 16];
        let iv = vec![0u8; 12];
        let data = KcapiAEADData::new_dec(ct, assocdata, tag);

        match crate::aead::decrypt("gcm(aes)", data, key, iv) {
            Ok(_output) => panic!("(BUG) cipher operation succeeded with invalid tag"),
            Err(e) => {
                assert_eq!(e.code, -libc::EBADMSG);
            }
        };
    }

    #[test]
    fn test_aead_send() {
        use crate::aead::KcapiAEAD;
        let ct = vec![
            0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
            0xbf, 0x39, 0xb6, 0xd4, 0xeb,
        ];
        let assocdata = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let tag = vec![
            0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
            0x70,
        ];

        let key = vec![0u8; 16];
        let iv = vec![0u8; 12];

        let mut out_exp = KcapiAEADData::new();
        out_exp.set_data(vec![
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41,
        ]);
        out_exp.set_tag(vec![
            0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
            0x70,
        ]);
        out_exp.set_assocdata(vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);

        let mut cipher = KcapiAEAD::new("gcm(aes)", !crate::INIT_AIO).expect("init to succeed");
        cipher.set_tag(tag).expect("tag setting to succeed");
        cipher.set_assocdata(assocdata);
        cipher.setkey(key).expect("key setting to succeed");

        std::thread::spawn(move || {
            let out = cipher
                .decrypt(ct, iv, crate::ACCESS_HEURISTIC)
                .expect("decryption to succeed");
            assert_eq!(out.get_data(), out_exp.get_data());
            assert_eq!(out.get_tag(), out_exp.get_tag());
        })
        .join()
        .unwrap();
    }
}
