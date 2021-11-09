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

    #[test]
    fn test_ctr_kdf() {
        let ctr_kdf_key: Vec<u8> = vec![
            0xdd, 0x1d, 0x91, 0xb7, 0xd9, 0xb, 0x2b, 0xd3, 0x13, 0x85, 0x33, 0xce, 0x92, 0xb2,
            0x72, 0xfb, 0xf8, 0xa3, 0x69, 0x31, 0x6a, 0xef, 0xe2, 0x42, 0xe6, 0x59, 0xcc, 0xa,
            0xe2, 0x38, 0xaf, 0xe0,
        ];

        let ctr_kdf_msg: Vec<u8> = vec![
            0x1, 0x32, 0x2b, 0x96, 0xb3, 0xa, 0xcd, 0x19, 0x79, 0x79, 0x44, 0x4e, 0x46, 0x8e, 0x1c,
            0x5c, 0x68, 0x59, 0xbf, 0x1b, 0x1c, 0xf9, 0x51, 0xb7, 0xe7, 0x25, 0x30, 0x3e, 0x23,
            0x7e, 0x46, 0xb8, 0x64, 0xa1, 0x45, 0xfa, 0xb2, 0x5e, 0x51, 0x7b, 0x8, 0xf8, 0x68,
            0x3d, 0x3, 0x15, 0xbb, 0x29, 0x11, 0xd8, 0xa, 0xe, 0x8a, 0xba, 0x17, 0xf3, 0xb4, 0x13,
            0xfa, 0xac,
        ];

        let ctr_kdf_exp: Vec<u8> = vec![
            0x10, 0x62, 0x13, 0x42, 0xbf, 0xb0, 0xfd, 0x40, 0x4, 0x6c, 0xe, 0x29, 0xf2, 0xcf, 0xdb,
            0xf0,
        ];

        let mut kdf = match crate::kdf::KcapiKDF::new("hmac(sha256)", 0) {
            Ok(kdf) => kdf,
            Err(e) => panic!("Failed to initialize CTR-KDF handle {}", e),
        };

        match kdf.setkey(ctr_kdf_key) {
            Ok(()) => {}
            Err(e) => panic!("Failed to set key for CTR-KDF, {}", e),
        };

        let key = match kdf.ctr_kdf(ctr_kdf_msg, 16) {
            Ok(key) => key,
            Err(e) => panic!("Failed to generate KDF output for CTR-KDF, {}", e),
        };
        assert_eq!(key, ctr_kdf_exp);
    }

    #[test]
    fn test_fb_kdf() {
        let fb_kdf_key: Vec<u8> = vec![
            0x93, 0xf6, 0x98, 0xe8, 0x42, 0xee, 0xd7, 0x53, 0x94, 0xd6, 0x29, 0xd9, 0x57, 0xe2,
            0xe8, 0x9c, 0x6e, 0x74, 0x1f, 0x81, 0xb, 0x62, 0x3c, 0x8b, 0x90, 0x1e, 0x38, 0x37,
            0x6d, 0x6, 0x8e, 0x7b,
        ]
        .to_vec();

        let fb_kdf_msg: Vec<u8> = vec![
            0x9f, 0x57, 0x5d, 0x90, 0x59, 0xd3, 0xe0, 0xc0, 0x80, 0x3f, 0x8, 0x11, 0x2f, 0x8a,
            0x80, 0x6d, 0xe3, 0xc3, 0x47, 0x19, 0x12, 0xcd, 0xf4, 0x2b, 0x9, 0x53, 0x88, 0xb1,
            0x4b, 0x33, 0x50, 0x8e, 0x53, 0xb8, 0x9c, 0x18, 0x69, 0xe, 0x20, 0x57, 0xa1, 0xd1,
            0x67, 0x82, 0x2e, 0x63, 0x6d, 0xe5, 0xb, 0xe0, 0x1, 0x85, 0x32, 0xc4, 0x31, 0xf7, 0xf5,
            0xe3, 0x7f, 0x77, 0x13, 0x92, 0x20, 0xd5, 0xe0, 0x42, 0x59, 0x9e, 0xbe, 0x26, 0x6a,
            0xf5, 0x76, 0x7e, 0xe1, 0x8c, 0xd2, 0xc5, 0xc1, 0x9a, 0x1f, 0xf, 0x80,
        ];

        let fb_kdf_exp: Vec<u8> = vec![
            0xbd, 0x14, 0x76, 0xf4, 0x3a, 0x4e, 0x31, 0x57, 0x47, 0xcf, 0x59, 0x18, 0xe0, 0xea,
            0x5b, 0xc0, 0xd9, 0x87, 0x69, 0x45, 0x74, 0x77, 0xc3, 0xab, 0x18, 0xb7, 0x42, 0xde,
            0xf0, 0xe0, 0x79, 0xa9, 0x33, 0xb7, 0x56, 0x36, 0x5a, 0xfb, 0x55, 0x41, 0xf2, 0x53,
            0xfe, 0xe4, 0x3c, 0x6f, 0xd7, 0x88, 0xa4, 0x40, 0x41, 0x3, 0x85, 0x9, 0xe9, 0xee, 0xb6,
            0x8f, 0x7d, 0x65, 0xff, 0xbb, 0x5f, 0x95,
        ];

        let mut kdf = match crate::kdf::KcapiKDF::new("hmac(sha256)", 0) {
            Ok(kdf) => kdf,
            Err(e) => panic!("Failed to initialize FB-KDF handle {}", e),
        };

        match kdf.setkey(fb_kdf_key) {
            Ok(()) => {}
            Err(e) => panic!("Failed to set key for FB-KDF, {}", e),
        };

        let key = match kdf.fb_kdf(fb_kdf_msg, 64) {
            Ok(key) => key,
            Err(e) => panic!("Failed to generate KDF output for FB-KDF, {}", e),
        };
        assert_eq!(key, fb_kdf_exp);
    }

    #[test]
    fn test_dpi_kdf() {
        let dpi_kdf_key: Vec<u8> = vec![
            0x2, 0xd3, 0x6f, 0xa0, 0x21, 0xc2, 0xd, 0xdb, 0xde, 0xe4, 0x69, 0xf0, 0x57, 0x94, 0x68,
            0xba, 0xe5, 0xcb, 0x13, 0xb5, 0x48, 0xb6, 0xc6, 0x1c, 0xdf, 0x9d, 0x3e, 0xc4, 0x19,
            0x11, 0x1d, 0xe2,
        ];

        let dpi_kdf_msg: Vec<u8> = vec![
            0x85, 0xab, 0xe3, 0x8b, 0xf2, 0x65, 0xfb, 0xdc, 0x64, 0x45, 0xae, 0x5c, 0x71, 0x15,
            0x9f, 0x15, 0x48, 0xc7, 0x3b, 0x7d, 0x52, 0x6a, 0x62, 0x31, 0x4, 0x90, 0x4a, 0xf, 0x87,
            0x92, 0x7, 0xb, 0x3d, 0xf9, 0x90, 0x2b, 0x96, 0x69, 0x49, 0x4, 0x25, 0xa3, 0x85, 0xea,
            0xdb, 0xf, 0x9c, 0x76, 0xe4, 0x6f, 0xf,
        ];

        let dpi_kdf_exp: Vec<u8> = vec![
            0xd6, 0x9f, 0x74, 0xf5, 0x18, 0xc9, 0xf6, 0x4f, 0x90, 0xa0, 0xbe, 0xeb, 0xab, 0x69,
            0xf6, 0x89, 0xb7, 0x3b, 0x5c, 0x13, 0xeb, 0xf, 0x86, 0xa, 0x95, 0xca, 0xd7, 0xd9, 0x81,
            0x4f, 0x8c, 0x50, 0x6e, 0xb7, 0xb1, 0x79, 0xa5, 0xc5, 0xb4, 0x46, 0x6a, 0x9e, 0xc1,
            0x54, 0xc3, 0xbf, 0x1c, 0x13, 0xef, 0xd6, 0xec, 0xd, 0x82, 0xb0, 0x2c, 0x29, 0xaf,
            0x2c, 0x69, 0x2, 0x99, 0xed, 0xc4, 0x53,
        ];

        let mut kdf = match crate::kdf::KcapiKDF::new("hmac(sha256)", 0) {
            Ok(kdf) => kdf,
            Err(e) => panic!("Failed to initialize DPI-KDF handle {}", e),
        };

        match kdf.setkey(dpi_kdf_key) {
            Ok(()) => {}
            Err(e) => panic!("Failed to set key for DPI-KDF, {}", e),
        };

        let key = match kdf.dpi_kdf(dpi_kdf_msg, 64) {
            Ok(key) => key,
            Err(e) => panic!("Failed to generate KDF output for DPI-KDF, {}", e),
        };
        assert_eq!(key, dpi_kdf_exp);
    }

    #[test]
    fn test_hkdf() {
        let hkdf_ikm: Vec<u8> = vec![
            0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
            0xb, 0xb, 0xb, 0xb, 0xb,
        ];

        let hkdf_salt: Vec<u8> = vec![
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc,
        ];

        let hkdf_info: Vec<u8> = vec![0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let hkdf_out_exp: Vec<u8> = vec![
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0xa, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x0, 0x72, 0x8, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let out = match crate::kdf::hkdf("hmac(sha256)", hkdf_ikm, hkdf_salt, hkdf_info, 42) {
            Ok(out) => out,
            Err(e) => panic!("Failed to perform HKDF algorithm, {}", e),
        };
        assert_eq!(hkdf_out_exp, out);
    }

    #[test]
    fn test_pbkdf_one_loop() {
        let pbkdf_salt: Vec<u8> = vec![0x73, 0x61, 0x6c, 0x74];
        let pbkdf_password: Vec<u8> = vec![0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64];
        let pbkdf_exp: Vec<u8> = vec![
            0xc, 0x60, 0xc8, 0xf, 0x96, 0x1f, 0xe, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12,
            0x6, 0x2f, 0xe0, 0x37, 0xa6,
        ];
        const LOOPS: u32 = 1;

        let out = match crate::kdf::pbkdf("hmac(sha1)", pbkdf_password, pbkdf_salt, LOOPS, 20) {
            Ok(out) => out,
            Err(e) => panic!("Failed to perform PBKDF transform {}", e),
        };
        assert_eq!(pbkdf_exp, out);
    }

    #[test]
    fn test_pbkdf_two_loops() {
        let pbkdf_salt: Vec<u8> = vec![0x73, 0x61, 0x6c, 0x74];
        let pbkdf_password: Vec<u8> = vec![0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64];
        let pbkdf_exp: Vec<u8> = vec![
            0xea, 0x6c, 0x1, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
            0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
        ];
        const LOOPS: u32 = 2;

        let out = match crate::kdf::pbkdf("hmac(sha1)", pbkdf_password, pbkdf_salt, LOOPS, 20) {
            Ok(out) => out,
            Err(e) => panic!("Failed to perform PBKDF transform {}", e),
        };
        assert_eq!(pbkdf_exp, out);
    }

    #[test]
    fn test_pbkdf_4k_loops() {
        let pbkdf_salt: Vec<u8> = vec![0x73, 0x61, 0x6c, 0x74];
        let pbkdf_password: Vec<u8> = vec![0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64];
        let pbkdf_exp: Vec<u8> = vec![
            0x4b, 0x0, 0x79, 0x1, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21,
            0xd0, 0x65, 0xa4, 0x29, 0xc1,
        ];
        const LOOPS: u32 = 4096;

        let out = match crate::kdf::pbkdf("hmac(sha1)", pbkdf_password, pbkdf_salt, LOOPS, 20) {
            Ok(out) => out,
            Err(e) => panic!("Failed to perform PBKDF transform {}", e),
        };
        assert_eq!(pbkdf_exp, out);
    }

    #[test]
    fn test_pbkdf_multiloop() {
        let pbkdf_salt: Vec<u8> = vec![0x73, 0x61, 0x6c, 0x74];
        let pbkdf_password: Vec<u8> = vec![0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64];
        let pbkdf_exp: Vec<u8> = vec![
            0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4, 0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2,
            0x15, 0x8c, 0x26, 0x34, 0xe9, 0x84,
        ];
        const LOOPS: u32 = 16777216;

        let out = match crate::kdf::pbkdf("hmac(sha1)", pbkdf_password, pbkdf_salt, LOOPS, 20) {
            Ok(out) => out,
            Err(e) => panic!("Failed to perform PBKDF transform {}", e),
        };
        assert_eq!(pbkdf_exp, out);
    }

    #[test]
    fn test_pbkdf_128_bit_key() {
        let pbkdf_salt: Vec<u8> = vec![0x73, 0x61, 0x00, 0x6c, 0x74];
        let pbkdf_password: Vec<u8> = vec![0x70, 0x61, 0x73, 0x73, 0x00, 0x77, 0x6f, 0x72, 0x64];
        let pbkdf_exp: Vec<u8> = vec![
            0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x9, 0x9d, 0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25,
            0xe0, 0xc3,
        ];
        const LOOPS: u32 = 4096;

        let out = match crate::kdf::pbkdf("hmac(sha1)", pbkdf_password, pbkdf_salt, LOOPS, 16) {
            Ok(out) => out,
            Err(e) => panic!("Failed to perform PBKDF transform {}", e),
        };
        assert_eq!(pbkdf_exp, out);
    }

    #[test]
    fn test_pbkdf_200_bit_key() {
        let pbkdf_salt: Vec<u8> = vec![
            0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74, 0x53, 0x41,
            0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74, 0x53, 0x41, 0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74,
            0x53, 0x41, 0x4c, 0x54, 0x73, 0x61, 0x6c, 0x74,
        ];
        let pbkdf_password: Vec<u8> = vec![
            0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x50, 0x41, 0x53, 0x53, 0x57, 0x4f,
            0x52, 0x44, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
        ];
        let pbkdf_exp: Vec<u8> = vec![
            0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0,
            0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38,
        ];
        const LOOPS: u32 = 4096;

        let out = match crate::kdf::pbkdf("hmac(sha1)", pbkdf_password, pbkdf_salt, LOOPS, 25) {
            Ok(out) => out,
            Err(e) => panic!("Failed to perform PBKDF transform {}", e),
        };
        assert_eq!(pbkdf_exp, out);
    }
}