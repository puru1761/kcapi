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
        let handle = match crate::rng::init("drbg_nopr_hmac_sha512", 0) {
            Ok(handle) => handle,
            Err(e) => panic!("{}", e),
        };

        match crate::rng::seed(&handle, vec![0u8; 16]) {
            Ok(()) => {}
            Err(e) => panic!("{}", e),
        };

        let mut out_last = match crate::rng::generate(&handle, RNG_GET_BYTECOUNT) {
            Ok(buf) => buf,
            Err(e) => panic!("{}", e),
        };
        for _i in 0..RNG_GET_BYTECOUNT {
            let out = match crate::rng::generate(&handle, RNG_GET_BYTECOUNT) {
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
        let handle = match crate::rng::init("drbg_nopr_hmac_sha512", 0) {
            Ok(handle) => handle,
            Err(e) => panic!("{}", e),
        };

        let _out = match crate::rng::generate(&handle, RNG_GET_BYTECOUNT) {
            Ok(_buf) => {
                panic!("[BUG] RNG generated randomness without being seeded.")
            }
            Err(_e) => {}
        };
    }

    #[test]
    #[ignore]
    fn test_rng_seedsize() {
        let handle = match crate::rng::init("drbg_nopr_hmac_sha512", 0) {
            Ok(handle) => handle,
            Err(e) => panic!("{}", e),
        };

        let seedsize = match crate::rng::seedsize(&handle) {
            Ok(seedsize) => seedsize,
            Err(e) => panic!("{}", e),
        };

        println!("seedsize = {}", seedsize);
    }
}
