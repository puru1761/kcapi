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

//!
//! # Random Number Generation (rng) using the Kernel Crypto API (KCAPI)
//!
//! This module provides the capability to perform random number generation using
//! the KCAPI. The APIs provided by this module allow the seeding of kernel RNGs,
//! as well as the generic output of randomness from the Linux kernel.
//!
//! # Layout
//!
//! This module provides one-shot convenience APIs for getting N random bytes
//! from the kernel's `stdrng` as a `Vec<u8>` og length 'N'. Additionally,
//! this module implements the `KcapiRNG` type which provides APIs to initialize,
//! seed, and generate random data from a kernel RNG algorithm as defined in
//! `/proc/crypto`.
//!

use std::{convert::TryInto, ffi::CString};

use crate::{KcapiError, KcapiResult, INIT_AIO};

///
/// # The `KcapiRNG` Type
///
/// This type denotes a generic context for an RNG transform in the kernel.
/// A new instance of this struct must be initialized in order to use it's APIs.
///
/// ## Panics
///
/// If the string provided to the `new()` method of this type cannot be converted
/// into a valid `std::ffi::CString`, the initialization will panic with the message
/// `Failed to create CString`.
///
/// ## Examples
///
/// A new instance of this struct must be initialized prior to use:
///
/// ```
/// use kcapi::rng::KcapiRNG;
///
/// let rng = match KcapiRNG::new("drbg_nopr_hmac_sha512") {
///     Ok(rng) => rng,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
#[derive(Debug, Eq, PartialEq)]
pub struct KcapiRNG {
    handle: *mut kcapi_sys::kcapi_handle,
    pub algorithm: String,
    pub seedsize: usize,
}

impl KcapiRNG {
    ///
    /// ## Initialize an RNG transform in the Linux Kernel
    ///
    /// This API provides the initialization of a new instance of `KcapiRNG` and
    /// makes the required connections to the Linux Kernel.
    /// The caller must specify the algorithm used for the RNG, and it must be
    /// specified in `/proc/crypto`.
    ///
    /// On success, an initialized instance of `KcapiRNG` is returned.
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::rng::KcapiRNG;
    ///
    /// let rng = KcapiRNG::new("drbg_nopr_hmac_sha512")
    ///     .expect("Failed to initialize KcapiRNG");
    /// ```
    ///
    pub fn new(algorithm: &str) -> KcapiResult<Self> {
        let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;

        let alg = CString::new(algorithm).expect("Failed to create CString");
        let seedsize: usize;

        unsafe {
            let ret = kcapi_sys::kcapi_rng_init(&mut handle as *mut _, alg.as_ptr(), !INIT_AIO);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to initialize RNG handle for algorithm '{}'",
                        algorithm,
                    ),
                });
            }

            seedsize = kcapi_sys::kcapi_rng_seedsize(handle)
                .try_into()
                .expect("Failed to convert u32 into usize");
        }

        Ok(KcapiRNG {
            handle,
            algorithm: algorithm.to_string(),
            seedsize,
        })
    }

    ///
    /// ## Set the initial entropy of the RNG (CAVP)
    ///
    /// Note, this call must be called to initialize the selected RNG. When the
    /// SP800-90A DRBG is used, this call causes the DRBG to seed itself from the
    /// provided data.
    ///
    /// Note, in case of using the SP800-90A DRBG, the `CRYPTO_USER_API_RNG_CAVP`
    /// kernel config knob must be set to `'y'` to use this API.
    ///
    /// A `Vec<u8>` must be provided as the initial entropy data.
    ///
    /// On failure a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```no_run
    /// use kcapi::rng::KcapiRNG;
    ///
    /// let ent = vec![0x00u8, 16];
    /// let mut rng = KcapiRNG::new("drbg_nopr_hmac_sha512")
    ///     .expect("Failed to initialize RNG");
    ///
    /// rng.setentropy(ent)
    ///     .expect("Failed to set initial entropy for RNG");
    /// ```
    ///
    pub fn setentropy(&self, mut entropy: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_rng_setentropy(
                self.handle,
                entropy.as_mut_ptr(),
                entropy.len() as u32,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to set RNG entropy for algorithm '{}'",
                        self.algorithm
                    ),
                });
            }
        }
        Ok(())
    }

    ///
    /// ## send additional data to the RNG (CAVP)
    ///
    /// Note, this call must be called immediately prior to calling
    /// kcapi_rng_generate in order to send additional data to be consumed by
    /// the RNG.
    ///
    /// Note, in case of using the SP800-90A DRBG, the CRYPTO_USER_API_RNG_CAVP
    /// kernel config knob must be set to 'y' to use this API.
    ///
    /// A `Vec<u8>` must be provided as the additional data.
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```no_run
    /// use kcapi::rng::KcapiRNG;
    ///
    /// let ent = vec![0x00u8, 16];
    /// let mut rng = KcapiRNG::new("drbg_nopr_hmac_sha512")
    ///     .expect("Failed to initialize RNG");
    ///
    /// rng.setentropy(ent)
    ///     .expect("Failed to set initial entropy for RNG");
    ///
    /// let addtl = vec![0x00u8; 16];
    /// rng.setaddtl(addtl)
    ///     .expect("Failed to set additional data for RNG");
    ///
    /// let data = rng.generate(128)
    ///     .expect("Failed to generate random");
    /// assert_eq!(data.len(), 128);
    /// ```
    pub fn setaddtl(&self, mut entropy: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_rng_setaddtl(
                self.handle,
                entropy.as_mut_ptr(),
                entropy.len() as u32,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to set RNG entropy for algorithm '{}'",
                        self.algorithm
                    ),
                });
            }
        }
        Ok(())
    }

    ///
    /// ## Seed the Kernel RNG
    ///
    /// This function must be called to initialize the selected RNG.
    /// When the SP800-90A DRBG is used, this call causes the DRBG to seed itself
    /// from the internal noise sources.
    /// An `Vec<u8>` must be provided as the input data (seed) to this function.
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::rng::KcapiRNG;
    ///
    /// let seed = vec![0xffu8; 16];
    /// let mut rng = KcapiRNG::new("drbg_nopr_hmac_sha512")
    ///     .expect("Failed to initialize KcapiRNG");
    ///
    /// rng.seed(seed)
    ///     .expect("Failed to seed the kernel RNG");
    /// ```
    ///
    pub fn seed(&self, mut data: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_rng_seed(self.handle, data.as_mut_ptr(), data.len() as u32);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!("Failed to seed RNG for algorithm '{}'", self.algorithm,),
                });
            }
        }
        Ok(())
    }

    ///
    /// ## Generate a random number
    ///
    /// This function is used to generate a random number of `count` bytes
    /// from an initialized and seeded RNG. The RNG must be seeded by calling
    /// `seed()` prior to calling this function.
    /// This function must be provided with a `count` argument of `usize`
    /// denoting the length (in bytes) of the random number to be generated.
    ///
    /// On success, returns a `Vec<u8>` of length `count` with the random data.
    /// On failure, returns a `KcapiError`.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::rng::KcapiRNG;
    ///
    /// let rng = KcapiRNG::new("drbg_nopr_hmac_sha512")
    ///     .expect("Failed to initialize KcapiRNG");
    ///
    /// let seed = vec![0xffu8; 16];
    /// rng.seed(seed)
    ///     .expect("Failed to seed KcapiRNG");
    ///
    /// let random = rng.generate(1024)
    ///     .expect("Failed to generate a random number of 1024 bytes");
    /// ```
    ///
    pub fn generate(&self, count: usize) -> KcapiResult<Vec<u8>> {
        let mut out = vec![0u8; count];
        unsafe {
            let ret = kcapi_sys::kcapi_rng_generate(
                self.handle,
                out.as_mut_ptr(),
                count as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.try_into().expect("failed to convert i64 into i32"),
                    message: format!(
                        "Failed to generate random data for algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        Ok(out)
    }
}

impl Drop for KcapiRNG {
    fn drop(&mut self) {
        unsafe {
            kcapi_sys::kcapi_rng_destroy(self.handle);
        }
    }
}

///
/// ## Convenience function to generate random bytes
///
/// This convenience function generates a `count` number of random bytes from
/// the `stdrng` from `/proc/crypto`.
/// This function accepts an argument `count` of type `usize` denoting the number
/// of random bytes to generate.
///
/// On success, returns a `Vec<u8>` of length `count` containing the random data.
/// On failure, returns a `KcapiError`.
///
/// ## Examples
///
/// ```
/// let random = kcapi::rng::get_bytes(1024)
///     .expect("Failed to generate random bytes");
/// assert_eq!(random.len(), 1024);
/// ```
///
pub fn get_bytes(count: usize) -> KcapiResult<Vec<u8>> {
    let mut out = vec![0u8; count];
    unsafe {
        let ret = kcapi_sys::kcapi_rng_get_bytes(out.as_mut_ptr(), count as kcapi_sys::size_t);
        if ret < 0 {
            return Err(KcapiError {
                code: ret.try_into().expect("failed to convert i64 into i32"),
                message: format!("Failed to obtain {} bytes from the stdrng", count),
            });
        }
    }

    Ok(out)
}
