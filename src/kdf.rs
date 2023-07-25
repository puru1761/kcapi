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
//! # Key Derivation Functions (kdf) using the Kernel Crypto API (KCAPI)
//!
//! This module provides the capability to perform Key Derivation Functions using
//! the KCAPI. The APIs provided by this module allow the initialization of
//! KDF handles, setting the key for HMAC based KDFs, as well as KDFs in
//! Counter Mode, Feedback Mode, and Double Pipeline Mode. Additionally,
//! convenience functions to perform Password-based and the Extract-and-Expand
//! HKDF (RFC5869) are also provided.
//!
//! # Layout
//!
//! This module provides the one-shot convenience APIs for performing
//! Password-based KDF as well as Extract-and-Expand HKDF (RFC5869).
//! Along with these, the `KcapiKDF` type is provided which allows
//! the initialization, and setkey functions for Counter Mode, Feedback Mode,
//! and Double Pipeline Mode KDFs.
//!
use std::{convert::TryInto, ffi::CString};

use crate::{KcapiError, KcapiResult, INIT_AIO};

///
/// # The `KcapiKDF` Type
///
/// This type denotes a generic context for KDF operations performed using the
/// KCAPI. A new instance of this struct must be initialized prior to accessing
/// any of it's APIs. A hash algorithm from `/proc/crypto` must be provided as
/// in order to create an instance of this struct using the `new()` method.
///
/// ## Panics
///
/// If the string provided to the `new()` method of this type cannot be converted
/// into a valid `std::ffi::CString`, the initialization will panic with the message
/// `Failed to allocate CString`.
///
/// ## Examples
///
/// ```
/// use kcapi::kdf::KcapiKDF;
///
/// let mut kdf = match KcapiKDF::new("hmac(sha1)") {
///     Ok(kdf) => kdf,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
#[derive(Debug, Eq, PartialEq)]
pub struct KcapiKDF {
    digestsize: usize,
    handle: *mut kcapi_sys::kcapi_handle,
    iteration_count: u32,
    key: Vec<u8>,
    pub algorithm: String,
}

impl KcapiKDF {
    ///
    /// ## Initialize a the `KcapiKDF` type.
    ///
    /// This function initializes the `KcapiKDF` type for a hash algorithm from
    /// `/proc/crypto`. The name of the hash provided as the `algorithm` argument
    /// to this function MUST be present in `/proc/crypto` on the target platform.
    ///
    /// On success, an initialized instance of the `KcapiKDF` type is returned.
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::kdf::KcapiKDF;
    ///
    /// let kdf = KcapiKDF::new("hmac(sha512)")
    ///     .expect("Failed to initialize KcapiKDF");
    /// ```
    pub fn new(algorithm: &str) -> KcapiResult<Self> {
        let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;

        let alg = CString::new(algorithm).expect("Failed to allocate Cstring");
        let iteration_count: u32;
        let digestsize: usize;
        unsafe {
            iteration_count = kcapi_sys::kcapi_pbkdf_iteration_count(alg.as_ptr(), 0);

            let ret = kcapi_sys::kcapi_md_init(&mut handle as *mut _, alg.as_ptr(), !INIT_AIO);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to Initialize hash handle for algorithm '{}'",
                        algorithm,
                    ),
                });
            }

            digestsize = kcapi_sys::kcapi_md_digestsize(handle) as usize;
            if digestsize == 0 {
                return Err(KcapiError {
                    code: -libc::EINVAL,
                    message: format!("Failed to obtain digestsize for algorithm '{}'", algorithm,),
                });
            }
        }

        let key: Vec<u8> = Vec::new();
        Ok(KcapiKDF {
            digestsize,
            handle,
            iteration_count,
            key,
            algorithm: algorithm.to_string(),
        })
    }

    ///
    /// ## Set the key for the `KcapiKDF` instance.
    ///
    /// This function sets the key used in a keyed message digest algorithm for
    /// the KDF operation. A call to this function is only required if the
    /// algorithm with which the `KcapiKDF` is initialized is a keyed message
    /// digest.
    ///
    /// This function takes a key as a `Vec<u8>`
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::kdf::KcapiKDF;
    ///
    /// let mut kdf = KcapiKDF::new("hmac(sha1)")
    ///     .expect("Failed to initialize KcapiKDF");
    ///
    /// let key = vec![0x00u8; 16];
    /// kdf.setkey(key)
    ///     .expect("Failed to set key for KcapiKDF");
    /// ```
    ///
    pub fn setkey(&mut self, key: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_md_setkey(self.handle, key.as_ptr(), key.len() as u32);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!("Failed to set key for KDF algorithm '{}'", self.algorithm,),
                });
            }
        }
        self.key = key;
        Ok(())
    }

    ///
    /// ## Counter Mode Key Derivation Function
    ///
    /// This function is an implementation of the KDF in counter mode according
    /// to SP800-108 section 5.1 as well as SP800-56A section 5.8.1
    /// (Single-step KDF).
    ///
    /// SP800-108: The caller must provide Label || 0x00 || Context in src.
    /// SP800-56A: If a keyed MAC is used, the key shall NOT be the shared secret
    /// from the DH operation, but an independently generated key. The src pointer
    /// is defined as Z || other info where Z is the shared secret from DH and
    /// other info is an arbitrary string (see SP800-56A section 5.8.1.2).
    ///
    /// This function takes input data of type `Vec<u8>`, and the size of the
    /// key to be output as `usize`.
    ///
    /// On success, a `Vec<u8>` of size `outsize` is returned.
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::kdf::KcapiKDF;
    ///
    /// let mut kdf = KcapiKDF::new("hmac(sha1)")
    ///     .expect("Failed to initialize CTR KDF");
    ///
    /// let key = vec![0x00u8; 16];
    /// kdf.setkey(key)
    ///     .expect("Failed to set key for CTR KDF");
    ///
    /// let inp = vec![0x01u8; 16];
    /// let out = kdf.ctr_kdf(inp, 16)
    ///     .expect("Failed to perform CTR KDF");
    ///
    /// assert_eq!(out.len(), 16);
    /// ```
    ///
    pub fn ctr_kdf(&self, input: Vec<u8>, outsize: usize) -> KcapiResult<Vec<u8>> {
        let mut out = vec![0u8; outsize];
        unsafe {
            let ret = kcapi_sys::kcapi_kdf_ctr(
                self.handle,
                input.as_ptr(),
                input.len() as kcapi_sys::size_t,
                out.as_mut_ptr(),
                outsize as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.try_into().expect("failed to convert i64 into i32"),
                    message: format!(
                        "Failed to generate key for KDF algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        Ok(out)
    }

    ///
    /// ## Double Pipeline Mode Key Derivation Function
    ///
    /// This function is an implementation of the KDF in double pipeline
    /// iteration mode according with counter to SP800-108 section 5.3.
    /// The caller must provide Label || 0x00 || Context in src.
    ///
    /// This function takes input data of type `Vec<u8>`, and the size of the
    /// key to be output as `usize`.
    ///
    /// On success, a `Vec<u8>` of size `outsize` is returned.
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::kdf::KcapiKDF;
    ///
    /// let mut kdf = KcapiKDF::new("hmac(sha1)")
    ///     .expect("Failed to initialize DPI KDF");
    ///
    /// let key = vec![0x00u8; 16];
    /// kdf.setkey(key)
    ///     .expect("Failed to set key for DPI KDF");
    ///
    /// let inp = vec![0x01u8; 16];
    /// let out = kdf.dpi_kdf(inp, 16)
    ///     .expect("Failed to perform DPI KDF");
    ///
    /// assert_eq!(out.len(), 16);
    /// ```
    ///
    pub fn dpi_kdf(&self, input: Vec<u8>, outsize: usize) -> KcapiResult<Vec<u8>> {
        let mut out = vec![0u8; outsize];
        unsafe {
            let ret = kcapi_sys::kcapi_kdf_dpi(
                self.handle,
                input.as_ptr(),
                input.len() as kcapi_sys::size_t,
                out.as_mut_ptr(),
                outsize as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.try_into().expect("failed to convert i64 into i32"),
                    message: format!(
                        "Failed to generate key for KDF algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        Ok(out)
    }

    ///
    /// ## Feedback Mode Key Derivation Function
    ///
    /// This function is an implementation of the KDF in feedback mode with a
    /// non-NULL IV and with counter according to SP800-108 section 5.2. The IV
    /// is supplied with src and must be equal to the digestsize of the used
    /// cipher.
    ///
    /// In addition, the caller must provide Label || 0x00 || Context in src.
    /// This src pointer must not be NULL as the IV is required. The ultimate
    /// format of the src pointer is IV || Label || 0x00 || Context where the
    /// length of the IV is equal to the block size (i.e. the digest size of
    /// the underlying hash) of the PRF.
    ///
    /// This function takes input data of type `Vec<u8>`, and the size of the
    /// key to be output as `usize`.
    ///
    /// On success, a `Vec<u8>` of size `outsize` is returned.
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::kdf::KcapiKDF;
    ///
    /// let mut kdf = KcapiKDF::new("hmac(sha1)")
    ///     .expect("Failed to initialize FB KDF");
    ///
    /// let key = vec![0x00u8; 32];
    /// kdf.setkey(key)
    ///     .expect("Failed to set key for FB KDF");
    ///
    /// let inp = vec![0x00u8; 20];
    /// let out = kdf.fb_kdf(inp, 16)
    ///     .expect("Failed to perform FB KDF");
    ///
    /// assert_eq!(out.len(), 16);
    /// ```
    ///
    pub fn fb_kdf(&self, input: Vec<u8>, outsize: usize) -> KcapiResult<Vec<u8>> {
        if input.len() < self.digestsize {
            return Err(KcapiError {
                code: -libc::EINVAL,
                message: format!(
                    "Invalid input of length {} < {} for FB-KDF algorithm '{}'",
                    input.len(),
                    self.digestsize,
                    self.algorithm,
                ),
            });
        }
        let mut out = vec![0u8; outsize];
        unsafe {
            let ret = kcapi_sys::kcapi_kdf_fb(
                self.handle,
                input.as_ptr(),
                input.len() as kcapi_sys::size_t,
                out.as_mut_ptr(),
                outsize as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.try_into().expect("failed to convert i64 into i32"),
                    message: format!(
                        "Failed to generate key for KDF algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        Ok(out)
    }
}

impl Drop for KcapiKDF {
    fn drop(&mut self) {
        unsafe {
            kcapi_sys::kcapi_md_destroy(self.handle);
        }
    }
}

///
/// ## Extract-and-Expand HKDF (RFC5869)
///
/// Perform the key-derivation function according to RFC5869. The input data is
/// defined in sections 2.2 und 2.3 of RFC5869.
///
/// This function takes:
/// * `hashname` - a `&str` representation of a hash algorithm from `/proc/crypto`.
/// * `ikm` - Input Key Material of type `Vec<u8>`.
/// * `salt` - Salt of type `Vec<u8>`
/// * `info` - Information buffer of type `Vec<u8>`.
/// * `outsize` - The size of the key to be generated of type `usize`.
///
/// On success, a `Vec<u8>` of length `outsize` is returned with the generated key.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let ikm = vec![0u8; 16];
/// let salt = vec![0u8; 16];
/// let info = vec![0u8; 16];
/// let outsize: usize = 32;
///
/// let key = kcapi::kdf::hkdf("hmac(sha1)", ikm, salt, info, outsize)
///     .expect("Failed to perform HKDF");
///
/// assert_eq!(key.len(), 32);
/// ```
pub fn hkdf(
    hashname: &str,
    ikm: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    outsize: usize,
) -> KcapiResult<Vec<u8>> {
    let mut out = vec![0u8; outsize];
    if ikm.is_empty() {
        return Err(KcapiError {
            code: -libc::EINVAL,
            message: format!(
                "Input key material is a required arguement for algorithm '{}'",
                hashname,
            ),
        });
    }

    let hash = CString::new(hashname).expect("Failed to allocate Cstring");
    unsafe {
        let ret = kcapi_sys::kcapi_hkdf(
            hash.as_ptr(),
            ikm.as_ptr(),
            ikm.len() as kcapi_sys::size_t,
            salt.as_ptr(),
            salt.len() as u32,
            info.as_ptr(),
            info.len() as kcapi_sys::size_t,
            out.as_mut_ptr(),
            outsize as kcapi_sys::size_t,
        );
        if ret < 0 {
            return Err(KcapiError {
                code: ret.try_into().expect("failed to convert i64 into i32"),
                message: format!("Failed HKDF operation for algorithm '{}'", hashname,),
            });
        }
    }
    Ok(out)
}

///
/// ## Password-based Key Derivation Function
///
/// This function is an implementation of the PBKDF as defined in SP800-132.
///
/// This function takes:
/// * `hashname` - A `&str` representation of a hash algorithm from `/proc/crypto`.
/// * `password` - A password of type `Vec<u8>` from which the key shall be derived.
/// * `salt` - A salt of type `Vec<u8>`.
/// * `iterations` - Number of iterations (`u32`) to be performed by the PBKDF.
/// * `outsize` - The size of the key (`usize`) to be generated.
///
/// On success, a `Vec<u8>` of length `outsize` containing the key is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let password = "Password123!".as_bytes().to_vec();
/// let salt = vec![0xffu8; 16];
/// let iterations = 32;
/// let outsize = 32;
///
/// let key = kcapi::kdf::pbkdf("hmac(sha256)", password, salt, iterations, outsize)
///     .expect("Failed to perform PBKDF");
/// ```
///
pub fn pbkdf(
    hashname: &str,
    password: Vec<u8>,
    salt: Vec<u8>,
    iterations: u32,
    outsize: usize,
) -> KcapiResult<Vec<u8>> {
    let mut out = vec![0u8; outsize];
    if password.is_empty() || salt.is_empty() {
        return Err(KcapiError {
            code: -libc::EINVAL,
            message: format!("Invalid input to PBKDF algorithm '{}'", hashname),
        });
    }

    let hash = CString::new(hashname).expect("Failed to allocate CString");
    unsafe {
        let iter = kcapi_sys::kcapi_pbkdf_iteration_count(hash.as_ptr(), 0);
        if iterations == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL,
                message: format!(
                    "Insufficient iteration count {}. Recommended count is {} for '{}'",
                    iterations, iter, hashname,
                ),
            });
        }

        let ret = kcapi_sys::kcapi_pbkdf(
            hash.as_ptr(),
            password.as_ptr(),
            password.len() as u32,
            salt.as_ptr(),
            salt.len() as kcapi_sys::size_t,
            iterations,
            out.as_mut_ptr(),
            outsize as kcapi_sys::size_t,
        );
        if ret < 0 {
            return Err(KcapiError {
                code: ret.try_into().expect("failed to convert i64 into i32"),
                message: format!("Failed PBKDF operation for algorithm '{}'", hashname,),
            });
        }
    }
    Ok(out)
}
