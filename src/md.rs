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
//! # Message Digest (md) using the Kernel Crypto API (KCAPI)
//!
//! This module provides the capability to perform message digests using the KCAPI.
//! APIs provided by this module allow users to calculate message digests as well as
//! keyed message digests (such as HMACs) on input data.
//!
//! # Layout
//!
//! This module provides one shot helper functions to perform `digest()` and `keyed_digest()`
//! on an input `Vec<u8>`. The digest itself is provided as a `Vec<u8>`. In addition to this,
//! a `KcapiHash` type is defined which provides an API to initialize, set HMAC keys, update, and
//! finalize hash data for incremental hash operations.
//!
//! In addition to this, convenience functions are provided to perform `sha{1,224,256,384,512}`
//! based hashes and HMACs.
//!

use std::{convert::TryInto, ffi::CString};

use crate::{KcapiError, KcapiResult, BITS_PER_BYTE, INIT_AIO};

const SHA1_BITSIZE: usize = 160;
const SHA224_BITSIZE: usize = 224;
const SHA256_BITSIZE: usize = 256;
const SHA384_BITSIZE: usize = 384;
const SHA512_BITSIZE: usize = 512;

pub const SHA1_DIGESTSIZE: usize = SHA1_BITSIZE / BITS_PER_BYTE;
pub const SHA224_DIGESTSIZE: usize = SHA224_BITSIZE / BITS_PER_BYTE;
pub const SHA256_DIGESTSIZE: usize = SHA256_BITSIZE / BITS_PER_BYTE;
pub const SHA384_DIGESTSIZE: usize = SHA384_BITSIZE / BITS_PER_BYTE;
pub const SHA512_DIGESTSIZE: usize = SHA512_BITSIZE / BITS_PER_BYTE;

///
/// # The `KcapiHash` type
///
/// This type denotes a generic context for a Hash transform.
/// An instance of this struct must be initialized using the `new()` method prior to use.
///
/// ## Panics
///
/// If the string provided as input to the `new()` function cannot be converted into a
/// `std::ffi::CString` type, the initialization will panic with the message
/// `Failed to create CString`.
///
/// ## Examples
///
/// Initializing a KcapiHash
///
/// ```
/// use kcapi::md::{KcapiHash, SHA1_DIGESTSIZE};
///
/// let mut hash = match KcapiHash::new("sha1") {
///     Ok(hash) => hash,
///     Err(e) => panic!("{}", e),
/// };
/// assert_eq!(hash.digestsize, SHA1_DIGESTSIZE);
/// ```
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KcapiHash {
    handle: *mut kcapi_sys::kcapi_handle,
    key: Vec<u8>,
    pub algorithm: String,
    pub blocksize: usize,
    pub digestsize: usize,
}

impl KcapiHash {
    ///
    /// ## Initialize a `KcapiHash`
    ///
    /// This API initializes a (keyed) message digest by establishing a connection
    /// to the Linux Kernel. The algorithm to be used by the (keyed) message digest
    /// must be defined in `/proc/crypto` and must be provided as an argument to
    /// this function.
    ///
    /// On success, it returns an instance of type `KcapiHash`.
    /// On failure, it returns a `KcapiError`.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::md::KcapiHash;
    ///
    /// let hash = KcapiHash::new("sha1")
    ///     .expect("Failed to initialize a KcapiHash");
    /// ```
    ///
    pub fn new(algorithm: &str) -> KcapiResult<Self> {
        let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;
        let digestsize: usize;
        let blocksize: usize;

        let alg = CString::new(algorithm).expect("Failed to create CString");
        unsafe {
            let ret = kcapi_sys::kcapi_md_init(&mut handle as *mut _, alg.as_ptr(), !INIT_AIO);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!(
                        "Failed to initialize hash handle for algorithm '{}'",
                        algorithm
                    ),
                });
            }
            digestsize = kcapi_sys::kcapi_md_digestsize(handle)
                .try_into()
                .expect("Failed to convert u32 into usize");
            if digestsize == 0 {
                return Err(KcapiError {
                    code: -libc::EINVAL as i64,
                    message: format!(
                        "Failed to obtained digest size for algorithm '{}",
                        algorithm
                    ),
                });
            }

            blocksize = kcapi_sys::kcapi_md_blocksize(handle)
                .try_into()
                .expect("Failed to convert u32 into usize");
            if blocksize == 0 {
                return Err(KcapiError {
                    code: -libc::EINVAL as i64,
                    message: format!("Failed to obtain block size for algorithm '{}'", algorithm),
                });
            }
        }

        let key: Vec<u8> = Vec::new();
        Ok(KcapiHash {
            handle,
            key,
            algorithm: algorithm.to_string(),
            blocksize,
            digestsize,
        })
    }

    ///
    /// ## Update the message digest (stream)
    ///
    /// This API updates the KcapiHash context with an input data buffer.
    /// The input data must be a `Vec<u8>`.
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// Call the update API on an initialized hash handle
    ///
    /// ```
    /// use kcapi::md::KcapiHash;
    ///
    /// let hash = KcapiHash::new("sha256")
    ///     .expect("Failed to initialize hash handle");
    ///
    /// hash.update("Hello, World".as_bytes().to_vec())
    ///     .expect("Failed to update hash with input buffer");
    /// ```
    pub fn update(&self, buffer: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_md_update(
                self.handle,
                buffer.as_ptr(),
                buffer.len() as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to update message digest for algorithm '{}'",
                        self.algorithm
                    ),
                });
            }
        }
        Ok(())
    }

    ///
    /// ## Finalize the message digest (stream)
    ///
    /// This function outputs the final message digest after performing a hash operation.
    /// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`.
    ///
    /// On Success, a `Vec<u8>` with length equal to the digestsize is returned.
    /// On Failure,  a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// Finalize a message digest
    ///
    /// ```
    /// use kcapi::md::KcapiHash;
    ///
    /// let hash = KcapiHash::new("sha256")
    ///     .expect("Failed to initialize hash handle");
    ///
    /// hash.update("Hello, World".as_bytes().to_vec())
    ///     .expect("Failed to update hash with input buffer");
    ///
    /// let digest = hash.finalize()
    ///     .expect("Failed to finalize message digest");
    /// ```
    ///
    pub fn finalize(&self) -> KcapiResult<Vec<u8>> {
        let mut digest = vec![0u8; self.digestsize];
        unsafe {
            let ret = kcapi_sys::kcapi_md_final(
                self.handle,
                digest.as_mut_ptr(),
                digest.len() as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to finalize digest for algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        Ok(digest)
    }

    ///
    /// ## Set the key for the message digest
    ///
    /// This function is used primarily to set the key in keyed message digest operations.
    /// The key must be a `Vec<u8>` of size less than `INT_MAX`.
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// Set the key for a message digest
    ///
    /// ```
    /// use kcapi::md::KcapiHash;
    ///
    /// let mut hmac = KcapiHash::new("hmac(sha256)")
    ///     .expect("Failed to initialize KcapiHash");
    ///
    /// let key = vec![0x01u8; 16];
    /// hmac.setkey(key)
    ///     .expect("Failed to set key for KcapiHash");
    /// ```
    ///
    pub fn setkey(&mut self, key: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_md_setkey(self.handle, key.as_ptr(), key.len() as u32);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!("Failed to set key for algorithm '{}'", self.algorithm),
                });
            }
            self.key = key;
        }
        Ok(())
    }

    ///
    /// ## Calculate message digest on a buffer (one-shot)
    ///
    /// With this one-shot function, the message digest for a buffer can be calculated.
    /// If a keyed message digest is to be calculated, then the `setkey()` function must
    /// also be called prior to calling `digest()`.
    ///
    /// On success, a `Vec<u8>` with length equal to the digestsize is returned.
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// One shot message digest
    ///
    /// ```
    /// use kcapi::md::KcapiHash;
    ///
    /// let hash = KcapiHash::new("sha512")
    ///     .expect("Failed to initialize KcapiHash");
    ///
    /// let digest = hash.digest("Hello, World!".as_bytes().to_vec())
    ///     .expect("Failed to calculate message digest");
    /// ```
    ///
    pub fn digest(&self, input: Vec<u8>) -> KcapiResult<Vec<u8>> {
        if self.digestsize == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Failed to obtain valid blocksize for algorithm '{}'",
                    self.algorithm
                ),
            });
        }

        let mut digest = vec![0u8; self.digestsize];
        unsafe {
            let ret = kcapi_sys::kcapi_md_digest(
                self.handle,
                input.as_ptr(),
                input.len() as kcapi_sys::size_t,
                digest.as_mut_ptr(),
                self.digestsize as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!("Failed to obtain digest for algorithm '{}'", self.algorithm),
                });
            }
        }
        Ok(digest)
    }
}

impl Drop for KcapiHash {
    fn drop(&mut self) {
        unsafe {
            kcapi_sys::kcapi_md_destroy(self.handle);
        }
    }
}

///
/// ## Calculate message digest on a buffer (one-shot)
///
/// With this one-shot function, the message digest for a buffer can be calculated.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`.
///
/// On success, a `Vec<u8>` with length equal to the digestsize is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// One shot message digest
///
/// ```
/// let digest = kcapi::md::digest("sha1", "Hello, World!".as_bytes().to_vec())
///     .expect("Failed to calculate message digest");
/// ```
///
pub fn digest(alg: &str, input: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let hash = crate::md::KcapiHash::new(alg)?;
    hash.update(input)?;
    let output = hash.finalize()?;

    Ok(output)
}

///
/// ## Calculate a keyed message digest on a buffer (one-shot)
///
/// With this one-shot function, a keyed message digest for a buffer can be calculated.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`.
/// The input key must be a `Vec<u8>` of size less than `INT_MAX`.
///
/// On success, a `Vec<u8>` with length equal to the digestsize is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let key = vec![0x41u8; 16];
/// let hmac = kcapi::md::keyed_digest("hmac(sha1)", key, "Hello, World!".as_bytes().to_vec())
///     .expect("Failed to calculate keyed message digest");
/// ```
///
pub fn keyed_digest(alg: &str, key: Vec<u8>, input: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let mut hmac = crate::md::KcapiHash::new(alg)?;
    hmac.setkey(key)?;
    hmac.update(input)?;
    let output = hmac.finalize()?;

    Ok(output)
}

///
/// ## Calculate a SHA-1 message digest on an input buffer
///
/// With this one-shot convenience function the SHA-1 message digest of an
/// input buffer can be obtained.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`
///
/// On success, a `[u8; SHA1_DIGESTSIZE]` is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let digest = kcapi::md::sha1("Hello, World!".as_bytes().to_vec());
/// ```
///
pub fn sha1(input: Vec<u8>) -> KcapiResult<[u8; SHA1_DIGESTSIZE]> {
    let mut digest = [0u8; SHA1_DIGESTSIZE];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_sha1(
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            digest.as_mut_ptr(),
            SHA1_DIGESTSIZE as kcapi_sys::size_t,
        );
    }

    if ret != SHA1_DIGESTSIZE as kcapi_sys::ssize_t {
        return Err(KcapiError {
            code: ret,
            message: "Failed to generate message digest".to_string(),
        });
    }

    Ok(digest)
}

///
/// ## Calculate a SHA-224 message digest on an input buffer
///
/// With this one-shot convenience function the SHA-224 message digest of an
/// input buffer can be obtained.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`
///
/// On success, a `[u8; SHA224_DIGESTSIZE]` is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let digest = kcapi::md::sha224("Hello, World!".as_bytes().to_vec());
/// ```
///
pub fn sha224(input: Vec<u8>) -> KcapiResult<[u8; SHA224_DIGESTSIZE]> {
    let mut digest = [0u8; SHA224_DIGESTSIZE];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_sha224(
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            digest.as_mut_ptr(),
            SHA224_DIGESTSIZE as kcapi_sys::size_t,
        );
    }

    if ret != SHA224_DIGESTSIZE as kcapi_sys::ssize_t {
        return Err(KcapiError {
            code: ret,
            message: "Failed to generate message digest".to_string(),
        });
    }

    Ok(digest)
}

///
/// ## Calculate a SHA-256 message digest on an input buffer
///
/// With this one-shot convenience function the SHA-256 message digest of an
/// input buffer can be obtained.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`
///
/// On success, a `[u8; SHA256_DIGESTSIZE]` is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let digest = kcapi::md::sha256("Hello, World!".as_bytes().to_vec());
/// ```
///
pub fn sha256(input: Vec<u8>) -> KcapiResult<[u8; SHA256_DIGESTSIZE]> {
    let mut digest = [0u8; SHA256_DIGESTSIZE];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_sha256(
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            digest.as_mut_ptr(),
            SHA256_DIGESTSIZE as kcapi_sys::size_t,
        );
    }

    if ret != SHA256_DIGESTSIZE as kcapi_sys::ssize_t {
        return Err(KcapiError {
            code: ret,
            message: "Failed to generate message digest".to_string(),
        });
    }

    Ok(digest)
}

///
/// ## Calculate a SHA-384 message digest on an input buffer
///
/// With this one-shot convenience function the SHA-384 message digest of an
/// input buffer can be obtained.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`
///
/// On success, a `[u8; SHA384_DIGESTSIZE]` is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let digest = kcapi::md::sha384("Hello, World!".as_bytes().to_vec());
/// ```
///
pub fn sha384(input: Vec<u8>) -> KcapiResult<[u8; SHA384_DIGESTSIZE]> {
    let mut digest = [0u8; SHA384_DIGESTSIZE];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_sha384(
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            digest.as_mut_ptr(),
            SHA384_DIGESTSIZE as kcapi_sys::size_t,
        );
    }

    if ret != SHA384_DIGESTSIZE as kcapi_sys::ssize_t {
        return Err(KcapiError {
            code: ret,
            message: "Failed to generate message digest".to_string(),
        });
    }

    Ok(digest)
}

///
/// ## Calculate a SHA-512 message digest on an input buffer
///
/// With this one-shot convenience function the SHA-512 message digest of an
/// input buffer can be obtained.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`
///
/// On success, a `[u8; SHA512_DIGESTSIZE]` is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let digest = kcapi::md::sha512("Hello, World!".as_bytes().to_vec());
/// ```
///
pub fn sha512(input: Vec<u8>) -> KcapiResult<[u8; SHA512_DIGESTSIZE]> {
    let mut digest = [0u8; SHA512_DIGESTSIZE];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_sha512(
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            digest.as_mut_ptr(),
            SHA512_DIGESTSIZE as kcapi_sys::size_t,
        );
    }

    if ret != SHA512_DIGESTSIZE as kcapi_sys::ssize_t {
        return Err(KcapiError {
            code: ret,
            message: "Failed to generate message digest".to_string(),
        });
    }

    Ok(digest)
}

///
/// ## Calculate HMAC SHA-1 keyed message digest on an input buffer
///
/// With this one-shot convenience function, the HMAC SHA-1 keyed message digest
/// of an input buffer can be obtained.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`.
/// The input key must be a `Vec<u8>`.
///
/// On success a `[u8; SHA1_DIGESTSIZE]` is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let key = vec![0xffu8; 16];
/// let hmac = kcapi::md::hmac_sha1("Hello, World!".as_bytes().to_vec(), key);
/// ```
///
pub fn hmac_sha1(input: Vec<u8>, key: Vec<u8>) -> KcapiResult<[u8; SHA1_DIGESTSIZE]> {
    let mut hmac = [0u8; SHA1_DIGESTSIZE];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_hmac_sha1(
            key.as_ptr(),
            key.len() as u32,
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            hmac.as_mut_ptr(),
            hmac.len() as kcapi_sys::size_t,
        );
    }

    if ret != SHA1_DIGESTSIZE as kcapi_sys::ssize_t {
        return Err(KcapiError {
            code: ret,
            message: "Failed to generate message hmac".to_string(),
        });
    }

    Ok(hmac)
}

///
/// ## Calculate HMAC SHA-224 keyed message digest on an input buffer
///
/// With this one-shot convenience function, the HMAC SHA-224 keyed message digest
/// of an input buffer can be obtained.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`.
/// The input key must be a `Vec<u8>`.
///
/// On success a `[u8; SHA224_DIGESTSIZE]` is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let key = vec![0xffu8; 16];
/// let hmac = kcapi::md::hmac_sha224("Hello, World!".as_bytes().to_vec(), key);
/// ```
///
pub fn hmac_sha224(input: Vec<u8>, key: Vec<u8>) -> KcapiResult<[u8; SHA224_DIGESTSIZE]> {
    let mut hmac = [0u8; SHA224_DIGESTSIZE];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_hmac_sha224(
            key.as_ptr(),
            key.len() as u32,
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            hmac.as_mut_ptr(),
            hmac.len() as kcapi_sys::size_t,
        );
    }

    if ret != SHA224_DIGESTSIZE as kcapi_sys::ssize_t {
        return Err(KcapiError {
            code: ret,
            message: "Failed to generate message hmac".to_string(),
        });
    }

    Ok(hmac)
}

///
/// ## Calculate HMAC SHA-256 keyed message digest on an input buffer
///
/// With this one-shot convenience function, the HMAC SHA-256 keyed message digest
/// of an input buffer can be obtained.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`.
/// The input key must be a `Vec<u8>`.
///
/// On success a `[u8; SHA256_DIGESTSIZE]` is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let key = vec![0xffu8; 16];
/// let hmac = kcapi::md::hmac_sha256("Hello, World!".as_bytes().to_vec(), key);
/// ```
///
pub fn hmac_sha256(input: Vec<u8>, key: Vec<u8>) -> KcapiResult<[u8; SHA256_DIGESTSIZE]> {
    let mut hmac = [0u8; SHA256_DIGESTSIZE];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_hmac_sha256(
            key.as_ptr(),
            key.len() as u32,
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            hmac.as_mut_ptr(),
            hmac.len() as kcapi_sys::size_t,
        );
    }

    if ret != SHA256_DIGESTSIZE as kcapi_sys::ssize_t {
        return Err(KcapiError {
            code: ret,
            message: "Failed to generate message hmac".to_string(),
        });
    }

    Ok(hmac)
}

///
/// ## Calculate HMAC SHA-384 keyed message digest on an input buffer
///
/// With this one-shot convenience function, the HMAC SHA-384 keyed message digest
/// of an input buffer can be obtained.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`.
/// The input key must be a `Vec<u8>`.
///
/// On success a `[u8; SHA384_DIGESTSIZE]` is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let key = vec![0xffu8; 16];
/// let hmac = kcapi::md::hmac_sha384("Hello, World!".as_bytes().to_vec(), key);
/// ```
///
pub fn hmac_sha384(input: Vec<u8>, key: Vec<u8>) -> KcapiResult<[u8; SHA384_DIGESTSIZE]> {
    let mut hmac = [0u8; SHA384_DIGESTSIZE];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_hmac_sha384(
            key.as_ptr(),
            key.len() as u32,
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            hmac.as_mut_ptr(),
            hmac.len() as kcapi_sys::size_t,
        );
    }

    if ret != SHA384_DIGESTSIZE as kcapi_sys::ssize_t {
        return Err(KcapiError {
            code: ret,
            message: "Failed to generate message hmac".to_string(),
        });
    }

    Ok(hmac)
}

///
/// ## Calculate HMAC SHA-512 keyed message digest on an input buffer
///
/// With this one-shot convenience function, the HMAC SHA-512 keyed message digest
/// of an input buffer can be obtained.
/// The input buffer must be a `Vec<u8>` of size less than `INT_MAX`.
/// The input key must be a `Vec<u8>`.
///
/// On success a `[u8; SHA512_DIGESTSIZE]` is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let key = vec![0xffu8; 16];
/// let hmac = kcapi::md::hmac_sha512("Hello, World!".as_bytes().to_vec(), key);
/// ```
///
pub fn hmac_sha512(input: Vec<u8>, key: Vec<u8>) -> KcapiResult<[u8; SHA512_DIGESTSIZE]> {
    let mut hmac = [0u8; SHA512_DIGESTSIZE];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_hmac_sha512(
            key.as_ptr(),
            key.len() as u32,
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            hmac.as_mut_ptr(),
            hmac.len() as kcapi_sys::size_t,
        );
    }

    if ret != SHA512_DIGESTSIZE as kcapi_sys::ssize_t {
        return Err(KcapiError {
            code: ret,
            message: "Failed to generate message hmac".to_string(),
        });
    }

    Ok(hmac)
}
