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

use std::{convert::TryInto, ffi::CString};

use crate::{KcapiError, KcapiResult, BITS_PER_BYTE};

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

pub struct KcapiHash {
    handle: *mut kcapi_sys::kcapi_handle,
    key: Vec<u8>,
    pub algorithm: String,
    pub blocksize: usize,
    pub digestsize: usize,
}

impl KcapiHash {
    pub fn new(algorithm: &str, flags: u32) -> KcapiResult<Self> {
        let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;
        let digestsize: usize;
        let blocksize: usize;

        let alg = CString::new(algorithm).expect("Failed to create CString");
        unsafe {
            let ret = kcapi_sys::kcapi_md_init(&mut handle as *mut _, alg.as_ptr(), flags);
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

pub fn digest(alg: &str, input: Vec<u8>, flags: u32) -> KcapiResult<Vec<u8>> {
    let hash = crate::md::KcapiHash::new(alg, flags)?;
    hash.update(input)?;
    let output = hash.finalize()?;

    Ok(output)
}

pub fn keyed_digest(alg: &str, key: Vec<u8>, input: Vec<u8>, flags: u32) -> KcapiResult<Vec<u8>> {
    let mut hmac = crate::md::KcapiHash::new(alg, flags)?;
    hmac.setkey(key)?;
    hmac.update(input)?;
    let output = hmac.finalize()?;

    Ok(output)
}

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
