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

use crate::{
    KcapiError, KcapiHandle, KcapiResult, BITS_PER_BYTE,
};

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


pub fn init(algorithm: &str, flags: u32) -> KcapiResult<KcapiHandle> {
    let mut handle = KcapiHandle::new(algorithm);
    let alg = CString::new(algorithm).expect("Failed to convert to CString");

    let ret: i32;
    unsafe {
        ret = kcapi_sys::kcapi_md_init(&mut handle.handle as *mut _, alg.as_ptr(), flags);
        if ret < 0 {
            return Err(KcapiError {
                code: ret.try_into().expect("Failed to convert i32 to kcapi_sys::ssize_t"),
                message: "Failed to init Message Digest Handle".to_string(),
            });
        }
    }

    Ok(handle)
}

pub fn setkey(handle: &KcapiHandle, key: Vec<u8>) -> KcapiResult<()> {
    let ret: i32;
    unsafe {
        ret = kcapi_sys::kcapi_md_setkey(handle.handle, key.as_ptr(), key.len() as u32);
        if ret < 0 {
            return Err(KcapiError {
                code: ret.try_into().expect("Failed to convert i32 to kcapi_sys::ssize_t"),
                message: "Failed to set key for keyed message digest".to_string(),
            });
        }
    }
    Ok(())
}

pub fn update(handle: &KcapiHandle, buffer: Vec<u8>) -> KcapiResult<()> {
    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_md_update(
            handle.handle,
            buffer.as_ptr(),
            buffer.len() as kcapi_sys::size_t,
        );

        if ret < 0 {
            return Err(KcapiError {
                code: ret,
                message: "Failed to update digest".to_string(),
            });
        }
    }
    Ok(())
}

pub fn destroy(handle: KcapiHandle) {
    unsafe {
        kcapi_sys::kcapi_md_destroy(handle.handle);
    }
}

pub fn digestsize(handle: &KcapiHandle) -> KcapiResult<usize> {
    let digest_size: usize;
    let ret: u32;
    unsafe {
        ret = kcapi_sys::kcapi_md_digestsize(handle.handle);
        if ret == 0 {
            return Err(KcapiError {
                code: -1,
                message:
                    format!("Failed to obtain digestsize for '{}'", handle.algorithm),
            });
        }
        digest_size = ret.try_into().expect("Failed to convert u32 into usize");
    }
    Ok(digest_size)
}

pub fn digest_final(handle: KcapiHandle) -> KcapiResult<Vec<u8>> {
    let ret: kcapi_sys::ssize_t;
    let mut digest: Vec<u8>;

    unsafe {
        let outlen: usize = (kcapi_sys::kcapi_md_digestsize(handle.handle))
            .try_into()
            .expect("Failed to convert u32 to usize");
        if outlen == 0 {
            return Err(KcapiError {
                code: -1,
                message: format!(
                    "Failed to obtain digestsize for algorithm {}",
                    handle.algorithm
                ),
            });
        }
        digest = vec![0u8; outlen];

        ret = kcapi_sys::kcapi_md_final(
            handle.handle,
            digest.as_mut_ptr(),
            outlen as kcapi_sys::size_t,
        );
        if ret < 0 {
            return Err(KcapiError {
                code: ret,
                message: "Failed to finalize message digest".to_string(),
            });
        }
    }
    Ok(digest)
}

pub fn digest(handle: KcapiHandle, input: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let mut output: Vec<u8>;

    let ret: kcapi_sys::ssize_t;
    unsafe {
        let outlen: u32 = kcapi_sys::kcapi_md_digestsize(handle.handle);
        if outlen == 0 {
            return Err(KcapiError {
                code: -1,
                message: format!(
                    "Failed to obtain digestsize for algorithm {}",
                    handle.algorithm
                ),
            });
        }
        output = vec![0u8; outlen as usize];

        ret = kcapi_sys::kcapi_md_digest(
            handle.handle,
            input.as_ptr(),
            input.len() as kcapi_sys::size_t,
            output.as_mut_ptr(),
            outlen as kcapi_sys::size_t,
        );
        if ret != outlen as kcapi_sys::ssize_t {
            return Err(KcapiError {
                code: ret,
                message: "Failed to obtain message digest.".to_string(),
            });
        }
    }

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