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

use crate::{KcapiError, KcapiHandle, KcapiResult, BITS_PER_BYTE};

const AES_BLOCKSIZE_BITS: usize = 128;
const AES128_KEYSIZE_BITS: usize = 128;
const AES192_KEYSIZE_BITS: usize = 192;
const AES256_KEYSIZE_BITS: usize = 256;

pub const AES_BLOCKSIZE: usize = AES_BLOCKSIZE_BITS / BITS_PER_BYTE;
pub const AES128_KEYSIZE: usize = AES128_KEYSIZE_BITS / BITS_PER_BYTE;
pub const AES192_KEYSIZE: usize = AES192_KEYSIZE_BITS / BITS_PER_BYTE;
pub const AES256_KEYSIZE: usize = AES256_KEYSIZE_BITS / BITS_PER_BYTE;

pub fn alg_ivsize(handle: &KcapiHandle) -> KcapiResult<usize> {
    let ivlen: usize;
    unsafe {
        ivlen = kcapi_sys::kcapi_cipher_ivsize(handle.handle)
            .try_into()
            .expect("Failed to convert u32 into usize");
        if ivlen == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Could not find IV size for algorithm '{}'",
                    handle.algorithm
                ),
            });
        }
    }
    Ok(ivlen)
}

fn check_ivsize(handle: &KcapiHandle, iv: &[u8]) -> KcapiResult<()> {
    let alg_ivsize = crate::skcipher::alg_ivsize(handle)?;
    if iv.len() != alg_ivsize {
        return Err(KcapiError {
            code: -libc::EINVAL as i64,
            message: format!("Invald IV Size for algorithm '{}'", handle.algorithm),
        });
    }
    Ok(())
}

pub fn alg_blocksize(handle: &KcapiHandle) -> KcapiResult<usize> {
    let blocklen: usize;
    unsafe {
        blocklen = kcapi_sys::kcapi_cipher_blocksize(handle.handle)
            .try_into()
            .expect("Failed to convert u32 into usize");
        if blocklen == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Could not find block size for algorithm '{}'",
                    handle.algorithm
                ),
            });
        }
    }
    Ok(blocklen)
}

fn check_blocksize(handle: &KcapiHandle, input: &[u8]) -> KcapiResult<()> {
    let alg_blocksize = crate::skcipher::alg_blocksize(handle)?;
    if input.len() % alg_blocksize != 0 {
        return Err(KcapiError {
            code: -libc::EINVAL as i64,
            message: format!("Invalid block size for algorithm '{}'", handle.algorithm),
        });
    }
    Ok(())
}

pub fn alg_init(algorithm: &str, flags: u32) -> KcapiResult<KcapiHandle> {
    let mut handle = KcapiHandle::new(algorithm, crate::KcapiAlgType::SKCipher);
    let alg = CString::new(algorithm).expect("Failed to create new CString");

    let ret: ::std::os::raw::c_int;
    unsafe {
        ret = kcapi_sys::kcapi_cipher_init(&mut handle.handle as *mut _, alg.as_ptr(), flags);
        if ret < 0 {
            return Err(KcapiError {
                code: ret.into(),
                message: format!("Failed to initialize cipher handle for '{}'", algorithm),
            });
        }
    }
    Ok(handle)
}

pub fn alg_setkey(handle: &KcapiHandle, key: Vec<u8>) -> KcapiResult<()> {
    // TODO: Need a function from upstream to check max and min keysizes
    // for skcipher type algorithms. Until we have this, this function will
    // fail when a key with invalid size is provided.
    unsafe {
        let ret: ::std::os::raw::c_int;
        ret = kcapi_sys::kcapi_cipher_setkey(
            handle.handle,
            key.as_ptr(),
            key.len()
                .try_into()
                .expect("Failed to convert usize into u32"),
        );
        if ret < 0 {
            return Err(KcapiError {
                code: ret.into(),
                message: format!("setkey failed for algorithm '{}'", handle.algorithm),
            });
        }
    }
    Ok(())
}

pub fn alg_encrypt(
    handle: KcapiHandle,
    pt: Vec<u8>,
    iv: Vec<u8>,
    access: u32,
) -> KcapiResult<Vec<u8>> {
    let mut ct: Vec<u8>;

    check_ivsize(&handle, &iv)?;
    check_blocksize(&handle, &pt)?;
    ct = vec![0u8; pt.len()];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_cipher_encrypt(
            handle.handle,
            pt.as_ptr(),
            pt.len() as kcapi_sys::size_t,
            iv.as_ptr(),
            ct.as_mut_ptr(),
            ct.len() as kcapi_sys::size_t,
            access as ::std::os::raw::c_int,
        );
        if ret < 0 {
            return Err(KcapiError {
                code: ret,
                message: format!(
                    "Failed cipher operation for algorithm '{}'",
                    handle.algorithm
                ),
            });
        }
    }

    Ok(ct)
}

pub fn alg_decrypt(
    handle: KcapiHandle,
    ct: Vec<u8>,
    iv: Vec<u8>,
    access: u32,
) -> KcapiResult<Vec<u8>> {
    let mut pt: Vec<u8>;

    check_ivsize(&handle, &iv)?;
    check_blocksize(&handle, &ct)?;
    pt = vec![0u8; ct.len()];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_cipher_decrypt(
            handle.handle,
            ct.as_ptr(),
            ct.len() as kcapi_sys::size_t,
            iv.as_ptr(),
            pt.as_mut_ptr(),
            ct.len() as kcapi_sys::size_t,
            access as ::std::os::raw::c_int,
        );
        if ret < 0 {
            return Err(KcapiError {
                code: ret,
                message: format!(
                    "Failed cipher operation for algorithm '{}'",
                    handle.algorithm
                ),
            });
        }
    }

    Ok(pt)
}

pub fn encrypt(
    alg: &str,
    key: Vec<u8>,
    pt: Vec<u8>,
    iv: Vec<u8>,
    access: u32,
    flags: u32,
) -> KcapiResult<Vec<u8>> {
    let handle = crate::skcipher::alg_init(alg, flags)?;
    crate::skcipher::alg_setkey(&handle, key)?;
    let ct = crate::skcipher::alg_encrypt(handle, pt, iv, access)?;

    Ok(ct)
}

pub fn decrypt(
    alg: &str,
    key: Vec<u8>,
    ct: Vec<u8>,
    iv: Vec<u8>,
    access: u32,
    flags: u32,
) -> KcapiResult<Vec<u8>> {
    let handle = crate::skcipher::alg_init(alg, flags)?;
    crate::skcipher::alg_setkey(&handle, key)?;
    let pt = crate::skcipher::alg_decrypt(handle, ct, iv, access)?;

    Ok(pt)
}

fn check_aes_input(key: &[u8], input: &[u8]) -> KcapiResult<()> {
    if input.len() % AES_BLOCKSIZE != 0 {
        return Err(KcapiError {
            code: (-libc::EINVAL).into(),
            message: format!(
                "Input plaintext must be a multiple of {} bytes",
                AES_BLOCKSIZE
            ),
        });
    }

    let keylen = key.len();
    match keylen {
        AES128_KEYSIZE => {}
        AES192_KEYSIZE => {}
        AES256_KEYSIZE => {}
        _ => {
            return Err(KcapiError {
                code: (-libc::EINVAL).into(),
                message: format!(
                    "Key must be {}, {}, or {} bytes long",
                    AES128_KEYSIZE, AES192_KEYSIZE, AES256_KEYSIZE
                ),
            })
        }
    }

    Ok(())
}

pub fn enc_aes_cbc(key: Vec<u8>, pt: Vec<u8>, iv: [u8; AES_BLOCKSIZE]) -> KcapiResult<Vec<u8>> {
    let mut ct: Vec<u8>;

    check_aes_input(&key, &pt)?;
    ct = vec![0u8; pt.len()];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_cipher_enc_aes_cbc(
            key.as_ptr(),
            key.len()
                .try_into()
                .expect("Failed to convert usize to u32"),
            pt.as_ptr(),
            pt.len() as kcapi_sys::size_t,
            iv.as_ptr(),
            ct.as_mut_ptr(),
            ct.len() as kcapi_sys::size_t,
        );
    }
    if ret < 0 {
        return Err(KcapiError {
            code: ret,
            message: "Failed skcipher operation".to_string(),
        });
    }
    Ok(ct)
}

pub fn dec_aes_cbc(key: Vec<u8>, ct: Vec<u8>, iv: [u8; AES_BLOCKSIZE]) -> KcapiResult<Vec<u8>> {
    let mut pt: Vec<u8>;

    check_aes_input(&key, &ct)?;
    pt = vec![0u8; ct.len()];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_cipher_dec_aes_cbc(
            key.as_ptr(),
            key.len()
                .try_into()
                .expect("Failed to convert usize to u32"),
            ct.as_ptr(),
            ct.len() as kcapi_sys::size_t,
            iv.as_ptr(),
            pt.as_mut_ptr(),
            pt.len() as kcapi_sys::size_t,
        );
    }
    if ret < 0 {
        return Err(KcapiError {
            code: ret,
            message: "Failed skcipher operation".to_string(),
        });
    }

    Ok(pt)
}

pub fn enc_aes_ctr(key: Vec<u8>, pt: Vec<u8>, ctr: [u8; AES_BLOCKSIZE]) -> KcapiResult<Vec<u8>> {
    let mut ct: Vec<u8>;

    check_aes_input(&key, &pt)?;
    ct = vec![0u8; pt.len()];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_cipher_enc_aes_ctr(
            key.as_ptr(),
            key.len()
                .try_into()
                .expect("Failed to convert usize to u32"),
            pt.as_ptr(),
            pt.len() as kcapi_sys::size_t,
            ctr.as_ptr(),
            ct.as_mut_ptr(),
            ct.len() as kcapi_sys::size_t,
        );
    }
    if ret < 0 {
        return Err(KcapiError {
            code: ret,
            message: "Failed skcipher operation".to_string(),
        });
    }
    Ok(ct)
}

pub fn dec_aes_ctr(key: Vec<u8>, ct: Vec<u8>, ctr: [u8; AES_BLOCKSIZE]) -> KcapiResult<Vec<u8>> {
    let mut pt: Vec<u8>;

    check_aes_input(&key, &ct)?;
    pt = vec![0u8; ct.len()];

    let ret: kcapi_sys::ssize_t;
    unsafe {
        ret = kcapi_sys::kcapi_cipher_dec_aes_ctr(
            key.as_ptr(),
            key.len()
                .try_into()
                .expect("Failed to convert usize to u32"),
            ct.as_ptr(),
            ct.len() as kcapi_sys::size_t,
            ctr.as_ptr(),
            pt.as_mut_ptr(),
            pt.len() as kcapi_sys::size_t,
        );
    }
    if ret < 0 {
        return Err(KcapiError {
            code: ret,
            message: "Failed skcipher operation".to_string(),
        });
    }

    Ok(pt)
}
