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

use std::ffi::CString;

use crate::{KcapiError, KcapiResult, KCAPI_INIT_AIO};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KcapiKDF {
    handle: *mut kcapi_sys::kcapi_handle,
    iteration_count: u32,
    key: Vec<u8>,
    pub algorithm: String,
}

impl KcapiKDF {
    pub fn new(algorithm: &str) -> KcapiResult<Self> {
        let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;

        let alg = CString::new(algorithm).expect("Failed to allocate Cstring");
        let iteration_count: u32;
        unsafe {
            iteration_count = kcapi_sys::kcapi_pbkdf_iteration_count(alg.as_ptr(), 0);

            let ret =
                kcapi_sys::kcapi_md_init(&mut handle as *mut _, alg.as_ptr(), !KCAPI_INIT_AIO);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!(
                        "Failed to Initialize hash handle for algorithm '{}'",
                        algorithm,
                    ),
                });
            }
        }

        let key: Vec<u8> = Vec::new();
        Ok(KcapiKDF {
            handle,
            iteration_count,
            key,
            algorithm: algorithm.to_string(),
        })
    }

    pub fn setkey(&mut self, key: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_md_setkey(self.handle, key.as_ptr(), key.len() as u32);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!("Failed to set key for KDF algorithm '{}'", self.algorithm,),
                });
            }
        }
        self.key = key;
        Ok(())
    }

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
                    code: ret,
                    message: format!(
                        "Failed to generate key for KDF algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        Ok(out)
    }

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
                    code: ret,
                    message: format!(
                        "Failed to generate key for KDF algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        Ok(out)
    }

    pub fn fb_kdf(&self, input: Vec<u8>, outsize: usize) -> KcapiResult<Vec<u8>> {
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
                    code: ret,
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
            code: -libc::EINVAL as i64,
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
                code: ret,
                message: format!("Failed HKDF operation for algorithm '{}'", hashname,),
            });
        }
    }
    Ok(out)
}

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
            code: -libc::EINVAL as i64,
            message: format!("Invalid input to PBKDF algorithm '{}'", hashname),
        });
    }

    let hash = CString::new(hashname).expect("Failed to allocate CString");
    unsafe {
        let iter = kcapi_sys::kcapi_pbkdf_iteration_count(hash.as_ptr(), 0);
        if iterations == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
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
                code: ret,
                message: format!("Failed PBKDF operation for algorithm '{}'", hashname,),
            });
        }
    }
    Ok(out)
}
