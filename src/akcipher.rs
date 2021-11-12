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

use crate::{KcapiError, KcapiResult, ACCESS_HEURISTIC, INIT_AIO};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KcapiAKCipher {
    handle: *mut kcapi_sys::kcapi_handle,
    pubkey: Vec<u8>,
    privkey: Vec<u8>,
    pub modsize: usize,
    pub algorithm: String,
}

impl KcapiAKCipher {
    pub fn new(algorithm: &str, flags: u32) -> KcapiResult<Self> {
        let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;
        let pubkey = Vec::<u8>::new();
        let privkey = Vec::<u8>::new();

        let alg = CString::new(algorithm).expect("Failed to create CString");
        unsafe {
            let ret = kcapi_sys::kcapi_akcipher_init(&mut handle as *mut _, alg.as_ptr(), flags);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!(
                        "Failed to initialize akcipher handle for algorithm '{}'",
                        algorithm
                    ),
                });
            }
        }

        Ok(KcapiAKCipher {
            algorithm: algorithm.to_string(),
            handle,
            modsize: 0,
            pubkey,
            privkey,
        })
    }

    pub fn setprivkey(&mut self, privkey: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_akcipher_setkey(
                self.handle,
                privkey.as_ptr(),
                privkey.len() as u32,
            );

            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!(
                        "Failed to set private key for algorithm '{}'",
                        self.algorithm
                    ),
                });
            }
            self.modsize = ret.try_into().expect("Failed to convert i32 into usize");
            self.privkey = privkey;
        }

        Ok(())
    }

    pub fn setpubkey(&mut self, pubkey: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_akcipher_setpubkey(
                self.handle,
                pubkey.as_ptr(),
                pubkey.len() as u32,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!(
                        "Failed to set public key for algorithm '{}'",
                        self.algorithm
                    ),
                });
            }
            self.modsize = ret.try_into().expect("Failed to convert i32 into usize");
            self.pubkey = pubkey;
        }
        Ok(())
    }

    pub fn encrypt(&self, pt: Vec<u8>, access: u32) -> KcapiResult<Vec<u8>> {
        crate::akcipher::check_input(self, pt.clone())?;

        let mut ct = vec![0u8; self.modsize];
        unsafe {
            let ret = kcapi_sys::kcapi_akcipher_encrypt(
                self.handle,
                pt.as_ptr(),
                pt.len() as kcapi_sys::size_t,
                ct.as_mut_ptr(),
                ct.len() as kcapi_sys::size_t,
                access as i32,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!("Failed to encrypt for algorithm '{}'", self.algorithm),
                });
            }
        }
        Ok(ct)
    }

    pub fn decrypt(&self, ct: Vec<u8>, access: u32) -> KcapiResult<Vec<u8>> {
        crate::akcipher::check_input(self, ct.clone())?;

        let mut pt = vec![0u8; self.modsize];
        unsafe {
            let ret = kcapi_sys::kcapi_akcipher_decrypt(
                self.handle,
                ct.as_ptr(),
                ct.len() as kcapi_sys::size_t,
                pt.as_mut_ptr(),
                pt.len() as kcapi_sys::size_t,
                access as ::std::os::raw::c_int,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!("Failed to decrypt for algorithm '{}'", self.algorithm),
                });
            }
        }
        Ok(pt)
    }

    pub fn sign(&self, message: Vec<u8>, access: u32) -> KcapiResult<Vec<u8>> {
        crate::akcipher::check_input(self, message.clone())?;

        let mut sig = vec![0u8; self.modsize];
        unsafe {
            let ret = kcapi_sys::kcapi_akcipher_sign(
                self.handle,
                message.as_ptr(),
                message.len() as kcapi_sys::size_t,
                sig.as_mut_ptr(),
                sig.len() as kcapi_sys::size_t,
                access as ::std::os::raw::c_int,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!("Failed to sign for algorithm '{}'", self.algorithm),
                });
            }
        }
        Ok(sig)
    }

    pub fn verify(&self, message: Vec<u8>, sig: Vec<u8>, access: u32) -> KcapiResult<()> {
        crate::akcipher::check_input(self, sig.clone())?;

        let mut inp = Vec::new();
        inp.extend(sig.iter().copied());
        inp.extend(message.iter().copied());

        let mut out = vec![0u8; self.modsize];
        unsafe {
            let ret = kcapi_sys::kcapi_akcipher_verify(
                self.handle,
                inp.as_ptr(),
                inp.len() as kcapi_sys::size_t,
                out.as_mut_ptr(),
                out.len() as kcapi_sys::size_t,
                access as ::std::os::raw::c_int,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: -libc::EBADMSG as i64,
                    message: format!(
                        "Failed to verify signature for algorithm '{}'",
                        self.algorithm
                    ),
                });
            }
        }
        Ok(())
    }
}

fn check_input(handle: &KcapiAKCipher, inp: Vec<u8>) -> KcapiResult<()> {
    if handle.privkey.is_empty() && handle.pubkey.is_empty() {
        return Err(KcapiError {
            code: -libc::EINVAL as i64,
            message: format!(
                "Required asymmetric key is not set for algorithm '{}'",
                handle.algorithm
            ),
        });
    }
    if inp.len() > handle.modsize {
        return Err(KcapiError {
            code: -libc::EINVAL as i64,
            message: format!(
                "Input to asymmetric cipher is larger than modulus size for algorithm {}",
                handle.algorithm
            ),
        });
    }
    Ok(())
}

pub fn encrypt(alg: &str, key: Vec<u8>, pt: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let mut handle = KcapiAKCipher::new(alg, !INIT_AIO)?;
    handle.setpubkey(key)?;
    let ct = handle.encrypt(pt, ACCESS_HEURISTIC)?;
    Ok(ct)
}

pub fn decrypt(alg: &str, key: Vec<u8>, ct: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let mut handle = KcapiAKCipher::new(alg, !INIT_AIO)?;
    handle.setprivkey(key)?;
    let pt = handle.decrypt(ct, ACCESS_HEURISTIC)?;
    Ok(pt)
}

pub fn sign(alg: &str, key: Vec<u8>, message: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let mut handle = KcapiAKCipher::new(alg, !INIT_AIO)?;
    handle.setprivkey(key)?;
    let sig = handle.sign(message, ACCESS_HEURISTIC)?;
    Ok(sig)
}

pub fn verify(alg: &str, key: Vec<u8>, message: Vec<u8>, sig: Vec<u8>) -> KcapiResult<()> {
    let mut handle = KcapiAKCipher::new(alg, !INIT_AIO)?;
    handle.setpubkey(key)?;
    handle.verify(message, sig, ACCESS_HEURISTIC)?;
    Ok(())
}
