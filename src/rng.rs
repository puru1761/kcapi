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

use crate::{KcapiError, KcapiResult};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KcapiRNG {
    handle: *mut kcapi_sys::kcapi_handle,
    pub algorithm: String,
    pub seedsize: usize,
}

impl KcapiRNG {
    pub fn new(algorithm: &str, flags: u32) -> KcapiResult<Self> {
        let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;

        let alg = CString::new(algorithm).expect("Failed to create CString");
        let seedsize: usize;

        unsafe {
            let ret = kcapi_sys::kcapi_rng_init(&mut handle as *mut _, alg.as_ptr(), flags);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
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

    pub fn seed(&self, mut data: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_rng_seed(self.handle, data.as_mut_ptr(), data.len() as u32);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!("Failed to seed RNG for algorithm '{}'", self.algorithm,),
                });
            }
        }
        Ok(())
    }

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
                    code: ret,
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

pub fn get_bytes(count: usize) -> KcapiResult<Vec<u8>> {
    let mut out = vec![0u8; count];
    unsafe {
        let ret = kcapi_sys::kcapi_rng_get_bytes(out.as_mut_ptr(), count as kcapi_sys::size_t);
        if ret < 0 {
            return Err(KcapiError {
                code: ret,
                message: format!("Failed to obtain {} bytes from the stdrng", count),
            });
        }
    }

    Ok(out)
}
