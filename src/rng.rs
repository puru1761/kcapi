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

use crate::{KcapiError, KcapiHandle, KcapiResult};

pub fn init(algorithm: &str, flags: u32) -> KcapiResult<KcapiHandle> {
    let alg = CString::new(algorithm).expect("Failed to allocate a CString");
    let mut handle = KcapiHandle::new(algorithm, crate::KcapiAlgType::RNG);

    unsafe {
        let ret = kcapi_sys::kcapi_rng_init(&mut handle.handle as *mut _, alg.as_ptr(), flags);
        if ret < 0 {
            return Err(KcapiError {
                code: ret.into(),
                message: format!(
                    "Failed to initialize RNG handle for algorithm '{}'",
                    algorithm
                ),
            });
        }
    }
    Ok(handle)
}

pub fn seed(handle: &KcapiHandle, seed: Vec<u8>) -> KcapiResult<()> {
    let mut seed_data = seed;
    unsafe {
        let ret = kcapi_sys::kcapi_rng_seed(
            handle.handle,
            seed_data.as_mut_ptr(),
            seed_data.len() as u32,
        );
        if ret < 0 {
            return Err(KcapiError {
                code: ret.into(),
                message: format!("Failed to seed RNG for algorithm '{}'", handle.algorithm),
            });
        }
    }
    Ok(())
}

pub fn generate(handle: &KcapiHandle, count: usize) -> KcapiResult<Vec<u8>> {
    let mut out = vec![0u8; count];
    unsafe {
        let ret = kcapi_sys::kcapi_rng_generate(
            handle.handle,
            out.as_mut_ptr(),
            count as kcapi_sys::size_t,
        );
        if ret < 0 {
            return Err(KcapiError {
                code: ret,
                message: format!(
                    "Failed to obtain {} bytes from the RNG '{}'",
                    count, handle.algorithm
                ),
            });
        }
    }

    Ok(out)
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

pub fn seedsize(handle: &KcapiHandle) -> KcapiResult<usize> {
    let ret: u32;
    unsafe {
        ret = kcapi_sys::kcapi_rng_seedsize(handle.handle);
        if ret == 0 {
            return Err(KcapiError {
                code: ret.into(),
                message: format!("Failed to obtain seedsize for RNG '{}'", handle.algorithm),
            });
        }
    }
    let seed_size: usize = ret.try_into().expect("Failed to convert u32 into usize");

    Ok(seed_size)
}
