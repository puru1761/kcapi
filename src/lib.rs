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

use std::fmt;

const BITS_PER_BYTE: usize = 8;

pub const KCAPI_ACCESS_HEURISTIC: u32 = kcapi_sys::KCAPI_ACCESS_HEURISTIC;
pub const KCAPI_ACCESS_VMSPLICE: u32 = kcapi_sys::KCAPI_ACCESS_VMSPLICE;
pub const KCAPI_ACCESS_SENDMSG: u32 = kcapi_sys::KCAPI_ACCESS_SENDMSG;

pub const KCAPI_INIT_AIO: u32 = kcapi_sys::KCAPI_INIT_AIO;

#[derive(Debug, Clone, Copy)]
pub enum KcapiAlgType {
    Hash = 1,
    SKCipher,
    AEAD,
    AKCipher,
    RNG,
}

pub type KcapiResult<T> = std::result::Result<T, KcapiError>;

#[derive(Debug, Clone)]
pub struct KcapiError {
    code: i64,
    message: String,
}

impl fmt::Display for KcapiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({})", &self.message, &self.code)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct kcapi_handle {
    _unused: [u8; 0],
}

#[derive(Debug, Clone)]
pub struct KcapiHandle {
    algorithm: String,
    alg_type: KcapiAlgType,
    handle: *mut kcapi_sys::kcapi_handle,
}

impl KcapiHandle {
    fn new(alg: &str, alg_type: KcapiAlgType) -> Self {
        let handle = Box::into_raw(Box::new(kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;
        KcapiHandle {
            algorithm: alg.to_string(),
            alg_type,
            handle,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IOVec {
    iovec: Vec<kcapi_sys::iovec>,
    iovlen: usize,
}

impl IOVec {
    fn new(iov: &mut Vec<Vec<u8>>, iovlen: usize) -> Self {
        let iovlen = iovlen;
        let mut iovec = Vec::new();
        for i in iov.iter_mut().take(iovlen) {
            iovec.push(kcapi_sys::iovec {
                iov_base: i.as_mut_ptr() as *mut ::std::os::raw::c_void,
                iov_len: i.len() as kcapi_sys::size_t,
            });
        }

        IOVec { iovec, iovlen }
    }
}

pub mod util;

pub mod aead;
pub mod md;
pub mod rng;
pub mod skcipher;
mod test;
