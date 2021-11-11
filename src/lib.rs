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

pub const ACCESS_HEURISTIC: u32 = kcapi_sys::KCAPI_ACCESS_HEURISTIC;
pub const ACCESS_SENDMSG: u32 = kcapi_sys::KCAPI_ACCESS_SENDMSG;
pub const ACCESS_VMSPLICE: u32 = kcapi_sys::KCAPI_ACCESS_VMSPLICE;

pub const INIT_AIO: u32 = kcapi_sys::KCAPI_INIT_AIO;

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
pub struct IOVec<T> {
    iovec: Vec<kcapi_sys::iovec>,
    iovlen: usize,
    data: Vec<T>,
}

pub trait IOVecTrait<T> {
    fn new(iov: Vec<T>) -> KcapiResult<Self>
    where
        Self: Sized;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn push(&mut self, buf: T);
    fn pop(&mut self) -> Option<T>;
}

impl IOVecTrait<Vec<u8>> for IOVec<Vec<u8>> {
    fn new(iov: Vec<Vec<u8>>) -> KcapiResult<Self> {
        if iov.is_empty() {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Cannot create an IOVec from a vector of length {}",
                    iov.len(),
                ),
            });
        }

        let mut iovec = Vec::new();
        let ilen = iov.len();
        let mut data = iov;
        for i in data.iter_mut().take(ilen) {
            iovec.push(kcapi_sys::iovec {
                iov_base: i.as_mut_ptr() as *mut ::std::os::raw::c_void,
                iov_len: i.len() as kcapi_sys::size_t,
            });
        }
        let iovlen = iovec.len();
        Ok(IOVec {
            iovec,
            iovlen,
            data,
        })
    }

    fn len(&self) -> usize {
        self.iovlen
    }

    fn is_empty(&self) -> bool {
        if self.iovlen == 0 {
            return true;
        }
        false
    }

    fn push(&mut self, buf: Vec<u8>) {
        let mut bufp = buf;
        self.iovec.push(kcapi_sys::iovec {
            iov_base: bufp.as_mut_ptr() as *mut ::std::os::raw::c_void,
            iov_len: bufp.len() as kcapi_sys::size_t,
        });
        self.iovlen += 1;
    }

    fn pop(&mut self) -> Option<Vec<u8>> {
        if let Some(_i) = self.iovec.pop() {
            self.iovlen -= 1;
            let out = self.data.pop();
            return out;
        }
        None
    }
}

pub mod util;

pub mod aead;
pub mod akcipher;
pub mod kdf;
pub mod md;
pub mod rng;
pub mod skcipher;
mod test;
