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
//! # `kcapi` - The Official High-level Rust Bindings for `libkcapi`
//!
//! This crate provides the official high-level Rust bindings for `libkcapi`.
//! The goal of this crate is to provide a rusty API to the C library `libkcapi`,
//! which itself provides consumers the capability to access the Linux Kernel's
//! Cryptographic API (KCAPI) from userland to perform cryptographic requests.
//!
//! This is a permissively (BSD-3-Clause) licensed crate which can be included
//! in your applications to remove dependence on OpenSSL or other cryptographic
//! libraries, and use the Linux KCAPI instead.
//!
//! # Layout
//!
//! This crate is divided into the following modules:
//!
//! * `md` - Message digest API.
//! * `skcipher` - Symmetric key cipher API.
//! * `aead` - Authenticated Encryption with Associated Data (AEAD) API.
//! * `rng` - Random Number Generation (RNG) API.
//! * `akcipher` - Asymmetric key cipher API.
//! * `kdf` - Key Derivation Function API.
//!
//! Each of these modules specify their own unique context type. For instance,
//! the `skcipher` module provides the `KcapiSKCipher` context type, which
//! can be used to perform encryption/decryption and other operations.
//!
//! This crate defines a `KcapiResult` type which can be used to encapsulate
//! output from any consumers of this API, and also propagate errors to callers.
//!
//! This crate also defines a custom error type `KcapiError` which implements
//! the `fmt::Display` trait.
//!
//! This crate also provides the `IOVec` type, which can be used to represent
//! a Linux Kernel Scatter/Gather list of `u8`s.
//!
//! # Pre-requisites
//!
//! This crate requires the Linux Kernel to be compiled with the following options:
//!
//! * `CONFIG_CRYPTO_USER=m` - Compile the `af_alg.ko` module.
//! * `CONFIG_CRYPTO_USER_API=y` - Enable Userland crypto API.
//! * `CONFIG_CRYPTO_USER_API_HASH=y` - Enable the hash API.
//! * `CONFIG_CRYPTO_USER_API_SKCIPHER=y` - Enable the Symmetric cipher API.
//! * `CONFIG_CRYPTO_USER_API_RNG=y` - Enable the RNG API.
//! * `CONFIG_CRYPTO_USER_API_AEAD=y` - Enable the AEAD API.
//!
//! If you wish to perform Cryptographic Algorithm Validation Program (CAVP)
//! testing on the RNG, then you must also enable the following option.
//!
//! * `CONFIG_CRYPTO_USER_API_RNG_CAVP=y` - Enable RNG CAVP testing from userland.
//!
//! After the patches in the `kernel-patches` directory of this crate are applied,
//! the following config option can also be enabled:
//!
//! * `CONFIG_CRYPTO_USER_API_AKCIPHER=y` - Enable the Asymmetric cipher API.
//!
//! Once these configuration options are enabled in the Linux Kernel, and the
//! compilation succeeds, you may use this crate to it's full potential.
//!

use std::fmt;

const BITS_PER_BYTE: usize = 8;

///
/// Fastest kernel access using internal heuristics.
///
pub const ACCESS_HEURISTIC: u32 = kcapi_sys::KCAPI_ACCESS_HEURISTIC;

///
/// Linux Kernel `sendmsg(2)` API access. See `man 2 sendmsg`.
///
pub const ACCESS_SENDMSG: u32 = kcapi_sys::KCAPI_ACCESS_SENDMSG;

///
/// Linux Kernel VMSplice Access
///
pub const ACCESS_VMSPLICE: u32 = kcapi_sys::KCAPI_ACCESS_VMSPLICE;

///
/// Use Kernel Asynchronous I/O interface if it is available.
///
pub const INIT_AIO: u32 = kcapi_sys::KCAPI_INIT_AIO;

///
/// # The `KcapiResult<T>` Type
///
/// This type defines a result which is returned from a majority
/// of the APIs in this crate. At a high level, it is an `enum` of
/// `Ok(T)`, and `Err(KcapiError)`.
///
/// ```
/// use kcapi::KcapiError;
///
/// enum KcapiResult<T> {
///     Ok(T),
///     Err(KcapiError),
/// };
/// ```
///
/// You can match against these when calling an API which returns
/// the `KcapiResult` type.
///
pub type KcapiResult<T> = std::result::Result<T, KcapiError>;

///
/// # The `KcapiError` Type
///
/// This type defines an error returned from the `kcapi` crate.
/// This type has two fields:
/// * `code` - The error code returned by the Kernel
/// * `message` - A string representation of what went wrong.
///
/// This error type also implements a `fmt::Display` method, which can
/// be used to print out the exact error which occured.
///
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

///
/// # The `IOVec` type
///
/// This type is used to represent a Linux Kernel scatter/gather list.
/// At a high level, this type accepts a `Vec<Vec<u8>>` and creates a scatter/gather
/// list from that.
///
/// This type also implements the following methods:
/// * `len()` - Return the number of entries in the scatter/gather list.
/// * `is_emtpy()` - Return whether the scatter/gather list is empty.
/// * `push()` - Add an entry to an existing scatter/gather list.
/// * `pop()` - Try to pop an entry from an existing scatter/gather list.
///
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
    ///
    /// ## Initialize an instance of type `IOVec`
    ///
    /// This function creates a Linux kernel scatterlist from a `Vec<Vec<T>>`.
    /// The scaterlest is stored in the `iovec` field of the returned `IOVec`.
    ///
    /// This function takes:
    /// * `iov` - A `Vec<Vec<u8>>` containing buffers to add to the scatterlist
    ///
    /// On success, an initialized instance of type `IOVec` is returned.
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::{IOVec, IOVecTrait};
    ///
    /// let mut sg = vec![vec![0xff; 16]; 16];
    /// let iovec = IOVec::new(sg)
    ///     .expect("Failed to intialize an IOVec");
    ///
    /// assert_eq!(iovec.len(), 16);
    /// ```
    ///
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

    ///
    /// ## Obtain the length of the `IOVec` instance.
    ///
    /// This function returns the length of an initialized `IOVec`.
    ///
    fn len(&self) -> usize {
        self.iovlen
    }

    ///
    /// ## Determine whether the `IOVec` is empty.
    ///
    /// This function returns `true` if the `IOVec` instance is empty.
    ///
    fn is_empty(&self) -> bool {
        if self.iovlen == 0 {
            return true;
        }
        false
    }

    ///
    /// ## Push a buffer into the `IOVec`
    ///
    /// This function is used to add a `Vec<u8>` to an existing scatter/gather
    /// list represented by an `IOVec`.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::{IOVec, IOVecTrait};
    ///
    /// let mut sg = vec![vec![0xff; 16]; 16];
    /// let mut iovec = IOVec::new(sg)
    ///     .expect("Failed to initialize an IOVec");
    ///
    /// iovec.push(vec![0x41; 16]);
    /// ```
    ///
    fn push(&mut self, buf: Vec<u8>) {
        let mut bufp = buf;
        self.iovec.push(kcapi_sys::iovec {
            iov_base: bufp.as_mut_ptr() as *mut ::std::os::raw::c_void,
            iov_len: bufp.len() as kcapi_sys::size_t,
        });
        self.iovlen += 1;
    }

    ///
    /// ## Pop a buffer from an `IOVec`
    ///
    /// This function is used to pop a `Vec<u8>` from an existing scatter/gather
    /// list represented by an `IOVec`.
    ///
    /// An `Option<Vec<u8>>` is returned if the `IOVec` has any data that can be
    /// popped. If the `IOVec` is empty, then `None` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::{IOVec, IOVecTrait};
    ///
    /// let mut sg = vec![vec![0xff; 16]; 16];
    /// let mut iovec = IOVec::new(sg)
    ///     .expect("Failed to initialize an IOVec");
    ///
    /// if let Some(buf) = iovec.pop() {
    ///     println!("{:#?}", buf);
    /// }
    /// ```
    ///
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
