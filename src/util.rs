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
//! # Generic Utilities
//!
//! This module provides generic utilities for convenience purposes.
//!
//! # Layout
//!
//! A number of public APIs are defined here.
//!

///
/// ## Pad the IV upto `ivsize` bytes
///
/// This is a utility function used to pad the IV provided to symmetric key
/// and AEAD ciphers such that unwanted errors do not occur.
///
/// This function takes:
/// * `ivsize` - A known good size for the IV (`usize`).
/// * `iv` - A `Vec<u8>` containing the IV to be padded.
///
/// This function returns an IV padded with `0x00`s up to `ivsize`.
///
pub fn pad_iv(ivsize: usize, iv: Vec<u8>) -> Vec<u8> {
    let mut newiv: Vec<u8>;
    newiv = vec![0u8; ivsize];
    newiv[..iv.len()].clone_from_slice(&iv);
    newiv
}

///
/// ## Obtain the version of `libkcapi`
///
/// The function returns a version number that is monotonic increasing for newer
/// versions. The version numbers are multiples of 100. For example, version 1.3.1
/// is converted to 1030100 -- the last two digits are reserved for future use.
///
/// ## Examples
///
/// ```no_run
/// use kcapi::util::lib_version;
///
/// assert_eq!(lib_version(), 1050000);
/// ```
pub fn lib_version() -> u32 {
    let version: u32;
    unsafe { version = kcapi_sys::kcapi_version() }
    version
}
