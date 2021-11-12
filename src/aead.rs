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
//! # Authenticated Encryption with Associated Data (AEAD) using the Kernel Crypto API (KCAPI)
//!
//! This module provides the capability to do authenticated encryption (such as AES-GCM)
//! using the KCAPI. The APIs provided by this module provide callers the ability
//! to perform encryption and decryption using AEAD algorithms.
//!
//! *Note:* Any AEAD algorithm used with this module must be present in `/proc/crypto`
//! on the target platform.
//!
//! # Layout
//!
//! This module provides one-shot convenience functions to perform encryption and
//! decryption, using any AEAD algorithm from `/proc/crypto`. This module also
//! provides the `KcapiAEAD` type which provides APIs to initialize, (in normal,
//!  asynchronous, and stream mode), decrypt (in normal, asynchronous, and stream
//!  mode), stream update, and stream output using any AEAD algorithm in
//! `/proc/crypto`.
//!

use std::{convert::TryInto, ffi::CString};

use crate::{KcapiError, KcapiResult};

///
/// # The `KcapiAEADData` Type
///
/// This type represents the input to, or the output from a AEAD encryption
/// or decryption operation. This type contains the associated data,
/// authentication tag, authentication tag size, and the plain/ciphertext
/// input to the encrypt or decrypt operations.
///
/// This type provides a number of setter and getter methods, which allow
/// setting the various private fields of this type.
///
/// ## Examples
///
/// ```
/// // Initialize new encryption input data
/// let mut aead_input = kcapi::aead::KcapiAEADData::new_enc(
///     vec![0u8; 16],  // plaintext
///     vec![0u8; 16],  // associated data
///     16,             // authentication tag size
/// );
///
/// // Initialize new decryption input data
/// let mut aead_input = kcapi::aead::KcapiAEADData::new_dec(
///     vec![0u8; 16],  // ciphertext
///     vec![0u8; 16],  // associated data
///     vec![0u8; 16],  // authentication tag
/// )
/// ```
///
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct KcapiAEADData {
    assocdata: Vec<u8>,
    data: Vec<u8>,
    tag: Vec<u8>,
    tagsize: usize,
}

impl KcapiAEADData {
    ///
    /// ## Initialize an instance of the `KcapiAEADData` Type.
    ///
    /// This function initializes the `KcapiAEADData` type by allocating
    /// memory for it's various fields.
    ///
    pub(crate) fn new() -> Self {
        let assocdata = Vec::new();
        let data = Vec::new();
        let tag = Vec::new();
        let tagsize = 0;
        KcapiAEADData {
            assocdata,
            data,
            tag,
            tagsize,
        }
    }

    ///
    /// ## Allocate Input Data to an AEAD Encryption Operation
    ///
    /// This function initializes a an instance of `KcapiAEADData` with
    /// the plaintext, associated data, and tag length to be provided to
    /// an AEAD Encryption operation.
    ///
    /// The resulting instance can then be used as an input to the
    /// `kcapi::aead::encrypt()` call.
    ///
    /// This function takes:
    /// * `pt` - The plaintext of type `Vec<u8>`
    /// * `assocdata` - The associated data of type `Vec<u8>`
    /// * `tagsize` - The expected size of the authentication tag (`usize`)
    ///
    /// Returns an initialized instance of `KcapiAEADData`.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::aead::KcapiAEADData;
    ///
    /// let pt = "Hello, World!".as_bytes().to_vec();
    /// let assocdata = vec![0u8; 16];
    /// let tagsize: usize = 16;
    ///
    /// let data = KcapiAEADData::new_enc(pt, assocdata, tagsize);
    /// ```
    ///
    pub fn new_enc(pt: Vec<u8>, assocdata: Vec<u8>, tagsize: usize) -> Self {
        let mut aead_data = Self::new();
        aead_data.set_data(pt);
        aead_data.set_assocdata(assocdata);
        aead_data.set_tagsize(tagsize);

        aead_data
    }

    ///
    /// ## Allocate Input Data to an AEAD Decryption Operation
    ///
    /// This function initializes a an instance of `KcapiAEADData` with
    /// the ciphertext, associated data, and tag length to be provided to
    /// an AEAD Encryption operation.
    ///
    /// The resulting instance can then be used as an input to the
    /// `kcapi::aead::decrypt()` call.
    ///
    /// This function takes:
    /// * `ct` - The ciphertext of type `Vec<u8>`
    /// * `assocdata` - The associated data of type `Vec<u8>`
    /// * `tagsize` - The expected size of the authentication tag (`usize`)
    ///
    /// Returns an initialized instance of `KcapiAEADData`.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::aead::KcapiAEADData;
    ///
    /// let ct = vec![
    ///     0x4b, 0xed, 0xb6, 0xa2, 0xf, 0x9a, 0x83, 0xc5, 0x9c, 0x5a, 0xae, 0xdd, 0x50
    /// ];
    /// let assocdata = vec![0u8; 16];
    /// let tag = vec![
    ///     0x2b, 0xcc, 0x9e, 0xbb, 0xd1, 0xe7, 0x11, 0xa5, 0x1a, 0x36, 0x7b, 0x3d, 0xe2, 0xa9,
    ///     0xb7, 0x85,
    /// ];
    ///
    /// let data = KcapiAEADData::new_dec(ct, assocdata, tag);
    /// ```
    ///
    pub fn new_dec(ct: Vec<u8>, assocdata: Vec<u8>, tag: Vec<u8>) -> Self {
        let mut aead_data = Self::new();
        aead_data.set_data(ct);
        aead_data.set_assocdata(assocdata);
        aead_data.set_tag(tag);

        aead_data
    }

    ///
    /// ## Set or alter the Authentication Tag
    ///
    /// This function sets or updates the `tag` field of `KcapiAEADData`
    ///
    pub(crate) fn set_tag(&mut self, tag: Vec<u8>) {
        self.tagsize = tag.len();
        self.tag = tag;
    }

    ///
    /// ## Set or alter the Authentication Tag Length
    ///
    /// This function sets or updates the `tagsize` field of `KcapiAEADData`
    ///
    pub(crate) fn set_tagsize(&mut self, tagsize: usize) {
        self.tagsize = tagsize;
    }

    ///
    /// ## Set or alter the Associated Data
    ///
    /// This function sets or updates the `assocdata` field of `KcapiAEADData`
    ///
    pub(crate) fn set_assocdata(&mut self, assocdata: Vec<u8>) {
        self.assocdata = assocdata;
    }

    ///
    /// ## Set or alter the Input Data
    ///
    /// This function sets or updates the `data` field of `KcapiAEADData`
    ///
    pub(crate) fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    ///
    /// ## Get the Associated Data
    ///
    /// This function gets the `assocdata` field of `KcapiAEADData`
    ///
    pub fn get_assocdata(&self) -> Vec<u8> {
        self.assocdata.clone()
    }

    ///
    /// ## Get the Input Data
    ///
    /// This function gets the `data` field of `KcapiAEADData`
    ///
    pub fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }

    ///
    /// ## Get the Authentication Tag
    ///
    /// This function gets the `tag` field of `KcapiAEADData`
    ///
    pub fn get_tag(&self) -> Vec<u8> {
        self.tag.clone()
    }

    ///
    /// ## Get the length of the Associated Data
    ///
    /// This function returns the length of the `assocdata` in `KcapiAEADData`
    ///
    pub fn assoclen(&self) -> usize {
        self.assocdata.len()
    }

    ///
    /// ## Get the length of the Input Data
    ///
    /// This function returns the length of the `data` in `KcapiAEADData`
    ///
    pub fn datalen(&self) -> usize {
        self.data.len()
    }

    ///
    /// ## Get the length of the Authentication Tag
    ///
    /// This function returns the length of the `tag` in `KcapiAEADData`
    ///
    pub fn taglen(&self) -> usize {
        self.tagsize
    }
}

///
/// # The `KcapiAEADMode` Type.
///
/// This type enumerates the modes of operation for the AEAD ciphers.
///
/// Currently there are two modes:
/// * `Encrypt`
/// * `Decrypt`
///
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KcapiAEADMode {
    Decrypt = 0,
    Encrypt,
}

///
/// # The `KcapiAEAD` Type
///
/// This type denotes a generic context for a AEAD transform in the Linux Kernel.
/// An instance of this struct must be initialized using the `new*()` calls prior
/// to being used. This type provides APIs to perform a number of operations
/// such as initialization, setting of keys, encryption, and decryption.
///
/// ## Panics
///
/// If the string provided as input to the `new()` function cannot be converted into a
/// `std::ffi::CString` type, the initialization will panic with the message
/// `Failed to create CString`.
///
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KcapiAEAD {
    handle: *mut kcapi_sys::kcapi_handle,
    iv: Vec<u8>,
    key: Vec<u8>,
    mode: KcapiAEADMode,
    data: KcapiAEADData,
    pub algorithm: String,
    pub blocksize: usize,
    pub flags: u32,
    pub ivsize: usize,
    pub max_tagsize: usize,
    pub inbuflen: usize,
    pub outbuflen: usize,
}

impl KcapiAEAD {
    ///
    /// ## Initialize an instance of `KcapiAEAD` type
    ///
    /// This function initializes an instance of the `KcapiAEAD` type, along
    /// with a corresponding handle for the AEAD transform in the kernel.
    ///
    /// On success, an initialized instance of `KcapiAEAD` is returned.
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::INIT_AIO;
    /// use kcapi::aead::KcapiAEAD;
    ///
    /// let mut aead = match KcapiAEAD::new("gcm(aes)", !INIT_AIO) {
    ///     Ok(aead) => aead,
    ///     Err(e) => panic!("{}", e),
    /// };
    /// ```
    ///
    pub fn new(algorithm: &str, flags: u32) -> KcapiResult<Self> {
        let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;
        let max_tagsize: usize;
        let blocksize: usize;
        let ivsize: usize;

        let alg = CString::new(algorithm).expect("Failed to create CString");
        unsafe {
            let ret = kcapi_sys::kcapi_aead_init(&mut handle as *mut _, alg.as_ptr(), flags);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!(
                        "Failed to initialize AEAD handle for algorithm '{}'",
                        algorithm,
                    ),
                });
            }

            max_tagsize = kcapi_sys::kcapi_aead_authsize(handle)
                .try_into()
                .expect("Failed to convert u32 into usize");
            if max_tagsize == 0 {
                return Err(KcapiError {
                    code: -libc::EINVAL as i64,
                    message: format!(
                        "Failed to obtain max authsize for algorithm '{}'",
                        algorithm,
                    ),
                });
            }

            blocksize = kcapi_sys::kcapi_aead_blocksize(handle)
                .try_into()
                .expect("Failed to convert u32 into usize");
            if blocksize == 0 {
                return Err(KcapiError {
                    code: -libc::EINVAL as i64,
                    message: format!("Failed to obtain blocksize for algorithm '{}'", algorithm,),
                });
            }

            ivsize = kcapi_sys::kcapi_aead_ivsize(handle)
                .try_into()
                .expect("Failed to convert u32 into usize");
            if ivsize == 0 {
                return Err(KcapiError {
                    code: -libc::EINVAL as i64,
                    message: format!("Failed to obtain ivsize for algorithm '{}'", algorithm,),
                });
            }
        }

        Ok(KcapiAEAD {
            handle,
            iv: Vec::new(),
            key: Vec::new(),
            mode: KcapiAEADMode::Decrypt,
            data: KcapiAEADData::new(),
            algorithm: algorithm.to_string(),
            blocksize,
            flags,
            ivsize,
            max_tagsize,
            inbuflen: 0,
            outbuflen: 0,
        })
    }

    ///
    /// ## Set the key for the AEAD transform
    ///
    /// With this function, the caller sets the key for subsequent encryption or
    /// decryption operations.
    ///
    /// This function takes:
    /// * `key` - a `Vec<u8>` containing the key.
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::INIT_AIO;
    /// use kcapi::aead::KcapiAEAD;
    ///
    /// let mut aead = match KcapiAEAD::new("gcm(aes)", !INIT_AIO) {
    ///     Ok(aead) => aead,
    ///     Err(e) => panic!("{}", e),
    /// };
    ///
    /// aead.setkey(vec![0u8; 16])
    ///     .expect("Failed to set key");
    /// ```
    pub fn setkey(&mut self, key: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_aead_setkey(self.handle, key.as_ptr(), key.len() as u32);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!("Failed to set key for algorithm '{}'", self.algorithm,),
                });
            }
        }
        self.key = key;
        Ok(())
    }

    fn set_inbufsize(&mut self, inlen: usize) -> KcapiResult<()> {
        if self.data.taglen() == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!("Tag size not set for algorithm '{}'", self.algorithm,),
            });
        }

        unsafe {
            let get_inbuflen = match self.mode {
                KcapiAEADMode::Decrypt => kcapi_sys::kcapi_aead_inbuflen_dec,
                KcapiAEADMode::Encrypt => kcapi_sys::kcapi_aead_inbuflen_enc,
            };
            self.inbuflen = get_inbuflen(
                self.handle,
                inlen as kcapi_sys::size_t,
                self.data.assoclen() as kcapi_sys::size_t,
                self.data.taglen() as kcapi_sys::size_t,
            )
            .try_into()
            .expect("Failed to convert u64 into usize");
        }
        Ok(())
    }

    fn set_outbufsize(&mut self, outlen: usize) -> KcapiResult<()> {
        if self.data.taglen() == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!("Tag size not set for algorithm '{}'", self.algorithm,),
            });
        }

        unsafe {
            let get_outbuflen = match self.mode {
                KcapiAEADMode::Decrypt => kcapi_sys::kcapi_aead_outbuflen_dec,
                KcapiAEADMode::Encrypt => kcapi_sys::kcapi_aead_outbuflen_enc,
            };
            self.outbuflen = get_outbuflen(
                self.handle,
                outlen as kcapi_sys::size_t,
                self.data.assocdata.len() as kcapi_sys::size_t,
                self.data.tagsize as kcapi_sys::size_t,
            )
            .try_into()
            .expect("Failed to convert u64 into usize");
        }
        Ok(())
    }

    ///
    /// # Set the Tag for an AEAD Decryption Operation.
    ///
    /// This function sets the authentication tag for an AEAD decryption
    /// operation. The length of this tag **MUST** be less than the maximum
    /// tag length defined for this algorithm in `/proc/crypto`.
    ///
    /// This function takes:
    /// * `tag` - A `Vec<u8>` containing the authentication tag.
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::INIT_AIO;
    /// use kcapi::aead::KcapiAEAD;
    ///
    /// let mut aead = match KcapiAEAD::new("gcm(aes)", !INIT_AIO) {
    ///     Ok(aead) => aead,
    ///     Err(e) => panic!("{}", e),
    /// };
    ///
    /// let tag = vec![0u8; 16];
    /// aead.set_tag(tag)
    ///     .expect("Failed to set tag");
    /// ```
    ///
    pub fn set_tag(&mut self, tag: Vec<u8>) -> KcapiResult<()> {
        if tag.len() > self.max_tagsize {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Invalid tagsize {} > {} for algorithm '{}'",
                    tag.len(),
                    self.max_tagsize,
                    self.algorithm,
                ),
            });
        }

        unsafe {
            let ret = kcapi_sys::kcapi_aead_settaglen(self.handle, tag.len() as u32);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!(
                        "Failed to set tag length for algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        self.data.set_tag(tag);
        Ok(())
    }

    ///
    /// ## Set Authenticaton Tag Size
    ///
    /// Set the authentication tag size needed for encryption operation. The tag
    /// is created during encryption operation with the size provided with this
    /// call.
    ///
    /// This function takes:
    /// * `tagsize` - The length of the tag in bytes `usize`.
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::INIT_AIO;
    /// use kcapi::aead::KcapiAEAD;
    ///
    /// let mut aead = match KcapiAEAD::new("gcm(aes)", !INIT_AIO) {
    ///     Ok(aead) => aead,
    ///     Err(e) => panic!("{}", e),
    /// };
    ///
    /// aead.set_tagsize(16)
    ///     .expect("Failed to set tagsize");
    /// ```
    ///
    pub fn set_tagsize(&mut self, tagsize: usize) -> KcapiResult<()> {
        if tagsize > self.max_tagsize {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Invalid tagsize {} > {} for algorithm '{}'",
                    tagsize, self.max_tagsize, self.algorithm,
                ),
            });
        }

        unsafe {
            let ret = kcapi_sys::kcapi_aead_settaglen(self.handle, tagsize as u32);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!(
                        "Failed to set tag length for algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        self.data.set_tagsize(tagsize);
        Ok(())
    }

    ///
    /// Set the Authentication Data
    ///
    /// This function sets the authentication data for the AEAD Operation.
    ///
    /// This function takes:
    /// * `assocdata` - A `Vec<u8>` Containing the authentication data.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::INIT_AIO;
    /// use kcapi::aead::KcapiAEAD;
    ///
    /// let mut aead = match KcapiAEAD::new("gcm(aes)", !INIT_AIO) {
    ///     Ok(aead) => aead,
    ///     Err(e) => panic!("{}", e),
    /// };
    ///
    /// aead.set_assocdata(vec![0u8; 16]);
    /// ```
    pub fn set_assocdata(&mut self, assocdata: Vec<u8>) {
        unsafe {
            kcapi_sys::kcapi_aead_setassoclen(self.handle, assocdata.len() as kcapi_sys::size_t);
        }
        self.data.set_assocdata(assocdata);
    }

    fn check_aead_input(&self, iv: &[u8]) -> KcapiResult<()> {
        if self.key.is_empty() {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Authenticated Encryption key is not set for algorithm '{}'",
                    self.algorithm,
                ),
            });
        }
        if self.data.taglen() == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Tag or Tag size is not set for algorithm '{}'",
                    self.algorithm,
                ),
            });
        }
        if iv.len() != self.ivsize {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Invalid IV of size {}, IV must be of size {} for algorithm '{}'",
                    iv.len(),
                    self.ivsize,
                    self.algorithm,
                ),
            });
        }
        Ok(())
    }

    ///
    /// ## Synchronously Encrypt AEAD data (one shot)
    ///
    /// This function encrypts the provided plaintext with the key to produce
    /// a ciphertext and an authentication tag.
    ///
    /// This function takes:
    /// * `pt` - A `Vec<u8>` containing the plaintext.
    /// * `iv` - A `Vec<u8>` containing the IV.
    /// * `access` - kernel access type (`u32`)
    ///     - `ACCESS_HEURISTIC` - internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, an instance of type `KcapiAEADData` is returned with the
    /// `tag` and `data` fields containing the authentication tag and ciphertext
    /// respectively.
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::{INIT_AIO, ACCESS_HEURISTIC};
    /// use kcapi::aead::KcapiAEAD;
    ///
    /// let mut aead = match KcapiAEAD::new("gcm(aes)", !INIT_AIO) {
    ///     Ok(aead) => aead,
    ///     Err(e) => panic!("{}", e),
    /// };
    ///
    /// aead.setkey(vec![0u8; 16])
    ///     .expect("Failed to set key");
    /// aead.set_tagsize(16)
    ///     .expect("Failed to set tagsize");
    /// aead.set_assocdata(vec![0u8; 16]);
    ///
    /// let pt = vec![0x41u8; 16];
    /// let iv = vec![0u8; 12];
    /// let out = match aead.encrypt(pt, iv, ACCESS_HEURISTIC) {
    ///     Ok(ct) => ct,
    ///     Err(e) => panic!("{}", e),
    /// };
    /// ```
    ///
    pub fn encrypt(&mut self, pt: Vec<u8>, iv: Vec<u8>, access: u32) -> KcapiResult<KcapiAEADData> {
        self.mode = KcapiAEADMode::Encrypt;
        self.check_aead_input(&iv)?;

        self.set_inbufsize(pt.len())?;
        self.set_outbufsize(pt.len())?;

        let mut outbuf = Vec::new();
        outbuf.extend(self.data.get_assocdata().iter().copied());
        outbuf.extend(pt.iter().copied());
        outbuf.extend(vec![0u8; self.data.taglen()].iter().copied());

        unsafe {
            let ret = kcapi_sys::kcapi_aead_encrypt(
                self.handle,
                outbuf.as_ptr(),
                self.inbuflen as kcapi_sys::size_t,
                iv.as_ptr(),
                outbuf.as_mut_ptr(),
                self.outbuflen as kcapi_sys::size_t,
                access as ::std::os::raw::c_int,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Authenticated Encryption failed for algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }

        let ct_offset = self.data.assoclen();
        let tag_offset = ct_offset + pt.len();

        let mut ct = vec![0u8; pt.len()];
        ct.clone_from_slice(&outbuf[ct_offset..tag_offset]);

        let mut tag = vec![0u8; self.data.taglen()];
        tag.clone_from_slice(&outbuf[tag_offset..]);

        self.data.set_data(ct);
        self.data.set_tag(tag);

        Ok(self.data.clone())
    }

    ///
    /// ## Synchronously Decrypt AEAD data (one shot)
    ///
    /// This function decrypts the provided ciphertext with the key to produce
    /// a ciphertext and an authentication tag.
    ///
    /// If this function fails to decrypt the data and the error code contained
    /// within the `KcapiError` instance contains `-EBADMSG`, then it can be
    /// determined that an authentication or integrity error has occured.
    ///
    /// This function takes:
    /// * `ct` - A `Vec<u8>` containing the ciphertext.
    /// * `iv` - A `Vec<u8>` containing the IV.
    /// * `access` - kernel access type (`u32`)
    ///     - `ACCESS_HEURISTIC` - internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, an instance of type `KcapiAEADData` is returned with the
    /// `data` field containing the decrypted plaintext.
    /// On failure, a `KcapiError` is returned.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::{INIT_AIO, ACCESS_HEURISTIC};
    /// use kcapi::aead::KcapiAEAD;
    ///
    /// let mut aead = match KcapiAEAD::new("gcm(aes)", !INIT_AIO) {
    ///     Ok(aead) => aead,
    ///     Err(e) => panic!("{}", e),
    /// };
    ///
    /// aead.setkey(vec![0u8; 16])
    ///     .expect("Failed to set key");
    ///
    /// let tag = vec![
    ///        0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
    ///        0x70,
    /// ];
    /// aead.set_tag(tag)
    ///     .expect("Failed to set tag");
    /// aead.set_assocdata(vec![0u8; 16]);
    ///
    /// let ct = vec![
    ///        0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
    ///        0xbf, 0x39, 0xb6, 0xd4, 0xeb,
    /// ];
    /// let iv = vec![0u8; 12];
    /// let out = match aead.decrypt(ct, iv, ACCESS_HEURISTIC) {
    ///     Ok(pt) => pt,
    ///     Err(e) => panic!("{}", e),
    /// };
    /// ```
    ///
    pub fn decrypt(&mut self, ct: Vec<u8>, iv: Vec<u8>, access: u32) -> KcapiResult<KcapiAEADData> {
        self.mode = KcapiAEADMode::Decrypt;
        self.check_aead_input(&iv)?;

        self.set_inbufsize(ct.len())?;
        self.set_outbufsize(ct.len())?;

        let mut outbuf = Vec::new();
        outbuf.extend(self.data.get_assocdata().iter().copied());
        outbuf.extend(ct.iter().copied());
        outbuf.extend(self.data.get_tag().iter().copied());

        unsafe {
            let ret = kcapi_sys::kcapi_aead_decrypt(
                self.handle,
                outbuf.as_ptr(),
                self.inbuflen as kcapi_sys::size_t,
                iv.as_ptr(),
                outbuf.as_mut_ptr(),
                self.outbuflen as kcapi_sys::size_t,
                access as ::std::os::raw::c_int,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Authenticated decryption failed for algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }

        let ct_offset = self.data.assoclen();
        let tag_offset = ct_offset + ct.len();
        let mut pt = vec![0u8; ct.len()];
        pt.clone_from_slice(&outbuf[ct_offset..tag_offset]);

        self.data.set_data(pt);

        Ok(self.data.clone())
    }
}

///
/// ## Convenience Function for AEAD Encryption (synchronous one-shot)
///
/// This is a convenience function for AEAD encryption in synchronous and
/// one-shot fashion. This function takes input in the form of a `KcapiAEADData`
/// instance, and provides output as a `KcapiAEADData` instance.
///
/// This function takes:
/// * `alg` - An `&str` representation of an AEAD algorithm from `/proc/crypto`
/// * `data` - An instance of `KcapiAEADData` initialized using `KcapiAEADData::new_enc()`
/// * `key` - A `Vec<u8>` containing the encryption key.
/// * `iv` - A `Vec<u8>` containing the IV.
///
/// On success, an instance of type `KcapiAEADData` is returned with the
/// `tag` and `data` fields containing the authentication tag and ciphertext
/// respectively.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let key = vec![0u8; 16];
/// let iv = vec![0u8; 12];
/// let assocdata = vec![0u8; 16];
/// let pt = vec![0x41u8; 16];
/// let tagsize = 16;
///
/// let data = kcapi::aead::KcapiAEADData::new_enc(pt, assocdata, tagsize);
/// let ct = match kcapi::aead::encrypt("gcm(aes)", data, key, iv) {
///     Ok(ct) => ct,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
pub fn encrypt(
    alg: &str,
    data: KcapiAEADData,
    key: Vec<u8>,
    iv: Vec<u8>,
) -> KcapiResult<KcapiAEADData> {
    let mut cipher = KcapiAEAD::new(alg, !crate::INIT_AIO)?;
    cipher.set_tagsize(data.taglen())?;
    cipher.set_assocdata(data.get_assocdata());
    cipher.setkey(key)?;
    let output = cipher.encrypt(data.get_data(), iv, crate::ACCESS_HEURISTIC)?;
    Ok(output)
}

///
/// ## Convenience Function for AEAD Decryption (synchronous one-shot)
///
/// This is a convenience function for AEAD decryption in synchronous and
/// one-shot fashion. This function takes input in the form of a `KcapiAEADData`
/// instance, and provides output as a `KcapiAEADData` instance.
///
/// This function takes:
/// * `alg` - An `&str` representation of an AEAD algorithm from `/proc/crypto`
/// * `data` - An instance of `KcapiAEADData` initialized using `KcapiAEADData::new_dec()`
/// * `key` - A `Vec<u8>` containing the decryption key.
/// * `iv` - A `Vec<u8>` containing the IV.
///
/// On success, an instance of type `KcapiAEADData` is returned with the
/// `data` field containing the decrypted plaintext.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let key = vec![0u8; 16];
/// let iv = vec![0u8; 12];
/// let assocdata = vec![0u8; 16];
/// let ct = vec![
///     0x42, 0xc9, 0x9b, 0x8f, 0x21, 0xf7, 0xe2, 0xd3, 0xb2, 0x69, 0x83, 0xf8, 0x30, 0xf3,
///     0xbf, 0x39, 0xb6, 0xd4, 0xeb,
/// ];
/// let tag = vec![
///     0x2, 0x3b, 0x86, 0x43, 0xae, 0x4, 0xb6, 0xce, 0xbd, 0x1c, 0x53, 0xe0, 0x53, 0xa5, 0x26,
///     0x70,
/// ];
///
/// let data = kcapi::aead::KcapiAEADData::new_dec(ct, assocdata, tag);
/// let ct = match kcapi::aead::decrypt("gcm(aes)", data, key, iv) {
///     Ok(ct) => ct,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
pub fn decrypt(
    alg: &str,
    data: KcapiAEADData,
    key: Vec<u8>,
    iv: Vec<u8>,
) -> KcapiResult<KcapiAEADData> {
    let mut cipher = KcapiAEAD::new(alg, !crate::INIT_AIO)?;
    cipher.set_tag(data.get_tag())?;
    cipher.set_assocdata(data.get_assocdata());
    cipher.setkey(key)?;
    let output = cipher.decrypt(data.get_data(), iv, crate::ACCESS_HEURISTIC)?;
    Ok(output)
}
