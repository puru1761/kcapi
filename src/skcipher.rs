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
//! # Symmetric Key Ciphers (skcipher) using the Kernel Crypto API (KCAPI)
//!
//! This module provides the capability to perform symmetric key operations using
//! the KCAPI. The APIs provided by this module provide callers the ability to
//! encrypt and decrypt data using symmetric key ciphers.
//!
//! # Layout
//!
//! This module provides one-shot convenience functions to perform encryption
//! and decryption using any algorithm from `/proc/crypto`. Additionally,
//! one-shot convenience functions are also provided to perform encryption
//! and decryption using the AES algorithm in CTR and CBC modes.
//!
//! This module also provides the `KcapiSKCipher` type which provides APIs to
//! initialize (in normal, asynchronous, and stream mode), set keys, encrypt
//! (in normal, asynchronous, and stream mode), decrypt (in normal, asynchronous,
//! and stream mode), stream update, and stream output using any algorithm
//! specified in `/proc/crypto`
//!

use std::{convert::TryInto, ffi::CString};

use crate::{IOVec, IOVecTrait, KcapiError, KcapiResult, BITS_PER_BYTE, INIT_AIO};

const AES_BLOCKSIZE_BITS: usize = 128;
const AES128_KEYSIZE_BITS: usize = 128;
const AES192_KEYSIZE_BITS: usize = 192;
const AES256_KEYSIZE_BITS: usize = 256;

pub const AES_BLOCKSIZE: usize = AES_BLOCKSIZE_BITS / BITS_PER_BYTE;
pub const AES128_KEYSIZE: usize = AES128_KEYSIZE_BITS / BITS_PER_BYTE;
pub const AES192_KEYSIZE: usize = AES192_KEYSIZE_BITS / BITS_PER_BYTE;
pub const AES256_KEYSIZE: usize = AES256_KEYSIZE_BITS / BITS_PER_BYTE;

#[derive(Debug, Clone, Eq, PartialEq)]
enum SKCipherMode {
    Decrypt = 0,
    Encrypt,
}

///
/// # The `KcapiSKCipher` Type
///
/// This type denotes a generic context for a Symmetric Key Cipher transform in
/// the Linux Kernel. An instance of the struct must be initialized using
/// the `new()`, `new_enc_stream()` (for stream encryption), or `new_dec_stream()`
/// (for stream decryption) prior to use.
///
/// ## Panics
///
/// If the string provided as input to the `new()` function cannot be converted into a
/// `std::ffi::CString` type, the initialization will panic with the message
/// `Failed to create CString`.
///
/// ## Examples
///
/// ```
/// use kcapi::INIT_AIO;
/// use kcapi::skcipher::KcapiSKCipher;
///
/// let cipher = match KcapiSKCipher::new("cbc(aes)", !INIT_AIO) {
///     Ok(cipher) => cipher,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KcapiSKCipher {
    handle: *mut kcapi_sys::kcapi_handle,
    iv: Vec<u8>,
    key: Vec<u8>,
    pub algorithm: String,
    pub blocksize: usize,
    pub flags: u32,
    pub ivsize: usize,
    /* For stream operations */
    invec: Vec<Vec<u8>>,
    stream_mode: SKCipherMode,
}

impl KcapiSKCipher {
    ///
    /// ## Initialize an instance of `KcapiSKCipher`
    ///
    /// This function initializes the `KcapiSKCipher` type and makes the required
    /// connections to the Linux kernel.
    ///
    /// This function takes:
    /// * `algorithm` - A `&str` representation of an skcipher algorithm in `/proc/crypto`.
    /// * `flags` - `INIT_AIO` for asynchronous operation, `!INIT_AIO` otherwise.
    ///
    /// On success, returns an initialized instance of `KcapiSKCipher`.
    /// On failure, returns a `KcapiError`
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::INIT_AIO;
    /// use kcapi::skcipher::KcapiSKCipher;
    ///
    /// let cipher = KcapiSKCipher::new("cbc(aes)", !INIT_AIO)
    ///     .expect("Failed to initialize KcapiSKCipher");
    /// ```
    ///
    pub fn new(algorithm: &str, flags: u32) -> KcapiResult<Self> {
        let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;
        let blocksize: usize;
        let ivsize: usize;

        let alg = CString::new(algorithm).expect("Failed to create CString");
        unsafe {
            let ret = kcapi_sys::kcapi_cipher_init(&mut handle as *mut _, alg.as_ptr(), flags);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.into(),
                    message: format!(
                        "Failed to initialize symmetric key handle for algorithm '{}'",
                        algorithm
                    ),
                });
            }

            blocksize = kcapi_sys::kcapi_cipher_blocksize(handle)
                .try_into()
                .expect("Failed to convert u32 into usize");
            if blocksize == 0 {
                return Err(KcapiError {
                    code: -libc::EINVAL as i64,
                    message: format!("Failed to obtain block size for algorithm '{}'", algorithm),
                });
            }

            ivsize = kcapi_sys::kcapi_cipher_ivsize(handle)
                .try_into()
                .expect("Failed to convert u32 into usize");
            if ivsize == 0 {
                return Err(KcapiError {
                    code: -libc::EINVAL as i64,
                    message: format!("Failed to obtain IV size for algorithm '{}'", algorithm),
                });
            }
        }

        let key: Vec<u8> = Vec::new();
        let iv: Vec<u8> = Vec::new();
        let invec: Vec<Vec<u8>> = Vec::new();
        Ok(KcapiSKCipher {
            handle,
            key,
            iv,
            algorithm: algorithm.to_string(),
            blocksize,
            flags,
            ivsize,
            stream_mode: SKCipherMode::Decrypt,
            invec,
        })
    }

    ///
    /// ## Set the key for the Symmetric Cipher Operation
    ///
    /// This function sets the key for subsequent encryption or
    /// decryption operations.
    ///
    /// This function takes:
    /// * `key` - An encryption/decryption key of type `Vec<u8>`
    ///
    /// On failure, a `KcapiError` is returned
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::INIT_AIO;
    /// use kcapi::skcipher::KcapiSKCipher;
    ///
    /// let mut cipher = KcapiSKCipher::new("ctr(aes)", !INIT_AIO)
    ///     .expect("Failed to initialize KcapiSKCipher");
    ///
    /// let key = vec![0x00u8; 16];
    /// cipher.setkey(key)
    ///     .expect("Failed to set key for KcapiSKCipher");
    /// ```
    ///
    pub fn setkey(&mut self, key: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_cipher_setkey(self.handle, key.as_ptr(), key.len() as u32);
            if ret < 0 {
                return Err(KcapiError {
                    code: -libc::EINVAL as i64,
                    message: format!("Failed to set key for algorithm '{}'", self.algorithm),
                });
            }
            self.key = key
        }
        Ok(())
    }

    fn check_skcipher_input(&self, iv: &[u8], input: &[u8]) -> KcapiResult<()> {
        if self.key.is_empty() {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!("No key has been set for algorithm '{}'", self.algorithm,),
            });
        }
        if iv.len() != self.ivsize || self.ivsize == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!("Invald IV Size for algorithm '{}'", self.algorithm),
            });
        }
        if input.len() % self.blocksize != 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Input for algorithm {} should be a multiple of block size {}",
                    self.algorithm, self.blocksize,
                ),
            });
        }
        Ok(())
    }

    ///
    /// ## Encrypt data (synchronous one shot)
    ///
    /// This function is used to encrypt data in a one-shot fashion by sending
    /// it to the kernel. The plaintext provided must be a multiple of the
    /// blocksize of the cipher. The IV must be self.ivsize bytes in size.
    ///
    /// This function takes:
    /// * `pt` - A plaintext of type `Vec<u8>`
    /// * `iv` - An IV of type `Vec<u8>`
    /// * `access` - Kernel access type (`u32`). This must be one of:
    ///     - `ACCESS_HEURISTIC` - use internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - use vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, returns a `Vec<u8>` with the ciphertext.
    /// On failure, returns a `KcapiError`.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::{INIT_AIO, ACCESS_HEURISTIC};
    /// use kcapi::skcipher::KcapiSKCipher;
    ///
    /// let mut cipher = KcapiSKCipher::new("ctr(aes)", !INIT_AIO)
    ///     .expect("Failed to initialize KcapiSKCipher");
    ///
    /// let key = vec![0x00u8; 16];
    /// cipher.setkey(key)
    ///     .expect("Failed to set key for KcapiSKCipher");
    ///
    /// let iv = vec![0xffu8; cipher.ivsize];
    /// let pt = "Hello, World!".as_bytes().to_vec();
    /// let ct = match cipher.encrypt(pt, iv, ACCESS_HEURISTIC) {
    ///     Ok(ct) => ct,
    ///     Err(e) => panic!("{}", e),
    /// };
    /// ```
    ///
    pub fn encrypt(&self, pt: Vec<u8>, iv: Vec<u8>, access: u32) -> KcapiResult<Vec<u8>> {
        self.check_skcipher_input(&iv, &pt)?;
        let mut ct = vec![0u8; pt.len()];

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_encrypt(
                self.handle,
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
                    message: format!("Encryption failed for algorithm '{}'", self.algorithm,),
                });
            }
        }
        Ok(ct)
    }

    ///
    /// ## Encrypt data (asynchronous one shot)
    ///
    /// This is a asynchronous one-shot function to perform encryption of an
    /// input plaintext represented as a `Vec<Vec<u8>>`. This gets converted
    /// into a scatter-gather list which can be processed by the linux kernel.
    /// The IV provided in this operation must be `self.ivsize` bytes in size.
    ///
    /// This function takes:
    /// * `pt` - A list of plaintexts to be encrypted of type `Vec<Vec<u8>>`
    /// * `iv` - An IV of type `Vec<u8>` of size `self.ivsize` bytes.
    /// * `access` - Kernel access type (`u32`). This must be one of:
    ///     - `ACCESS_HEURISTIC` - use internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - use vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, returns a `Vec<Vec<u8>>` with the ciphertexts.
    /// On failure, returns a `KcapiError`
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::{INIT_AIO, ACCESS_HEURISTIC};
    /// use kcapi::skcipher::KcapiSKCipher;
    ///
    /// let mut cipher = KcapiSKCipher::new("ctr(aes)", INIT_AIO)
    ///     .expect("Failed to initialize SKCipher in AIO mode");
    ///
    /// let key = vec![0u8; 16];
    /// cipher.setkey(key)
    ///     .expect("Failed to set key for cipher in AIO mode");
    ///
    /// let pt = vec![
    ///     "This is a".as_bytes().to_vec(),
    ///     "plaintext".as_bytes().to_vec(),
    ///     "To AIO Encrypt".as_bytes().to_vec(),
    /// ];
    /// let iv = vec![0u8; cipher.ivsize];
    /// let ct = match cipher.encrypt_aio(pt, iv, ACCESS_HEURISTIC) {
    ///     Ok(ct) => ct,
    ///     Err(e) => panic!("{}", e),
    /// };
    /// ```
    ///
    pub fn encrypt_aio(
        &self,
        pt: Vec<Vec<u8>>,
        iv: Vec<u8>,
        access: u32,
    ) -> KcapiResult<Vec<Vec<u8>>> {
        if iv.len() != self.ivsize {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!("Invalid IV size for algorithm '{}'", self.algorithm),
            });
        }

        let mut iniov = IOVec::new(pt.clone())?;
        let mut outiov = IOVec::new(pt)?;

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_encrypt_aio(
                self.handle,
                iniov.iovec.as_mut_ptr(),
                outiov.iovec.as_mut_ptr(),
                iniov.len() as kcapi_sys::size_t,
                iv.as_ptr(),
                access as ::std::os::raw::c_int,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!("AIO Encryption failed for algorithm '{}'", self.algorithm),
                });
            }
        }
        Ok(outiov.data)
    }

    ///
    /// ## Decrypt data (synchronous one shot)
    ///
    /// This function is used to decrypt data in a one-shot fashion by sending
    /// it to the kernel. The ciphertext provided must be a multiple of the
    /// blocksize of the cipher. The IV must be self.ivsize bytes in size.
    ///
    /// This function takes:
    /// * `ct` - A ciphertext of type `Vec<u8>`
    /// * `iv` - An IV of type `Vec<u8>`
    /// * `access` - Kernel access type (`u32`). This must be one of:
    ///     - `ACCESS_HEURISTIC` - use internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - use vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, returns a `Vec<u8>` with the plaintext.
    /// On failure, returns a `KcapiError`.
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::{INIT_AIO, ACCESS_HEURISTIC};
    /// use kcapi::skcipher::KcapiSKCipher;
    ///
    /// let mut cipher = KcapiSKCipher::new("ctr(aes)", !INIT_AIO)
    ///     .expect("Failed to initialize KcapiSKCipher");
    ///
    /// let key = vec![0x00u8; 16];
    /// cipher.setkey(key)
    ///     .expect("Failed to set key for KcapiSKCipher");
    ///
    /// let iv = vec![0xffu8; cipher.ivsize];
    /// let ct = vec![0x2e, 0x8c, 0x27, 0xb8, 0x80, 0xa6, 0xc, 0x6c, 0xe7, 0x3e, 0x96, 0x3d, 0xeb];
    /// let pt = match cipher.decrypt(ct, iv, ACCESS_HEURISTIC) {
    ///     Ok(pt) => pt, // Hello, World!
    ///     Err(e) => panic!("{}", e),
    /// };
    /// ```
    ///
    pub fn decrypt(&self, ct: Vec<u8>, iv: Vec<u8>, access: u32) -> KcapiResult<Vec<u8>> {
        self.check_skcipher_input(&iv, &ct)?;
        let mut pt = vec![0u8; ct.len()];

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_decrypt(
                self.handle,
                ct.as_ptr(),
                ct.len() as kcapi_sys::size_t,
                iv.as_ptr(),
                pt.as_mut_ptr(),
                pt.len() as kcapi_sys::size_t,
                access as ::std::os::raw::c_int,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!("Decryption failed for algorithm '{}'", self.algorithm,),
                });
            }
        }
        Ok(pt)
    }

    ///
    /// ## Decrypt data (asynchronous one shot)
    ///
    /// This is a asynchronous one-shot function to perform decryption of an
    /// input ciphertext represented as a `Vec<Vec<u8>>`. This gets converted
    /// into a scatter-gather list which can be processed by the linux kernel.
    /// The IV provided in this operation must be `self.ivsize` bytes in size.
    ///
    /// This function takes:
    /// * `ct` - A list of ciphertexts to be decrypted of type `Vec<Vec<u8>>`
    /// * `iv` - An IV of type `Vec<u8>` of size `self.ivsize` bytes.
    /// * `access` - Kernel access type (`u32`). This must be one of:
    ///     - `ACCESS_HEURISTIC` - use internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - use vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, returns a `Vec<Vec<u8>>` with the plaintexts.
    /// On failure, returns a `KcapiError`
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::{INIT_AIO, ACCESS_HEURISTIC};
    /// use kcapi::skcipher::KcapiSKCipher;
    ///
    /// let mut cipher = KcapiSKCipher::new("ctr(aes)", INIT_AIO)
    ///     .expect("Failed to initialize SKCipher in AIO mode");
    ///
    /// let key = vec![0u8; 16];
    /// cipher.setkey(key)
    ///     .expect("Failed to set key for cipher in AIO mode");
    ///
    /// let ct = vec![
    ///     vec![0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61,],
    ///     vec![0x70, 0x6c, 0x61, 0x69, 0x6e, 0x74, 0x65, 0x78, 0x74,],
    ///     vec![
    ///         0x54, 0x6f, 0x20, 0x41, 0x49, 0x4f, 0x20, 0x45, 0x6e, 0x63, 0x72, 0x79,
    ///         0x70, 0x74,
    ///     ],
    /// ];
    /// let iv = vec![0u8; cipher.ivsize];
    /// let ct = match cipher.decrypt_aio(ct, iv, ACCESS_HEURISTIC) {
    ///     Ok(pt) => pt,
    ///     Err(e) => panic!("{}", e),
    /// };
    /// ```
    ///
    pub fn decrypt_aio(
        &self,
        ct: Vec<Vec<u8>>,
        iv: Vec<u8>,
        access: u32,
    ) -> KcapiResult<Vec<Vec<u8>>> {
        if iv.len() != self.ivsize {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!("Invalid IV size for algorithm '{}'", self.algorithm),
            });
        }

        let mut iniov = IOVec::new(ct.clone())?;
        let mut outiov = IOVec::new(ct)?;

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_decrypt_aio(
                self.handle,
                iniov.iovec.as_mut_ptr(),
                outiov.iovec.as_mut_ptr(),
                iniov.len() as kcapi_sys::size_t,
                iv.as_ptr(),
                access as ::std::os::raw::c_int,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!("AIO Decryption failed for algorithm '{}'", self.algorithm,),
                });
            }
        }
        Ok(outiov.data)
    }

    ///
    /// ## Initialize a `KcapiSKCipher` instance for stream encryption
    ///
    /// This function initializes a `KcapiSKcipher` instance for stream encryption.
    /// Multiple successive `self.stream_update()` function calls can be invoked
    /// to send more plaintext data to be encrypted. The kernel buffers the input
    /// until `self.stream_op()` picks up the encrypted data. Once plaintext is
    /// encrypted  it is removed from the kernel buffer.
    ///
    /// The function calls of `self.stream_update()` and `self.stream_op()` can
    /// be mixed, even by multiple threads of an application.
    ///
    /// This function takes:
    /// * `algorithm` - An `&str` representation of a skcipher algorithm from `/proc/crypto`.
    /// * `key` - An encryption key of type `Vec<u8>`.
    /// * `iv` - An IV of type `Vec<u8>`.
    /// * `pt` - An initial plaintext stream of type `Vec<Vec<u8>>`.
    ///
    /// On success, returns an instance of `KcapiSKCipher` initialized for stream encryption.
    /// On failure, returns a `KcapiError`
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::skcipher::KcapiSKCipher;
    ///
    /// let key = vec![0u8; 16];
    /// let iv = vec![0u8; 16];
    /// let pt = vec![vec![0x41; 16]];
    /// let enc_stream = match KcapiSKCipher::new_enc_stream("ctr(aes)", key, iv, pt) {
    ///     Ok(stream) => stream,
    ///     Err(e) => panic!("{}", e),
    /// };
    /// ```
    ///
    pub fn new_enc_stream(
        algorithm: &str,
        key: Vec<u8>,
        iv: Vec<u8>,
        pt: Vec<Vec<u8>>,
    ) -> KcapiResult<Self> {
        let mut cipher = Self::new(algorithm, !INIT_AIO)?;
        cipher.setkey(key)?;

        if iv.len() != cipher.ivsize {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Invalid IV of length {}, Expected IV of length {} for algorithm '{}'",
                    iv.len(),
                    cipher.ivsize,
                    algorithm,
                ),
            });
        }
        cipher.iv = iv.clone();
        cipher.stream_mode = SKCipherMode::Encrypt;

        if pt.is_empty() {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Invalid input vector of length 0 for algorithm '{}'",
                    cipher.algorithm,
                ),
            });
        }
        let mut iov = IOVec::new(pt)?;

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_stream_init_enc(
                cipher.handle,
                iv.as_ptr(),
                iov.iovec.as_mut_ptr(),
                iov.len() as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to initialize stream cipher operation for algorithm '{}'",
                        algorithm,
                    ),
                });
            }
        }
        cipher.invec.extend_from_slice(iov.data.as_slice());
        Ok(cipher)
    }

    ///
    /// ## Initialize a `KcapiSKCipher` instance for stream decryption
    ///
    /// This function initializes a `KcapiSKcipher` instance for stream decryption.
    /// Multiple successive `self.stream_update()` function calls can be invoked
    /// to send more ciphertext data to be decrypted. The kernel buffers the input
    /// until `self.stream_op()` picks up the decrypted data. Once ciphertext is
    /// decrypted  it is removed from the kernel buffer.
    ///
    /// The function calls of `self.stream_update()` and `self.stream_op()` can
    /// be mixed, even by multiple threads of an application.
    ///
    /// This function takes:
    /// * `algorithm` - An `&str` representation of a skcipher algorithm from `/proc/crypto`.
    /// * `key` - An decryption key of type `Vec<u8>`.
    /// * `iv` - An IV of type `Vec<u8>`.
    /// * `ct` - An initial ciphertext stream of type `Vec<Vec<u8>>`.
    ///
    /// On success, returns an instance of `KcapiSKCipher` initialized for stream decryction.
    /// On failure, returns a `KcapiError`
    ///
    /// ## Examples
    ///
    /// ```
    /// use kcapi::skcipher::KcapiSKCipher;
    ///
    /// let key = vec![0u8; 16];
    /// let iv = vec![0u8; 16];
    /// let ct = vec![vec![0x41; 16]];
    /// let dec_stream = match KcapiSKCipher::new_dec_stream("ctr(aes)", key, iv, ct) {
    ///     Ok(stream) => stream,
    ///     Err(e) => panic!("{}", e),
    /// };
    /// ```
    ///
    pub fn new_dec_stream(
        algorithm: &str,
        key: Vec<u8>,
        iv: Vec<u8>,
        ct: Vec<Vec<u8>>,
    ) -> KcapiResult<Self> {
        let mut cipher = Self::new(algorithm, !INIT_AIO)?;
        cipher.setkey(key)?;

        if iv.len() != cipher.ivsize {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Invalid IV of length {}, Expected IV of length {} for algorithm '{}'",
                    iv.len(),
                    cipher.ivsize,
                    algorithm,
                ),
            });
        }
        cipher.iv = iv.clone();
        cipher.stream_mode = SKCipherMode::Decrypt;

        if ct.is_empty() {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Invalid input vector of length 0 for algorithm '{}'",
                    cipher.algorithm,
                ),
            });
        }
        let mut iov = IOVec::new(ct)?;

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_stream_init_dec(
                cipher.handle,
                iv.as_ptr(),
                iov.iovec.as_mut_ptr(),
                iov.len() as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to initialize stream cipher operation for algorithm '{}'",
                        algorithm,
                    ),
                });
            }
        }
        cipher.invec.extend_from_slice(iov.data.as_slice());
        Ok(cipher)
    }

    ///
    /// ## Update the encryption/decryption input stream
    ///
    /// Using this function call, more plaintext for encryption or ciphertext for
    /// decryption can be submitted to the kernel.
    ///
    /// This function may cause the caller to sleep if the kernel buffer holding
    /// the data is getting full. The process will be woken up once more buffer
    /// space becomes available by calling `stream_op()`.
    ///
    /// *Note:* with the separate API calls of `stream_update()` and `stream_op()`
    /// a multi-threaded application can be implemented where one thread sends
    /// data to be processed and one thread picks up data processed by the cipher
    /// operation.
    ///
    /// **WARNING:** The memory referenced by `input` is not accessed by the kernel
    /// during this call. The memory is first accessed when `stream_op()` is
    /// called. Thus, you MUST make sure that the referenced memory is still
    /// present at the time `stream_op()` is called.
    ///
    /// This function takes:
    /// * `input` - The a stream of input data as `Vec<Vec<u8>>`
    ///
    /// On failure, returns a `KcapiError`
    ///
    pub fn stream_update(&mut self, input: Vec<Vec<u8>>) -> KcapiResult<()> {
        let mut iov = IOVec::new(input)?;
        unsafe {
            let ret = kcapi_sys::kcapi_cipher_stream_update(
                self.handle,
                iov.iovec.as_mut_ptr(),
                iov.len() as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to update data stream for algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        self.invec.extend_from_slice(iov.data.as_slice());
        Ok(())
    }

    ///
    /// ## Send the last update to the encryption/decryption input stream
    ///
    /// This call is identical to the `stream_update()` call with the
    /// exception that it marks the last data buffer before the cipher operation
    /// is triggered. This is call is important for stream ciphers like CTR or
    /// CTS mode when providing the last block. It is permissible to provide a
    /// zero buffer if all data including the last block is already provided by
    /// `stream_update()`.
    ///
    /// **WARNING:** If this call is not made for stream ciphers with input data
    /// that is not a multiple of the block size of the block cipher, the kernel
    /// will not return the last block that contains less data than the block
    /// size of the block cipher. For example, sending 257 bytes of data to be
    /// encrypted with ctr(aes), the kernel will return only 256 bytes without
    /// this call.
    ///
    /// This function takes:
    /// * `input` - Final input data to to the encryption/decryption stream as `Vec<Vec<u8>>`
    ///
    /// On failure, returns a `KcapiError`.
    ///
    pub fn stream_update_last(&mut self, input: Vec<Vec<u8>>) -> KcapiResult<()> {
        let mut iov = IOVec::new(input)?;

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_stream_update_last(
                self.handle,
                iov.iovec.as_mut_ptr(),
                iov.len() as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to update last data stream for algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        self.invec.extend_from_slice(iov.data.as_slice());
        Ok(())
    }

    ///
    /// ## Obtain encrypted/decrypted data from the stream
    ///
    /// This call can be called interleaved with `stream_update()` to fetch the
    /// processed data.
    ///
    /// This function may cause the caller to sleep if the kernel buffer holding
    /// the data is empty. The process will be woken up once more data is sent by
    /// calling `stream_update()`.
    ///
    /// **Note:** when supplying buffers that are not multiple of block size, the
    /// buffers will only be filled up to the maximum number of full block sizes
    /// that fit into the buffer.
    ///
    /// The kernel supports multithreaded applications where one or more threads
    /// send data via the `stream_update()` function and another thread collects
    /// the processed data via `stream_op()`. The kernel, however, will return
    /// data via `stream_op()` as soon as it has some data available.
    ///
    /// For example, one thread sends 4096 bytes to be encrypted and another
    /// thread already waits for the ciphertext. The kernel may send only, say,
    /// 2048 bytes back to the waiting process during one `stream_op()` call. In
    /// a subsequent calls to `stream_op()` more ciphertext is returned. This
    /// implies that when the receiving thread shall collect all data there is,
    /// `stream_op()` must be called in a loop until all data is received.
    ///
    /// On success, returns any processed data as a `Vec<Vec<u8>>`
    ///
    pub fn stream_op(&mut self) -> KcapiResult<Vec<Vec<u8>>> {
        let outvec = self.invec.clone();
        let mut iov = IOVec::new(outvec)?;

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_stream_op(
                self.handle,
                iov.iovec.as_mut_ptr(),
                iov.len() as kcapi_sys::size_t,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to obtain output stream for algorithm '{}'",
                        self.algorithm,
                    ),
                });
            }
        }
        self.invec = Vec::new();
        Ok(iov.data)
    }
}

///
/// ## One-shot convenience function for synchronous encyption
///
/// This function is a convenience function to decrypt data using an algorithm
/// specified in `/proc/crypto`.
///
/// *Note:* The algorithm used for encryption **MUST** be present in `/proc/crypto`
///
/// This function takes:
/// * `alg` - The algorithm to use for the encryption operation as an `&str`.
/// * `key` - The key to use for encryption of type `Vec<u8>`.
/// * `pt` - The plaintext to be encrypted of type `Vec<u8>`.
/// * `iv` - The IV used of type `Vec<u8>`.
///
/// On success, returns a `Vec<u8>` with the ciphertext.
/// On failure, returns a `KcapiError`.
///
/// ## Examples
///
/// ```
/// let pt = "Hello, World!".as_bytes().to_vec();
/// let key = vec![0x00u8; 16];
/// let iv = vec![0x00u8; 16];
///
/// let ct = match kcapi::skcipher::encrypt("ctr(aes)", key, pt, iv) {
///     Ok(ct) => ct,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
pub fn encrypt(alg: &str, key: Vec<u8>, pt: Vec<u8>, iv: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let mut cipher = KcapiSKCipher::new(alg, !INIT_AIO)?;
    cipher.setkey(key)?;
    let ct = cipher.encrypt(pt, iv, crate::ACCESS_HEURISTIC)?;

    Ok(ct)
}

///
/// ## Convenience function to encrypt data (asynchronous one shot)
///
/// This is a asynchronous convenience function to perform encryption of an
/// input plaintext represented as a `Vec<Vec<u8>>`. This gets converted
/// into a scatter-gather list which can be processed by the linux kernel.
/// The IV provided in this operation must be `self.ivsize` bytes in size.
///
/// This function takes:
/// * `alg` - An `&str` representation of an skcipher algorithm from `/proc/crypto`.
/// * `key` - A key of type `Vec<u8>`
/// * `pt` - A list of plaintexts to be encrypted of type `Vec<Vec<u8>>`
/// * `iv` - An IV of type `Vec<u8>`.
///
/// On success, returns a `Vec<Vec<u8>>` with the ciphertexts.
/// On failure, returns a `KcapiError`
///
/// ## Examples
///
/// ```
/// let key = vec![0u8; 16];
/// let pt = vec![
///     "This is a".as_bytes().to_vec(),
///     "plaintext".as_bytes().to_vec(),
///     "To AIO Encrypt".as_bytes().to_vec(),
/// ];
/// let iv = vec![0u8; 16];
/// let ct = match kcapi::skcipher::encrypt_aio("ctr(aes)", key, pt, iv) {
///     Ok(ct) => ct,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
pub fn encrypt_aio(
    alg: &str,
    key: Vec<u8>,
    pt: Vec<Vec<u8>>,
    iv: Vec<u8>,
) -> KcapiResult<Vec<Vec<u8>>> {
    let mut cipher = KcapiSKCipher::new(alg, INIT_AIO)?;
    cipher.setkey(key)?;
    let ct = cipher.encrypt_aio(pt, iv, crate::ACCESS_HEURISTIC)?;

    Ok(ct)
}

///
/// ## One-shot convenience function for synchronous decyption
///
/// This function is a convenience function to decrypt data using an algorithm
/// specified in `/proc/crypto`.
///
/// *Note:* The algorithm used for decryption **MUST** be present in `/proc/crypto`
///
/// This function takes:
/// * `alg` - The algorithm to use for the decryption operation as an `&str`.
/// * `key` - The key to use for decryption of type `Vec<u8>`.
/// * `ct` - The ciphertext to be decrypted of type `Vec<u8>`.
/// * `iv` - The IV used of type `Vec<u8>`.
///
/// On success, returns a `Vec<u8>` with the plaintext.
/// On failure, returns a `KcapiError`.
///
/// ## Examples
///
/// ```
/// let ct = vec![0x2e, 0x8c, 0x27, 0xb8, 0x80, 0xa6, 0xc, 0x6c, 0xe7, 0x3e, 0x96, 0x3d, 0xeb];
/// let key = vec![0x00u8; 16];
/// let iv = vec![0x00u8; 16];
///
/// let pt = match kcapi::skcipher::decrypt("ctr(aes)", key, ct, iv) {
///     Ok(pt) => pt,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
pub fn decrypt(alg: &str, key: Vec<u8>, ct: Vec<u8>, iv: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let mut cipher = KcapiSKCipher::new(alg, !INIT_AIO)?;
    cipher.setkey(key)?;
    let pt = cipher.decrypt(ct, iv, crate::ACCESS_HEURISTIC)?;

    Ok(pt)
}

///
/// ## Convenience function to decrypt data (asynchronous one shot)
///
/// This is a asynchronous convenience function to perform decryption of an
/// input ciphertext represented as a `Vec<Vec<u8>>`. This gets converted
/// into a scatter-gather list which can be processed by the linux kernel.
/// The IV provided in this operation must be `self.ivsize` bytes in size.
///
/// This function takes:
/// * `alg` - An `&str` representation of an skcipher algorithm from `/proc/crypto`.
/// * `key` - A key of type `Vec<u8>`
/// * `pt` - A list of ciphertexts to be decrypted of type `Vec<Vec<u8>>`
/// * `iv` - An IV of type `Vec<u8>`.
///
/// On success, returns a `Vec<Vec<u8>>` with the plaintexts.
/// On failure, returns a `KcapiError`.
///
/// ## Examples
///
/// ```
/// let key = vec![0u8; 16];
/// let ct = vec![
///     "This is a".as_bytes().to_vec(),
///     "ciphertext".as_bytes().to_vec(),
///     "To AIO Decrypt".as_bytes().to_vec(),
/// ];
/// let iv = vec![0u8; 16];
/// let pt = match kcapi::skcipher::decrypt_aio("ctr(aes)", key, ct, iv) {
///     Ok(pt) => pt,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
pub fn decrypt_aio(
    alg: &str,
    key: Vec<u8>,
    ct: Vec<Vec<u8>>,
    iv: Vec<u8>,
) -> KcapiResult<Vec<Vec<u8>>> {
    let mut cipher = crate::skcipher::KcapiSKCipher::new(alg, INIT_AIO)?;
    cipher.setkey(key)?;
    let pt = cipher.decrypt_aio(ct, iv, crate::ACCESS_HEURISTIC)?;

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

///
/// ## Convenience function for AES CBC encryption
///
/// The convenience function performs an AES CBC encryption operation using the
/// provided key, the given input buffer and the given IV.
///
/// **Note:** AES CBC requires an input data that is a multiple of 16 bytes. If you
/// have data that is not guaranteed to be multiples of 16 bytes, either add zero
/// bytes at the end of the buffer to pad it up to a multiple of 16 bytes.
/// Otherwise, the CTR mode encryption operation may be usable.
///
/// The IV must be exactly 16 bytes in size.
///
/// The AES type (AES-128, AES-192 or AES-256) is determined by the size of the
/// given key. If the key is 16 bytes long, AES-128 is used. A 24 byte key
/// implies AES-192 and a 32 byte key implies AES-256.
///
/// This function takes:
/// * `key` - A key of type `Vec<u8>` of exactly 16, 24, or 32 bytes.
/// * `pt` - A plaintext of type `Vec<u8>` which must be a multiple of 16 bytes long.
/// * `iv` - An IV of type `[u8; AES_BLOCKSIZE]`
///
/// On success, a ciphertext of type `Vec<u8>` is returned.
/// On failure, a `KcapiError` is returned
///
/// ## Examples
///
/// ```
/// let key = vec![0u8; 16]; // AES128 CBC
/// let iv = [0u8; kcapi::skcipher::AES_BLOCKSIZE];
/// let pt = "sixteen byte str".as_bytes().to_vec();
///
/// let ct = kcapi::skcipher::enc_aes_cbc(key, pt, iv)
///     .expect("Failed AES Encryption");
/// ```
///
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

///
/// ## Convenience function for AES CBC decryption
///
/// The convenience function performs an AES CBC decryption operation using the
/// provided key, the given input buffer and the given IV.
///
/// Note, AES CBC requires an input data that is a multiple of 16 bytes. If you
/// have data that is not guaranteed to be multiples of 16 bytes, either add zero
/// bytes at the end of the buffer to pad it up to a multiple of 16 bytes.
/// Otherwise, the CTR mode operation may be usable.
///
/// The output buffer must be at least as large as the input buffer.
///
/// The IV must be exactly 16 bytes in size.
///
/// The AES type (AES-128, AES-192 or AES-256) is determined by the size of the
/// given key. If the key is 16 bytes long, AES-128 is used. A 24 byte key
/// implies AES-192 and a 32 byte key implies AES-256.
///
/// This function takes:
/// * `key` - A key of type `Vec<u8>`
/// * `ct` - A ciphertext of type `Vec<u8>` with length a multiple of `AES_BLOCKSIZE`
/// * `iv` - An IV of type `[u8; AES_BLOCKSIZE]`
///
/// On success, a `Vec<u8>` filled with plaintext is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let key = vec![0u8; 16]; // AES128 CBC
/// let iv = [0u8; kcapi::skcipher::AES_BLOCKSIZE];
/// let pt = "sixteen byte str".as_bytes().to_vec();
///
/// let ct = kcapi::skcipher::enc_aes_cbc(key.clone(), pt, iv.clone())
///     .expect("Failed AES Encryption");
///
/// let plain = kcapi::skcipher::dec_aes_cbc(key, ct, iv)
///     .expect("Failed AES Decryption");
/// ```
///
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

///
/// ## Convenience function for AES CTR encryption
///
/// The convenience function performs an AES counter mode encryption operation
/// using the provided key, the given input buffer and the given IV.
///
/// The input buffer can be of arbitrary length.
///
/// The start counter can contain all zeros (not a NULL buffer!) and must be
/// exactly 16 bytes in size.
///
/// The AES type (AES-128, AES-192 or AES-256) is determined by the size of the
/// given key. If the key is 16 bytes long, AES-128 is used. A 24 byte key
/// implies AES-192 and a 32 byte key implies AES-256.
///
/// This function takes:
/// * `key` - An encryption key of type `Vec<u8>`.
/// * `pt` - The plaintext to be encrypted of type `Vec<u8>`.
/// * `ctr` - A start counter of type `[u8; AES_BLOCKSIZE]`.
///
/// On success, a `Vec<u8>` of ciphertext is returned.
/// On failure, a `KcapiError` is returned.
///
/// ## Examples
///
/// ```
/// let key = vec![0u8; 16]; // AES128 CTR
/// let ctr = [0u8; 16];
/// let pt = vec![0u8; 16];
///
/// let ct = match kcapi::skcipher::enc_aes_ctr(key, pt, ctr) {
///     Ok(ct) => ct,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
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

///
/// ## Convenience function for AES CTR decryption
///
/// The convenience function performs an AES counter mode decryption operation
/// using the provided key, the given input buffer and the given IV.
///
/// The input buffer can be of arbitrary length.
///
/// The start counter can contain all zeros (not a NULL buffer!) and must be
/// exactly 16 bytes in size.
///
/// The AES type (AES-128, AES-192 or AES-256) is determined by the size of the
/// given key. If the key is 16 bytes long, AES-128 is used. A 24 byte key
/// implies AES-192 and a 32 byte key implies AES-256.
///
/// This function takes:
/// * `key` - An decryption key of type `Vec<u8>`.
/// * `pt` - The ciphertext to be decrypted of type `Vec<u8>`.
/// * `ctr` - A start counter of type `[u8; AES_BLOCKSIZE]`.
///
/// On success, a `Vec<u8>` of plaintext is returned.
/// On failure, a `KcapiError` is returned.
/// ## Examples
///
/// ```
/// let key = vec![0u8; 16]; // AES128 CTR
/// let ctr = [0u8; 16];
/// let pt = vec![0u8; 16];
///
/// let ct = match kcapi::skcipher::enc_aes_ctr(key.clone(), pt, ctr.clone()) {
///     Ok(ct) => ct,
///     Err(e) => panic!("{}", e),
/// };
///
/// let plain = match kcapi::skcipher::dec_aes_ctr(key, ct, ctr) {
///     Ok(plain) => plain,
///     Err(e) => panic!("{}", e),
/// };
/// ```
///
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
