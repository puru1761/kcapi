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
//! # Asymmetric Key Ciphers (akcipher) using the Kernel Crypto API
//!
//! This module is **EXPERIMENTAL**
//!
//! This module provides the capability to perform asymmetric key encryption,
//! decryption, signing, and verification using the KCAPI provided the following
//! conditions are met:
//!
//! 1. The patches in the `kernel-patches` directory are successfully applied.
//! 2. The kernel is compiled with `CONFIG_CRYPTO_USER_API_AKCIPHER=y`
//!
//! *Note:* Any asymmetric key cipher used with this module **MUST** be present
//! in `/proc/crypto` on the target device.
//!
//! # Layout
//!
//! This module provides one-shot convenience functions to perform encryption,
//! decryption, signing, and verification using any AK cipher present in
//! `/proc/crypto`. This module also provides the `KcapiAKCipher` type which
//! provides APIs to initialize, set public and private keys, encrypt, decrypt,
//! sign, and verify using the appropriate algorithm from `/proc/crypto`.
//!
//!
//! ## Caveats
//!
//! Since the support to perform asymmetric cipher operations from userland is
//! not present in the upstream Linux kernel, this module is still **EXPERIMENTAL**.
//!

use std::{convert::TryInto, ffi::CString};

use crate::{KcapiError, KcapiResult, VMSplice, ACCESS_HEURISTIC, INIT_AIO};

///
/// # The `KcapiAKCipher` Type
///
/// This type denotes a generic context for an Asymmetric Key cipher transform
/// in the Linux Kernel. An instance of this struct must be initialized using
/// the `new()` call prior to being used. This type provides APIs to perform:
///
/// * setting of public and private keys.
/// * encryption
/// * decryption
/// * signing
/// * verification
///
/// ## Panics
///
/// If the string provided as input to the `new()` function cannot be converted into a
/// `std::ffi::CString` type, the initialization will panic with the message
/// `Failed to create CString`.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KcapiAKCipher {
    handle: *mut kcapi_sys::kcapi_handle,
    pubkey: Vec<u8>,
    privkey: Vec<u8>,
    pub modsize: usize,
    pub algorithm: String,
}

impl KcapiAKCipher {
    ///
    /// ## Initialize an instance of the `KcapiAKCipher` Type.
    ///
    /// This function initializes an instance of the `KcapiAKCipher` Type and
    /// makes the necessary connections to the kernel through `kcapi-sys`.
    ///
    /// This function takes:
    /// * `algorithm` - a `&str` representation of an `akcipher` algorithm in `/proc/crypto`
    /// * `flags` - `u32` flags specifying the type of cipher handle.
    ///
    /// On success, an initialized instance of `KcapiAKCipher` is returned.
    /// On failure, a `KcapiError` is returned.
    ///
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
                    code: ret,
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

    ///
    /// ## Set the Private Key
    ///
    /// This function is used to set the private key for decryption and
    /// signing operations.
    ///
    /// The key must be a `Vec<u8>` in DER format as follows:
    ///
    /// ```none
    /// SEQUENCE {
    ///     version INTEGER,
    ///     n INTEGER ({ rsa_get_n }),
    ///     e INTEGER ({ rsa_get_e }),
    ///     d INTEGER ({ rsa_get_d }),
    ///     prime1 INTEGER,
    ///     prime2 INTEGER,
    ///     exponent1 INTEGER,
    ///     exponent2 INTEGER,
    ///     coefficient INTEGER
    /// }
    /// ```
    ///
    /// This function takes:
    /// * `privkey` - A `Vec<u8>` containing the key in the above format.
    ///
    /// On failure, a `KcapiError` is returned.
    pub fn setprivkey(&mut self, privkey: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_akcipher_setkey(
                self.handle,
                privkey.as_ptr(),
                privkey.len() as u32,
            );

            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
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

    ///
    /// ## Set the Public Key
    ///
    /// This function is used to set the public key for encryption and
    /// verification operations.
    ///
    /// The public key must be a `Vec<u8>` in DER format as follows:
    ///
    /// ```none
    /// SEQUENCE {
    ///     n INTEGER ({ rsa_get_n }),
    ///     e INTEGER ({ rsa_get_e })
    /// }
    /// ```
    ///
    /// This function takes:
    /// * `pubkey` - A `Vec<u8>` containing the public key in the above format.
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    pub fn setpubkey(&mut self, pubkey: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_akcipher_setpubkey(
                self.handle,
                pubkey.as_ptr(),
                pubkey.len() as u32,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
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

    ///
    /// ## Perform Asymmetric Encryption
    ///
    /// This function encrypts data using a public key. It is necessary to
    /// set the publickey prior to calling `encrypt()`.
    ///
    /// *Note:* Only `self.modsize` bytes of data can be encrypted at a time.
    ///
    /// This function takes:
    /// * `pt` - A `Vec<u8>` containing the plaintext to be encrypted.
    /// * `access` - kernel access type (`u32`)
    ///     - `ACCESS_HEURISTIC` - internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, returns a `Vec<u8>` wih the encrypted ciphertext.
    /// On failure, returns `KcapiError`
    ///
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
                    code: ret.try_into().expect("failed to convert i64 into i32"),
                    message: format!("Failed to encrypt for algorithm '{}'", self.algorithm),
                });
            }
        }
        Ok(ct)
    }

    ///
    /// ## Perform Asymmetric Decryption
    ///
    /// This function decrypts data using a private key. It is necessary to
    /// set the privatekey prior to calling `decrypt()`.
    ///
    /// *Note:* Only `self.modsize` bytes of data can be decrypted at a time.
    ///
    /// This function takes:
    /// * `pt` - A `Vec<u8>` containing the ciphertext to be decrypted.
    /// * `access` - kernel access type (`u32`)
    ///     - `ACCESS_HEURISTIC` - internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, returns a `Vec<u8>` wih the decrypted plaintext.
    /// On failure, returns `KcapiError`
    ///
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
                    code: ret.try_into().expect("failed to convert i64 into i32"),
                    message: format!("Failed to decrypt for algorithm '{}'", self.algorithm),
                });
            }
        }
        Ok(pt)
    }

    ///
    /// ## Perform Signing
    ///
    /// This function signs data using a private key. It is necessary to
    /// set the privatekey prior to calling `sign()`.
    ///
    /// This function takes:
    /// * `message` - A `Vec<u8>` containing the message to be signed.
    /// * `access` - kernel access type (`u32`)
    ///     - `ACCESS_HEURISTIC` - internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, returns a `Vec<u8>` wih the signature.
    /// On failure, returns `KcapiError`
    ///
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
                    code: ret.try_into().expect("failed to convert i64 into i32"),
                    message: format!("Failed to sign for algorithm '{}'", self.algorithm),
                });
            }
        }
        Ok(sig)
    }

    ///
    /// ## Perform Signature Verification
    ///
    /// This function verifys data using a private key. It is necessary to
    /// set the privatekey prior to calling `verify()`.
    ///
    /// This function takes:
    /// * `message` - A `Vec<u8>` containing the message to be verified.
    /// * `sig` - A `Vec<u8>` containing the signature to be verified.
    /// * `access` - kernel access type (`u32`)
    ///     - `ACCESS_HEURISTIC` - internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On failure to verify the signature, returns `KcapiError` with the `code`
    /// field set to `EBADMSG`.
    ///
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
                    code: -libc::EBADMSG,
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

impl Drop for KcapiAKCipher {
    fn drop(&mut self) {
        unsafe {
            kcapi_sys::kcapi_akcipher_destroy(self.handle);
        }
    }
}

impl VMSplice for KcapiAKCipher {
    ///
    /// ## Get Maximum buffer size of VMSPLICE Access
    ///
    /// This function returns the maximum number of bytes that can be handled
    /// by a VMSPLICE call to the kernel.
    ///
    fn get_max_splicesize(&self) -> usize {
        let size: usize;
        unsafe {
            size = kcapi_sys::kcapi_get_maxsplicesize(self.handle) as usize;
        }
        size
    }

    ///
    /// ## Set Maximum Buffer Size for VMSPLICE Access
    ///
    /// When using vmsplice/splice to avoid copying of data into the kernel, the
    /// kernel enforces a maximum number of bytes which can be spliced. If larger
    /// data is to be processed, sendmsg will be used.
    ///
    /// Using this call, the buffer size can be increased.
    ///
    /// *NOTE:* Splice uses a pipe pair. Therefore, the maximum number of bytes
    /// that can be stored with the pipe governs the maximum data size to be
    /// spliced. Increasing the pipe buffer size is only allowed up to the maximum
    /// specified with `/proc/sys/fs/pipe-max-size`.
    ///
    /// This function takes:
    /// `size` - A `usize` denoting the size of the vmsplice buffer.
    ///
    /// On failure a `KcapiResult` is returned.
    ///
    fn set_max_splicesize(&self, size: usize) -> KcapiResult<()> {
        unsafe {
            let ret =
                kcapi_sys::kcapi_set_maxsplicesize(self.handle, size as ::std::os::raw::c_uint);

            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Unable to set max splice size {} for algorithm {}",
                        size, self.algorithm,
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
            code: -libc::EINVAL,
            message: format!(
                "Required asymmetric key is not set for algorithm '{}'",
                handle.algorithm
            ),
        });
    }
    if inp.len() > handle.modsize {
        return Err(KcapiError {
            code: -libc::EINVAL,
            message: format!(
                "Input to asymmetric cipher is larger than modulus size for algorithm {}",
                handle.algorithm
            ),
        });
    }
    Ok(())
}

///
/// ## Convenience Function to Perform Asymmetric Encryption
///
/// This function encrypts data using a public key. The key provided
/// for the encryption operation should be DER encoded in the following
/// format:
///
/// ```none
/// SEQUENCE {
///     n INTEGER ({ rsa_get_n }),
///     e INTEGER ({ rsa_get_e })
/// }
/// ```
///
/// *Note:* Only `self.modsize` bytes of data can be encrypted at a time.
///
/// This function takes:
/// * `alg` - A `&str` representation of an akcipher algorithm from `/proc/crypto`.
/// * `key` - A `Vec<u8>` with the public key.
/// * `pt` - A `Vec<u8>` containing the plaintext to be encrypted.
///
/// On success, returns a `Vec<u8>` wih the encrypted ciphertext.
/// On failure, returns `KcapiError`
///
pub fn encrypt(alg: &str, key: Vec<u8>, pt: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let mut handle = KcapiAKCipher::new(alg, !INIT_AIO)?;
    handle.setpubkey(key)?;
    let ct = handle.encrypt(pt, ACCESS_HEURISTIC)?;
    Ok(ct)
}

///
/// ## Convenience Function to Perform Asymmetric Decryption
///
/// This function decrypts data using a private key.
/// The key must be a `Vec<u8>` in DER format as follows:
///
/// ```none
/// SEQUENCE {
///     version INTEGER,
///     n INTEGER ({ rsa_get_n }),
///     e INTEGER ({ rsa_get_e }),
///     d INTEGER ({ rsa_get_d }),
///     prime1 INTEGER,
///     prime2 INTEGER,
///     exponent1 INTEGER,
///     exponent2 INTEGER,
///     coefficient INTEGER
/// }
/// ```
///
/// *Note:* Only `self.modsize` bytes of data can be decrypted at a time.
///
/// This function takes:
/// * `alg` - A `&str` representation of an akcipher algorithm from `/proc/crypto`.
/// * `key` - A `Vec<u8>` with the private key.
/// * `ct` - A `Vec<u8>` containing the ciphertext to be decrypted.
///
/// On success, returns a `Vec<u8>` wih the decrypted plaintext.
/// On failure, returns `KcapiError`
///
pub fn decrypt(alg: &str, key: Vec<u8>, ct: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let mut handle = KcapiAKCipher::new(alg, !INIT_AIO)?;
    handle.setprivkey(key)?;
    let pt = handle.decrypt(ct, ACCESS_HEURISTIC)?;
    Ok(pt)
}

///
/// ## Convenience Function to Perform Signing
///
/// This function signs data using a private key.
/// The key must be a `Vec<u8>` in DER format as follows:
///
/// ```none
/// SEQUENCE {
///     version INTEGER,
///     n INTEGER ({ rsa_get_n }),
///     e INTEGER ({ rsa_get_e }),
///     d INTEGER ({ rsa_get_d }),
///     prime1 INTEGER,
///     prime2 INTEGER,
///     exponent1 INTEGER,
///     exponent2 INTEGER,
///     coefficient INTEGER
/// }
/// ```
///
/// This function takes:
/// * `alg` - A `&str` representation of an akcipher algorithm from `/proc/crypto`.
/// * `key` - A `Vec<u8>` with the private key.
/// * `message` - A `Vec<u8>` containing the message to be signed.
///
/// On success, returns a `Vec<u8>` wih the signature.
/// On failure, returns `KcapiError`
///
pub fn sign(alg: &str, key: Vec<u8>, message: Vec<u8>) -> KcapiResult<Vec<u8>> {
    let mut handle = KcapiAKCipher::new(alg, !INIT_AIO)?;
    handle.setprivkey(key)?;
    let sig = handle.sign(message, ACCESS_HEURISTIC)?;
    Ok(sig)
}

///
/// ## Perform Signature Verification
///
/// This function verifys data using a private key. The key provided
/// for the encryption operation should be DER encoded in the following
/// format:
///
/// ```none
/// SEQUENCE {
///     n INTEGER ({ rsa_get_n }),
///     e INTEGER ({ rsa_get_e })
/// }
/// ```
///
/// This function takes:
/// * `alg` - A `&str` representation of an akcipher algorithm from `/proc/crypto`.
/// * `key` - A `Vec<u8>` with the public key.
/// * `message` - A `Vec<u8>` containing the message to be verified.
/// * `sig` - A `Vec<u8>` containing the signature to be verified.
///
/// On failure to verify the signature, returns `KcapiError` with the `code`
/// field set to `EBADMSG`.
///
pub fn verify(alg: &str, key: Vec<u8>, message: Vec<u8>, sig: Vec<u8>) -> KcapiResult<()> {
    let mut handle = KcapiAKCipher::new(alg, !INIT_AIO)?;
    handle.setpubkey(key)?;
    handle.verify(message, sig, ACCESS_HEURISTIC)?;
    Ok(())
}
