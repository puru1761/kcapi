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
//! # Key Protocol Primitives (kpp) using the Kernel Crypto API
//!
//! This module is **EXPERIMENTAL**
//!
//! This module provides the capability to perform Diffie-Hellman (`dh`) and
//! Elliptic Curve Diffie-Hellman (`ecdh`) key agreement using the KCAPI,
//! provided the following conditions are met:
//!
//! 1. The patches in the `kernel-patches` directory are successfully applied
//!    (the `algif_kpp` AF_ALG interface is not in the upstream Linux kernel).
//! 2. The kernel is compiled with `CONFIG_CRYPTO_USER_API_KPP=y`, `CONFIG_CRYPTO_DH`,
//!    and (for ECDH) `CONFIG_CRYPTO_ECDH`.
//!
//! *Note:* Any KPP algorithm used with this module **MUST** be present in
//! `/proc/crypto` on the target device.
//!
//! # Layout
//!
//! This module provides the `KcapiKPP` type, which provides APIs to initialize,
//! set the DH parameters or ECC curve, set the private key, generate the public
//! key, and generate the shared secret using the appropriate algorithm from
//! `/proc/crypto`.
//!
//! A typical (EC)DH exchange with this module looks like:
//!
//! 1. `KcapiKPP::new("ecdh", 0)` to obtain a handle.
//! 2. `ecdh_setcurve(ECC_CURVE_NIST_P256)` (ECDH) or `dh_setparam_pkcs3(params)` (DH).
//! 3. `setkey(key)` to install the private key. An empty key requests the kernel
//!    to generate an ephemeral private key internally.
//! 4. `keygen()` to obtain the local public key, which is sent to the peer.
//! 5. `ssgen(peer_pubkey)` to obtain the shared secret.
//!
//! ## Caveats
//!
//! Since the support to perform KPP operations from userland is not present in
//! the upstream Linux kernel, this module is still **EXPERIMENTAL** and is only
//! available when the `kpp` feature is enabled (on by default). This is because
//! the `kpp_*` APIs are available only when `libkcapi` is configured to have them.
//!
//! **WARNING**: Prior to using this API with the `local-kcapi` feature enabled,
//! ensure that you have `lib-kpp` configured for your `libkcapi` installation.
//!

use std::{convert::TryInto, ffi::CString};

use crate::{KcapiError, KcapiResult, ACCESS_HEURISTIC, INIT_AIO};

///
/// The NIST P-192 elliptic curve identifier for use with `ecdh_setcurve()`.
///
pub const ECC_CURVE_NIST_P192: u64 = kcapi_sys::ECC_CURVE_NIST_P192 as u64;

///
/// The NIST P-256 elliptic curve identifier for use with `ecdh_setcurve()`.
///
pub const ECC_CURVE_NIST_P256: u64 = kcapi_sys::ECC_CURVE_NIST_P256 as u64;

///
/// # The `KcapiKPP` Type
///
/// This type denotes a generic context for a Key Protocol Primitives (DH / ECDH)
/// transform in the Linux Kernel. An instance of this struct must be initialized
/// using the `new()` call prior to being used. This type provides APIs to:
///
/// * set the DH parameters (PKCS#3) or the ECC curve.
/// * set the private key (or request kernel-generated ephemeral keys).
/// * generate the public key.
/// * generate the shared secret.
///
/// ## Panics
///
/// If the string provided as input to the `new()` function cannot be converted
/// into a `std::ffi::CString` type, the initialization will panic with the
/// message `Failed to create CString`.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KcapiKPP {
    handle: *mut kcapi_sys::kcapi_handle,
    pub outsize: usize,
    pub algorithm: String,
}

impl KcapiKPP {
    ///
    /// ## Initialize an instance of the `KcapiKPP` Type.
    ///
    /// This function initializes an instance of the `KcapiKPP` Type and makes
    /// the necessary connections to the kernel through `kcapi-sys`.
    ///
    /// This function takes:
    /// * `algorithm` - a `&str` representation of a `kpp` algorithm in `/proc/crypto`
    ///   (for example `"dh"` or `"ecdh"`).
    /// * `flags` - `u32` flags specifying the type of cipher handle.
    ///
    /// On success, an initialized instance of `KcapiKPP` is returned.
    /// On failure, a `KcapiError` is returned.
    ///
    pub fn new(algorithm: &str, flags: u32) -> KcapiResult<Self> {
        let mut handle = Box::into_raw(Box::new(crate::kcapi_handle { _unused: [0u8; 0] }))
            as *mut kcapi_sys::kcapi_handle;

        let alg = CString::new(algorithm).expect("Failed to create CString");
        unsafe {
            let ret = kcapi_sys::kcapi_kpp_init(&mut handle as *mut _, alg.as_ptr(), flags);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to initialize kpp handle for algorithm '{}'",
                        algorithm
                    ),
                });
            }
        }

        Ok(KcapiKPP {
            algorithm: algorithm.to_string(),
            handle,
            outsize: 0,
        })
    }

    ///
    /// ## Set the DH parameters from a PKCS#3 structure
    ///
    /// This function sets the Diffie-Hellman parameters (prime and generator)
    /// for subsequent key generation and shared secret operations. The
    /// parameters must be provided as a `Vec<u8>` holding a DER-encoded PKCS#3
    /// `DHParameter` structure.
    ///
    /// This function takes:
    /// * `pkcs3` - A `Vec<u8>` containing the DER-encoded PKCS#3 parameters.
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    pub fn dh_setparam_pkcs3(&mut self, pkcs3: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_kpp_dh_setparam_pkcs3(
                self.handle,
                pkcs3.as_ptr(),
                pkcs3.len() as u32,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to set DH PKCS#3 parameters for algorithm '{}'",
                        self.algorithm
                    ),
                });
            }
        }
        Ok(())
    }

    ///
    /// ## Set the ECC curve for an ECDH operation
    ///
    /// This function sets the ECC curve for subsequent key generation and shared
    /// secret operations, and selects an ECC Diffie-Hellman operation.
    ///
    /// This function takes:
    /// * `curve_id` - One of the `ECC_CURVE_NIST_*` identifiers exported by this
    ///   module (for example `ECC_CURVE_NIST_P256`).
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    pub fn ecdh_setcurve(&mut self, curve_id: u64) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_kpp_ecdh_setcurve(
                self.handle,
                curve_id as ::std::os::raw::c_ulong,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!(
                        "Failed to set ECC curve {} for algorithm '{}'",
                        curve_id, self.algorithm
                    ),
                });
            }
        }
        Ok(())
    }

    ///
    /// ## Set the private key of the DH / ECDH operation
    ///
    /// This function sets the private key for subsequent public key generation
    /// or shared secret generation operations.
    ///
    /// If `key` is empty, the kernel attempts to generate the private key itself
    /// and retains it internally. This is useful for ephemeral (EC)DH operations
    /// where the caller is only interested in the eventual shared secret.
    ///
    /// *Note:* the DH parameters or the ECC curve **must** be set (via
    /// `dh_setparam_pkcs3()` or `ecdh_setcurve()`) before calling `setkey()`.
    ///
    /// On success, the maximum output size of subsequent operations is stored in
    /// `self.outsize` and used to size the buffers returned by `keygen()` and
    /// `ssgen()`.
    ///
    /// This function takes:
    /// * `key` - A `Vec<u8>` containing the private key, or an empty `Vec<u8>`
    ///   to request a kernel-generated ephemeral private key.
    ///
    /// On failure, a `KcapiError` is returned.
    ///
    pub fn setkey(&mut self, key: Vec<u8>) -> KcapiResult<()> {
        unsafe {
            let ret = kcapi_sys::kcapi_kpp_setkey(self.handle, key.as_ptr(), key.len() as u32);
            if ret < 0 {
                return Err(KcapiError {
                    code: ret,
                    message: format!("Failed to set key for algorithm '{}'", self.algorithm),
                });
            }
            self.outsize = ret.try_into().expect("Failed to convert i32 into usize");
        }
        Ok(())
    }

    ///
    /// ## Generate the local public key
    ///
    /// This function generates the public key corresponding to the private key
    /// previously installed with `setkey()`. The resulting public key is sent to
    /// the peer of the key agreement.
    ///
    /// `setkey()` must be called before `keygen()` so that the output size is
    /// known.
    ///
    /// This function takes:
    /// * `access` - kernel access type (`u32`)
    ///     - `ACCESS_HEURISTIC` - internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, returns a `Vec<u8>` with the public key.
    /// On failure, returns a `KcapiError`.
    ///
    pub fn keygen(&self, access: u32) -> KcapiResult<Vec<u8>> {
        let mut pubkey = vec![0u8; self.outsize];
        let ret: kcapi_sys::ssize_t;
        unsafe {
            ret = kcapi_sys::kcapi_kpp_keygen(
                self.handle,
                pubkey.as_mut_ptr(),
                pubkey.len() as kcapi_sys::size_t,
                access as ::std::os::raw::c_int,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.try_into().expect("failed to convert i64 into i32"),
                    message: format!(
                        "Failed to generate public key for algorithm '{}'",
                        self.algorithm
                    ),
                });
            }
        }
        pubkey.truncate(ret as usize);
        Ok(pubkey)
    }

    ///
    /// ## Generate the shared secret
    ///
    /// This function generates the shared secret from the local private key
    /// (installed with `setkey()`) and the peer's public key.
    ///
    /// `setkey()` must be called before `ssgen()` so that the output size is
    /// known.
    ///
    /// This function takes:
    /// * `pubkey` - A `Vec<u8>` containing the peer's public key (as produced by
    ///   the peer's `keygen()`).
    /// * `access` - kernel access type (`u32`)
    ///     - `ACCESS_HEURISTIC` - internal heuristic for fastest kernel access
    ///     - `ACCESS_VMSPLICE` - vmsplice access
    ///     - `ACCESS_SENDMSG` - sendmsg access
    ///
    /// On success, returns a `Vec<u8>` with the shared secret.
    /// On failure, returns a `KcapiError`.
    ///
    pub fn ssgen(&self, pubkey: Vec<u8>, access: u32) -> KcapiResult<Vec<u8>> {
        let mut ss = vec![0u8; self.outsize];
        let ret: kcapi_sys::ssize_t;
        unsafe {
            ret = kcapi_sys::kcapi_kpp_ssgen(
                self.handle,
                pubkey.as_ptr(),
                pubkey.len() as kcapi_sys::size_t,
                ss.as_mut_ptr(),
                ss.len() as kcapi_sys::size_t,
                access as ::std::os::raw::c_int,
            );
            if ret < 0 {
                return Err(KcapiError {
                    code: ret.try_into().expect("failed to convert i64 into i32"),
                    message: format!(
                        "Failed to generate shared secret for algorithm '{}'",
                        self.algorithm
                    ),
                });
            }
        }
        ss.truncate(ret as usize);
        Ok(ss)
    }
}

impl Drop for KcapiKPP {
    fn drop(&mut self) {
        unsafe {
            kcapi_sys::kcapi_kpp_destroy(self.handle);
        }
    }
}

///
/// ## Convenience function to perform an ephemeral ECDH key agreement
///
/// This one-shot convenience function performs the local half of an ephemeral
/// Elliptic Curve Diffie-Hellman key agreement: it selects the given curve,
/// requests a kernel-generated ephemeral private key, and returns the resulting
/// local public key together with an initialized `KcapiKPP` handle that can be
/// used to compute the shared secret via [`KcapiKPP::ssgen`].
///
/// This function takes:
/// * `curve_id` - One of the `ECC_CURVE_NIST_*` identifiers (for example
///   `ECC_CURVE_NIST_P256`).
///
/// On success, returns a tuple of `(KcapiKPP, Vec<u8>)` where the `Vec<u8>` is
/// the local public key to send to the peer.
/// On failure, returns a `KcapiError`.
///
pub fn ecdh_ephemeral_keygen(curve_id: u64) -> KcapiResult<(KcapiKPP, Vec<u8>)> {
    let mut kpp = KcapiKPP::new("ecdh", !INIT_AIO)?;
    kpp.ecdh_setcurve(curve_id)?;
    kpp.setkey(Vec::new())?;
    let pubkey = kpp.keygen(ACCESS_HEURISTIC)?;
    Ok((kpp, pubkey))
}
