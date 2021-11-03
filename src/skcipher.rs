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

use crate::{IOVec, KcapiError, KcapiResult, BITS_PER_BYTE, KCAPI_INIT_AIO};

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

        let iovlen = pt.len();
        let mut ptvec = pt.clone();
        let mut ctvec = pt;

        let mut iniov = IOVec::new(&mut ptvec, iovlen);
        let mut outiov = IOVec::new(&mut ctvec, iovlen);

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_encrypt_aio(
                self.handle,
                iniov.iovec.as_mut_ptr(),
                outiov.iovec.as_mut_ptr(),
                iovlen as kcapi_sys::size_t,
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
        Ok(ctvec)
    }

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

        let iovlen = ct.len();
        let mut ctvec = ct.clone();
        let mut ptvec = ct;

        let mut iniov = IOVec::new(&mut ctvec, iovlen);
        let mut outiov = IOVec::new(&mut ptvec, iovlen);

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_decrypt_aio(
                self.handle,
                iniov.iovec.as_mut_ptr(),
                outiov.iovec.as_mut_ptr(),
                iovlen as kcapi_sys::size_t,
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
        Ok(ptvec)
    }

    pub fn new_enc_stream(
        algorithm: &str,
        key: Vec<u8>,
        iv: Vec<u8>,
        pt: Vec<Vec<u8>>,
    ) -> KcapiResult<Self> {
        let mut cipher = Self::new(algorithm, !KCAPI_INIT_AIO)?;
        cipher.setkey(key)?;
        cipher.iv = iv.clone();
        cipher.stream_mode = SKCipherMode::Encrypt;

        let iovlen = pt.len();
        if iovlen == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Invalid input vector of length 0 for algorithm '{}'",
                    cipher.algorithm,
                ),
            });
        }

        let mut ptvec = pt;
        let mut iov = IOVec::new(&mut ptvec, iovlen);

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_stream_init_enc(
                cipher.handle,
                iv.as_ptr(),
                iov.iovec.as_mut_ptr(),
                iovlen as kcapi_sys::size_t,
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
        cipher.invec.extend_from_slice(ptvec.as_slice());
        Ok(cipher)
    }

    pub fn new_dec_stream(
        algorithm: &str,
        key: Vec<u8>,
        iv: Vec<u8>,
        ct: Vec<Vec<u8>>,
    ) -> KcapiResult<Self> {
        let mut cipher = Self::new(algorithm, !KCAPI_INIT_AIO)?;
        cipher.setkey(key)?;
        cipher.iv = iv.clone();
        cipher.stream_mode = SKCipherMode::Decrypt;

        let iovlen = ct.len();
        if iovlen == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Invalid input vector of length 0 for algorithm '{}'",
                    cipher.algorithm,
                ),
            });
        }

        let mut ctvec = ct;
        let mut iov = IOVec::new(&mut ctvec, iovlen);

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_stream_init_dec(
                cipher.handle,
                iv.as_ptr(),
                iov.iovec.as_mut_ptr(),
                iovlen as kcapi_sys::size_t,
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
        cipher.invec.extend_from_slice(ctvec.as_slice());
        Ok(cipher)
    }

    pub fn stream_update(&mut self, input: Vec<Vec<u8>>) -> KcapiResult<()> {
        let iovlen = input.len();
        let mut ivec = input;
        let mut iov = IOVec::new(&mut ivec, iovlen);

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_stream_update(
                self.handle,
                iov.iovec.as_mut_ptr(),
                iovlen as kcapi_sys::size_t,
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
        self.invec.extend_from_slice(ivec.as_slice());
        Ok(())
    }

    pub fn stream_update_last(&mut self, input: Vec<Vec<u8>>) -> KcapiResult<()> {
        let iovlen = input.len();
        let mut ivec = input;
        let mut iov = IOVec::new(&mut ivec, iovlen);

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_stream_update_last(
                self.handle,
                iov.iovec.as_mut_ptr(),
                iovlen as kcapi_sys::size_t,
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
        self.invec.extend_from_slice(ivec.as_slice());
        Ok(())
    }

    pub fn stream_op(&mut self) -> KcapiResult<Vec<Vec<u8>>> {
        let iovlen = self.invec.len();
        let mut outvec = self.invec.clone();
        let mut iov = IOVec::new(&mut outvec, iovlen);

        unsafe {
            let ret = kcapi_sys::kcapi_cipher_stream_op(
                self.handle,
                iov.iovec.as_mut_ptr(),
                iovlen as kcapi_sys::size_t,
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
        Ok(outvec)
    }
}

pub fn encrypt(
    alg: &str,
    key: Vec<u8>,
    pt: Vec<u8>,
    iv: Vec<u8>,
    access: u32,
) -> KcapiResult<Vec<u8>> {
    let mut cipher = KcapiSKCipher::new(alg, !KCAPI_INIT_AIO)?;
    cipher.setkey(key)?;
    let ct = cipher.encrypt(pt, iv, access)?;

    Ok(ct)
}

pub fn encrypt_aio(
    alg: &str,
    key: Vec<u8>,
    pt: Vec<Vec<u8>>,
    iv: Vec<u8>,
    access: u32,
) -> KcapiResult<Vec<Vec<u8>>> {
    let mut cipher = KcapiSKCipher::new(alg, KCAPI_INIT_AIO)?;
    cipher.setkey(key)?;
    let ct = cipher.encrypt_aio(pt, iv, access)?;

    Ok(ct)
}

pub fn decrypt(
    alg: &str,
    key: Vec<u8>,
    ct: Vec<u8>,
    iv: Vec<u8>,
    access: u32,
) -> KcapiResult<Vec<u8>> {
    let mut cipher = KcapiSKCipher::new(alg, !KCAPI_INIT_AIO)?;
    cipher.setkey(key)?;
    let pt = cipher.decrypt(ct, iv, access)?;

    Ok(pt)
}

pub fn decrypt_aio(
    alg: &str,
    key: Vec<u8>,
    ct: Vec<Vec<u8>>,
    iv: Vec<u8>,
    access: u32,
) -> KcapiResult<Vec<Vec<u8>>> {
    let mut cipher = crate::skcipher::KcapiSKCipher::new(alg, KCAPI_INIT_AIO)?;
    cipher.setkey(key)?;
    let pt = cipher.decrypt_aio(ct, iv, access)?;

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
