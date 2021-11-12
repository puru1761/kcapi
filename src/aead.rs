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

use crate::{KcapiError, KcapiResult};

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct KcapiAEADData {
    assocdata: Vec<u8>,
    data: Vec<u8>,
    tag: Vec<u8>,
    tagsize: usize,
}

impl KcapiAEADData {
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

    pub fn new_enc(pt: Vec<u8>, assocdata: Vec<u8>, tagsize: usize) -> Self {
        let mut aead_data = Self::new();
        aead_data.set_data(pt);
        aead_data.set_assocdata(assocdata);
        aead_data.set_tagsize(tagsize);

        aead_data
    }

    pub fn new_dec(ct: Vec<u8>, assocdata: Vec<u8>, tag: Vec<u8>) -> Self {
        let mut aead_data = Self::new();
        aead_data.set_data(ct);
        aead_data.set_assocdata(assocdata);
        aead_data.set_tag(tag);

        aead_data
    }

    pub(crate) fn set_tag(&mut self, tag: Vec<u8>) {
        self.tagsize = tag.len();
        self.tag = tag;
    }

    pub(crate) fn set_tagsize(&mut self, tagsize: usize) {
        self.tagsize = tagsize;
    }

    pub(crate) fn set_assocdata(&mut self, assocdata: Vec<u8>) {
        self.assocdata = assocdata;
    }

    pub(crate) fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    pub fn get_assocdata(&self) -> Vec<u8> {
        self.assocdata.clone()
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn get_tag(&self) -> Vec<u8> {
        self.tag.clone()
    }

    pub fn assoclen(&self) -> usize {
        self.assocdata.len()
    }

    pub fn datalen(&self) -> usize {
        self.data.len()
    }

    pub fn taglen(&self) -> usize {
        self.tagsize
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KcapiAEADMode {
    Decrypt = 0,
    Encrypt,
}

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
