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

use crate::{KcapiAlgType, KcapiError, KcapiHandle, KcapiResult};

pub const AEAD_ENCRYPT: u32 = 0;
pub const AEAD_DECRYPT: u32 = 1;

#[derive(Debug, Clone)]
pub struct KCAPIAEADOutput {
    pub assocdata: Vec<u8>,
    pub output: Vec<u8>,
    pub tag: Vec<u8>,
}

pub fn alg_init(algorithm: &str, flags: u32) -> KcapiResult<KcapiHandle> {
    let mut handle = KcapiHandle::new(algorithm, KcapiAlgType::AEAD);
    let alg = CString::new(algorithm).expect("Failed to allocate CString");

    unsafe {
        let ret = kcapi_sys::kcapi_aead_init(&mut handle.handle as *mut _, alg.as_ptr(), flags);
        if ret < 0 {
            return Err(KcapiError {
                code: ret.into(),
                message: format!("Failed to init aead handle for algorithm '{}'", algorithm),
            });
        }
    }

    Ok(handle)
}

pub fn alg_setkey(handle: &KcapiHandle, key: Vec<u8>) -> KcapiResult<()> {
    unsafe {
        let ret = kcapi_sys::kcapi_aead_setkey(handle.handle, key.as_ptr(), key.len() as u32);
        if ret < 0 {
            return Err(KcapiError {
                code: ret.into(),
                message: format!("Failed to setkey for algorithm '{}'", handle.algorithm),
            });
        }
    }
    Ok(())
}

pub fn alg_authsize(handle: &KcapiHandle) -> KcapiResult<usize> {
    let authsize: usize;
    unsafe {
        authsize = kcapi_sys::kcapi_aead_authsize(handle.handle)
            .try_into()
            .expect("Failed to convert u32 into usize");
        if authsize == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Failed to obtain max tag length for algorithm '{}'",
                    handle.algorithm
                ),
            });
        }
    }
    Ok(authsize)
}

pub fn alg_blocksize(handle: &KcapiHandle) -> KcapiResult<usize> {
    let blocksize: usize;
    unsafe {
        blocksize = kcapi_sys::kcapi_aead_blocksize(handle.handle)
            .try_into()
            .expect("Failed to convert u32 into usize");
        if blocksize == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Failed to obtain blocksize for algorithm '{}'",
                    handle.algorithm
                ),
            });
        }
    }
    Ok(blocksize)
}

pub fn alg_ivsize(handle: &KcapiHandle) -> KcapiResult<usize> {
    let ivsize: usize;
    unsafe {
        ivsize = kcapi_sys::kcapi_aead_ivsize(handle.handle)
            .try_into()
            .expect("Failed to convert u32 into usize");
        if ivsize == 0 {
            return Err(KcapiError {
                code: -libc::EINVAL as i64,
                message: format!(
                    "Failed to obtain IV size for algorithm '{}'",
                    handle.algorithm
                ),
            });
        }
    }
    Ok(ivsize)
}

pub fn alg_inbuflen(
    handle: &KcapiHandle,
    inlen: usize,
    assoclen: usize,
    taglen: usize,
    mode: u32,
) -> usize {
    let inbuflen: usize;
    unsafe {
        if mode == AEAD_ENCRYPT {
            inbuflen = kcapi_sys::kcapi_aead_inbuflen_enc(
                handle.handle,
                inlen as kcapi_sys::size_t,
                assoclen as kcapi_sys::size_t,
                taglen as kcapi_sys::size_t,
            )
            .try_into()
            .expect("Failed to convert u32 into usize")
        } else {
            inbuflen = kcapi_sys::kcapi_aead_inbuflen_dec(
                handle.handle,
                inlen as kcapi_sys::size_t,
                assoclen as kcapi_sys::size_t,
                taglen as kcapi_sys::size_t,
            )
            .try_into()
            .expect("Failed to convert u32 into usize")
        }
    }
    inbuflen
}

pub fn alg_outbuflen(
    handle: &KcapiHandle,
    inlen: usize,
    assoclen: usize,
    taglen: usize,
    mode: u32,
) -> usize {
    let outbuflen: usize;
    unsafe {
        if mode == AEAD_ENCRYPT {
            outbuflen = kcapi_sys::kcapi_aead_outbuflen_enc(
                handle.handle,
                inlen as kcapi_sys::size_t,
                assoclen as kcapi_sys::size_t,
                taglen as kcapi_sys::size_t,
            )
            .try_into()
            .expect("Failed to convert u32 into usize");
        } else {
            outbuflen = kcapi_sys::kcapi_aead_outbuflen_dec(
                handle.handle,
                inlen as kcapi_sys::size_t,
                assoclen as kcapi_sys::size_t,
                taglen as kcapi_sys::size_t,
            )
            .try_into()
            .expect("Failed to convert u32 into usize");
        }
    }
    outbuflen
}

pub fn alg_settaglen(handle: &KcapiHandle, taglen: usize) -> KcapiResult<()> {
    let max_taglen = crate::aead::alg_authsize(handle)?;
    if taglen > max_taglen {
        return Err(KcapiError {
            code: -libc::EINVAL as i64,
            message: format!(
                "Invalid tag length {} specified for algorithm '{}' max taglen is: {}",
                taglen, handle.algorithm, max_taglen
            ),
        });
    }
    unsafe {
        let ret = kcapi_sys::kcapi_aead_settaglen(handle.handle, taglen as u32);
        if ret < 0 {
            return Err(KcapiError {
                code: ret.into(),
                message: format!(
                    "Failed to set tag length for algorithm '{}'",
                    handle.algorithm
                ),
            });
        }
    }
    Ok(())
}

pub fn alg_setassoclen(handle: &KcapiHandle, assoclen: usize) {
    unsafe {
        kcapi_sys::kcapi_aead_setassoclen(handle.handle, assoclen as kcapi_sys::size_t);
    }
}

fn aead_check_input(handle: &KcapiHandle, iv: &[u8], taglen: &usize) -> KcapiResult<()> {
    let ivsize = crate::aead::alg_ivsize(handle)?;
    if iv.len() != ivsize {
        return Err(KcapiError {
            code: -libc::EINVAL as i64,
            message: format!(
                "Invalid IV Size for algorithm '{}' correct IV size: {}",
                handle.algorithm, ivsize
            ),
        });
    }
    let max_taglen = crate::aead::alg_authsize(handle)?;
    if taglen > &max_taglen {
        return Err(KcapiError {
            code: -libc::EINVAL as i64,
            message: format!(
                "Invalid tag length for algorithm '{}' (max tag length = {})",
                handle.algorithm, max_taglen
            ),
        });
    }

    Ok(())
}

pub fn alg_encrypt(
    handle: KcapiHandle,
    key: Vec<u8>,
    pt: Vec<u8>,
    iv: Vec<u8>,
    aad: Vec<u8>,
    taglen: usize,
    access: u32,
) -> KcapiResult<Vec<u8>> {
    crate::aead::alg_setkey(&handle, key)?;
    crate::aead::alg_settaglen(&handle, taglen)?;
    crate::aead::alg_setassoclen(&handle, aad.len());

    let inbuflen = crate::aead::alg_inbuflen(&handle, pt.len(), aad.len(), taglen, AEAD_ENCRYPT);

    let outbuflen = crate::aead::alg_outbuflen(&handle, pt.len(), aad.len(), taglen, AEAD_ENCRYPT);

    let mut outbuf = Vec::new();
    outbuf.extend(aad.iter().copied());
    outbuf.extend(pt.iter().copied());
    outbuf.extend(vec![0u8; taglen].iter().copied());

    unsafe {
        let ret = kcapi_sys::kcapi_aead_encrypt(
            handle.handle,
            outbuf.as_ptr(),
            inbuflen as kcapi_sys::size_t,
            iv.as_ptr(),
            outbuf.as_mut_ptr(),
            outbuflen as kcapi_sys::size_t,
            access as ::std::os::raw::c_int,
        );
        if ret < 0 {
            return Err(KcapiError {
                code: ret,
                message: format!(
                    "Failed to encrypt input data for algorithm '{}'",
                    handle.algorithm
                ),
            });
        }
    }
    Ok(outbuf)
}

pub fn alg_decrypt(
    handle: KcapiHandle,
    key: Vec<u8>,
    ct: Vec<u8>,
    iv: Vec<u8>,
    aad: Vec<u8>,
    tag: Vec<u8>,
    access: u32,
) -> KcapiResult<Vec<u8>> {
    crate::aead::alg_setkey(&handle, key)?;
    crate::aead::alg_settaglen(&handle, tag.len())?;
    crate::aead::alg_setassoclen(&handle, aad.len());

    let inbuflen = crate::aead::alg_inbuflen(&handle, ct.len(), aad.len(), tag.len(), AEAD_DECRYPT);

    let outbuflen =
        crate::aead::alg_outbuflen(&handle, ct.len(), aad.len(), tag.len(), AEAD_DECRYPT);

    let mut inbuf = Vec::new();
    inbuf.extend(aad.iter().copied());
    inbuf.extend(ct.iter().copied());
    inbuf.extend(tag.iter().copied());

    unsafe {
        let ret = kcapi_sys::kcapi_aead_decrypt(
            handle.handle,
            inbuf.as_ptr(),
            inbuflen as kcapi_sys::size_t,
            iv.as_ptr(),
            inbuf.as_mut_ptr(),
            outbuflen as kcapi_sys::size_t,
            access as ::std::os::raw::c_int,
        );
        if ret < 0 {
            return Err(KcapiError {
                code: ret,
                message: format!(
                    "Failed to encrypt input data for algorithm '{}'",
                    handle.algorithm
                ),
            });
        }
    }
    Ok(inbuf)
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt(
    alg: &str,
    key: Vec<u8>,
    pt: Vec<u8>,
    iv: Vec<u8>,
    aad: Vec<u8>,
    taglen: usize,
    access: u32,
    flags: u32,
) -> KcapiResult<KCAPIAEADOutput> {
    let handle = crate::aead::alg_init(alg, flags)?;
    let ct_len = pt.len();
    let ct_offset = aad.len();
    let tag_offset = ct_offset + pt.len();

    aead_check_input(&handle, &iv, &taglen)?;
    let ct_buf = crate::aead::alg_encrypt(handle, key, pt, iv, aad.clone(), taglen, access)?;

    let mut ct = vec![0u8; ct_len];
    ct.clone_from_slice(&ct_buf[ct_offset..tag_offset]);
    let mut tag = vec![0u8; taglen];
    tag.clone_from_slice(&ct_buf[tag_offset..]);

    Ok(KCAPIAEADOutput {
        output: ct,
        tag,
        assocdata: aad,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt(
    alg: &str,
    key: Vec<u8>,
    ct: Vec<u8>,
    iv: Vec<u8>,
    aad: Vec<u8>,
    tag: Vec<u8>,
    access: u32,
    flags: u32,
) -> KcapiResult<KCAPIAEADOutput> {
    let handle = crate::aead::alg_init(alg, flags)?;
    let pt_len = ct.len();
    let ct_offset = aad.len();
    let tag_offset = ct_offset + ct.len();

    aead_check_input(&handle, &iv, &tag.len())?;
    let ct_buf = crate::aead::alg_decrypt(handle, key, ct, iv, aad.clone(), tag.clone(), access)?;

    let mut pt = vec![0u8; pt_len];
    pt.clone_from_slice(&ct_buf[ct_offset..tag_offset]);

    Ok(KCAPIAEADOutput {
        output: pt,
        tag,
        assocdata: aad,
    })
}
