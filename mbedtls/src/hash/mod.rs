/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use error::IntoResult;

#[mbedtls_use]
use {
    mbedtls_ecp_keypair, mbedtls_md, mbedtls_md_finish, mbedtls_md_get_size, mbedtls_md_get_type,
    mbedtls_md_hmac, mbedtls_md_info_from_type, mbedtls_md_info_t, mbedtls_md_setup,
    mbedtls_md_starts, mbedtls_md_type_t, mbedtls_md_update, mbedtls_pkcs5_pbkdf2_hmac,
    mbedtls_rsa_context, mbedtls_rsa_set_padding, MBEDTLS_MD_MD2, MBEDTLS_MD_MD4, MBEDTLS_MD_MD5,
    MBEDTLS_MD_NONE, MBEDTLS_MD_RIPEMD160, MBEDTLS_MD_SHA1, MBEDTLS_MD_SHA224, MBEDTLS_MD_SHA256,
    MBEDTLS_MD_SHA384, MBEDTLS_MD_SHA512,
};

use mbedtls_sys::*;

define!(enum Type -> mbedtls_md_type_t {
	None => MBEDTLS_MD_NONE,
	Md2 => MBEDTLS_MD_MD2,
	Md4 => MBEDTLS_MD_MD4,
	Md5 => MBEDTLS_MD_MD5,
	Sha1 => MBEDTLS_MD_SHA1,
	Sha224 => MBEDTLS_MD_SHA224,
	Sha256 => MBEDTLS_MD_SHA256,
	Sha384 => MBEDTLS_MD_SHA384,
	Sha512 => MBEDTLS_MD_SHA512,
	Ripemd => MBEDTLS_MD_RIPEMD160,
});

impl From<md_type_t> for Type {
    fn from(inner: md_type_t) -> Type {
        match inner {
            MD_NONE => Type::None,
            MD_MD2 => Type::Md2,
            MD_MD4 => Type::Md4,
            MD_MD5 => Type::Md5,
            MD_SHA1 => Type::Sha1,
            MD_SHA224 => Type::Sha224,
            MD_SHA256 => Type::Sha256,
            MD_SHA384 => Type::Sha384,
            MD_SHA512 => Type::Sha512,
            MD_RIPEMD160 => Type::Ripemd,
            _ => panic!("Invalid Md type"),
        }
    }
}

#[derive(Copy, Clone)]
pub struct MdInfo {
    inner: &'static md_info_t,
}

impl Into<Option<MdInfo>> for Type {
    fn into(self) -> Option<MdInfo> {
        unsafe { md_info_from_type(self.into()).as_ref() }.map(|r| MdInfo { inner: r })
    }
}

impl Into<*const md_info_t> for MdInfo {
    fn into(self) -> *const md_info_t {
        self.inner
    }
}

define!(struct Md(mbedtls_md_context_t) {
	fn init = mbedtls_md_init;
	fn drop = mbedtls_md_free;
	impl<'a> Into<*>;
});

impl MdInfo {
    pub fn size(&self) -> usize {
        unsafe { md_get_size(self.inner).into() }
    }
    pub fn get_type(&self) -> Type {
        unsafe { md_get_type(self.inner).into() }
    }
}

impl Md {
    pub fn new(md: Type) -> ::Result<Md> {
        let md: MdInfo = match md.into() {
            Some(md) => md,
            None => return Err(::Error::MdBadInputData),
        };

        let mut ctx = Md::init();
        unsafe {
            try!(md_setup(&mut ctx.inner, md.into(), 0).into_result());
            try!(md_starts(&mut ctx.inner).into_result());
        }
        Ok(ctx)
    }

    pub fn update(&mut self, data: &[u8]) -> ::Result<()> {
        unsafe {
            try!(md_update(&mut self.inner, data.as_ptr(), data.len()).into_result());
        }
        Ok(())
    }

    pub fn finish(mut self, out: &mut [u8]) -> ::Result<usize> {
        unsafe {
            let olen = (*self.inner.md_info).size as usize;
            if out.len() < olen {
                return Err(::Error::MdBadInputData);
            }
            try!(md_finish(&mut self.inner, out.as_mut_ptr()).into_result());
            Ok(olen)
        }
    }

    pub fn hash(md: Type, data: &[u8], out: &mut [u8]) -> ::Result<usize> {
        let md: MdInfo = match md.into() {
            Some(md) => md,
            None => return Err(::Error::MdBadInputData),
        };

        unsafe {
            let olen = md.inner.size as usize;
            if out.len() < olen {
                return Err(::Error::MdBadInputData);
            }
            try!(
                ::mbedtls_sys::mbedtls_md(md.inner, data.as_ptr(), data.len(), out.as_mut_ptr())
                    .into_result()
            );
            Ok(olen)
        }
    }

    pub fn hmac(md: Type, key: &[u8], data: &[u8], out: &mut [u8]) -> ::Result<usize> {
        let md: MdInfo = match md.into() {
            Some(md) => md,
            None => return Err(::Error::MdBadInputData),
        };

        unsafe {
            let olen = md.inner.size as usize;
            if out.len() < olen {
                return Err(::Error::MdBadInputData);
            }
            try!(
                md_hmac(
                    md.inner,
                    key.as_ptr(),
                    key.len(),
                    data.as_ptr(),
                    data.len(),
                    out.as_mut_ptr()
                ).into_result()
            );
            Ok(olen)
        }
    }
}

pub fn pbkdf2_hmac(
    md: Type,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key: &mut [u8],
) -> ::Result<()> {
    let md: MdInfo = match md.into() {
        Some(md) => md,
        None => return Err(::Error::MdBadInputData),
    };

    unsafe {
        let mut ctx = Md::init();
        try!(md_setup((&mut ctx).into(), md.into(), 1).into_result());
        try!(
            pkcs5_pbkdf2_hmac(
                (&mut ctx).into(),
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                iterations,
                key.len() as u32,
                key.as_mut_ptr()
            ).into_result()
        );
        Ok(())
    }
}
