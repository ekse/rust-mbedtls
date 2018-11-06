/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(not(feature = "std"))]
use alloc_prelude::*;

#[mbedtls_use]
use {
    mbedtls_ecp_gen_key, mbedtls_ecp_keypair, mbedtls_pk_can_do, mbedtls_pk_check_pair,
    mbedtls_pk_context, mbedtls_pk_decrypt, mbedtls_pk_encrypt, mbedtls_pk_free,
    mbedtls_pk_get_bitlen, mbedtls_pk_get_name, mbedtls_pk_get_type, mbedtls_pk_info_from_type,
    mbedtls_pk_init, mbedtls_pk_parse_key, mbedtls_pk_parse_public_key, mbedtls_pk_setup,
    mbedtls_pk_sign, mbedtls_pk_type_t, mbedtls_pk_verify, mbedtls_pk_write_key_der,
    mbedtls_pk_write_key_pem, mbedtls_pk_write_pubkey_der, mbedtls_pk_write_pubkey_pem,
    mbedtls_rsa_context, mbedtls_rsa_gen_key, mbedtls_rsa_set_padding, MBEDTLS_PK_ECDSA,
    MBEDTLS_PK_ECKEY, MBEDTLS_PK_ECKEY_DH, MBEDTLS_PK_NONE, MBEDTLS_PK_RSA, MBEDTLS_PK_RSASSA_PSS,
    MBEDTLS_PK_RSA_ALT, MBEDTLS_RSA_PKCS_V15, MBEDTLS_RSA_PKCS_V21,
};

use mbedtls_sys::*;

use error::IntoResult;
use private::UnsafeFrom;

pub(crate) mod dhparam;
mod ec;

#[doc(inline)]
pub use self::ec::{EcGroupId, ECDSA_MAX_LEN};

define!(enum Type -> mbedtls_pk_type_t {
	None => MBEDTLS_PK_NONE,
	Rsa => MBEDTLS_PK_RSA,
	Eckey => MBEDTLS_PK_ECKEY,
	EckeyDh => MBEDTLS_PK_ECKEY_DH,
	// This type is never returned by the mbedTLS key parsing routines
	Ecdsa => MBEDTLS_PK_ECDSA,
	RsaAlt => MBEDTLS_PK_RSA_ALT,
	RsassaPss => MBEDTLS_PK_RSASSA_PSS,
});

impl From<pk_type_t> for Type {
    fn from(inner: pk_type_t) -> Type {
        match inner {
            PK_NONE => Type::None,
            PK_RSA => Type::Rsa,
            PK_ECKEY => Type::Eckey,
            PK_ECKEY_DH => Type::EckeyDh,
            PK_ECDSA => Type::Ecdsa,
            PK_RSA_ALT => Type::RsaAlt,
            PK_RSASSA_PSS => Type::RsassaPss,
            _ => panic!("Invalid PK type"),
        }
    }
}

pub enum RsaPadding {
    Pkcs1V15,
    /// Use OAEP for encryption, or PSS for signing.
    Pkcs1V21 {
        /// The Mask Generating Function (MGF) to use.
        mgf: ::hash::Type,
    },
}

pub enum Options {
    Rsa { padding: RsaPadding },
}

define!(#[repr(C)]
struct Pk(mbedtls_pk_context) {
	fn init = mbedtls_pk_init;
	fn drop = mbedtls_pk_free;
	impl<'a> Into<*>;
	impl<'a> UnsafeFrom<*>;
});

impl Pk {
    /// Takes both DER and PEM forms of PKCS#1 or PKCS#8 encoded keys.
    ///
    /// When calling on PEM-encoded data, `key` must be NULL-terminated
    pub fn from_private_key(key: &[u8], password: Option<&[u8]>) -> ::Result<Pk> {
        let mut ret = Self::init();
        unsafe {
            try!(
                pk_parse_key(
                    &mut ret.inner,
                    key.as_ptr(),
                    key.len(),
                    password.map(<[_]>::as_ptr).unwrap_or(::core::ptr::null()),
                    password.map(<[_]>::len).unwrap_or(0)
                ).into_result()
            )
        };
        Ok(ret)
    }

    /// Takes both DER and PEM encoded SubjectPublicKeyInfo keys.
    ///
    /// When calling on PEM-encoded data, `key` must be NULL-terminated
    pub fn from_public_key(key: &[u8]) -> ::Result<Pk> {
        let mut ret = Self::init();
        unsafe { try!(pk_parse_public_key(&mut ret.inner, key.as_ptr(), key.len()).into_result()) };
        Ok(ret)
    }

    pub fn generate_rsa<F: ::rng::Random>(rng: &mut F, bits: u32, exponent: u32) -> ::Result<Pk> {
        let mut ret = Self::init();
        unsafe {
            try!(pk_setup(&mut ret.inner, pk_info_from_type(Type::Rsa.into())).into_result());
            try!(
                rsa_gen_key(
                    ret.inner.pk_ctx as *mut _,
                    Some(F::call),
                    rng.data_ptr(),
                    bits,
                    exponent as _
                ).into_result()
            );
        }
        Ok(ret)
    }

    pub fn generate_ec<F: ::rng::Random>(rng: &mut F, curve: EcGroupId) -> ::Result<Pk> {
        let mut ret = Self::init();
        unsafe {
            try!(pk_setup(&mut ret.inner, pk_info_from_type(Type::Eckey.into())).into_result());
            try!(
                ecp_gen_key(
                    curve.into(),
                    ret.inner.pk_ctx as *mut _,
                    Some(F::call),
                    rng.data_ptr()
                ).into_result()
            );
        }
        Ok(ret)
    }

    /// Panics if the options are not valid for this key type.
    pub fn set_options(&mut self, options: Options) {
        unsafe {
            match (Type::from(pk_get_type(&self.inner)), options) {
                (Type::Rsa, Options::Rsa { padding })
                | (Type::RsassaPss, Options::Rsa { padding }) => {
                    let (padding, hash_id) = match padding {
                        RsaPadding::Pkcs1V15 => (RSA_PKCS_V15, 0),
                        RsaPadding::Pkcs1V21 { mgf } => (RSA_PKCS_V21, mgf.into()),
                    };
                    rsa_set_padding(self.inner.pk_ctx as *mut rsa_context, padding, hash_id as _);
                }
                _ => panic!("Invalid options for this key type"),
            }
        }
    }

    pub fn can_do(&self, t: Type) -> bool {
        if unsafe { pk_can_do(&self.inner, t.into()) } == 0 {
            false
        } else {
            true
        }
    }

    pub fn check_pair(public: &Self, private: &Self) -> bool {
        unsafe { pk_check_pair(&public.inner, &private.inner) }
            .into_result()
            .is_ok()
    }

    /// Key length in bits
    getter!(len() -> usize = fn mbedtls_pk_get_bitlen);
    getter!(pk_type() -> Type = fn mbedtls_pk_get_type);

    pub fn curve(&self) -> ::Result<EcGroupId> {
        match self.pk_type() {
            Type::Eckey | Type::EckeyDh | Type::Ecdsa => {}
            _ => return Err(::Error::PkTypeMismatch),
        }

        unsafe { Ok((*(self.inner.pk_ctx as *const ecp_keypair)).grp.id.into()) }
    }

    pub fn name(&self) -> ::Result<&str> {
        let s = unsafe { ::private::cstr_to_slice(pk_get_name(&self.inner)) };
        Ok(try!(::core::str::from_utf8(s)))
    }

    pub fn decrypt<F: ::rng::Random>(
        &mut self,
        cipher: &[u8],
        plain: &mut [u8],
        rng: &mut F,
    ) -> ::Result<usize> {
        let mut ret;
        unsafe {
            ret = ::core::mem::uninitialized();
            try!(
                pk_decrypt(
                    &mut self.inner,
                    cipher.as_ptr(),
                    cipher.len(),
                    plain.as_mut_ptr(),
                    &mut ret,
                    plain.len(),
                    Some(F::call),
                    rng.data_ptr()
                ).into_result()
            );
        }
        Ok(ret)
    }

    pub fn encrypt<F: ::rng::Random>(
        &mut self,
        plain: &[u8],
        cipher: &mut [u8],
        rng: &mut F,
    ) -> ::Result<usize> {
        let mut ret;
        unsafe {
            ret = ::core::mem::uninitialized();
            try!(
                pk_encrypt(
                    &mut self.inner,
                    plain.as_ptr(),
                    plain.len(),
                    cipher.as_mut_ptr(),
                    &mut ret,
                    cipher.len(),
                    Some(F::call),
                    rng.data_ptr()
                ).into_result()
            );
        }
        Ok(ret)
    }

    /// Sign the hash `hash` of type `md`, placing the signature in `sig`. `rng` must be a
    /// cryptographically secure RNG.
    ///
    /// For RSA signatures, the length of `sig` must be greater than or equal to the RSA
    /// modulus length, otherwise `sign()` fails with `Error::PkSigLenMismatch`.
    ///
    /// For EC signatures, the length of `sig` must be greater than or equal to `ECDSA_MAX_LEN`,
    /// otherwise `sign()` fails with `Error::PkSigLenMismatch`.
    ///
    /// On success, returns the actual number of bytes written to `sig`.
    pub fn sign<F: ::rng::Random>(
        &mut self,
        md: ::hash::Type,
        hash: &[u8],
        sig: &mut [u8],
        rng: &mut F,
    ) -> ::Result<usize> {
        let mut ret;
        match self.pk_type() {
            Type::Rsa | Type::RsaAlt | Type::RsassaPss => {
                if sig.len() < (self.len() / 8) {
                    return Err(::Error::PkSigLenMismatch);
                }
            }
            Type::Eckey | Type::Ecdsa => {
                if sig.len() < ECDSA_MAX_LEN {
                    return Err(::Error::PkSigLenMismatch);
                }
            }
            _ => return Err(::Error::PkSigLenMismatch),
        }
        unsafe {
            ret = ::core::mem::uninitialized();
            try!(
                pk_sign(
                    &mut self.inner,
                    md.into(),
                    hash.as_ptr(),
                    hash.len(),
                    sig.as_mut_ptr(),
                    &mut ret,
                    Some(F::call),
                    rng.data_ptr()
                ).into_result()
            );
        }
        Ok(ret)
    }

    pub fn verify(&mut self, md: ::hash::Type, hash: &[u8], sig: &[u8]) -> ::Result<()> {
        unsafe {
            pk_verify(
                &mut self.inner,
                md.into(),
                hash.as_ptr(),
                hash.len(),
                sig.as_ptr(),
                sig.len(),
            ).into_result()
            .map(|_| ())
        }
    }

    /// Agree on a shared secret with another public key.
    pub fn agree<F: ::rng::Random>(
        &mut self,
        other: &Pk,
        shared: &mut [u8],
        rng: &mut F,
    ) -> ::Result<usize> {
        match (self.pk_type(), other.pk_type()) {
            (Type::Eckey, Type::Eckey)
            | (Type::EckeyDh, Type::Eckey)
            | (Type::Eckey, Type::EckeyDh)
            | (Type::EckeyDh, Type::EckeyDh) => unsafe {
                let mut ecdh = ec::Ecdh::from_keys(
                    UnsafeFrom::from(self.inner.pk_ctx as *const _).unwrap(),
                    UnsafeFrom::from(other.inner.pk_ctx as *const _).unwrap(),
                )?;
                ecdh.calc_secret(shared, rng)
            },
            _ => return Err(::Error::PkTypeMismatch),
        }
    }

    pub fn write_private_der<'buf>(&mut self, buf: &'buf mut [u8]) -> ::Result<Option<&'buf [u8]>> {
        match unsafe {
            pk_write_key_der(&mut self.inner, buf.as_mut_ptr(), buf.len()).into_result()
        } {
            Err(::Error::Asn1BufTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_private_der_vec(&mut self) -> ::Result<Vec<u8>> {
        ::private::alloc_vec_repeat(
            |buf, size| unsafe { pk_write_key_der(&mut self.inner, buf, size) },
            true,
        )
    }

    pub fn write_private_pem<'buf>(&mut self, buf: &'buf mut [u8]) -> ::Result<Option<&'buf [u8]>> {
        match unsafe {
            pk_write_key_pem(&mut self.inner, buf.as_mut_ptr(), buf.len()).into_result()
        } {
            Err(::Error::Base64BufferTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_private_pem_string(&mut self) -> ::Result<String> {
        ::private::alloc_string_repeat(|buf, size| unsafe {
            match pk_write_key_pem(&mut self.inner, buf as _, size) {
                0 => ::private::cstr_to_slice(buf as _).len() as _,
                r => r,
            }
        })
    }

    pub fn write_public_der<'buf>(&mut self, buf: &'buf mut [u8]) -> ::Result<Option<&'buf [u8]>> {
        match unsafe {
            pk_write_pubkey_der(&mut self.inner, buf.as_mut_ptr(), buf.len()).into_result()
        } {
            Err(::Error::Asn1BufTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_public_der_vec(&mut self) -> ::Result<Vec<u8>> {
        ::private::alloc_vec_repeat(
            |buf, size| unsafe { pk_write_pubkey_der(&mut self.inner, buf, size) },
            true,
        )
    }

    pub fn write_public_pem<'buf>(&mut self, buf: &'buf mut [u8]) -> ::Result<Option<&'buf [u8]>> {
        match unsafe {
            pk_write_pubkey_pem(&mut self.inner, buf.as_mut_ptr(), buf.len()).into_result()
        } {
            Err(::Error::Base64BufferTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_public_pem_string(&mut self) -> ::Result<String> {
        ::private::alloc_string_repeat(|buf, size| unsafe {
            match pk_write_pubkey_pem(&mut self.inner, buf as _, size) {
                0 => ::private::cstr_to_slice(buf as _).len() as _,
                r => r,
            }
        })
    }
}

// pk_verify_ext
//
// pk_info_from_type
// pk_setup
// pk_setup_rsa_alt
//
// pk_debug
// pk_parse_keyfile
// pk_parse_public_keyfile
// pk_write_key_der
// pk_write_key_pem
// pk_write_pubkey_der
// pk_write_pubkey_pem
//

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(rustfmt,rustfmt_skip)]
	// This is test data that must match library output *exactly*
	const TEST_PEM: &'static str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAh1aoz6wFwVHaCVDISSy+dZ8rOsJmfYBCrgzUjX+VNb2RwdT8
xv5fF0j0IXq+fKBShdZA+WGEQd6BMU0fqc2o7ACLvPWbvdKrLcwWpnL/UpFV8PxJ
yLemR8CBkGYcN2EJHhRhZcAGMBKwR1lI+ymOPJz4+nyDWVh9ttrvkKZU9b59zDkP
ET6PDJb5x9+fd41laQVOLvwlF4Xrl0b0DakXF3BVYpJIJ+b51QnMnwQ2xHVybFlZ
ONBwv1h52Xy7chvx79zPXzxZFbEc0phIhRqenv0/6/8HxpqqctSs9HHUn5A+4d/o
955ki8ZB1Nl5EuY+S59HzdsnQXR+OZxt3PxjTQIDAQABAoIBAANfW3UaPdfOTFqh
S5jXNbUhFgp3sa2ufaWMraHvQYPwM9Vo6KSIXGleIZV7/jVo0x6BVry1e2ICmMGR
FjWSIqAkPuVp36DD+9QGU+zVBan9SSgTD5SFh+4dzNWfOVRVSSJu+c13hKG70e5/
5KLKDvmKXSye/Ftg8VuysWmS6bxolGm86b+tltQ95V2qgim41MpaOUzilf1sDc5A
3hnorZvxH+kbMSGTRBdlPX54dux0SlT+o7sh9ig2sPJKkevnHeWd6nEeyeVYzP05
vH5yXirYb1CttPb5tqLcNCKRgawR5ByMMycn8bRSHScxyCLKco++JWL7L8hmcFTM
qFqCa9kCgYEAunw/Qofipch+bcMDsNmd6d9s9l1bBpXkP1ARQohuoVpsJITg+CH6
Dm3tWHnawwCxuQEUZ1/2cqZtrDBukgC90HK0H5j6b8FfyQ0mS3OOnqBHnhV66AXM
Hzlin1Vgaqwuhooy/CfOAyqpMqAfCgCAscxs6EOMteYrY+Xy7Ou02fMCgYEAucme
nNMsSElhsQwW7xpz8rr4k3THKSoetg2pbaUwXR4XDz/J1XWCIkSo8RuN1hA+z6+a
GzJa7CozmaM1j7aGo91U/LN/aNZ9etEbDOO+WCU/K0uTFtVAwgivRqETMARzEvuy
r1M2amUUDM5pX8Jk/Q19cGXQdyJdpShqp8Y93b8CgYEAhukkCsmrmiv16wpOPT7y
EyPj/EeFdroxqewO0IdLIcf8vF61Mk3CTXYRYxSkwrZZ3HF/hVnTPRZR+WQAWffX
WlnhHYragsbuuNCeh69N2kwyA5eelwS6q0wkoQhu/D0cW5DXWbyiOYA/b7SPP/kl
IXu2vkFAJsghU+AjYmsTJykCgYBtuzvHfKKG/3CH1ZAmIQWis/Plg++tzIbfGCqd
7BcoqIEOLKrVPNZjzxHJdnDLokS2/gyTS6aQHkzjzZXxD+luF2f+6TWzghwS0jab
4lemUDmDJNv3fHUHJYIAwVpH3hjpeWgMTaWyKYkyFyf9ux9SpwkTvc7mzpFo3vo/
pcMcmQKBgCVZpfRJxJ1pc4v0M2pxF3zsyDo3CbvhO7ZjOwYyNa5A+p65BsGbOjuR
2v6GLNvYtgqM+FXqTyqz2RkyoKIOqXyOWdSDPHaP2mu5A0xaTom6H7F8PuNFIm4F
iy6KC991zzvaWY/Ys+q/84Afqa+0qJKQnPuy/7F5GkVdQA/lfbhi
-----END RSA PRIVATE KEY-----
\0";

    const TEST_DER: &'static [u8] = &[
        0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0x8d, 0x76, 0xa1,
        0x2e, 0xb6, 0xc0, 0xe5, 0x1e, 0x1a, 0x06, 0x74, 0x13, 0x57, 0x6a, 0xc2, 0x6c, 0x02, 0x9d,
        0x82, 0x91, 0x5b, 0xb0, 0xe5, 0xa9, 0x7f, 0xe0, 0x6d, 0x3f, 0xc0, 0x94, 0x88, 0x8e, 0x72,
        0xd4, 0x4a, 0xc1, 0xf5, 0x54, 0x71, 0x63, 0x10, 0xaa, 0xef, 0x9d, 0xa5, 0x1a, 0xdc, 0x00,
        0x82, 0x2d, 0xea, 0x5f, 0x5b, 0xe8, 0x73, 0x6e, 0x03, 0xf8, 0x07, 0x90, 0x8c, 0xd5, 0x52,
        0xf5, 0x6d, 0xfc, 0x4d, 0xe5, 0x6a, 0x87, 0x5a, 0x85, 0xf7, 0x34, 0x85, 0x9a, 0x19, 0x3a,
        0x74, 0x46, 0x1e, 0xcb, 0x30, 0x77, 0x8d, 0x68, 0x8a, 0xb8, 0xfd, 0x6e, 0xbc, 0xee, 0xd2,
        0xd0, 0xb3, 0xd0, 0x1c, 0x44, 0x29, 0xd0, 0xd6, 0x91, 0xb5, 0xa8, 0xc1, 0xe3, 0x88, 0x64,
        0x40, 0x16, 0x31, 0x6c, 0xdc, 0x4b, 0xba, 0x69, 0xc3, 0xcd, 0x8d, 0x4a, 0xd8, 0x7d, 0xf4,
        0xa7, 0xe2, 0xe8, 0xc5, 0x01, 0x6f, 0xcc, 0x91, 0x22, 0x81, 0x52, 0x83, 0x11, 0x28, 0xb3,
        0x97, 0x1d, 0x57, 0xa2, 0x2a, 0x01, 0x77, 0x65, 0x87, 0x3e, 0xdc, 0x6c, 0x7f, 0x0a, 0xca,
        0x95, 0x04, 0x6a, 0x4e, 0x47, 0xa4, 0xfb, 0xa1, 0x42, 0x19, 0x0f, 0x80, 0x14, 0xed, 0xf9,
        0x4a, 0x42, 0x9c, 0x6f, 0xef, 0x0f, 0x82, 0x51, 0xbb, 0x46, 0x66, 0xc6, 0xfd, 0xd9, 0x01,
        0x93, 0x6d, 0xda, 0x36, 0xc7, 0x58, 0x37, 0x4b, 0xa7, 0xdb, 0xbd, 0xb2, 0x6f, 0x5b, 0x33,
        0x4b, 0x78, 0x70, 0x7e, 0xe8, 0x02, 0xdd, 0x5f, 0xa4, 0x2f, 0xea, 0x3c, 0x6b, 0xfb, 0x51,
        0xe1, 0x19, 0x21, 0x9f, 0x52, 0xd6, 0x29, 0x53, 0x09, 0x98, 0xbc, 0x3e, 0x3b, 0xb3, 0xdc,
        0x25, 0x13, 0x36, 0x1b, 0x24, 0xf4, 0x33, 0xdd, 0xdf, 0xa8, 0xd6, 0xe8, 0x97, 0x11, 0x2f,
        0x9a, 0x81, 0xc1, 0xb6, 0xf1, 0x7b, 0xa5, 0xa4, 0x2c, 0xda, 0x41, 0xb6, 0x11, 0x02, 0x03,
        0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x38, 0x98, 0xb9, 0xab, 0xe2, 0xda, 0x11, 0xd0,
        0x95, 0x40, 0xf7, 0xb7, 0xb5, 0x45, 0xb5, 0x3b, 0x59, 0x60, 0x83, 0x18, 0x7c, 0xc2, 0xad,
        0x5f, 0xbf, 0x15, 0x9f, 0x1f, 0xde, 0x80, 0x8e, 0x91, 0xcf, 0x47, 0x38, 0x11, 0x99, 0x81,
        0x8b, 0x4b, 0xc3, 0x23, 0x60, 0x72, 0x85, 0xd7, 0xd5, 0x25, 0x2e, 0xf0, 0x07, 0xd0, 0xd7,
        0x08, 0x8d, 0x05, 0xfa, 0xf8, 0x84, 0xae, 0x44, 0x6a, 0x24, 0xa2, 0xa4, 0xba, 0x48, 0xbf,
        0xfc, 0x7a, 0xe2, 0xb0, 0xae, 0x52, 0x89, 0x11, 0x39, 0xfe, 0xb4, 0xfe, 0x48, 0xdb, 0xaa,
        0x2c, 0x6a, 0x9a, 0xe4, 0xc5, 0x56, 0x3f, 0xb3, 0xbf, 0x29, 0x00, 0xee, 0xaf, 0xd8, 0x5f,
        0x3d, 0x0b, 0x9c, 0x8c, 0xf7, 0x4c, 0xe9, 0x25, 0x8b, 0x2f, 0xf0, 0xa3, 0xf0, 0x6a, 0x49,
        0x48, 0xd2, 0xef, 0xf5, 0xb2, 0x8b, 0x50, 0xe2, 0x84, 0xa2, 0x19, 0x79, 0x22, 0xff, 0x8e,
        0x16, 0xbe, 0x00, 0x70, 0xc4, 0x6d, 0xd0, 0x29, 0x54, 0x28, 0x99, 0x97, 0x84, 0xc9, 0xaf,
        0xd8, 0xb6, 0xb1, 0x44, 0x6d, 0x4a, 0x74, 0x82, 0x4e, 0xde, 0x44, 0x1c, 0x47, 0x11, 0x52,
        0x86, 0x48, 0xd7, 0x78, 0x52, 0xa9, 0x98, 0x20, 0x9d, 0x83, 0x39, 0x3d, 0xe5, 0xd6, 0xed,
        0x94, 0x6a, 0x67, 0xd0, 0x65, 0x23, 0xf6, 0xdd, 0xe1, 0xe3, 0xed, 0xe9, 0x6b, 0x85, 0xcb,
        0x91, 0x0b, 0xcd, 0xc4, 0x6b, 0xe4, 0x90, 0xd4, 0xeb, 0x7b, 0x80, 0x0b, 0x67, 0x9d, 0xb5,
        0x37, 0x0b, 0x83, 0x7d, 0x79, 0x45, 0x6b, 0x60, 0x7d, 0x6f, 0xe3, 0xe0, 0x5e, 0x92, 0xf6,
        0x13, 0x67, 0xd2, 0xd4, 0xdc, 0x43, 0x5f, 0xd8, 0xee, 0xf5, 0x28, 0x05, 0x64, 0x78, 0x6a,
        0x6f, 0xaf, 0xef, 0x64, 0x52, 0x93, 0x70, 0x4f, 0x9a, 0xab, 0xce, 0x4a, 0x51, 0x63, 0x2a,
        0xf1, 0x33, 0xfd, 0xd8, 0x1e, 0xf9, 0xef, 0xf1, 0x02, 0x81, 0x81, 0x00, 0xcf, 0xa7, 0x89,
        0x75, 0xdd, 0x09, 0x66, 0x8b, 0x4e, 0xda, 0x52, 0x38, 0x4a, 0xc3, 0x7c, 0xca, 0x90, 0x68,
        0x4a, 0xbb, 0x78, 0x14, 0xc1, 0x83, 0x24, 0xb2, 0x2e, 0x39, 0x20, 0x8a, 0x00, 0x97, 0x8d,
        0xf3, 0x21, 0x5a, 0xad, 0x03, 0xc7, 0xb2, 0xe9, 0x17, 0x10, 0x85, 0x63, 0x23, 0xe3, 0xc9,
        0x73, 0x91, 0xa8, 0x5a, 0x8d, 0xb6, 0x40, 0x0f, 0x98, 0xb8, 0x2a, 0x8f, 0x7e, 0x59, 0x80,
        0x8a, 0xee, 0xb9, 0xe9, 0x9b, 0x2e, 0x83, 0xd4, 0x85, 0xc1, 0xdc, 0x1e, 0xc9, 0x44, 0x48,
        0x2a, 0x13, 0x06, 0x09, 0x02, 0x3e, 0x3f, 0xfb, 0xf2, 0xe8, 0x1a, 0x2d, 0xec, 0x40, 0xea,
        0x0e, 0x2b, 0x7f, 0xf3, 0x79, 0xdc, 0x11, 0x3b, 0x0d, 0xb8, 0x3f, 0x4f, 0x06, 0x02, 0x17,
        0x7c, 0x79, 0xa7, 0x36, 0x56, 0xef, 0xcd, 0x1a, 0x41, 0x00, 0x2c, 0xe8, 0x2e, 0x55, 0x9b,
        0x10, 0xea, 0x19, 0xb2, 0xe3, 0x02, 0x81, 0x81, 0x00, 0xae, 0x66, 0x06, 0x29, 0xcd, 0x44,
        0x6b, 0x4d, 0xb0, 0x1e, 0xba, 0xb8, 0x4f, 0x5e, 0x06, 0xaa, 0x02, 0x58, 0xc9, 0xb5, 0x46,
        0x68, 0xe0, 0xaf, 0x48, 0x48, 0x82, 0x45, 0xd2, 0x9c, 0xa5, 0x2d, 0x9d, 0xe6, 0x7a, 0x16,
        0xe6, 0xba, 0x8c, 0xe9, 0x2b, 0x61, 0xaf, 0x40, 0x8c, 0xab, 0x38, 0x17, 0x4e, 0xe1, 0xf7,
        0x0d, 0x52, 0xb8, 0x78, 0xcc, 0x4d, 0xcb, 0xdc, 0xe4, 0xb7, 0x4f, 0x41, 0xdf, 0xde, 0x34,
        0x20, 0x5f, 0xac, 0x45, 0x6f, 0xed, 0xcd, 0xc0, 0x4d, 0x88, 0x7a, 0xf4, 0xc9, 0x8a, 0xa4,
        0xf7, 0x40, 0x41, 0x4d, 0xb6, 0x98, 0x1f, 0x2a, 0x42, 0x42, 0x62, 0xd2, 0xb1, 0xef, 0x84,
        0x94, 0x87, 0x09, 0xfe, 0xf1, 0xba, 0xb2, 0xb8, 0x6c, 0x99, 0xb2, 0x77, 0xa6, 0xd8, 0x91,
        0x07, 0xb5, 0xd9, 0x7d, 0xe8, 0x59, 0xc0, 0xfa, 0x5a, 0x55, 0xf4, 0x3a, 0x82, 0xf4, 0x78,
        0xa1, 0x7b, 0x02, 0x81, 0x80, 0x3f, 0x6e, 0xfa, 0x7a, 0xda, 0xce, 0xe8, 0x58, 0x5d, 0xfa,
        0x2b, 0x6b, 0xae, 0xcb, 0x10, 0xf0, 0x00, 0x35, 0x1b, 0xbf, 0x30, 0xeb, 0x86, 0x41, 0xbd,
        0x90, 0x00, 0xb6, 0xca, 0xcd, 0xdd, 0x68, 0x6e, 0xa0, 0x7a, 0xeb, 0xec, 0x36, 0x5f, 0x66,
        0xb3, 0xf5, 0xab, 0xc2, 0x53, 0x8a, 0xbf, 0x26, 0xe6, 0xfa, 0xf3, 0xe6, 0xd5, 0xab, 0x7a,
        0xde, 0x48, 0xd4, 0xd9, 0x8b, 0x84, 0x19, 0x6b, 0x3f, 0x05, 0xb6, 0x1d, 0x3a, 0x9e, 0x76,
        0xff, 0x10, 0xed, 0x2b, 0x84, 0xec, 0x0e, 0xc3, 0xcc, 0xb6, 0x8a, 0xfd, 0x6d, 0x85, 0xfe,
        0x9d, 0xc4, 0x92, 0x4a, 0x8d, 0x04, 0xc2, 0xbf, 0xbd, 0x1c, 0x64, 0xb5, 0xc7, 0xe0, 0x06,
        0x13, 0x78, 0x19, 0x74, 0x9d, 0x7b, 0x44, 0x60, 0x50, 0x52, 0x09, 0x56, 0x7c, 0x30, 0x3d,
        0x03, 0x6c, 0x1f, 0xd5, 0x98, 0x07, 0xaf, 0x76, 0xf3, 0x2f, 0xd0, 0x31, 0xe9, 0x02, 0x81,
        0x81, 0x00, 0xa6, 0x61, 0x77, 0x67, 0xd2, 0x09, 0x80, 0x45, 0xb1, 0xcc, 0xdf, 0x5e, 0x8f,
        0x79, 0xa8, 0xe9, 0xf1, 0x2b, 0x3b, 0xe4, 0xd1, 0xb3, 0xa5, 0x08, 0x14, 0xf1, 0xf8, 0x37,
        0x1c, 0xe3, 0x8d, 0x42, 0xa3, 0xee, 0x0a, 0x74, 0x66, 0xd3, 0x7b, 0x33, 0xc8, 0xcb, 0x7d,
        0x23, 0x1c, 0x11, 0x0d, 0x86, 0x4f, 0x1f, 0x8d, 0x4f, 0x0c, 0xa8, 0x29, 0xb6, 0xe0, 0x51,
        0xaa, 0x00, 0x1a, 0x52, 0x67, 0x0a, 0x69, 0x37, 0x59, 0xdb, 0x6c, 0xc3, 0x22, 0x31, 0xc1,
        0xa5, 0xc1, 0x52, 0x7f, 0xdb, 0xa1, 0x9b, 0xc0, 0x1e, 0x93, 0x12, 0xba, 0x4d, 0x85, 0x7b,
        0xd6, 0x19, 0x38, 0xb4, 0x87, 0x46, 0x72, 0xb8, 0x0d, 0xeb, 0x77, 0x41, 0xde, 0xe4, 0xbb,
        0x34, 0xef, 0x87, 0x02, 0x98, 0xdc, 0x78, 0xa8, 0x84, 0xae, 0x9d, 0x3c, 0x5d, 0xbb, 0xa3,
        0x3c, 0x35, 0x8a, 0xe3, 0x62, 0x1f, 0x25, 0x95, 0x20, 0x99, 0x02, 0x81, 0x80, 0x5b, 0xfb,
        0x99, 0x65, 0xaa, 0x0d, 0x55, 0xf5, 0x66, 0x27, 0x95, 0xc8, 0xb2, 0x68, 0x7f, 0x8b, 0xd3,
        0x26, 0xd1, 0x51, 0x68, 0xe3, 0x5f, 0x84, 0x1b, 0x13, 0xbf, 0xec, 0xb4, 0x92, 0x09, 0xa8,
        0x0c, 0xac, 0x5f, 0x99, 0x3a, 0xd5, 0xda, 0xdd, 0xee, 0xba, 0x1c, 0xce, 0x92, 0x7c, 0x54,
        0xd4, 0xf8, 0x6a, 0xc3, 0xb3, 0x07, 0xea, 0xce, 0x18, 0xad, 0x8e, 0x26, 0x5e, 0x54, 0xa1,
        0x87, 0x77, 0x6a, 0x7b, 0x23, 0x2e, 0x76, 0xb6, 0x3a, 0xe7, 0xd9, 0x67, 0x0d, 0x7e, 0x19,
        0xd9, 0x6e, 0x2c, 0xe0, 0x00, 0xd6, 0x8e, 0xd2, 0x5a, 0xc9, 0x59, 0x44, 0x58, 0xd8, 0x73,
        0x15, 0x0f, 0x17, 0x63, 0x3e, 0xef, 0x74, 0x2f, 0xfe, 0xbd, 0x50, 0x07, 0x5f, 0x7d, 0x15,
        0x23, 0xab, 0xc2, 0x77, 0x6d, 0xc9, 0x3d, 0x08, 0x1a, 0x88, 0xdd, 0x45, 0x26, 0xd9, 0x2d,
        0xe9, 0xde, 0xb9, 0x58, 0x36, 0x5f,
    ];

    #[test]
    fn generate_rsa() {
        let generated = Pk::generate_rsa(&mut ::test_support::rand::test_rng(), 2048, 0x10001)
            .unwrap()
            .write_private_pem_string()
            .unwrap();
        assert_eq!(generated, TEST_PEM[..TEST_PEM.len() - 1]);
    }

    #[test]
    fn generate_ec_curve25519() {
        let _generated =
            Pk::generate_ec(&mut ::test_support::rand::test_rng(), EcGroupId::Curve25519).unwrap();
        // mbedtls does not have an OID for Curve25519, so can't write it as PEM
    }

    #[test]
    fn generate_ec_secp192r1() {
        let _generated =
            Pk::generate_ec(&mut ::test_support::rand::test_rng(), EcGroupId::SecP192R1)
                .unwrap()
                .write_private_pem_string()
                .unwrap();
    }

    #[test]
    fn generate_ec_secp256r1() {
        let mut _generated =
            Pk::generate_ec(&mut ::test_support::rand::test_rng(), EcGroupId::SecP256R1)
                .unwrap()
                .write_private_pem_string()
                .unwrap();
    }

    #[test]
    fn generate_ec_secp256k1() {
        let _generated =
            Pk::generate_ec(&mut ::test_support::rand::test_rng(), EcGroupId::SecP256K1)
                .unwrap()
                .write_private_pem_string()
                .unwrap();
    }

    #[test]
    fn parse_write_pem() {
        let parsed = Pk::from_private_key(TEST_PEM.as_bytes(), None)
            .unwrap()
            .write_private_pem_string()
            .unwrap();
        assert_eq!(parsed, TEST_PEM[..TEST_PEM.len() - 1]);
    }

    #[test]
    fn parse_write_der() {
        let parsed = Pk::from_private_key(TEST_DER, None)
            .unwrap()
            .write_private_der_vec()
            .unwrap();
        assert!(parsed == TEST_DER);
    }

    #[test]
    fn encrypt_v15_oaep() {
        let mut pk = Pk::from_private_key(TEST_DER, None).unwrap();
        let mut cipher1 = [0u8; 2048 / 8];
        let mut cipher2 = [0u8; 2048 / 8];
        assert_eq!(
            pk.encrypt(b"test", &mut cipher1, &mut ::test_support::rand::test_rng())
                .unwrap(),
            cipher1.len()
        );
        pk.set_options(Options::Rsa {
            padding: RsaPadding::Pkcs1V21 {
                mgf: ::hash::Type::Sha256,
            },
        });
        assert_eq!(
            pk.encrypt(b"test", &mut cipher2, &mut ::test_support::rand::test_rng())
                .unwrap(),
            cipher2.len()
        );
        assert_ne!(&cipher1[..], &cipher2[..]);
    }
}
