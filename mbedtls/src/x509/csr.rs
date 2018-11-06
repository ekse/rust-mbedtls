/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;

#[cfg(not(feature = "std"))]
use alloc_prelude::*;

#[mbedtls_use]
use {
    mbedtls_x509_csr_info, mbedtls_x509_csr_parse, mbedtls_x509_csr_parse_der,
    mbedtls_x509_dn_gets, mbedtls_x509write_csr_der, mbedtls_x509write_csr_pem,
    mbedtls_x509write_csr_set_extension, mbedtls_x509write_csr_set_key,
    mbedtls_x509write_csr_set_key_usage, mbedtls_x509write_csr_set_md_alg,
    mbedtls_x509write_csr_set_subject_name,
};

use error::IntoResult;

define!(
/// Certificate Signing Request
struct Csr(mbedtls_x509_csr) {
	fn init=mbedtls_x509_csr_init;
	fn drop=mbedtls_x509_csr_free;
});

impl Csr {
    pub fn from_der(der: &[u8]) -> ::Result<Csr> {
        let mut ret = Self::init();
        unsafe { try!(x509_csr_parse_der(&mut ret.inner, der.as_ptr(), der.len()).into_result()) };
        Ok(ret)
    }

    pub fn from_pem(pem: &[u8]) -> ::Result<Csr> {
        let mut ret = Self::init();
        unsafe { try!(x509_csr_parse(&mut ret.inner, pem.as_ptr(), pem.len()).into_result()) };
        Ok(ret)
    }

    pub fn subject(&self) -> ::Result<String> {
        ::private::alloc_string_repeat(|buf, size| unsafe {
            x509_dn_gets(buf, size, &self.inner.subject)
        })
    }

    pub fn subject_raw(&self) -> ::Result<Vec<u8>> {
        ::private::alloc_vec_repeat(
            |buf, size| unsafe { x509_dn_gets(buf as _, size, &self.inner.subject) },
            false,
        )
    }

    pub fn public_key(&self) -> &::pk::Pk {
        unsafe { &*(&self.inner.pk as *const _ as *const _) }
    }

    pub fn as_der(&self) -> &[u8] {
        unsafe { ::core::slice::from_raw_parts(self.inner.raw.p, self.inner.raw.len) }
    }
}

impl fmt::Debug for Csr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match ::private::alloc_string_repeat(|buf, size| unsafe {
            x509_csr_info(buf, size, b"\0".as_ptr() as *const _, &self.inner)
        }) {
            Err(_) => Err(fmt::Error),
            Ok(s) => f.write_str(&s),
        }
    }
}

define!(struct Builder<'a>(mbedtls_x509write_csr) {
	pub fn new = mbedtls_x509write_csr_init;
	fn drop = mbedtls_x509write_csr_free;
});

impl<'a> Builder<'a> {
    unsafe fn subject_with_nul_unchecked(&mut self, subject: &[u8]) -> ::Result<&mut Self> {
        try!(
            x509write_csr_set_subject_name(&mut self.inner, subject.as_ptr() as *const _)
                .into_result()
        );
        Ok(self)
    }

    #[cfg(feature = "std")]
    pub fn subject(&mut self, subject: &str) -> ::Result<&mut Self> {
        match ::std::ffi::CString::new(subject) {
            Err(_) => Err(::Error::X509InvalidName),
            Ok(s) => unsafe { self.subject_with_nul_unchecked(s.as_bytes_with_nul()) },
        }
    }

    pub fn subject_with_nul(&mut self, subject: &str) -> ::Result<&mut Self> {
        if subject.as_bytes().iter().any(|&c| c == 0) {
            unsafe { self.subject_with_nul_unchecked(subject.as_bytes()) }
        } else {
            Err(::Error::X509InvalidName)
        }
    }

    pub fn key(&mut self, key: &'a mut ::pk::Pk) -> &mut Self {
        unsafe { x509write_csr_set_key(&mut self.inner, key.into()) };
        self
    }

    pub fn signature_hash(&mut self, md: ::hash::Type) -> &mut Self {
        unsafe { x509write_csr_set_md_alg(&mut self.inner, md.into()) };
        self
    }

    pub fn key_usage(&mut self, usage: ::x509::KeyUsage) -> ::Result<&mut Self> {
        let usage = usage.bits();
        if (usage & !0xfe) != 0 {
            // according to x509write_**crt**_set_key_usage
            return Err(::Error::X509FeatureUnavailable);
        }

        unsafe {
            try!(x509write_csr_set_key_usage(&mut self.inner, (usage & 0xfe) as u8).into_result())
        };
        Ok(self)
    }

    pub fn extension(&mut self, oid: &[u8], val: &[u8]) -> ::Result<&mut Self> {
        unsafe {
            try!(
                x509write_csr_set_extension(
                    &mut self.inner,
                    oid.as_ptr() as *const _,
                    oid.len(),
                    val.as_ptr(),
                    val.len()
                ).into_result()
            )
        };
        Ok(self)
    }

    pub fn write_der<'buf, F: ::rng::Random>(
        &mut self,
        buf: &'buf mut [u8],
        rng: &mut F,
    ) -> ::Result<Option<&'buf [u8]>> {
        match unsafe {
            x509write_csr_der(
                &mut self.inner,
                buf.as_mut_ptr(),
                buf.len(),
                Some(F::call),
                rng.data_ptr(),
            ).into_result()
        } {
            Err(::Error::Asn1BufTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_der_vec<F: ::rng::Random>(&mut self, rng: &mut F) -> ::Result<Vec<u8>> {
        ::private::alloc_vec_repeat(
            |buf, size| unsafe {
                x509write_csr_der(&mut self.inner, buf, size, Some(F::call), rng.data_ptr())
            },
            true,
        )
    }

    pub fn write_pem<'buf, F: ::rng::Random>(
        &mut self,
        buf: &'buf mut [u8],
        rng: &mut F,
    ) -> ::Result<Option<&'buf [u8]>> {
        match unsafe {
            x509write_csr_der(
                &mut self.inner,
                buf.as_mut_ptr(),
                buf.len(),
                Some(F::call),
                rng.data_ptr(),
            ).into_result()
        } {
            Err(::Error::Base64BufferTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_pem_string<F: ::rng::Random>(&mut self, rng: &mut F) -> ::Result<String> {
        ::private::alloc_string_repeat(|buf, size| unsafe {
            match x509write_csr_pem(
                &mut self.inner,
                buf as _,
                size,
                Some(F::call),
                rng.data_ptr(),
            ) {
                0 => ::private::cstr_to_slice(buf as _).len() as _,
                r => r,
            }
        })
    }
}

// TODO
// x509write_csr_set_ns_cert_type
//

#[cfg(test)]
mod tests {
    use super::*;
    use pk::Pk;

    struct Test {
        key: Pk,
    }

    impl Test {
        fn new() -> Self {
            Test {
                key: Pk::from_private_key(::test_support::keys::PEM_KEY, None).unwrap(),
            }
        }

        fn builder<'a>(&'a mut self) -> Builder<'a> {
            let mut b = Builder::new();
            b.key(&mut self.key);
            b.subject_with_nul("CN=mbedtls.example\0").unwrap();
            b
        }
    }

    const TEST_PEM: &'static str = r"-----BEGIN CERTIFICATE REQUEST-----
MIICXzCCAUcCAQAwGjEYMBYGA1UEAxMPbWJlZHRscy5leGFtcGxlMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxYwIJgiVJigEPzgINDAYdxNvpeWrEh3Q
TZk5tIK975p5hXFKpSKVBtwRnfOaNHPV+ap8QSiWn0yS7tsUao8dUzJQXbVaT9Al
8uaj2MLzvFFiBsq7J4svBn6Q41xpFBW5vdQsNXP5Qg+0depSxyvuzaavaMaZNynz
B4r0KKxXd9W8qNFcWb/7BWFYgmw7TmJjIn0F/6pKrG75MUrj5Jc6cQMRfNuJrSjE
YpsBkG2eLWy5QBTboDtNnldB6vMR8X25ja25UqiMuvP1HY4OGPX3hYvDVX2IP67B
Y7i/hb/93SwQYWjH38lfSdHlC14FcOWVzWkICm+rEgUKolNy37Rw0wIDAQABoAAw
DQYJKoZIhvcNAQELBQADggEBAG58jOY2qIQqI+e4NtGUFxgZGNpAzN9ju79ONuxU
B2/Ga9eRam08/ESGf4rFUirvUWOEr4SsyPCXSGqNVxWnVNbxUlZczxkJkyDxnHYP
7J+RlsxGXC2Ati62noKeeVX9bFJkABNDKTRk7DxQTs8dkPHHWo8BpqIus/FuG085
BR+1DwYmL7aP8XccmcXsbPx/albpZwc35yKIEB+Bouaam8bLDEoljOKXwtpsFHvm
Jh1RujRAg6MK6AsYanZP+sAS8faK4P1fonwcBfnZg7H+obAtn/BnQm7Rzc62GZaO
L9kiqglOzjFqAjAjIbzmQfeyu+vYrTglvjfskf0V+vgvCMs=
-----END CERTIFICATE REQUEST-----
";

    const TEST_DER: &'static [u8] = &[
        0x30, 0x82, 0x02, 0x5f, 0x30, 0x82, 0x01, 0x47, 0x02, 0x01, 0x00, 0x30, 0x1a, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0f, 0x6d, 0x62, 0x65, 0x64, 0x74, 0x6c,
        0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82,
        0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc5, 0x8c, 0x08,
        0x26, 0x08, 0x95, 0x26, 0x28, 0x04, 0x3f, 0x38, 0x08, 0x34, 0x30, 0x18, 0x77, 0x13, 0x6f,
        0xa5, 0xe5, 0xab, 0x12, 0x1d, 0xd0, 0x4d, 0x99, 0x39, 0xb4, 0x82, 0xbd, 0xef, 0x9a, 0x79,
        0x85, 0x71, 0x4a, 0xa5, 0x22, 0x95, 0x06, 0xdc, 0x11, 0x9d, 0xf3, 0x9a, 0x34, 0x73, 0xd5,
        0xf9, 0xaa, 0x7c, 0x41, 0x28, 0x96, 0x9f, 0x4c, 0x92, 0xee, 0xdb, 0x14, 0x6a, 0x8f, 0x1d,
        0x53, 0x32, 0x50, 0x5d, 0xb5, 0x5a, 0x4f, 0xd0, 0x25, 0xf2, 0xe6, 0xa3, 0xd8, 0xc2, 0xf3,
        0xbc, 0x51, 0x62, 0x06, 0xca, 0xbb, 0x27, 0x8b, 0x2f, 0x06, 0x7e, 0x90, 0xe3, 0x5c, 0x69,
        0x14, 0x15, 0xb9, 0xbd, 0xd4, 0x2c, 0x35, 0x73, 0xf9, 0x42, 0x0f, 0xb4, 0x75, 0xea, 0x52,
        0xc7, 0x2b, 0xee, 0xcd, 0xa6, 0xaf, 0x68, 0xc6, 0x99, 0x37, 0x29, 0xf3, 0x07, 0x8a, 0xf4,
        0x28, 0xac, 0x57, 0x77, 0xd5, 0xbc, 0xa8, 0xd1, 0x5c, 0x59, 0xbf, 0xfb, 0x05, 0x61, 0x58,
        0x82, 0x6c, 0x3b, 0x4e, 0x62, 0x63, 0x22, 0x7d, 0x05, 0xff, 0xaa, 0x4a, 0xac, 0x6e, 0xf9,
        0x31, 0x4a, 0xe3, 0xe4, 0x97, 0x3a, 0x71, 0x03, 0x11, 0x7c, 0xdb, 0x89, 0xad, 0x28, 0xc4,
        0x62, 0x9b, 0x01, 0x90, 0x6d, 0x9e, 0x2d, 0x6c, 0xb9, 0x40, 0x14, 0xdb, 0xa0, 0x3b, 0x4d,
        0x9e, 0x57, 0x41, 0xea, 0xf3, 0x11, 0xf1, 0x7d, 0xb9, 0x8d, 0xad, 0xb9, 0x52, 0xa8, 0x8c,
        0xba, 0xf3, 0xf5, 0x1d, 0x8e, 0x0e, 0x18, 0xf5, 0xf7, 0x85, 0x8b, 0xc3, 0x55, 0x7d, 0x88,
        0x3f, 0xae, 0xc1, 0x63, 0xb8, 0xbf, 0x85, 0xbf, 0xfd, 0xdd, 0x2c, 0x10, 0x61, 0x68, 0xc7,
        0xdf, 0xc9, 0x5f, 0x49, 0xd1, 0xe5, 0x0b, 0x5e, 0x05, 0x70, 0xe5, 0x95, 0xcd, 0x69, 0x08,
        0x0a, 0x6f, 0xab, 0x12, 0x05, 0x0a, 0xa2, 0x53, 0x72, 0xdf, 0xb4, 0x70, 0xd3, 0x02, 0x03,
        0x01, 0x00, 0x01, 0xa0, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x6e, 0x7c, 0x8c, 0xe6, 0x36,
        0xa8, 0x84, 0x2a, 0x23, 0xe7, 0xb8, 0x36, 0xd1, 0x94, 0x17, 0x18, 0x19, 0x18, 0xda, 0x40,
        0xcc, 0xdf, 0x63, 0xbb, 0xbf, 0x4e, 0x36, 0xec, 0x54, 0x07, 0x6f, 0xc6, 0x6b, 0xd7, 0x91,
        0x6a, 0x6d, 0x3c, 0xfc, 0x44, 0x86, 0x7f, 0x8a, 0xc5, 0x52, 0x2a, 0xef, 0x51, 0x63, 0x84,
        0xaf, 0x84, 0xac, 0xc8, 0xf0, 0x97, 0x48, 0x6a, 0x8d, 0x57, 0x15, 0xa7, 0x54, 0xd6, 0xf1,
        0x52, 0x56, 0x5c, 0xcf, 0x19, 0x09, 0x93, 0x20, 0xf1, 0x9c, 0x76, 0x0f, 0xec, 0x9f, 0x91,
        0x96, 0xcc, 0x46, 0x5c, 0x2d, 0x80, 0xb6, 0x2e, 0xb6, 0x9e, 0x82, 0x9e, 0x79, 0x55, 0xfd,
        0x6c, 0x52, 0x64, 0x00, 0x13, 0x43, 0x29, 0x34, 0x64, 0xec, 0x3c, 0x50, 0x4e, 0xcf, 0x1d,
        0x90, 0xf1, 0xc7, 0x5a, 0x8f, 0x01, 0xa6, 0xa2, 0x2e, 0xb3, 0xf1, 0x6e, 0x1b, 0x4f, 0x39,
        0x05, 0x1f, 0xb5, 0x0f, 0x06, 0x26, 0x2f, 0xb6, 0x8f, 0xf1, 0x77, 0x1c, 0x99, 0xc5, 0xec,
        0x6c, 0xfc, 0x7f, 0x6a, 0x56, 0xe9, 0x67, 0x07, 0x37, 0xe7, 0x22, 0x88, 0x10, 0x1f, 0x81,
        0xa2, 0xe6, 0x9a, 0x9b, 0xc6, 0xcb, 0x0c, 0x4a, 0x25, 0x8c, 0xe2, 0x97, 0xc2, 0xda, 0x6c,
        0x14, 0x7b, 0xe6, 0x26, 0x1d, 0x51, 0xba, 0x34, 0x40, 0x83, 0xa3, 0x0a, 0xe8, 0x0b, 0x18,
        0x6a, 0x76, 0x4f, 0xfa, 0xc0, 0x12, 0xf1, 0xf6, 0x8a, 0xe0, 0xfd, 0x5f, 0xa2, 0x7c, 0x1c,
        0x05, 0xf9, 0xd9, 0x83, 0xb1, 0xfe, 0xa1, 0xb0, 0x2d, 0x9f, 0xf0, 0x67, 0x42, 0x6e, 0xd1,
        0xcd, 0xce, 0xb6, 0x19, 0x96, 0x8e, 0x2f, 0xd9, 0x22, 0xaa, 0x09, 0x4e, 0xce, 0x31, 0x6a,
        0x02, 0x30, 0x23, 0x21, 0xbc, 0xe6, 0x41, 0xf7, 0xb2, 0xbb, 0xeb, 0xd8, 0xad, 0x38, 0x25,
        0xbe, 0x37, 0xec, 0x91, 0xfd, 0x15, 0xfa, 0xf8, 0x2f, 0x08, 0xcb,
    ];

    #[test]
    fn write_der() {
        let mut t = Test::new();
        let output = t
            .builder()
            .signature_hash(::hash::Type::Sha256)
            .write_der_vec(&mut ::test_support::rand::test_rng())
            .unwrap();
        assert!(output == TEST_DER);
    }

    #[test]
    fn write_pem() {
        let mut t = Test::new();
        let output = t
            .builder()
            .signature_hash(::hash::Type::Sha256)
            .write_pem_string(&mut ::test_support::rand::test_rng())
            .unwrap();
        assert_eq!(output, TEST_PEM);
    }
}
