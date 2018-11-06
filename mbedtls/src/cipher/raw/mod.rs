/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[mbedtls_use]
use {
    mbedtls_cipher_auth_decrypt, mbedtls_cipher_auth_encrypt, mbedtls_cipher_check_tag,
    mbedtls_cipher_finish, mbedtls_cipher_free, mbedtls_cipher_id_t,
    mbedtls_cipher_info_from_values, mbedtls_cipher_init, mbedtls_cipher_mode_t,
    mbedtls_cipher_reset, mbedtls_cipher_set_iv, mbedtls_cipher_set_padding_mode,
    mbedtls_cipher_setkey, mbedtls_cipher_setup, mbedtls_cipher_update, mbedtls_cipher_write_tag,
    mbedtls_des_key_set_parity, mbedtls_md_get_type, MBEDTLS_CIPHER_AES_128_CBC,
    MBEDTLS_CIPHER_AES_128_CCM, MBEDTLS_CIPHER_AES_128_CFB128, MBEDTLS_CIPHER_AES_128_CTR,
    MBEDTLS_CIPHER_AES_128_ECB, MBEDTLS_CIPHER_AES_128_GCM, MBEDTLS_CIPHER_AES_192_CBC,
    MBEDTLS_CIPHER_AES_192_CCM, MBEDTLS_CIPHER_AES_192_CFB128, MBEDTLS_CIPHER_AES_192_CTR,
    MBEDTLS_CIPHER_AES_192_ECB, MBEDTLS_CIPHER_AES_192_GCM, MBEDTLS_CIPHER_AES_256_CBC,
    MBEDTLS_CIPHER_AES_256_CCM, MBEDTLS_CIPHER_AES_256_CFB128, MBEDTLS_CIPHER_AES_256_CTR,
    MBEDTLS_CIPHER_AES_256_ECB, MBEDTLS_CIPHER_ARC4_128, MBEDTLS_CIPHER_BLOWFISH_CBC,
    MBEDTLS_CIPHER_BLOWFISH_CFB64, MBEDTLS_CIPHER_BLOWFISH_CTR, MBEDTLS_CIPHER_BLOWFISH_ECB,
    MBEDTLS_CIPHER_CAMELLIA_128_CBC, MBEDTLS_CIPHER_CAMELLIA_128_CCM,
    MBEDTLS_CIPHER_CAMELLIA_128_CFB128, MBEDTLS_CIPHER_CAMELLIA_128_CTR,
    MBEDTLS_CIPHER_CAMELLIA_128_ECB, MBEDTLS_CIPHER_CAMELLIA_128_GCM,
    MBEDTLS_CIPHER_CAMELLIA_192_CBC, MBEDTLS_CIPHER_CAMELLIA_192_CCM,
    MBEDTLS_CIPHER_CAMELLIA_192_CFB128, MBEDTLS_CIPHER_CAMELLIA_192_CTR,
    MBEDTLS_CIPHER_CAMELLIA_192_ECB, MBEDTLS_CIPHER_CAMELLIA_192_GCM,
    MBEDTLS_CIPHER_CAMELLIA_256_CBC, MBEDTLS_CIPHER_CAMELLIA_256_CCM,
    MBEDTLS_CIPHER_CAMELLIA_256_CFB128, MBEDTLS_CIPHER_CAMELLIA_256_CTR,
    MBEDTLS_CIPHER_CAMELLIA_256_ECB, MBEDTLS_CIPHER_CAMELLIA_256_GCM, MBEDTLS_CIPHER_DES_CBC,
    MBEDTLS_CIPHER_DES_ECB, MBEDTLS_CIPHER_DES_EDE3_CBC, MBEDTLS_CIPHER_DES_EDE3_ECB,
    MBEDTLS_CIPHER_DES_EDE_CBC, MBEDTLS_CIPHER_DES_EDE_ECB, MBEDTLS_CIPHER_ID_3DES,
    MBEDTLS_CIPHER_ID_AES, MBEDTLS_CIPHER_ID_ARC4, MBEDTLS_CIPHER_ID_BLOWFISH,
    MBEDTLS_CIPHER_ID_CAMELLIA, MBEDTLS_CIPHER_ID_DES, MBEDTLS_CIPHER_ID_NONE,
    MBEDTLS_CIPHER_ID_NULL, MBEDTLS_CIPHER_NONE, MBEDTLS_CIPHER_NULL, MBEDTLS_DECRYPT,
    MBEDTLS_ENCRYPT, MBEDTLS_MODE_CBC, MBEDTLS_MODE_CCM, MBEDTLS_MODE_CFB, MBEDTLS_MODE_CTR,
    MBEDTLS_MODE_ECB, MBEDTLS_MODE_GCM, MBEDTLS_MODE_NONE, MBEDTLS_MODE_OFB, MBEDTLS_MODE_STREAM,
    MBEDTLS_OPERATION_NONE, MBEDTLS_PADDING_NONE, MBEDTLS_PADDING_ONE_AND_ZEROS,
    MBEDTLS_PADDING_PKCS7, MBEDTLS_PADDING_ZEROS, MBEDTLS_PADDING_ZEROS_AND_LEN,
};

use mbedtls_sys::*;

use error::IntoResult;

mod serde;

define!(enum CipherId -> mbedtls_cipher_id_t {
	None => MBEDTLS_CIPHER_ID_NONE,
	Null => MBEDTLS_CIPHER_ID_NULL,
	Aes => MBEDTLS_CIPHER_ID_AES,
	Des => MBEDTLS_CIPHER_ID_DES,
	Des3 => MBEDTLS_CIPHER_ID_3DES,
	Camellia => MBEDTLS_CIPHER_ID_CAMELLIA,
	Blowfish => MBEDTLS_CIPHER_ID_BLOWFISH,
	Arc4 => MBEDTLS_CIPHER_ID_ARC4,
});

impl From<cipher_id_t> for CipherId {
    fn from(inner: cipher_id_t) -> Self {
        match inner {
            CIPHER_ID_NONE => CipherId::None,
            CIPHER_ID_NULL => CipherId::Null,
            CIPHER_ID_AES => CipherId::Aes,
            CIPHER_ID_DES => CipherId::Des,
            CIPHER_ID_3DES => CipherId::Des3,
            CIPHER_ID_CAMELLIA => CipherId::Camellia,
            CIPHER_ID_BLOWFISH => CipherId::Blowfish,
            CIPHER_ID_ARC4 => CipherId::Arc4,
            // This should be replaced with TryFrom once it is stable.
            _ => panic!("Invalid cipher_id_t"),
        }
    }
}

define!(#[derive(Copy, Clone, Eq, PartialEq)] enum CipherMode -> mbedtls_cipher_mode_t {
	None => MBEDTLS_MODE_NONE,
	ECB => MBEDTLS_MODE_ECB,
	CBC => MBEDTLS_MODE_CBC,
	CFB => MBEDTLS_MODE_CFB,
	OFB => MBEDTLS_MODE_OFB,
	CTR => MBEDTLS_MODE_CTR,
	GCM => MBEDTLS_MODE_GCM,
	STREAM => MBEDTLS_MODE_STREAM,
	CCM => MBEDTLS_MODE_CCM,
});

impl From<cipher_mode_t> for CipherMode {
    fn from(inner: cipher_mode_t) -> Self {
        match inner {
            MODE_NONE => CipherMode::None,
            MODE_ECB => CipherMode::ECB,
            MODE_CBC => CipherMode::CBC,
            MODE_CFB => CipherMode::CFB,
            MODE_OFB => CipherMode::OFB,
            MODE_CTR => CipherMode::CTR,
            MODE_GCM => CipherMode::GCM,
            MODE_STREAM => CipherMode::STREAM,
            MODE_CCM => CipherMode::CCM,
            // This should be replaced with TryFrom once it is stable.
            _ => panic!("Invalid cipher_mode_t"),
        }
    }
}

define!(enum CipherType -> mbedtls_cipher_type_t {
	None              => MBEDTLS_CIPHER_NONE,
	Null              => MBEDTLS_CIPHER_NULL,
	Aes128Ecb         => MBEDTLS_CIPHER_AES_128_ECB,
	Aes192Ecb         => MBEDTLS_CIPHER_AES_192_ECB,
	Aes256Ecb         => MBEDTLS_CIPHER_AES_256_ECB,
	Aes128Cbc         => MBEDTLS_CIPHER_AES_128_CBC,
	Aes192Cbc         => MBEDTLS_CIPHER_AES_192_CBC,
	Aes256Cbc         => MBEDTLS_CIPHER_AES_256_CBC,
	Aes128Cfb128      => MBEDTLS_CIPHER_AES_128_CFB128,
	Aes192Cfb128      => MBEDTLS_CIPHER_AES_192_CFB128,
	Aes256Cfb128      => MBEDTLS_CIPHER_AES_256_CFB128,
	Aes128Ctr         => MBEDTLS_CIPHER_AES_128_CTR,
	Aes192Ctr         => MBEDTLS_CIPHER_AES_192_CTR,
	Aes256Ctr         => MBEDTLS_CIPHER_AES_256_CTR,
	Aes128Gcm         => MBEDTLS_CIPHER_AES_128_GCM,
	Aes192Gcm         => MBEDTLS_CIPHER_AES_192_GCM,
	Aes256Gcm         => MBEDTLS_CIPHER_AES_256_GCM,
	Camellia128Ecb    => MBEDTLS_CIPHER_CAMELLIA_128_ECB,
	Camellia192Ecb    => MBEDTLS_CIPHER_CAMELLIA_192_ECB,
	Camellia256Ecb    => MBEDTLS_CIPHER_CAMELLIA_256_ECB,
	Camellia128Cbc    => MBEDTLS_CIPHER_CAMELLIA_128_CBC,
	Camellia192Cbc    => MBEDTLS_CIPHER_CAMELLIA_192_CBC,
	Camellia256Cbc    => MBEDTLS_CIPHER_CAMELLIA_256_CBC,
	Camellia128Cfb128 => MBEDTLS_CIPHER_CAMELLIA_128_CFB128,
	Camellia192Cfb128 => MBEDTLS_CIPHER_CAMELLIA_192_CFB128,
	Camellia256Cfb128 => MBEDTLS_CIPHER_CAMELLIA_256_CFB128,
	Camellia128Ctr    => MBEDTLS_CIPHER_CAMELLIA_128_CTR,
	Camellia192Ctr    => MBEDTLS_CIPHER_CAMELLIA_192_CTR,
	Camellia256Ctr    => MBEDTLS_CIPHER_CAMELLIA_256_CTR,
	Camellia128Gcm    => MBEDTLS_CIPHER_CAMELLIA_128_GCM,
	Camellia192Gcm    => MBEDTLS_CIPHER_CAMELLIA_192_GCM,
	Camellia256Gcm    => MBEDTLS_CIPHER_CAMELLIA_256_GCM,
	DesEcb            => MBEDTLS_CIPHER_DES_ECB,
	DesCbc            => MBEDTLS_CIPHER_DES_CBC,
	DesEdeEcb         => MBEDTLS_CIPHER_DES_EDE_ECB,
	DesEdeCbc         => MBEDTLS_CIPHER_DES_EDE_CBC,
	DesEde3Ecb        => MBEDTLS_CIPHER_DES_EDE3_ECB,
	DesEde3Cbc        => MBEDTLS_CIPHER_DES_EDE3_CBC,
	BlowfishEcb       => MBEDTLS_CIPHER_BLOWFISH_ECB,
	BlowfishCbc       => MBEDTLS_CIPHER_BLOWFISH_CBC,
	BlowfishCfb64     => MBEDTLS_CIPHER_BLOWFISH_CFB64,
	BlowfishCtr       => MBEDTLS_CIPHER_BLOWFISH_CTR,
	Arcfour128        => MBEDTLS_CIPHER_ARC4_128,
	Aes128Ccm         => MBEDTLS_CIPHER_AES_128_CCM,
	Aes192Ccm         => MBEDTLS_CIPHER_AES_192_CCM,
	Aes256Ccm         => MBEDTLS_CIPHER_AES_256_CCM,
	Camellia128Ccm    => MBEDTLS_CIPHER_CAMELLIA_128_CCM,
	Camellia192Ccm    => MBEDTLS_CIPHER_CAMELLIA_192_CCM,
	Camellia256Ccm    => MBEDTLS_CIPHER_CAMELLIA_256_CCM,
});

define!(
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
enum CipherPadding -> mbedtls_cipher_padding_t {
	Pkcs7       => MBEDTLS_PADDING_PKCS7,
	IsoIec78164 => MBEDTLS_PADDING_ONE_AND_ZEROS,
	AnsiX923    => MBEDTLS_PADDING_ZEROS_AND_LEN,
	Zeros       => MBEDTLS_PADDING_ZEROS,
	None        => MBEDTLS_PADDING_NONE,
});

define!(enum Operation -> mbedtls_operation_t {
	None => MBEDTLS_OPERATION_NONE,
	Decrypt => MBEDTLS_DECRYPT,
	Encrypt => MBEDTLS_ENCRYPT,
});

define!(#[repr(C)]
struct Cipher(mbedtls_cipher_context_t) {
	fn init = mbedtls_cipher_init;
	fn drop = mbedtls_cipher_free;
	impl<'a> Into<*>;
});

impl Cipher {
    // Setup routine - this should be the first function called
    // it combines several steps into one call here, they are
    // Cipher init, Cipher setup
    pub fn setup(
        cipher_id: CipherId,
        cipher_mode: CipherMode,
        key_bit_len: u32,
    ) -> ::Result<Cipher> {
        let mut ret = Self::init();
        unsafe {
            // Do setup with proper cipher_info based on algorithm, key length and mode
            try!(
                cipher_setup(
                    &mut ret.inner,
                    cipher_info_from_values(
                        cipher_id.into(),
                        key_bit_len as i32,
                        cipher_mode.into()
                    )
                ).into_result()
            );
        }
        Ok(ret)
    }

    // Cipher set key - should be called after setup
    pub fn set_key(&mut self, op: Operation, key: &[u8]) -> ::Result<()> {
        unsafe {
            cipher_setkey(
                &mut self.inner,
                key.as_ptr(),
                (key.len() * 8) as _,
                op.into(),
            ).into_result_discard()
        }
    }

    pub fn set_padding(&mut self, padding: CipherPadding) -> ::Result<()> {
        unsafe { cipher_set_padding_mode(&mut self.inner, padding.into()).into_result_discard() }
    }

    // Cipher set IV - should be called after setup
    pub fn set_iv(&mut self, iv: &[u8]) -> ::Result<()> {
        unsafe { cipher_set_iv(&mut self.inner, iv.as_ptr(), iv.len()).into_result_discard() }
    }

    pub fn reset(&mut self) -> ::Result<()> {
        unsafe { cipher_reset(&mut self.inner).into_result_discard() }
    }

    pub fn update(&mut self, indata: &[u8], outdata: &mut [u8]) -> ::Result<usize> {
        // Check that minimum required space is available in outdata buffer
        let reqd_size = if unsafe { *self.inner.cipher_info }.mode == MODE_ECB {
            self.block_size()
        } else {
            indata.len() + self.block_size()
        };

        if outdata.len() < reqd_size {
            return Err(::Error::CipherFullBlockExpected);
        }

        let mut olen = 0;
        unsafe {
            try!(
                cipher_update(
                    &mut self.inner,
                    indata.as_ptr(),
                    indata.len(),
                    outdata.as_mut_ptr(),
                    &mut olen
                ).into_result()
            );
        }
        Ok(olen)
    }

    pub fn finish(&mut self, outdata: &mut [u8]) -> ::Result<usize> {
        // Check that minimum required space is available in outdata buffer
        if outdata.len() < self.block_size() {
            return Err(::Error::CipherFullBlockExpected);
        }

        let mut olen = 0;
        unsafe {
            try!(cipher_finish(&mut self.inner, outdata.as_mut_ptr(), &mut olen).into_result());
        }
        Ok(olen)
    }

    pub fn write_tag(&mut self, tag: &mut [u8]) -> ::Result<()> {
        unsafe {
            cipher_write_tag(&mut self.inner, tag.as_mut_ptr(), tag.len()).into_result_discard()
        }
    }

    pub fn check_tag(&mut self, tag: &[u8]) -> ::Result<()> {
        unsafe { cipher_check_tag(&mut self.inner, tag.as_ptr(), tag.len()).into_result_discard() }
    }

    // Utility function to get block size for the selected / setup cipher_info
    pub fn block_size(&self) -> usize {
        unsafe { (*self.inner.cipher_info).block_size as usize }
    }

    // Utility function to get IV size for the selected / setup cipher_info
    pub fn iv_size(&self) -> usize {
        unsafe { (*self.inner.cipher_info).iv_size as usize }
    }

    // Utility function to get mdoe for the selected / setup cipher_info
    pub fn is_authenticated(&self) -> bool {
        unsafe {
            if (*self.inner.cipher_info).mode == MODE_GCM
                || (*self.inner.cipher_info).mode == MODE_CCM
            {
                return true;
            } else {
                return false;
            }
        }
    }

    // Utility function to set odd parity - used for DES keys
    pub fn set_parity(key: &mut [u8]) -> ::Result<()> {
        unsafe { des_key_set_parity(key.as_mut_ptr()) }
        Ok(())
    }

    pub fn encrypt(&mut self, plain: &[u8], cipher: &mut [u8]) -> ::Result<usize> {
        self.do_crypto(plain, cipher)
    }

    pub fn decrypt(&mut self, cipher: &[u8], plain: &mut [u8]) -> ::Result<usize> {
        self.do_crypto(cipher, plain)
    }

    pub fn encrypt_auth(
        &mut self,
        ad: &[u8],
        plain: &[u8],
        cipher: &mut [u8],
        tag: &mut [u8],
    ) -> ::Result<usize> {
        if plain.len() > cipher.len() {
            return Err(::Error::CipherBadInputData);
        }

        let iv = self.inner.iv;
        let iv_len = self.inner.iv_size;
        let mut cipher_len = cipher.len();
        unsafe {
            cipher_auth_encrypt(
                &mut self.inner,
                iv.as_ptr(),
                iv_len,
                ad.as_ptr(),
                ad.len(),
                plain.as_ptr(),
                plain.len(),
                cipher.as_mut_ptr(),
                &mut cipher_len,
                tag.as_mut_ptr(),
                tag.len(),
            ).into_result()?
        };

        Ok(cipher_len)
    }

    pub fn decrypt_auth(
        &mut self,
        ad: &[u8],
        cipher: &[u8],
        plain: &mut [u8],
        tag: &[u8],
    ) -> ::Result<usize> {
        if cipher.len() > plain.len() {
            return Err(::Error::CipherBadInputData);
        }

        let iv = self.inner.iv;
        let iv_len = self.inner.iv_size;
        let mut plain_len = plain.len();
        unsafe {
            cipher_auth_decrypt(
                &mut self.inner,
                iv.as_ptr(),
                iv_len,
                ad.as_ptr(),
                ad.len(),
                cipher.as_ptr(),
                cipher.len(),
                plain.as_mut_ptr(),
                &mut plain_len,
                tag.as_ptr(),
                tag.len(),
            ).into_result()?
        };

        Ok(plain_len)
    }

    fn do_crypto(&mut self, indata: &[u8], outdata: &mut [u8]) -> ::Result<usize> {
        self.reset()?;

        // The total number of bytes writte to outdata so far. It's safe to
        // use this as a start index for slicing: &slice[slice.len()..] will
        // return an empty slice, it doesn't panic.
        let mut total_len = 0;

        if unsafe { *self.inner.cipher_info }.mode == MODE_ECB {
            // ECB mode requires single-block updates
            for chunk in indata.chunks(self.block_size()) {
                let len = self.update(chunk, &mut outdata[total_len..])?;
                total_len += len;
            }
        } else {
            total_len = self.update(indata, outdata)?;
            total_len += self.finish(&mut outdata[total_len..])?;
        }

        Ok(total_len)
    }
}

#[test]
fn no_overflow() {
    let mut c = Cipher::setup(CipherId::Aes, CipherMode::CBC, 128).unwrap();
    c.set_key(Operation::Encrypt, &[0u8; 16]).unwrap();
    c.set_iv(&[0u8; 16]).unwrap();
    let mut out = [0u8; 48];
    let encrypt_result = c.encrypt(&[0u8; 16][..], &mut out[..16]);
    assert_eq!(out[16..], [0u8; 32]);
    encrypt_result.expect_err("Returned OK with too small buffer");
}

#[test]
fn one_part_ecb() {
    let mut c = Cipher::setup(CipherId::Aes, CipherMode::ECB, 128).unwrap();
    c.set_key(
        Operation::Encrypt,
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    ).unwrap();
    let mut out = [0u8; 48];
    let len = c.encrypt(b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", &mut out).unwrap();
    assert_eq!(len, 32);
    assert_eq!(&out[..len], b"\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a");
}
