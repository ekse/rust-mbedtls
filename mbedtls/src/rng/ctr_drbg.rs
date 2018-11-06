/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
pub use mbedtls_sys::MBEDTLS_CTR_DRBG_RESEED_INTERVAL as RESEED_INTERVAL;

#[mbedtls_use]
use {
    mbedtls_ctr_drbg_random, mbedtls_ctr_drbg_reseed, mbedtls_ctr_drbg_seed,
    mbedtls_ctr_drbg_set_prediction_resistance, mbedtls_ctr_drbg_update, MBEDTLS_CTR_DRBG_PR_OFF,
    MBEDTLS_CTR_DRBG_PR_ON,
};

use super::{EntropyCallback, RngCallback};
use error::IntoResult;

// ==== BEGIN IMMOVABLE TYPE KLUDGE ====
// `ctr_drbg_context` inlines an `aes_context`, which is immovable. See
// https://github.com/ARMmbed/mbedtls/issues/2147. We work around this
// by always boxing up the context, which requires this module to depend on
// std/alloc.
//
// If `ctr_drbg_context` were moveable, this entire section could be replaced
// by basically:
// ```
// define!(struct CtrDrbg<'entropy>(ctr_drbg_context) {
// 	fn init=ctr_drbg_init;
// 	fn drop=ctr_drbg_free;
// });
// ```

use self::private::CtrDrbgInner;
#[cfg(not(feature = "std"))]
use alloc_prelude::*;
use core::ops::{Deref, DerefMut};

mod private {
    use core::marker::PhantomData;
    #[mbedtls_use]
    use {mbedtls_ctr_drbg_context, mbedtls_ctr_drbg_free, mbedtls_ctr_drbg_init};

    pub struct CtrDrbgInner<'entropy> {
        pub(super) inner: ctr_drbg_context,
        r: PhantomData<&'entropy ()>,
    }

    impl<'entropy> CtrDrbgInner<'entropy> {
        pub(super) fn init() -> Self {
            let mut inner;
            unsafe {
                inner = ::core::mem::uninitialized();
                ctr_drbg_init(&mut inner)
            };
            CtrDrbgInner {
                inner,
                r: PhantomData,
            }
        }
    }

    impl<'entropy> Drop for CtrDrbgInner<'entropy> {
        fn drop(&mut self) {
            unsafe { ctr_drbg_free(&mut self.inner) };
        }
    }
}

pub struct CtrDrbg<'entropy> {
    boxed: Box<CtrDrbgInner<'entropy>>,
}

impl<'entropy> CtrDrbg<'entropy> {
    fn init() -> Self {
        CtrDrbg {
            boxed: Box::new(CtrDrbgInner::init()),
        }
    }
}

#[doc(hidden)]
impl<'entropy> Deref for CtrDrbg<'entropy> {
    type Target = CtrDrbgInner<'entropy>;
    fn deref(&self) -> &Self::Target {
        &self.boxed
    }
}

#[doc(hidden)]
impl<'entropy> DerefMut for CtrDrbg<'entropy> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.boxed
    }
}

// ==== END IMMOVABLE TYPE KLUDGE ====

#[cfg(feature = "threading")]
unsafe impl<'entropy> Sync for CtrDrbg<'entropy> {}

impl<'entropy> CtrDrbg<'entropy> {
    pub fn new<F: EntropyCallback>(
        source: &'entropy mut F,
        additional_entropy: Option<&[u8]>,
    ) -> ::Result<CtrDrbg<'entropy>> {
        let mut ret = Self::init();
        unsafe {
            try!(
                ctr_drbg_seed(
                    &mut ret.inner,
                    Some(F::call),
                    source.data_ptr(),
                    additional_entropy
                        .map(<[_]>::as_ptr)
                        .unwrap_or(::core::ptr::null()),
                    additional_entropy.map(<[_]>::len).unwrap_or(0)
                ).into_result()
            )
        };
        Ok(ret)
    }

    pub fn prediction_resistance(&self) -> bool {
        if self.inner.prediction_resistance == CTR_DRBG_PR_OFF as c_int {
            false
        } else {
            true
        }
    }

    pub fn set_prediction_resistance(&mut self, pr: bool) {
        unsafe {
            ctr_drbg_set_prediction_resistance(
                &mut self.inner,
                if pr {
                    CTR_DRBG_PR_ON as c_int
                } else {
                    CTR_DRBG_PR_OFF as c_int
                },
            )
        }
    }

    getter!(entropy_len() -> size_t = .entropy_len);
    setter!(set_entropy_len(len: size_t) = mbedtls_ctr_drbg_set_entropy_len);
    getter!(reseed_interval() -> c_int = .reseed_interval);
    setter!(set_reseed_interval(i: c_int) = mbedtls_ctr_drbg_set_reseed_interval);

    pub fn reseed(&mut self, additional_entropy: Option<&[u8]>) -> ::Result<()> {
        unsafe {
            try!(
                ctr_drbg_reseed(
                    &mut self.inner,
                    additional_entropy
                        .map(<[_]>::as_ptr)
                        .unwrap_or(::core::ptr::null()),
                    additional_entropy.map(<[_]>::len).unwrap_or(0)
                ).into_result()
            )
        };
        Ok(())
    }

    pub fn update(&mut self, entropy: &[u8]) {
        unsafe { ctr_drbg_update(&mut self.inner, entropy.as_ptr(), entropy.len()) };
    }

    // TODO:
    //
    // ctr_drbg_random_with_add
    // ctr_drbg_write_seed_file
    // ctr_drbg_update_seed_file
    //
}

impl<'entropy> RngCallback for CtrDrbg<'entropy> {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        ctr_drbg_random(user_data, data, len)
    }

    fn data_ptr(&mut self) -> *mut c_void {
        &mut self.inner as *mut _ as *mut _
    }
}
