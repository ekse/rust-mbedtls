/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use error::IntoResult;

#[mbedtls_use]
use mbedtls_dhm_parse_dhm;

use mbedtls_sys::*;

define!(#[repr(C)]
struct Dhm(mbedtls_dhm_context) {
	fn init = mbedtls_dhm_init;
	fn drop = mbedtls_dhm_free;
	impl<'a> Into<*>;
});

impl Dhm {
    /// Takes both DER and PEM forms of FFDH parameters in `DHParams` format.
    ///
    /// When calling on PEM-encoded data, `params` must be NULL-terminated
    pub(crate) fn from_params(params: &[u8]) -> ::Result<Dhm> {
        let mut ret = Self::init();
        unsafe { try!(dhm_parse_dhm(&mut ret.inner, params.as_ptr(), params.len()).into_result()) };
        Ok(ret)
    }
}
