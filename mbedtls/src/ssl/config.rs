/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::slice::from_raw_parts;

use mbedtls_sys::types::raw_types::{c_char, c_int, c_uchar, c_uint, c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;

#[mbedtls_use]
use {
    mbedtls_ecp_group_id, mbedtls_ssl_conf_ca_chain, mbedtls_ssl_conf_cert_profile,
    mbedtls_ssl_conf_ciphersuites, mbedtls_ssl_conf_ciphersuites_for_version,
    mbedtls_ssl_conf_curves, mbedtls_ssl_conf_dh_param_ctx, mbedtls_ssl_conf_own_cert,
    mbedtls_ssl_conf_session_tickets_cb, mbedtls_ssl_conf_sni, mbedtls_ssl_conf_verify,
    mbedtls_ssl_config, mbedtls_ssl_config_defaults, mbedtls_ssl_config_free,
    mbedtls_ssl_config_init, mbedtls_ssl_context, mbedtls_x509_crt, MBEDTLS_SSL_IS_CLIENT,
    MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_PRESET_DEFAULT, MBEDTLS_SSL_PRESET_SUITEB,
    MBEDTLS_SSL_SESSION_TICKETS_DISABLED, MBEDTLS_SSL_SESSION_TICKETS_ENABLED,
    MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_VERIFY_NONE,
    MBEDTLS_SSL_VERIFY_OPTIONAL, MBEDTLS_SSL_VERIFY_REQUIRED,
};

use error::IntoResult;
use pk::dhparam::Dhm;
use private::UnsafeFrom;
use ssl::context::HandshakeContext;
use ssl::ticket::TicketCallback;
use x509::{certificate, Crl, LinkedCertificate, Profile, VerifyError};

define!(enum Endpoint -> c_int {
	Client => MBEDTLS_SSL_IS_CLIENT,
	Server => MBEDTLS_SSL_IS_SERVER,
});

define!(enum Transport -> c_int {
	/// TLS
	Stream => MBEDTLS_SSL_TRANSPORT_STREAM,
	/// DTLS
	Datagram => MBEDTLS_SSL_TRANSPORT_DATAGRAM,
});

define!(enum Preset -> c_int {
	Default => MBEDTLS_SSL_PRESET_DEFAULT,
	SuiteB => MBEDTLS_SSL_PRESET_SUITEB,
});

define!(enum AuthMode -> c_int {
	/// **INSECURE** on client, default on server
	None => MBEDTLS_SSL_VERIFY_NONE,
	/// **INSECURE**
	Optional => MBEDTLS_SSL_VERIFY_OPTIONAL,
	/// default on client
	Required => MBEDTLS_SSL_VERIFY_REQUIRED,
});

define!(enum UseSessionTickets -> c_int {
	Enabled => MBEDTLS_SSL_SESSION_TICKETS_ENABLED,
	Disabled => MBEDTLS_SSL_SESSION_TICKETS_DISABLED,
});

callback!(DbgCallback:Sync(level: c_int, file: *const c_char, line: c_int, message: *const c_char) -> ());

define!(struct Config<'c>(mbedtls_ssl_config) {
	fn init = mbedtls_ssl_config_init;
	fn drop = mbedtls_ssl_config_free;
	impl<'q> Into<*>;
	impl<'q> UnsafeFrom<*>;
});

#[cfg(feature = "threading")]
unsafe impl<'c> Sync for Config<'c> {}

impl<'c> Config<'c> {
    pub fn new(e: Endpoint, t: Transport, p: Preset) -> Self {
        let mut c = Config::init();
        unsafe {
            ssl_config_defaults(&mut c.inner, e.into(), t.into(), p.into());
        }
        c
    }

    // need bitfield support getter!(endpoint() -> Endpoint = field endpoint);
    setter!(set_endpoint(e: Endpoint) = mbedtls_ssl_conf_endpoint);
    // need bitfield support getter!(transport() -> Transport = field transport);
    setter!(set_transport(t: Transport) = mbedtls_ssl_conf_transport);
    // need bitfield support getter!(authmode() -> AuthMode = field authmode);
    setter!(set_authmode(am: AuthMode) = mbedtls_ssl_conf_authmode);
    getter!(read_timeout() -> u32 = .read_timeout);
    setter!(set_read_timeout(t: u32) = mbedtls_ssl_conf_read_timeout);

    fn check_c_list<T: Default + Eq>(list: &[T]) {
        assert!(list.last() == Some(&T::default()));
    }

    pub fn set_ciphersuites(&mut self, list: &'c [c_int]) {
        Self::check_c_list(list);
        unsafe { ssl_conf_ciphersuites(&mut self.inner, list.as_ptr()) }
    }

    pub fn set_ciphersuites_for_version(&mut self, list: &'c [c_int], major: c_int, minor: c_int) {
        Self::check_c_list(list);
        unsafe { ssl_conf_ciphersuites_for_version(&mut self.inner, list.as_ptr(), major, minor) }
    }

    pub fn set_curves(&mut self, list: &'c [ecp_group_id]) {
        Self::check_c_list(list);
        unsafe { ssl_conf_curves(&mut self.inner, list.as_ptr()) }
    }

    setter!(set_cert_profile(p: &'c Profile) = mbedtls_ssl_conf_cert_profile);

    /// Takes both DER and PEM forms of FFDH parameters in `DHParams` format.
    ///
    /// When calling on PEM-encoded data, `params` must be NULL-terminated
    pub fn set_dh_params(&mut self, params: &[u8]) -> ::Result<()> {
        let mut ctx = Dhm::from_params(params)?;
        unsafe {
            ssl_conf_dh_param_ctx(&mut self.inner, (&mut ctx).into())
                .into_result()
                .map(|_| ())
        }
    }

    pub fn set_ca_list<C: Into<&'c mut LinkedCertificate>>(
        &mut self,
        list: Option<C>,
        crl: Option<&'c mut Crl>,
    ) {
        unsafe {
            ssl_conf_ca_chain(
                &mut self.inner,
                list.map(Into::into)
                    .map(Into::into)
                    .unwrap_or(::core::ptr::null_mut()),
                crl.map(Into::into).unwrap_or(::core::ptr::null_mut()),
            )
        }
    }

    pub fn push_cert<C: Into<&'c mut LinkedCertificate>>(
        &mut self,
        chain: C,
        key: &'c mut ::pk::Pk,
    ) -> ::Result<()> {
        unsafe {
            ssl_conf_own_cert(&mut self.inner, chain.into().into(), key.into())
                .into_result()
                .map(|_| ())
        }
    }

    pub fn certs(&'c self) -> KeyCertIter<'c> {
        KeyCertIter {
            key_cert: unsafe { UnsafeFrom::from(self.inner.key_cert as *const _) },
        }
    }

    /// Server only: configure callback to use for generating/interpreting session tickets.
    pub fn set_session_tickets_callback<F: TicketCallback>(&mut self, cb: &'c mut F) {
        unsafe {
            ssl_conf_session_tickets_cb(
                &mut self.inner,
                Some(F::call_write),
                Some(F::call_parse),
                cb.data_ptr(),
            )
        };
    }

    /// Client only: whether to remember and use session tickets
    setter!(set_session_tickets(u: UseSessionTickets) = mbedtls_ssl_conf_session_tickets);

    /// Client only: minimal FFDH group size
    setter!(set_ffdh_min_bitlen(bitlen: c_uint) = mbedtls_ssl_conf_dhm_min_bitlen);

    // TODO: The lifetime restrictions on HandshakeContext here are too strict.
    // Once we need something else, we might fix it.
    pub fn set_sni_callback<F: FnMut(&mut HandshakeContext, &[u8]) -> Result<(), ()>>(
        &mut self,
        cb: &'c mut F,
    ) {
        unsafe extern "C" fn sni_callback<
            F: FnMut(&mut HandshakeContext, &[u8]) -> Result<(), ()>,
        >(
            closure: *mut c_void,
            ctx: *mut ssl_context,
            name: *const c_uchar,
            name_len: size_t,
        ) -> c_int {
            let cb = &mut *(closure as *mut F);
            let mut ctx = ::private::UnsafeFrom::from(ctx).expect("valid context");
            let name = from_raw_parts(name, name_len);
            match cb(&mut ctx, name) {
                Ok(()) => 0,
                Err(()) => -1,
            }
        }

        unsafe { ssl_conf_sni(&mut self.inner, Some(sni_callback::<F>), cb as *mut F as _) }
    }

    // The docs for mbedtls_x509_crt_verify say "The [callback] should return 0 for anything but a
    // fatal error.", so verify callbacks should return Ok(()) for anything but a fatal error.
    // Report verification errors by updating the flags in VerifyError.
    pub fn set_verify_callback<F>(&mut self, cb: &'c mut F)
    where
        F: FnMut(&mut LinkedCertificate, i32, &mut VerifyError) -> ::Result<()>,
    {
        unsafe extern "C" fn verify_callback<F>(
            closure: *mut c_void,
            crt: *mut x509_crt,
            depth: c_int,
            flags: *mut u32,
        ) -> c_int
        where
            F: FnMut(&mut LinkedCertificate, i32, &mut VerifyError) -> ::Result<()>,
        {
            let cb = &mut *(closure as *mut F);
            let crt: &mut LinkedCertificate =
                ::private::UnsafeFrom::from(crt).expect("valid certificate");
            let mut verify_error = match VerifyError::from_bits(*flags) {
                Some(ve) => ve,
                // This can only happen if mbedtls is setting flags in VerifyError that are
                // missing from our definition.
                None => return ::mbedtls_sys::MBEDTLS_ERR_X509_BAD_INPUT_DATA,
            };
            let res = cb(crt, depth, &mut verify_error);
            *flags = verify_error.bits();
            match res {
                Ok(()) => 0,
                Err(e) => e.to_int(),
            }
        }

        unsafe {
            ssl_conf_verify(
                &mut self.inner,
                Some(verify_callback::<F>),
                cb as *mut F as _,
            )
        }
    }
}

setter_callback!(Config<'c>::set_rng(f: ::rng::Random) = mbedtls_ssl_conf_rng);
setter_callback!(Config<'c>::set_dbg(f: DbgCallback) = mbedtls_ssl_conf_dbg);

define!(struct KeyCert(mbedtls_ssl_key_cert) {
	impl<'a> UnsafeFrom<*>;
});

pub struct KeyCertIter<'a> {
    key_cert: Option<&'a KeyCert>,
}

impl<'a> Iterator for KeyCertIter<'a> {
    type Item = (certificate::Iter<'a>, &'a ::pk::Pk);

    fn next(&mut self) -> Option<Self::Item> {
        self.key_cert.take().map(|key_cert| unsafe {
            self.key_cert = UnsafeFrom::from(key_cert.inner.next as *const _);
            (
                UnsafeFrom::from(key_cert.inner.cert as *const _).expect("not null"),
                UnsafeFrom::from(key_cert.inner.key as *const _).expect("not null"),
            )
        })
    }
}

// TODO
// ssl_conf_export_keys_cb
// ssl_conf_dtls_cookies
// ssl_conf_dtls_anti_replay
// ssl_conf_dtls_badmac_limit
// ssl_conf_handshake_timeout
// ssl_conf_session_cache
// ssl_conf_psk
// ssl_conf_psk_cb
// ssl_conf_sig_hashes
// ssl_conf_alpn_protocols
// ssl_conf_max_version
// ssl_conf_min_version
// ssl_conf_fallback
// ssl_conf_encrypt_then_mac
// ssl_conf_extended_master_secret
// ssl_conf_arc4_support
// ssl_conf_max_frag_len
// ssl_conf_truncated_hmac
// ssl_conf_cbc_record_splitting
// ssl_conf_renegotiation
// ssl_conf_legacy_renegotiation
// ssl_conf_renegotiation_enforced
// ssl_conf_renegotiation_period
//
