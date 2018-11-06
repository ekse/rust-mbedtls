/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;
use core::str::Utf8Error;
#[cfg(feature = "std")]
use std::error::Error as StdError;

use mbedtls_sys::types::raw_types::c_int;

pub type Result<T> = ::core::result::Result<T, Error>;

pub trait IntoResult: Sized {
    fn into_result(self) -> Result<Self>;
    fn into_result_discard(self) -> Result<()> {
        self.into_result().map(|_| ())
    }
}

// This is intended not to overlap with mbedtls error codes. Utf8Error is
// generated in the bindings when converting to rust UTF-8 strings. Only in rare
// circumstances (callbacks from mbedtls to rust) do we need to pass a Utf8Error
// back in to mbedtls.
pub const ERR_UTF8_INVALID: c_int = -0x10000;

macro_rules! error_enum {
	{$n:ident {$($rust:ident => $c:ident,)*}} => {
		#[derive(Debug, Eq, PartialEq)]
		pub enum $n {
			$($rust,)*
			Other(c_int),
			Utf8Error(Option<Utf8Error>),
		}

		impl IntoResult for c_int {
			fn into_result(self) -> Result<c_int> {
				let err_code = match self {
					_ if self >= 0 => return Ok(self),
					ERR_UTF8_INVALID => return Err(Error::Utf8Error(None)),
					_ => -self,
				};
				let (high_level_code, low_level_code) = (err_code & 0xFF80, err_code & 0x7F);
				Err($n::from_mbedtls_code(if high_level_code > 0 { -high_level_code } else { -low_level_code }))
			}
		}

		impl $n {
			pub fn from_mbedtls_code(code: c_int) -> Self {
				match code {
					$(::mbedtls_sys::$c => $n::$rust),*,
					_ => $n::Other(code)
				}
			}

			pub fn as_str(&self) -> &'static str {
				match self {
					$(&$n::$rust => concat!("mbedTLS error ",stringify!($n::$rust)),)*
					&$n::Other(_) => "mbedTLS unknown error",
					&$n::Utf8Error(_) => "error converting to UTF-8",
				}
			}

			pub fn to_int(&self) -> c_int {
				match *self {
					$($n::$rust => ::mbedtls_sys::$c,)*
					$n::Other(code) => code,
					$n::Utf8Error(_) => ERR_UTF8_INVALID,
				}
			}
		}
	};
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Error {
        Error::Utf8Error(Some(e))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Utf8Error(Some(ref e)) => {
                f.write_fmt(format_args!("Error converting to UTF-8: {}", e))
            }
            &Error::Utf8Error(None) => f.write_fmt(format_args!("Error converting to UTF-8")),
            &Error::Other(i) => f.write_fmt(format_args!("mbedTLS unknown error ({})", i)),
            e @ _ => f.write_fmt(format_args!("mbedTLS error {:?}", e)),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for Error {
    fn description(&self) -> &str {
        self.as_str()
    }
}

error_enum!(Error {
	MpiFileIoError                => MBEDTLS_ERR_MPI_FILE_IO_ERROR,
	MpiBadInputData               => MBEDTLS_ERR_MPI_BAD_INPUT_DATA,
	MpiInvalidCharacter           => MBEDTLS_ERR_MPI_INVALID_CHARACTER,
	MpiBufferTooSmall             => MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL,
	MpiNegativeValue              => MBEDTLS_ERR_MPI_NEGATIVE_VALUE,
	MpiDivisionByZero             => MBEDTLS_ERR_MPI_DIVISION_BY_ZERO,
	MpiNotAcceptable              => MBEDTLS_ERR_MPI_NOT_ACCEPTABLE,
	MpiAllocFailed                => MBEDTLS_ERR_MPI_ALLOC_FAILED,
	MdFeatureUnavailable          => MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE,
	MdBadInputData                => MBEDTLS_ERR_MD_BAD_INPUT_DATA,
	MdAllocFailed                 => MBEDTLS_ERR_MD_ALLOC_FAILED,
	MdFileIoError                 => MBEDTLS_ERR_MD_FILE_IO_ERROR,
	EcpBadInputData               => MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
	EcpBufferTooSmall             => MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL,
	EcpFeatureUnavailable         => MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE,
	EcpVerifyFailed               => MBEDTLS_ERR_ECP_VERIFY_FAILED,
	EcpAllocFailed                => MBEDTLS_ERR_ECP_ALLOC_FAILED,
	EcpRandomFailed               => MBEDTLS_ERR_ECP_RANDOM_FAILED,
	EcpInvalidKey                 => MBEDTLS_ERR_ECP_INVALID_KEY,
	EcpSigLenMismatch             => MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH,
	RsaBadInputData               => MBEDTLS_ERR_RSA_BAD_INPUT_DATA,
	RsaInvalidPadding             => MBEDTLS_ERR_RSA_INVALID_PADDING,
	RsaKeyGenFailed               => MBEDTLS_ERR_RSA_KEY_GEN_FAILED,
	RsaKeyCheckFailed             => MBEDTLS_ERR_RSA_KEY_CHECK_FAILED,
	RsaPublicFailed               => MBEDTLS_ERR_RSA_PUBLIC_FAILED,
	RsaPrivateFailed              => MBEDTLS_ERR_RSA_PRIVATE_FAILED,
	RsaVerifyFailed               => MBEDTLS_ERR_RSA_VERIFY_FAILED,
	RsaOutputTooLarge             => MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE,
	RsaRngFailed                  => MBEDTLS_ERR_RSA_RNG_FAILED,
	Asn1OutOfData                 => MBEDTLS_ERR_ASN1_OUT_OF_DATA,
	Asn1UnexpectedTag             => MBEDTLS_ERR_ASN1_UNEXPECTED_TAG,
	Asn1InvalidLength             => MBEDTLS_ERR_ASN1_INVALID_LENGTH,
	Asn1LengthMismatch            => MBEDTLS_ERR_ASN1_LENGTH_MISMATCH,
	Asn1InvalidData               => MBEDTLS_ERR_ASN1_INVALID_DATA,
	Asn1AllocFailed               => MBEDTLS_ERR_ASN1_ALLOC_FAILED,
	Asn1BufTooSmall               => MBEDTLS_ERR_ASN1_BUF_TOO_SMALL,
	PkAllocFailed                 => MBEDTLS_ERR_PK_ALLOC_FAILED,
	PkTypeMismatch                => MBEDTLS_ERR_PK_TYPE_MISMATCH,
	PkBadInputData                => MBEDTLS_ERR_PK_BAD_INPUT_DATA,
	PkFileIoError                 => MBEDTLS_ERR_PK_FILE_IO_ERROR,
	PkKeyInvalidVersion           => MBEDTLS_ERR_PK_KEY_INVALID_VERSION,
	PkKeyInvalidFormat            => MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
	PkUnknownPkAlg                => MBEDTLS_ERR_PK_UNKNOWN_PK_ALG,
	PkPasswordRequired            => MBEDTLS_ERR_PK_PASSWORD_REQUIRED,
	PkPasswordMismatch            => MBEDTLS_ERR_PK_PASSWORD_MISMATCH,
	PkInvalidPubkey               => MBEDTLS_ERR_PK_INVALID_PUBKEY,
	PkInvalidAlg                  => MBEDTLS_ERR_PK_INVALID_ALG,
	PkUnknownNamedCurve           => MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE,
	PkFeatureUnavailable          => MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE,
	PkSigLenMismatch              => MBEDTLS_ERR_PK_SIG_LEN_MISMATCH,
	X509FeatureUnavailable        => MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE,
	X509UnknownOid                => MBEDTLS_ERR_X509_UNKNOWN_OID,
	X509InvalidFormat             => MBEDTLS_ERR_X509_INVALID_FORMAT,
	X509InvalidVersion            => MBEDTLS_ERR_X509_INVALID_VERSION,
	X509InvalidSerial             => MBEDTLS_ERR_X509_INVALID_SERIAL,
	X509InvalidAlg                => MBEDTLS_ERR_X509_INVALID_ALG,
	X509InvalidName               => MBEDTLS_ERR_X509_INVALID_NAME,
	X509InvalidDate               => MBEDTLS_ERR_X509_INVALID_DATE,
	X509InvalidSignature          => MBEDTLS_ERR_X509_INVALID_SIGNATURE,
	X509InvalidExtensions         => MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
	X509UnknownVersion            => MBEDTLS_ERR_X509_UNKNOWN_VERSION,
	X509UnknownSigAlg             => MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG,
	X509SigMismatch               => MBEDTLS_ERR_X509_SIG_MISMATCH,
	X509CertVerifyFailed          => MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,
	X509CertUnknownFormat         => MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT,
	X509BadInputData              => MBEDTLS_ERR_X509_BAD_INPUT_DATA,
	X509AllocFailed               => MBEDTLS_ERR_X509_ALLOC_FAILED,
	X509FileIoError               => MBEDTLS_ERR_X509_FILE_IO_ERROR,
	X509BufferTooSmall            => MBEDTLS_ERR_X509_BUFFER_TOO_SMALL,
	CipherFeatureUnavailable      => MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE,
	CipherBadInputData            => MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA,
	CipherAllocFailed             => MBEDTLS_ERR_CIPHER_ALLOC_FAILED,
	CipherInvalidPadding          => MBEDTLS_ERR_CIPHER_INVALID_PADDING,
	CipherFullBlockExpected       => MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED,
	CipherAuthFailed              => MBEDTLS_ERR_CIPHER_AUTH_FAILED,
	CipherInvalidContext          => MBEDTLS_ERR_CIPHER_INVALID_CONTEXT,
	DhmBadInputData               => MBEDTLS_ERR_DHM_BAD_INPUT_DATA,
	DhmReadParamsFailed           => MBEDTLS_ERR_DHM_READ_PARAMS_FAILED,
	DhmMakeParamsFailed           => MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED,
	DhmReadPublicFailed           => MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED,
	DhmMakePublicFailed           => MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED,
	DhmCalcSecretFailed           => MBEDTLS_ERR_DHM_CALC_SECRET_FAILED,
	DhmInvalidFormat              => MBEDTLS_ERR_DHM_INVALID_FORMAT,
	DhmAllocFailed                => MBEDTLS_ERR_DHM_ALLOC_FAILED,
	DhmFileIoError                => MBEDTLS_ERR_DHM_FILE_IO_ERROR,
	SslFeatureUnavailable         => MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE,
	SslBadInputData               => MBEDTLS_ERR_SSL_BAD_INPUT_DATA,
	SslInvalidMac                 => MBEDTLS_ERR_SSL_INVALID_MAC,
	SslInvalidRecord              => MBEDTLS_ERR_SSL_INVALID_RECORD,
	SslConnEof                    => MBEDTLS_ERR_SSL_CONN_EOF,
	SslNoCipherChosen             => MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN,
	SslNoRng                      => MBEDTLS_ERR_SSL_NO_RNG,
	SslNoClientCertificate        => MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE,
	SslCertificateTooLarge        => MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE,
	SslCertificateRequired        => MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED,
	SslPrivateKeyRequired         => MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED,
	SslCaChainRequired            => MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED,
	SslUnexpectedMessage          => MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE,
	SslFatalAlertMessage          => MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE,
	SslPeerVerifyFailed           => MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED,
	SslPeerCloseNotify            => MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY,
	SslBadHsClientHello           => MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO,
	SslBadHsServerHello           => MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO,
	SslBadHsCertificate           => MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE,
	SslBadHsCertificateRequest    => MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST,
	SslBadHsServerKeyExchange     => MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE,
	SslBadHsServerHelloDone       => MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE,
	SslBadHsClientKeyExchange     => MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE,
	SslBadHsClientKeyExchangeRp   => MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP,
	SslBadHsClientKeyExchangeCs   => MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS,
	SslBadHsCertificateVerify     => MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY,
	SslBadHsChangeCipherSpec      => MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC,
	SslBadHsFinished              => MBEDTLS_ERR_SSL_BAD_HS_FINISHED,
	SslAllocFailed                => MBEDTLS_ERR_SSL_ALLOC_FAILED,
	SslHwAccelFailed              => MBEDTLS_ERR_SSL_HW_ACCEL_FAILED,
	SslHwAccelFallthrough         => MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH,
	SslCompressionFailed          => MBEDTLS_ERR_SSL_COMPRESSION_FAILED,
	SslBadHsProtocolVersion       => MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION,
	SslBadHsNewSessionTicket      => MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET,
	SslSessionTicketExpired       => MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED,
	SslPkTypeMismatch             => MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH,
	SslUnknownIdentity            => MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY,
	SslInternalError              => MBEDTLS_ERR_SSL_INTERNAL_ERROR,
	SslCounterWrapping            => MBEDTLS_ERR_SSL_COUNTER_WRAPPING,
	SslWaitingServerHelloRenego   => MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO,
	SslHelloVerifyRequired        => MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED,
	SslBufferTooSmall             => MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL,
	SslNoUsableCiphersuite        => MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE,
	SslWantRead                   => MBEDTLS_ERR_SSL_WANT_READ,
	SslTimeout                    => MBEDTLS_ERR_SSL_TIMEOUT,
	SslClientReconnect            => MBEDTLS_ERR_SSL_CLIENT_RECONNECT,
	SslUnexpectedRecord           => MBEDTLS_ERR_SSL_UNEXPECTED_RECORD,
	AesInvalidKeyLength           => MBEDTLS_ERR_AES_INVALID_KEY_LENGTH,
	AesInvalidInputLength         => MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH,
	XteaInvalidInputLength        => MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH,
	Pkcs5BadInputData             => MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA,
	Pkcs5InvalidFormat            => MBEDTLS_ERR_PKCS5_INVALID_FORMAT,
	Pkcs5FeatureUnavailable       => MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE,
	Pkcs5PasswordMismatch         => MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH,
	Pkcs12BadInputData            => MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA,
	Pkcs12FeatureUnavailable      => MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE,
	Pkcs12PbeInvalidFormat        => MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT,
	Pkcs12PasswordMismatch        => MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH,
	PadlockDataMisaligned         => MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED,
	OidNotFound                   => MBEDTLS_ERR_OID_NOT_FOUND,
	OidBufTooSmall                => MBEDTLS_ERR_OID_BUF_TOO_SMALL,
	NetSocketFailed               => MBEDTLS_ERR_NET_SOCKET_FAILED,
	NetConnectFailed              => MBEDTLS_ERR_NET_CONNECT_FAILED,
	NetBindFailed                 => MBEDTLS_ERR_NET_BIND_FAILED,
	NetListenFailed               => MBEDTLS_ERR_NET_LISTEN_FAILED,
	NetAcceptFailed               => MBEDTLS_ERR_NET_ACCEPT_FAILED,
	NetRecvFailed                 => MBEDTLS_ERR_NET_RECV_FAILED,
	NetSendFailed                 => MBEDTLS_ERR_NET_SEND_FAILED,
	NetConnReset                  => MBEDTLS_ERR_NET_CONN_RESET,
	NetUnknownHost                => MBEDTLS_ERR_NET_UNKNOWN_HOST,
	NetBufferTooSmall             => MBEDTLS_ERR_NET_BUFFER_TOO_SMALL,
	NetInvalidContext             => MBEDTLS_ERR_NET_INVALID_CONTEXT,
	HmacDrbgRequestTooBig         => MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG,
	HmacDrbgInputTooBig           => MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG,
	HmacDrbgFileIoError           => MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR,
	HmacDrbgEntropySourceFailed   => MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED,
	GcmAuthFailed                 => MBEDTLS_ERR_GCM_AUTH_FAILED,
	GcmBadInput                   => MBEDTLS_ERR_GCM_BAD_INPUT,
	EntropySourceFailed           => MBEDTLS_ERR_ENTROPY_SOURCE_FAILED,
	EntropyMaxSources             => MBEDTLS_ERR_ENTROPY_MAX_SOURCES,
	EntropyNoSourcesDefined       => MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED,
	EntropyNoStrongSource         => MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE,
	EntropyFileIoError            => MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR,
	DesInvalidInputLength         => MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH,
	CtrDrbgEntropySourceFailed    => MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED,
	CtrDrbgRequestTooBig          => MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG,
	CtrDrbgInputTooBig            => MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG,
	CtrDrbgFileIoError            => MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR,
	CcmBadInput                   => MBEDTLS_ERR_CCM_BAD_INPUT,
	CcmAuthFailed                 => MBEDTLS_ERR_CCM_AUTH_FAILED,
	CamelliaInvalidKeyLength      => MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH,
	CamelliaInvalidInputLength    => MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH,
	BlowfishInvalidKeyLength      => MBEDTLS_ERR_BLOWFISH_INVALID_KEY_LENGTH,
	BlowfishInvalidInputLength    => MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH,
	Base64BufferTooSmall          => MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL,
	Base64InvalidCharacter        => MBEDTLS_ERR_BASE64_INVALID_CHARACTER,
	PemNoHeaderFooterPresent      => MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT,
	PemInvalidData                => MBEDTLS_ERR_PEM_INVALID_DATA,
	PemAllocFailed                => MBEDTLS_ERR_PEM_ALLOC_FAILED,
	PemInvalidEncIv               => MBEDTLS_ERR_PEM_INVALID_ENC_IV,
	PemUnknownEncAlg              => MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG,
	PemPasswordRequired           => MBEDTLS_ERR_PEM_PASSWORD_REQUIRED,
	PemPasswordMismatch           => MBEDTLS_ERR_PEM_PASSWORD_MISMATCH,
	PemFeatureUnavailable         => MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE,
	PemBadInputData               => MBEDTLS_ERR_PEM_BAD_INPUT_DATA,
});
