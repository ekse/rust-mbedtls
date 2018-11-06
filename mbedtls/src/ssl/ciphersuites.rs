/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::c_int;

define!(enum CipherSuite -> c_int {
	RsaWithNullMd5 => MBEDTLS_TLS_RSA_WITH_NULL_MD5,
	RsaWithNullSha => MBEDTLS_TLS_RSA_WITH_NULL_SHA,
	RsaWithRc4128Md5 => MBEDTLS_TLS_RSA_WITH_RC4_128_MD5,
	RsaWithRc4128Sha => MBEDTLS_TLS_RSA_WITH_RC4_128_SHA,
	RsaWithDesCbcSha => MBEDTLS_TLS_RSA_WITH_DES_CBC_SHA,
	RsaWith3desEdeCbcSha => MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	DheRsaWithDesCbcSha => MBEDTLS_TLS_DHE_RSA_WITH_DES_CBC_SHA,
	DheRsaWith3desEdeCbcSha => MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	PskWithNullSha => MBEDTLS_TLS_PSK_WITH_NULL_SHA,
	DhePskWithNullSha => MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA,
	RsaPskWithNullSha => MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA,
	RsaWithAes128CbcSha => MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
	DheRsaWithAes128CbcSha => MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	RsaWithAes256CbcSha => MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
	DheRsaWithAes256CbcSha => MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	RsaWithNullSha256 => MBEDTLS_TLS_RSA_WITH_NULL_SHA256,
	RsaWithAes128CbcSha256 => MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
	RsaWithAes256CbcSha256 => MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
	RsaWithCamellia128CbcSha => MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
	DheRsaWithCamellia128CbcSha => MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
	DheRsaWithAes128CbcSha256 => MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	DheRsaWithAes256CbcSha256 => MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	RsaWithCamellia256CbcSha => MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
	DheRsaWithCamellia256CbcSha => MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
	PskWithRc4128Sha => MBEDTLS_TLS_PSK_WITH_RC4_128_SHA,
	PskWith3desEdeCbcSha => MBEDTLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA,
	PskWithAes128CbcSha => MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA,
	PskWithAes256CbcSha => MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA,
	DhePskWithRc4128Sha => MBEDTLS_TLS_DHE_PSK_WITH_RC4_128_SHA,
	DhePskWith3desEdeCbcSha => MBEDTLS_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
	DhePskWithAes128CbcSha => MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
	DhePskWithAes256CbcSha => MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
	RsaPskWithRc4128Sha => MBEDTLS_TLS_RSA_PSK_WITH_RC4_128_SHA,
	RsaPskWith3desEdeCbcSha => MBEDTLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
	RsaPskWithAes128CbcSha => MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
	RsaPskWithAes256CbcSha => MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
	RsaWithAes128GcmSha256 => MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
	RsaWithAes256GcmSha384 => MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
	DheRsaWithAes128GcmSha256 => MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	DheRsaWithAes256GcmSha384 => MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	PskWithAes128GcmSha256 => MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
	PskWithAes256GcmSha384 => MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,
	DhePskWithAes128GcmSha256 => MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
	DhePskWithAes256GcmSha384 => MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
	RsaPskWithAes128GcmSha256 => MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
	RsaPskWithAes256GcmSha384 => MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
	PskWithAes128CbcSha256 => MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
	PskWithAes256CbcSha384 => MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,
	PskWithNullSha256 => MBEDTLS_TLS_PSK_WITH_NULL_SHA256,
	PskWithNullSha384 => MBEDTLS_TLS_PSK_WITH_NULL_SHA384,
	DhePskWithAes128CbcSha256 => MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
	DhePskWithAes256CbcSha384 => MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
	DhePskWithNullSha256 => MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA256,
	DhePskWithNullSha384 => MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA384,
	RsaPskWithAes128CbcSha256 => MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
	RsaPskWithAes256CbcSha384 => MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
	RsaPskWithNullSha256 => MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA256,
	RsaPskWithNullSha384 => MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA384,
	RsaWithCamellia128CbcSha256 => MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
	DheRsaWithCamellia128CbcSha256 => MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
	RsaWithCamellia256CbcSha256 => MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
	DheRsaWithCamellia256CbcSha256 => MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
	EcdhEcdsaWithNullSha => MBEDTLS_TLS_ECDH_ECDSA_WITH_NULL_SHA,
	EcdhEcdsaWithRc4128Sha => MBEDTLS_TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
	EcdhEcdsaWith3desEdeCbcSha => MBEDTLS_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
	EcdhEcdsaWithAes128CbcSha => MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
	EcdhEcdsaWithAes256CbcSha => MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
	EcdheEcdsaWithNullSha => MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA,
	EcdheEcdsaWithRc4128Sha => MBEDTLS_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	EcdheEcdsaWith3desEdeCbcSha => MBEDTLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	EcdheEcdsaWithAes128CbcSha => MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	EcdheEcdsaWithAes256CbcSha => MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	EcdhRsaWithNullSha => MBEDTLS_TLS_ECDH_RSA_WITH_NULL_SHA,
	EcdhRsaWithRc4128Sha => MBEDTLS_TLS_ECDH_RSA_WITH_RC4_128_SHA,
	EcdhRsaWith3desEdeCbcSha => MBEDTLS_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
	EcdhRsaWithAes128CbcSha => MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
	EcdhRsaWithAes256CbcSha => MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
	EcdheRsaWithNullSha => MBEDTLS_TLS_ECDHE_RSA_WITH_NULL_SHA,
	EcdheRsaWithRc4128Sha => MBEDTLS_TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	EcdheRsaWith3desEdeCbcSha => MBEDTLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	EcdheRsaWithAes128CbcSha => MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	EcdheRsaWithAes256CbcSha => MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	EcdheEcdsaWithAes128CbcSha256 => MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	EcdheEcdsaWithAes256CbcSha384 => MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	EcdhEcdsaWithAes128CbcSha256 => MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
	EcdhEcdsaWithAes256CbcSha384 => MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
	EcdheRsaWithAes128CbcSha256 => MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	EcdheRsaWithAes256CbcSha384 => MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	EcdhRsaWithAes128CbcSha256 => MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
	EcdhRsaWithAes256CbcSha384 => MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
	EcdheEcdsaWithAes128GcmSha256 => MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	EcdheEcdsaWithAes256GcmSha384 => MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	EcdhEcdsaWithAes128GcmSha256 => MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
	EcdhEcdsaWithAes256GcmSha384 => MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
	EcdheRsaWithAes128GcmSha256 => MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	EcdheRsaWithAes256GcmSha384 => MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	EcdhRsaWithAes128GcmSha256 => MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
	EcdhRsaWithAes256GcmSha384 => MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
	EcdhePskWithRc4128Sha => MBEDTLS_TLS_ECDHE_PSK_WITH_RC4_128_SHA,
	EcdhePskWith3desEdeCbcSha => MBEDTLS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
	EcdhePskWithAes128CbcSha => MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
	EcdhePskWithAes256CbcSha => MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
	EcdhePskWithAes128CbcSha256 => MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	EcdhePskWithAes256CbcSha384 => MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
	EcdhePskWithNullSha => MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA,
	EcdhePskWithNullSha256 => MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA256,
	EcdhePskWithNullSha384 => MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA384,
	EcdheEcdsaWithCamellia128CbcSha256 => MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
	EcdheEcdsaWithCamellia256CbcSha384 => MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
	EcdhEcdsaWithCamellia128CbcSha256 => MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
	EcdhEcdsaWithCamellia256CbcSha384 => MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
	EcdheRsaWithCamellia128CbcSha256 => MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
	EcdheRsaWithCamellia256CbcSha384 => MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
	EcdhRsaWithCamellia128CbcSha256 => MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
	EcdhRsaWithCamellia256CbcSha384 => MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
	RsaWithCamellia128GcmSha256 => MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	RsaWithCamellia256GcmSha384 => MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	DheRsaWithCamellia128GcmSha256 => MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	DheRsaWithCamellia256GcmSha384 => MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	EcdheEcdsaWithCamellia128GcmSha256 => MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
	EcdheEcdsaWithCamellia256GcmSha384 => MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
	EcdhEcdsaWithCamellia128GcmSha256 => MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
	EcdhEcdsaWithCamellia256GcmSha384 => MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
	EcdheRsaWithCamellia128GcmSha256 => MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	EcdheRsaWithCamellia256GcmSha384 => MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	EcdhRsaWithCamellia128GcmSha256 => MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
	EcdhRsaWithCamellia256GcmSha384 => MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
	PskWithCamellia128GcmSha256 => MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
	PskWithCamellia256GcmSha384 => MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
	DhePskWithCamellia128GcmSha256 => MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
	DhePskWithCamellia256GcmSha384 => MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
	RsaPskWithCamellia128GcmSha256 => MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
	RsaPskWithCamellia256GcmSha384 => MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
	PskWithCamellia128CbcSha256 => MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
	PskWithCamellia256CbcSha384 => MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
	DhePskWithCamellia128CbcSha256 => MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
	DhePskWithCamellia256CbcSha384 => MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
	RsaPskWithCamellia128CbcSha256 => MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
	RsaPskWithCamellia256CbcSha384 => MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
	EcdhePskWithCamellia128CbcSha256 => MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
	EcdhePskWithCamellia256CbcSha384 => MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
	RsaWithAes128Ccm => MBEDTLS_TLS_RSA_WITH_AES_128_CCM,
	RsaWithAes256Ccm => MBEDTLS_TLS_RSA_WITH_AES_256_CCM,
	DheRsaWithAes128Ccm => MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
	DheRsaWithAes256Ccm => MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
	RsaWithAes128Ccm8 => MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8,
	RsaWithAes256Ccm8 => MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8,
	DheRsaWithAes128Ccm8 => MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8,
	DheRsaWithAes256Ccm8 => MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8,
	PskWithAes128Ccm => MBEDTLS_TLS_PSK_WITH_AES_128_CCM,
	PskWithAes256Ccm => MBEDTLS_TLS_PSK_WITH_AES_256_CCM,
	DhePskWithAes128Ccm => MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM,
	DhePskWithAes256Ccm => MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM,
	PskWithAes128Ccm8 => MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,
	PskWithAes256Ccm8 => MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,
	DhePskWithAes128Ccm8 => MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8,
	DhePskWithAes256Ccm8 => MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8,
	EcdheEcdsaWithAes128Ccm => MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
	EcdheEcdsaWithAes256Ccm => MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
	EcdheEcdsaWithAes128Ccm8 => MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
	EcdheEcdsaWithAes256Ccm8 => MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
	EcjpakeWithAes128Ccm8 => MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8,
});
