/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2018-2020 Intel Labs */

#include <mbedtls/x509_crt.h>
#include <stdint.h>
#include <sys/ioctl.h>


#define RA_TLS_MRSIGNER    "RA_TLS_MRSIGNER"
#define RA_TLS_MRENCLAVE   "RA_TLS_MRENCLAVE"
#define RA_TLS_ISV_PROD_ID "RA_TLS_ISV_PROD_ID"
#define RA_TLS_ISV_SVN     "RA_TLS_ISV_SVN"

#define RA_TLS_IAS_PUB_KEY_PEM "RA_TLS_IAS_PUB_KEY_PEM"
#define RA_TLS_IAS_REPORT_URL  "RA_TLS_IAS_REPORT_URL"
#define RA_TLS_IAS_SIGRL_URL   "RA_TLS_IAS_SIGRL_URL"

#define RA_TLS_CERT_TIMESTAMP_NOT_BEFORE "RA_TLS_CERT_TIMESTAMP_NOT_BEFORE"
#define RA_TLS_CERT_TIMESTAMP_NOT_AFTER  "RA_TLS_CERT_TIMESTAMP_NOT_AFTER"

#define SHA256_DIGEST_SIZE       32
#define RSA_PUB_3072_KEY_LEN     3072
#define RSA_PUB_3072_KEY_DER_LEN 422
#define RSA_PUB_EXPONENT         65537
#define PUB_KEY_SIZE_MAX         512
#define IAS_REQUEST_NONCE_LEN    32

#define OID(N) \
    { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N) }
static const uint8_t quote_oid[] = OID(0x06);
static const size_t quote_oid_len = sizeof(quote_oid);
#define QUOTE_MAX_SIZE 8192

int ra_tls_create_key_and_crt(mbedtls_pk_context* key, mbedtls_x509_crt* crt);

/*!
 * \brief Generic function to generate a key and a corresponding RA-TLS certificate (DER format).
 *
 * The function behaves the same as ra_tls_create_key_and_crt() but generates key and certificate
 * in the DER format. The function allocates memory for key and certificate; user is expected to
 * free them after use.
 *
 * \param[out] der_key       Pointer to buffer populated with generated RSA keypair in DER format.
 * \param[out] der_key_size  Pointer to size of generated RSA keypair.
 * \param[out] der_crt       Pointer to buffer populated with self-signed RA-TLS certificate.
 * \param[out] der_crt_size  Pointer to size of self-signed RA-TLS certificate.
 *
 * \return                   0 on success, specific mbedTLS error code (negative int) otherwise.
 */
__attribute__ ((visibility("default")))
int ra_tls_create_key_and_crt_der(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                  size_t* der_crt_size);
