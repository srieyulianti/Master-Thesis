#ifndef _RA_ATTESTER_H_
#define _RA_ATTESTER_H_

#include <sgx_quote.h>

struct ecdsa_ra_tls_options {
	char subscription_key[32];
};

void ecdsa_create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len
);

#endif
