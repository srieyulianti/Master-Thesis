/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2018-2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of verification callbacks for TLS libraries. The callbacks
 * verify the correctness of a self-signed RA-TLS certificate with an SGX quote embedded in it. The
 * callbacks call into the `libsgx_dcap_quoteverify` DCAP library for ECDSA-based verification. A
 * callback ra_tls_verify_callback() can be used directly in mbedTLS, and a more generic version
 * ra_tls_verify_callback_der() should be used for other TLS libraries.
 *
 * This file is part of the RA-TLS verification library which is typically linked into client
 * applications. This library is *not* thread-safe.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sgx_report.h>
#include <sys/ioctl.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#include "quote_verification.h"
#include "attestation.h"
#include "ra_tls.h"
#include "util.h"


/* RA_TLS verify callback main function running on Occlum enclave */
int ra_tls_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    (void)data;

    int ret;
    int sgx_fd;
    FILE *fptr =NULL;

    /* Allocate supplemental size and buffer */
    if ((sgx_fd = open("/dev/sgx", O_RDONLY)) < 0){
	    printf("[-] failed to open /dev/sgx\n");
	    return -1;
    }
    uint32_t supplemental_size = get_supplemental_data_size(sgx_fd);
    uint8_t *supplemental_buffer = (uint8_t *)malloc(supplemental_size);
    if (NULL == supplemental_buffer){
	    printf("Couldn't allocate quote buffer\n");
	    close(sgx_fd);
	    return -1;
    }
    memset(supplemental_buffer, 0, supplemental_size);

    if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }

    /* extract SGX quote from "quote" OID extension from crt */
    sgx_quote_t* quote;
    size_t quote_size;
    sgx_report_body_t *body = NULL;

    ret = find_oid(crt->v3_ext.p, crt->v3_ext.len, quote_oid, quote_oid_len, (uint8_t**)&quote,
                   &quote_size);

    if (ret < 0)
        goto out;

    if (quote_size < sizeof(*quote)) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    uint8_t *quote_buffer = quote;

    fptr = fopen("host/quote.dat","wb");
    fwrite(quote_buffer, quote_size, 1, fptr);
    fclose(fptr);

    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    sgxioc_ver_dcap_quote_arg_t ver_quote_arg = {
	    .quote_buf = quote_buffer,
	    .quote_size = quote_size,
	    .collateral_expiration_status = &collateral_expiration_status,
	    .quote_verification_result = &quote_verification_result,
	    .supplemental_data_size = supplemental_size,
	    .supplemental_data = supplemental_buffer
    };

    if (verify_dcap_quote(sgx_fd, &ver_quote_arg) != 0){
	    printf("[-] failed to verify quote\n");
	    close(sgx_fd);
	    return -1;
    }
    close(sgx_fd);

    if (collateral_expiration_status != 0){
	    printf("[-] the verification collateral has expired\n");
    }
    body = &quote->report_body;

    switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
	    printf("Succeed to verify the quote!\n");
	    printf("#################################################################\n");
            printf("[+] Server's SGX identity:\n");
            printf("[+] MRENCLAVE:\n");
                for (int i = 0; i < SGX_HASH_SIZE; ++i)
                            printf("%02x", body->mr_enclave.m[i]);
                printf("\n");
                printf("[+] MRSIGNER:\n");
                for (int i = 0; i < SGX_HASH_SIZE; ++i)
                            printf("%02x", body->mr_signer.m[i]);
                printf("\n");
            printf("#################################################################\n");
	    return 0;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
	    printf("WARN: App: Verification completed with Non-terminal result: %x\n", quote_verification_result);
	    printf("#################################################################\n");
	    printf("[+] Server's SGX identity:\n");
	    printf("[+] MRENCLAVE:\n");
	    	for (int i = 0; i < SGX_HASH_SIZE; ++i)
			    printf("%02x", body->mr_enclave.m[i]);
		printf("\n");
		printf("[+] MRSIGNER:\n");
		for (int i = 0; i < SGX_HASH_SIZE; ++i)
                	    printf("%02x", body->mr_signer.m[i]);
        	printf("\n");
	    printf("#################################################################\n");
	    return 0;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
	    //printf("\tError: App: Verification completed with Terminal result: %x\n", quote_verification_result);
	    ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
	    break;
    }
    ret = 0;
out:
    free(supplemental_buffer);
    return ret;
}

int sgx_qv_get_quote_supplemental_data_size(uint32_t* p_data_size);
int sgx_qv_verify_quote(const uint8_t* p_quote, uint32_t quote_size, void* p_quote_collateral,
                        const time_t expiration_check_date,
                        uint32_t* p_collateral_expiration_status,
                        sgx_ql_qv_result_t* p_quote_verification_result, void* p_qve_report_info,
                        uint32_t supplemental_data_size, uint8_t* p_supplemental_data);

int ra_tls_verify_callback_non_enclave(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
	(void)data;
	int ret;

	uint8_t* supplemental_data      = NULL;
	uint32_t supplemental_data_size = 0;

	if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
	}
	
	if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
	}

	/* extract SGX quote from "quote" OID extension from crt */
	sgx_quote_t* quote;
	size_t quote_size;
	sgx_report_body_t *body = NULL;
	ret = find_oid(crt->v3_ext.p, crt->v3_ext.len, quote_oid, quote_oid_len, (uint8_t**)&quote,
                   &quote_size);
	
	if (ret < 0)
		goto out;
	
	if (quote_size < sizeof(*quote)) {
		ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
		goto out;
	}

	/* call into libsgx_dcap_quoteverify to verify ECDSA/based SGX quote */
	ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
	if (ret) {
		ret = MBEDTLS_ERR_X509_FATAL_ERROR;
		goto out;
	}
	supplemental_data = (uint8_t*)malloc(supplemental_data_size);
	if (!supplemental_data) {
		ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
		goto out;
	}
	
	time_t current_time = time(NULL);
	if (current_time == ((time_t)-1)) {
		ret = MBEDTLS_ERR_X509_FATAL_ERROR;
		goto out;
	}
	
	uint32_t collateral_expiration_status  = 1;
	sgx_ql_qv_result_t verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	
	ret = sgx_qv_verify_quote((uint8_t*)quote, (uint32_t)quote_size, /*p_quote_collateral=*/NULL,
                              current_time, &collateral_expiration_status, &verification_result,
                              /*p_qve_report_info=*/NULL, supplemental_data_size,
                              supplemental_data);
	if (ret) {
		ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
		goto out;
	}
	body = &quote->report_body;

    	switch (verification_result) {
        	case SGX_QL_QV_RESULT_OK:
            		printf("Succeed to verify the quote!\n");
            		printf("#################################################################\n");
            		printf("[+] Server's SGX identity:\n");
            		printf("[+] MRENCLAVE:\n");
                	for (int i = 0; i < SGX_HASH_SIZE; ++i)
                            	printf("%02x", body->mr_enclave.m[i]);
                	printf("\n");
                	printf("[+] MRSIGNER:\n");
                	for (int i = 0; i < SGX_HASH_SIZE; ++i)
                            	printf("%02x", body->mr_signer.m[i]);
                	printf("\n");
            		printf("#################################################################\n");
            		return 0;
        	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        	case SGX_QL_QV_RESULT_OUT_OF_DATE:
        	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            		printf("WARN: App: Verification completed with Non-terminal result: %x\n", verification_result);
            		printf("#################################################################\n");
            		printf("[+] Server's SGX identity:\n");
            		printf("[+] MRENCLAVE:\n");
                	for (int i = 0; i < SGX_HASH_SIZE; ++i)
                            	printf("%02x", body->mr_enclave.m[i]);
                	printf("\n");
                	printf("[+] MRSIGNER:\n");
                	for (int i = 0; i < SGX_HASH_SIZE; ++i)
                            	printf("%02x", body->mr_signer.m[i]);
                	printf("\n");
            		printf("#################################################################\n");
            		return 0;
		case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        	case SGX_QL_QV_RESULT_REVOKED:
        	case SGX_QL_QV_RESULT_UNSPECIFIED:
        	default:
            		//printf("\tError: App: Verification completed with Terminal result: %x\n", quote_verification_result);
            		ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            		break;
    	}
	ret = 0;
out:
    free(supplemental_data);
    return ret;
}





