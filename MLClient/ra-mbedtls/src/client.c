/*
 *  SSL client demonstration program (with RA-TLS).
 *  This program is heavily based on an mbedTLS 2.26.0 example ssl_client1.c
 *  but uses RA-TLS flows (SGX Remote Attestation flows) if RA-TLS library
 *  is required by user.
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *                2020, Intel Labs
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/* mbedtls config include */
#include "mbedtls/config.h"

/* usual libraries include */
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* mbedtls print functions definition */
#define mbedtls_fprintf fprintf
#define mbedtls_printf printf

/* mbedtls exit definition */
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE

/* mbedtls libraries include */
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

/* RA-TLS: on client, only need to register ra_tls_verify_callback() for cert verification */
int (*ra_tls_verify_callback_f)(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags);

/* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                          const char* isv_prod_id, const char* isv_svn));

/* Server environment definition */
#define SERVER_PORT "8081"
#define SERVER_NAME "server"

#define SIZE 1024
#define DEBUG_LEVEL 0

/* Debug function */
static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

/* parse_hex function */
static int parse_hex(const char* hex, void* buffer, size_t buffer_size) {
    if (strlen(hex) != buffer_size * 2)
        return -1;

    for (size_t i = 0; i < buffer_size; i++) {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1]))
            return -1;
        sscanf(hex + i * 2, "%02hhx", &((uint8_t*)buffer)[i]);
    }
    return 0;
}


/* expected SGX measurements in binary form */
static char g_expected_mrenclave[32];
static char g_expected_mrsigner[32];
static char g_expected_isv_prod_id[2];
static char g_expected_isv_svn[2];

static bool g_verify_mrenclave   = false;
static bool g_verify_mrsigner    = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn     = false;

/************************************* MAIN FUNCTION ****************************************/

int main(int argc, char** argv) {
    int ret;
    size_t len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char* pers = "ssl_client1";

    char* error;
    void* ra_tls_verify_lib           = NULL;
    ra_tls_verify_callback_f          = NULL;
    ra_tls_set_measurement_callback_f = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_entropy_init(&entropy);

    if (argc < 2 || (strcmp(argv[1], "enclave") && strcmp(argv[1], "non-enclave"))) {
	    mbedtls_printf("USAGE: %s enclave|non-enclave [SGX measurements]\n", argv[0]);
	    return 1;
    }

    /* Open libsgx_urts.so and libra_tls_verify_dcap.so for ra-tls dcap */
    if(!strcmp(argv[1], "enclave")){
    	void* helper_sgx_urts_lib = dlopen("../lib/libsgx_urts.so", RTLD_NOW | RTLD_GLOBAL);
    	if (!helper_sgx_urts_lib) {
	    	mbedtls_printf("%s\n", dlerror());
	    	mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find helper"
			    " libsgx_urts.so lib\n");
	    	return 1;
    	}
    	ra_tls_verify_lib = dlopen("../lib/libra_tls_verify_dcap.so", RTLD_LAZY);
    	if (!ra_tls_verify_lib) {
		    mbedtls_printf("%s\n", dlerror());
	    	mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
	    	return 1;
    	}

    	/* Define functions taken from the library opened */
    	ra_tls_verify_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_verify_callback");
    	if ((error = dlerror()) != NULL) {
	    	mbedtls_printf("%s\n", error);
	    	return 1;
    	}
    	ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
    	if ((error = dlerror()) != NULL) {
	    	mbedtls_printf("%s\n", error);
	    	return 1;
    	}
    }else{
	void* helper_sgx_urts_lib = dlopen("../lib/libsgx_urts.so", RTLD_NOW | RTLD_GLOBAL);
        if (!helper_sgx_urts_lib) {
                mbedtls_printf("%s\n", dlerror());
                mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find helper"
                            " libsgx_urts.so lib\n");
                return 1;
        }
        ra_tls_verify_lib = dlopen("../lib/libra_tls_verify_dcap.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
                    mbedtls_printf("%s\n", dlerror());
                mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
                return 1;
        }

        /* Define functions taken from the library opened */
        ra_tls_verify_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_verify_callback_non_enclave");
        if ((error = dlerror()) != NULL) {
                mbedtls_printf("%s\n", error);
                return 1;
        }
        ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL) {
                mbedtls_printf("%s\n", error);
                return 1;
        }
    }
    
    /* Default SGX-measurement verification callback declaration */
    mbedtls_printf("[ using default SGX-measurement verification callback]\n");
    (*ra_tls_set_measurement_callback_f)(NULL); /* just to test RA-TLS code */

    mbedtls_printf("[+] Seeding the random number generator...\n");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf("[+] OK\n");

    /* set up the connection to the server */
    mbedtls_printf("[+] Connecting to tcp/%s/%s...\n", SERVER_NAME, SERVER_PORT);
    fflush(stdout);

    ret = mbedtls_net_connect(&server_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf("[+] OK\n");

    /* mbedtls setting up SSL/TLS structure */
    mbedtls_printf("[+] Setting up the SSL/TLS structure...\n");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf("[+] OK\n");

    /* mbedtls loading CA certificate if any. However in this case, certificate verification callback
     * will be used instead of CA certificate loading
     */
    mbedtls_printf("[+] Loading the CA root certificate ...\n");
    fflush(stdout);

    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char*)mbedtls_test_cas_pem,
                                 mbedtls_test_cas_pem_len);
    if (ret < 0) {
        mbedtls_printf( "[-] failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_printf("[+] OK\n");
    
    /* use RA-TLS verification callback; this will overwrite CA chain set up above */
    mbedtls_printf("[+] Installing RA-TLS callback ...\n");
    mbedtls_ssl_conf_verify(&conf, ra_tls_verify_callback_f, NULL);
    mbedtls_printf("[+] OK\n");

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    /* mbedtls set hostname */
    ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* Performing SSL/TLS handshake with server */
    mbedtls_printf("#################################################################\n");

    mbedtls_printf("[+] Performing the SSL/TLS handshake...\n");
    fflush(stdout);

    mbedtls_printf("#################################################################\n");

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("[-] failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            goto exit;
        }
    }

    mbedtls_printf("[+] OK\n");

    /* start verifying server certificate */
    mbedtls_printf("[+] Verifying peer X.509 certificate...\n");

    flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_printf("[-] failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        goto exit;
    } else {
        mbedtls_printf("[+] OK\n");
    }

    /* once server's certificate is verified successfully, client starts sending
     * a message or writing the buffer to the server
     */
    mbedtls_printf("[+] Handshake has been performed successfully...\n\n");
    mbedtls_printf("[+]  > Send tflite model to server...\n");
    fflush(stdout);

    /***************************** MODEL DEFINITION AND SUBMITION ********************************/
    /* Send tflite model to Server */
    {
	    char* filename = "../models/mobilenet_v1_1.0_224.tflite";
	    char sendbuffer[SIZE];
	    mbedtls_printf("[+] Client sending %s to the Server...\n", filename);
	    FILE *fp = fopen(filename, "r");
	    if (fp == NULL)
	    {
		    mbedtls_printf("[-] ERROR: File %s not found.\n", filename);
		    exit(1);
	    }
	    bzero (sendbuffer, SIZE);
	    int fp_block_sz;
	    while ((fp_block_sz = fread(sendbuffer, sizeof(char), SIZE, fp)) > 0)
	    {
		    if (mbedtls_ssl_write(&ssl, sendbuffer, fp_block_sz) < 0)
		    {
			    mbedtls_fprintf(stderr, "[-] ERROR: Failed to send model %s. (errno = %d)\n", filename, errno);
			    break;
		    }
		    bzero (sendbuffer, SIZE);
	    }
	    mbedtls_printf ("[+] OK\n");
	    mbedtls_printf ("[+] Model %s from Client was sent successfully!\n", filename);
    }

    /*********************************** WAITING RESPONSE FROM SERVER **************************************/    
    /* Receive response from server */
    mbedtls_printf("\n\n[+]  < Read from server:\n");
    fflush(stdout);

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            break;

        if (ret < 0) {
            //mbedtls_printf("[-] failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
	    if (errno == EAGAIN)
	    {
		    mbedtls_printf(" read() timed out.\n");
	    }else
	    {
		    mbedtls_fprintf(stderr, "read() failed due to errno = %d\n", errno);
	    }
            break;
        }

        if (ret == 0) {
            mbedtls_printf("\n\nEOF\n\n");
            break;
        }

        len = ret;
        mbedtls_printf(" %lu bytes read\n\n%s", len, (char*)buf);
    } while (1);

    /************************************ CONNECTION TERMINATION ****************************************/
    /* once the handshake success, the socket will be closed */
    mbedtls_ssl_close_notify(&ssl);
    exit_code = MBEDTLS_EXIT_SUCCESS;
    mbedtls_printf("[+] Connection is closed by server...\n");
exit:
#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    dlclose(ra_tls_verify_lib);
    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return exit_code;
}
