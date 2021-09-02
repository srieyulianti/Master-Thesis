/*
 *  SSL server demonstration program (with RA-TLS)
 *  This program is heavily based on an mbedTLS 2.26.0 example ssl_server.c
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

#define _GNU_SOURCE

/* mbedtls config include */
#include <mbedtls/config.h>

/* usual libraries include */
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <unistd.h>
#include <math.h>

/* print library include */
#define mbedtls_fprintf fprintf
#define mbedtls_printf printf

/* other mbedtls libraries include */
#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>

#include "object_detector.h"
#include "ujpeg.h"

/* RA-TLS: on server, only need ra_tls_create_key_and_crt() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_f)(mbedtls_pk_context* key, mbedtls_x509_crt* crt);

#define HTTP_RESPONSE                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
	"<h2>Connection to the link succeed</h2>\r\n"	\
    "<p>Successful connection with the client using: %s</p>\r\n"

#define DEBUG_LEVEL 0
#define false 0
#define SIZE 1024

/* declare debug function */
static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);
    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

/* main function declaration */
int main(void) {
    int ret;
    char* model_name = "mobilenet_v1_1.0_224.tflite";
    char* label_file = "labels.txt";
    char* image_file = "image.jpeg";
    size_t len;
    mbedtls_net_context listen_fd;
    mbedtls_net_context client_fd;
    unsigned char buf[1024];
    const char* pers = "ssl_server";

    void* ra_tls_attest_lib     = NULL;
    ra_tls_create_key_and_crt_f = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif
    
    /* Generate key and certificate file */
    ra_tls_attest_lib = dlopen("../lib/libra_tls_attest.so", RTLD_LAZY);
    if (!ra_tls_attest_lib) {
        mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
        return 1;
    }

    char* error;
    ra_tls_create_key_and_crt_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt");
    if ((error = dlerror()) != NULL) {
        mbedtls_printf("%s\n", error);
        return 1;
    }
    mbedtls_printf("[+] Creating the RA-TLS server cert and key...\n");
    fflush(stdout);

    ret = (*ra_tls_create_key_and_crt_f)(&pkey, &srvcert);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  !  ra_tls_create_key_and_crt returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf("[+] OK\n");

    /* Attach mbedtls to the socket */
    mbedtls_printf("[+] Bind on https://localhost:8081/...\n");
    fflush(stdout);

    ret = mbedtls_net_bind(&listen_fd, NULL, "8081", MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf("[+] OK\n");

    mbedtls_printf("[+] Seeding the random number generator...\n");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf("[+] OK\n");

    mbedtls_printf("[+] Setting up the SSL data....\n");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    if (!ra_tls_attest_lib) {
        /* no RA-TLS attest library present, use embedded CA chain */
        mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    }

    ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf("[+] OK\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    mbedtls_printf("[+] Waiting for a remote connection from model client...\n");
    fflush(stdout);

    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf("[+] OK\n");

    mbedtls_printf("[+] Performing the SSL/TLS handshake...\n");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("[-] failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto exit;
        }
    }

    mbedtls_printf("[+] OK\n");
    mbedtls_printf("[+] Handshake has been performed successfully...\n\n");

    /********************************** MODEL RECEPTION *************************************/
    mbedtls_printf("[+]  < Get model from client:\n");
    fflush(stdout);
    {
    	//char* filename = "host/mobilenet_v1_1.0_224.tflite";
    	FILE *fp = fopen(model_name, "a");
    	char rcvbuffer[SIZE];

    	if (fp == NULL)
	    	mbedtls_printf("[+] File %s cannot be opened file on server.\n", model_name);
    	else
    	{
	    	bzero (rcvbuffer, SIZE);
	    	int fp_block_sz = 0;
	    	while ((fp_block_sz = mbedtls_ssl_read(&ssl, rcvbuffer, SIZE)) > 0)
	    	{
		    	int write_sz = fwrite(rcvbuffer, sizeof(char), fp_block_sz, fp);
		    	if (write_sz < fp_block_sz)
		    	{
			    	perror ("[-] Writing file failed on server.\n");
		    	}
		    	bzero (rcvbuffer, SIZE);
		    	if (fp_block_sz == 0 || fp_block_sz != 1024)
		    	{
			    	break;
		    	}
	    	}
	    	if (fp_block_sz < 0)
	    	{
		    	if (errno == EAGAIN)
		    	{
			    	mbedtls_printf("read() timed out.\n");
		    	}
		    	else
		    	{
			    	mbedtls_fprintf(stderr, "read() failed due to errno = %d\n", errno);
			    	exit(1);
		    	}
	    	}
	    	mbedtls_printf("[+] OK\n");
		mbedtls_printf("[+] Received from client!\n");
	    	fclose(fp);
    	}
    }

    /******************************** WRITING RESPONSE TO THE CLIENT ********************************/
    /* Send response to client */
    mbedtls_printf("\n\n[+]  > Write to client:\n");
    fflush(stdout);

    len = sprintf((char*)buf, HTTP_RESPONSE, mbedtls_ssl_get_ciphersuite(&ssl));

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf("[-] failed\n  ! peer closed the connection\n\n");
            goto exit;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("[-] failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf("[+] %lu bytes written\n\n%s\n", len, (char*)buf);

    /*********************************** CLOSING THE CONNECTION *************************************/
    mbedtls_printf("[+] Closing the connection with the model owner...\n");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("[-] failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto exit;
        }
    }

    mbedtls_printf("[+] OK\n");

    ret = 0;
    goto next_conn;

    /*************************** WAITING NEXT CONNECTION FROM DATA CLIENT ***************************/
next_conn:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    mbedtls_printf("[+] Waiting for a remote connection from data client...\n");
    fflush(stdout);

    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    if (ret != 0) {
        mbedtls_printf("[-] failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf("[+] OK\n");

    mbedtls_printf("[+] Performing the SSL/TLS handshake...\n");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("[-] failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto exit;
        }
    }

    mbedtls_printf("[+] OK\n");
    mbedtls_printf("[+] Handshake has been performed successfully...\n\n");

    /********************************** RECEIVE DATA FROM CLIENT *************************************/
    mbedtls_printf("[+]  < Get data from client:\n");
    fflush(stdout);
    {
        //char* filename = "host/image.bmp";
        FILE *fp = fopen(image_file, "a");
        char rcvbuffer[SIZE];

        if (fp == NULL)
                mbedtls_printf("[+] File %s cannot be opened file on server.\n", image_file);
        else
        {
                bzero (rcvbuffer, SIZE);
                int fp_block_sz = 0;
                while ((fp_block_sz = mbedtls_ssl_read(&ssl, rcvbuffer, SIZE)) > 0)
                {
                        int write_sz = fwrite(rcvbuffer, sizeof(char), fp_block_sz, fp);
                        if (write_sz < fp_block_sz)
                        {
                                perror ("[-] Writing file failed on server.\n");
                        }
                        bzero (rcvbuffer, SIZE);
                        if (fp_block_sz == 0 || fp_block_sz != 1024)
                        {
                                break;
                        }
                }
		if (fp_block_sz < 0)
                {
                        if (errno == EAGAIN)
                        {
                                mbedtls_printf("read() timed out.\n");
                        }
                        else
                        {
                                mbedtls_fprintf(stderr, "read() failed due to errno = %d\n", errno);
                                exit(1);
                        }
                }
                mbedtls_printf("[+] OK\n");
                mbedtls_printf("[+] Received from client!\n");
                fclose(fp);
        }
    }

    /*********************************** RUNNING THE APPLICATION ************************************/
    mbedtls_printf("\n[+] Running the model with the input image from data client\n");
    
    char buffer[1024];
    ObjectDetector(model_name, image_file, buffer);
    mbedtls_printf("%s", buffer);

    //mbedtls_printf("[+] Category: %.0f", category);
    //mbedtls_printf(", probability: %f\n", probability);

    mbedtls_printf("[+] Finished running the model and prepare to write the result to the client\n");
    
    /******************************** WRITING RESPONSE TO THE CLIENT ********************************/
    /* Send response to client */
    mbedtls_printf("\n\n[+] Send the image classification result to the data client:\n");
    fflush(stdout);

    len = sprintf((char*)buf, buffer, mbedtls_ssl_get_ciphersuite(&ssl));

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf("[-] failed\n  ! peer closed the connection\n\n");
            goto exit;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("[-] failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf("[+] %lu bytes written\n\n%s\n", len, (char*)buf);

    /*********************************** CLOSING THE CONNECTION *************************************/
    mbedtls_printf("[+] Closing the connection with the data client...\n");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("[-] failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto exit;
        }
    }

    mbedtls_printf("[+] OK\n");

    ret = 0;
    goto exit;

exit:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}
