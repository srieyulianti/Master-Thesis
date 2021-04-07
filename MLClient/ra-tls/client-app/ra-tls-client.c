/* ra-tls-server.c 
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef SGX_RATLS_MUTUAL
#include <assert.h>
#endif
#include "App.h"
#include "ra-tls-client.h"

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>

/* wolfssl include */
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#define SERV_PORT 8081
#define MAXDATASIZE  4096 

#include <sgx_quote.h>

#ifdef RATLS_ECDSA
#include <sgx_quote_3.h>
#endif

#include <sgx_urts.h>
#include "ra.h"

#ifdef SGX_RATLS_MUTUAL
#include "ra-attester.h"
#endif

#include "ra-challenger.h"

/* only for lareport */
/* TODO: This global variable is referenced in the underlying library */
sgx_enclave_id_t g_eid = -1;

static int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX * store)
{
	(void)preverify;
	int ret = verify_sgx_cert_extensions(store->certs->buffer,
					     store->certs->length);

	fprintf(stderr, "Verifying SGX certificate extensions ... %s\n",
		ret == 0 ? "Success" : "Failure");
	return !ret;
}

#ifdef SGX_RATLS_MUTUAL
extern struct ra_tls_options my_ra_tls_options;
#endif


int client_connect(sgx_enclave_id_t id)
{
	int     		sgxStatus;                  
	int     		sockfd;                     /* socket file descriptor */
	struct  sockaddr_in 	servAddr;       /* struct for server address */
	struct 	hostent		*hostname;
	struct	in_addr		ip_addr;
	int     		ret = 0;                    /* variable for error checking */
	
	/* data to send to the server, data recieved from the server */
	char    sendBuff[] = "Hello Server!";
	char    rcvBuff[MAXDATASIZE] = {0};

    	/* internet address family, stream based tcp, default protocol */
    	hostname = gethostbyname("server");
	ip_addr = *(struct in_addr *)(hostname->h_addr);
    	sockfd = socket(AF_INET, SOCK_STREAM, 0);

    	if (sockfd < 0) {
        	printf("Failed to create socket. errno: %i\n", errno);
        	return EXIT_FAILURE;
   	 }

    	memset(&servAddr, 0, sizeof(servAddr)); /* clears memory block for use */
    	servAddr.sin_family = AF_INET;          /* sets addressfamily to internet*/
    	servAddr.sin_port = htons(SERV_PORT);   /* sets port to defined port */

    	/* looks for the server at the entered address (ip in the command line) */
    	if (inet_pton(AF_INET, inet_ntoa(ip_addr), &servAddr.sin_addr) < 1) {
        	/* checks validity of address */
        	ret = errno;
        	printf("Invalid Address. errno: %i\n", ret);
        	return EXIT_FAILURE;
   	 }

    	if (connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        	ret = errno;
        	printf("Connect error. Error: %i\n", ret);
        	return EXIT_FAILURE;
    	}

	printf("[+] Connection with server has been established\n");

    	enc_wolfSSL_Debugging_ON(id);
    	enc_wolfSSL_Init(id, &sgxStatus);

    	WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!ctx) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
		goto err;
	}

#ifdef SGX_RATLS_MUTUAL
	uint8_t key[2048];
	uint8_t crt[8192];
	int key_len = sizeof(key);
	int crt_len = sizeof(crt);

#ifdef RATLS_ECDSA
	ecdsa_create_key_and_x509(key, &key_len, crt, &crt_len);
#else
	create_key_and_x509(key, &key_len, crt, &crt_len, &my_ra_tls_options);
#endif

    	int ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, key_len,
						    SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);

	ret = wolfSSL_CTX_use_certificate_buffer(ctx, crt, crt_len,
						 SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);

#endif

    	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cert_verify_callback);

	WOLFSSL *ssl = wolfSSL_new(ctx);
	if (!ssl) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
		goto err_ctx;
	}

    	/* Attach wolfSSL to the socket */
	wolfSSL_set_fd(ssl, sockfd);

    	if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
		fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
		goto err_ssl;
	}

    	WOLFSSL_X509 *srvcrt = wolfSSL_get_peer_certificate(ssl);

    	int derSz;
	const unsigned char *der = wolfSSL_X509_get_der(srvcrt, &derSz);
	sgx_report_body_t *body = NULL;

#ifdef RATLS_ECDSA
	uint8_t quote_buff[8192] = {0,};
	ecdsa_get_quote_from_dcap_cert(der, derSz, (sgx_quote3_t*)quote_buff);
	sgx_quote3_t* quote = (sgx_quote3_t*)quote_buff;
	body = &quote->report_body;
	printf("[+] ECDSA verification\n");
#elif defined LA_REPORT
    	sgx_report_t report = {0,};
    	la_get_report_from_cert(der, derSz, &report);
    	body = &report.body;
    	printf("Local report verification\n");
#else
	uint8_t quote_buff[8192] = {0,};
	get_quote_from_cert(der, derSz, (sgx_quote_t*)quote_buff);
	sgx_quote_t* quote = (sgx_quote_t*)quote_buff;
	body = &quote->report_body;
	printf("EPID verification\n");
#endif

    	printf("[+] Server's SGX identity:\n");
	printf("  . MRENCLAVE = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i)
		printf("%02x", body->mr_enclave.m[i]);
	printf("\n");
	printf("  . MRSIGNER  = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i)
		printf("%02x", body->mr_signer.m[i]);
	printf("\n");

    	if (wolfSSL_write(ssl, sendBuff, strlen(sendBuff)) != (int)strlen(sendBuff)) {
		fprintf(stderr, "ERROR: failed to write\n");
		goto err_ssl;
	}

    	ret = wolfSSL_read(ssl, rcvBuff, MAXDATASIZE);
	if (ret == -1) {
		fprintf(stderr, "ERROR: failed to read\n");
		goto err_ssl;
	}

    	err_ssl:
	    	wolfSSL_free(ssl);
    	err_ctx:
	    	wolfSSL_CTX_free(ctx);
    	err:
	    	wolfSSL_Cleanup();

	return ret;

}

