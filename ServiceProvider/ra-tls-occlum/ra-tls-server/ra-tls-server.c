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

#include "App.h"
#include "ra-tls-server.h"

/* the usual suspects */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>

#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
#include <time.h>

#define SRV_PORT 8081

#define CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"

int server_connect()
{
	int                sgxStatus;
	int                sockfd;
	int                connd;
	struct sockaddr_in servAddr;
	struct sockaddr_in clientAddr;
	socklen_t          size = sizeof(clientAddr);
	struct hostent	   *hostname;
	struct in_addr	   ip_addr;
	char               buff[256];
	size_t             len;
	int                ret; /* variable for error checking */
	
	hostname = gethostbyname("server");
	ip_addr = *(struct in_addr *)(hostname->h_addr);
	
#ifdef SGX_DEBUG
	wolfSSL_Debugging_ON();
#else
	wolfSSL_Debugging_OFF();
#endif

	/* Initialize wolfSSL */
	wolfSSL_Init();

	/* Create a socket that uses an internet IPv4 address,
     	* Sets the socket to be stream based (TCP),
     	* 0 means choose the default protocol. */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        	fprintf(stderr, "ERROR: failed to create the socket\n");
        	return -1;
	}

	/* Create and initialize WOLFSSL_CTX */

	WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
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

	/* Initialize the server address struct with zeros */
	memset(&servAddr, 0, sizeof(servAddr));
	
	/* Fill in the server address */
	servAddr.sin_family      = AF_INET;             /* using IPv4      */
	servAddr.sin_port        = htons(SRV_PORT); 	/* on DEFAULT_PORT */
	servAddr.sin_addr.s_addr = INADDR_ANY;  /* from anywhere   */
	
	/* Bind the server socket to our port */
    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
       	fprintf(stderr, "ERROR: failed to bind\n");
       	return -1;
    }

    /* Listen for a new connection, allow 5 pending connections */
	if (listen(sockfd, 5) == -1) {
        fprintf(stderr, "ERROR: failed to listen\n");
        return -1;
	}

    printf("[+] Waiting for a connection...\n");

    /* Accept client connections */
    if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size)) == -1) {
       	fprintf(stderr, "ERROR: failed to accept the connection\n\n");
       	return -1;
    }

	WOLFSSL *ssl = wolfSSL_new(ctx);
	if (!ssl) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
		goto err_ctx;
	}

	/* Attach wolfSSL to the socket */
	wolfSSL_set_fd(ssl, sockfd);

	fprintf(stdout, "[+] Client connected successfully\n");

	/* Read the client data into our buff array */
	memset(buff, 0, sizeof(buff));

	ret = wolfSSL_read(ssl, buff, sizeof(buff));
	if (ret == -1) {
		fprintf(stderr, "ERROR: failed to read\n");
		goto err_ssl;
	}

	/* Print to stdout any data the client sends */
	fprintf(stdout, "Client: %s\n", buff);

	/* Write our reply into buff */
	memset(buff, 0, sizeof(buff));
	memcpy(buff, "I hear ya fa shizzle!\n", sizeof(buff));
	len = strnlen(buff, sizeof(buff));	

	/* Reply back to the client */
	sgxStatus = enc_wolfSSL_write(id, &ret, ssl, buff, len);
	if (sgxStatus != SGX_SUCCESS || ret != len)
		ret = -1;

	if (wolfSSL_write(ssl, buff, len) != (int)len) {
		fprintf(stderr, "ERROR: failed to write\n");
		goto err_ssl;
	}

	err_ssl:
		/* Cleanup after this connection */
		wolfSSL_free(ssl);
	err_ctx:
		/* Cleanup and return */
		wolfSSL_CTX_free(ctx);
	err:
		wolfSSL_Cleanup();

	return ret;
}




