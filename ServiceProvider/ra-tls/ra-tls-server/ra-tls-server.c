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

#define SRV_PORT 8081

#define CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"

int server_connect(sgx_enclave_id_t id)
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
	enc_wolfSSL_Debugging_ON(id);
#else
	enc_wolfSSL_Debugging_OFF(id);
#endif

	/* Initialize wolfSSL */
	sgxStatus = enc_wolfSSL_Init(id, &ret);
	if (sgxStatus != SGX_SUCCESS || ret != WOLFSSL_SUCCESS)
		return -1;

	/* Create a socket that uses an internet IPv4 address,
     	* Sets the socket to be stream based (TCP),
     	* 0 means choose the default protocol. */
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        	fprintf(stderr, "ERROR: failed to create the socket\n");
        	return -1;
	}

	/* Create and initialize WOLFSSL_CTX */
	WOLFSSL_METHOD *method;
	sgxStatus = enc_wolfTLSv1_2_server_method(id, &method);
	if (sgxStatus != SGX_SUCCESS || !method)
		return -1;

	
	WOLFSSL_CTX *ctx;
	sgxStatus = enc_wolfSSL_CTX_new(id, &ctx, method);
	if (sgxStatus != SGX_SUCCESS || !ctx)
		goto err;

	sgxStatus = enc_create_key_and_x509(id, ctx);
	assert(sgxStatus == SGX_SUCCESS);

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

	WOLFSSL *ssl;
	sgxStatus = enc_wolfSSL_new(id, &ssl, ctx);
	if (sgxStatus != SGX_SUCCESS || !ssl)
		goto err;

	/* Attach wolfSSL to the socket */
	sgxStatus = enc_wolfSSL_set_fd(id, &ret, ssl, connd);
	if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS)
		goto err_ssl;

	fprintf(stdout, "Client connected successfully\n");

	/* Read the client data into our buff array */
	memset(buff, 0, sizeof(buff));
	sgxStatus = enc_wolfSSL_read(id, &ret, ssl, buff, sizeof(buff) - 1);
	if (sgxStatus != SGX_SUCCESS || ret == -1)
		goto err_ssl;

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

	err_ssl:
		/* Cleanup after this connection */
		enc_wolfSSL_free(id, ssl);
	err_ctx:
		/* Cleanup and return */
		sgxStatus = enc_wolfSSL_CTX_free(id, ctx);
		close(connd);
	err:
		sgxStatus = enc_wolfSSL_Cleanup(id, &ret);
		close(sockfd);

	return ret;
}




