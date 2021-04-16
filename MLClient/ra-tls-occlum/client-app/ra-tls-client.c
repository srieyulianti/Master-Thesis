/* ra-tls-client.c 
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
#include <wolfssl/options.h>
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

#include "ra-challenger.h"

/* Certifcate verification callback function */
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

int main()
{
	int						ret;			/* variable for error checking */                  
	int     				sockfd;         /* socket file descriptor */
	struct  sockaddr_in 	servAddr;       /* struct for server address */
	struct 	hostent			*hostname;
	struct	in_addr			ip_addr;
                    
	/* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;

	/* data to send to the server, data recieved from the server */
	char    sendBuff[] = "Hello Server!";
	char    rcvBuff[MAXDATASIZE] = {0};

    /* internet address family, stream based tcp, default protocol */
    hostname = gethostbyname("server");
	ip_addr = *(struct in_addr *)(hostname->h_addr);

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1;
        goto end;
    }

    /* Initialize the server address struct with zeros */
	memset(&servAddr, 0, sizeof(servAddr)); 

	/* Fill in the server address */	
	servAddr.sin_family = AF_INET;          /* sets addressfamily to internet*/
    servAddr.sin_port = htons(SERV_PORT);   /* sets port to defined port */

	/* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, inet_ntoa(ip_addr), &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        ret = -1;
        goto end;
    }
    
	/* Connect to the server */
    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr))) == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto end;
    }

    printf("[+] Connection with server has been established\n");

	/*---------------------------------*/
    /* Start of security */
    /*---------------------------------*/
    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto socket_cleanup;
    }
			
    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto socket_cleanup;
    }

	/* Create ECDSA key and Certificate */

#ifdef RATLS_ECDSA
	uint8_t key[2048];
	uint8_t crt[8192];
	int key_len = sizeof(key);
	int crt_len = sizeof(crt);

	ecdsa_create_key_and_x509(key, &key_len, crt, &crt_len);

	/* Load server key into WOLFSSL_CTX */
	if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, key_len, SSL_FILETYPE_ASN1)
        != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                key);
        return -1;
    }

	/* Load server certificate into WOLFSSL_CTX */
	if (wolfSSL_CTX_use_certificate_buffer(ctx, crt, crt_len, SSL_FILETYPE_ASN1)
        != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                crt);
        return -1;
    }
	
#endif

	/* Verify peer's certificate */
   	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cert_verify_callback);

	/* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1;
        goto ctx_cleanup;
    }
	
	/* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }	
	
	/* Connect to wolfSSL on the server side */
    if ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        goto cleanup;
    }

	/* Get server's certificate */
	WOLFSSL_X509 *srvcrt = wolfSSL_get_peer_certificate(ssl);

	/* Convert certificate to DER */
	int derSz;
	const unsigned char *der = wolfSSL_X509_get_der(srvcrt, &derSz);
	sgx_report_body_t *body = NULL;
	

#ifdef RATLS_ECDSA
	uint8_t quote_buff[8192] = {0,};
	ecdsa_get_quote_from_dcap_cert(der, derSz, (sgx_quote3_t*)quote_buff);
	sgx_quote3_t* quote = (sgx_quote3_t*)quote_buff;
	body = &quote->report_body;
	printf("[+] ECDSA verification\n");
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

    /* Send the message to the server */
    if ((ret = wolfSSL_write(ssl, sendBuff, strlen(sendBuff))) != (int)strlen(sendBuff)) {
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int) len);
        goto cleanup;
    }

	/* Read the server data into our buff array */
    memset(rcvBuff, 0, MAXDATASIZE);
    if ((ret = wolfSSL_read(ssl, rcvBuff, MAXDATASIZE-1)) == -1) {
        fprintf(stderr, "ERROR: failed to read\n");
        goto cleanup;
    }
    
	/* Print to stdout any data the server sends */
    printf("Server: %s\n", rcvBuff);

 	/* Cleanup and return */
cleanup:
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
ctx_cleanup:
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
socket_cleanup:
    close(sockfd);          /* Close the connection to the server       */
end:
    return ret;               /* Return reporting a success               */

}

