#include "Wolfssl_Enclave_u.h"
#include <errno.h>

typedef struct ms_wc_test_t {
	int ms_retval;
	void* ms_args;
} ms_wc_test_t;

typedef struct ms_wc_benchmark_test_t {
	int ms_retval;
	void* ms_args;
} ms_wc_benchmark_test_t;

typedef struct ms_enc_wolfSSL_Init_t {
	int ms_retval;
} ms_enc_wolfSSL_Init_t;

typedef struct ms_enc_wolfTLSv1_2_client_method_t {
	WOLFSSL_METHOD* ms_retval;
} ms_enc_wolfTLSv1_2_client_method_t;

typedef struct ms_enc_wolfTLSv1_2_server_method_t {
	WOLFSSL_METHOD* ms_retval;
} ms_enc_wolfTLSv1_2_server_method_t;

typedef struct ms_enc_wolfSSL_CTX_new_t {
	WOLFSSL_CTX* ms_retval;
	WOLFSSL_METHOD* ms_method;
} ms_enc_wolfSSL_CTX_new_t;

typedef struct ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_load_verify_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_load_verify_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t;

typedef struct ms_enc_wolfSSL_CTX_use_certificate_buffer_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	const unsigned char* ms_buf;
	long int ms_sz;
	int ms_type;
} ms_enc_wolfSSL_CTX_use_certificate_buffer_t;

typedef struct ms_enc_wolfSSL_CTX_set_cipher_list_t {
	int ms_retval;
	WOLFSSL_CTX* ms_ctx;
	const char* ms_list;
	size_t ms_list_len;
} ms_enc_wolfSSL_CTX_set_cipher_list_t;

typedef struct ms_enc_wolfSSL_new_t {
	WOLFSSL* ms_retval;
	WOLFSSL_CTX* ms_ctx;
} ms_enc_wolfSSL_new_t;

typedef struct ms_enc_wolfSSL_set_fd_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	int ms_fd;
} ms_enc_wolfSSL_set_fd_t;

typedef struct ms_enc_wolfSSL_connect_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
} ms_enc_wolfSSL_connect_t;

typedef struct ms_enc_wolfSSL_write_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	const void* ms_in;
	int ms_sz;
} ms_enc_wolfSSL_write_t;

typedef struct ms_enc_wolfSSL_get_error_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	int ms_ret;
} ms_enc_wolfSSL_get_error_t;

typedef struct ms_enc_wolfSSL_read_t {
	int ms_retval;
	WOLFSSL* ms_ssl;
	void* ms_out;
	int ms_sz;
} ms_enc_wolfSSL_read_t;

typedef struct ms_enc_wolfSSL_free_t {
	WOLFSSL* ms_ssl;
} ms_enc_wolfSSL_free_t;

typedef struct ms_enc_wolfSSL_CTX_free_t {
	WOLFSSL_CTX* ms_ctx;
} ms_enc_wolfSSL_CTX_free_t;

typedef struct ms_enc_wolfSSL_Cleanup_t {
	int ms_retval;
} ms_enc_wolfSSL_Cleanup_t;

typedef struct ms_enc_create_key_and_x509_t {
	WOLFSSL_CTX* ms_ctx;
} ms_enc_create_key_and_x509_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_current_time_t {
	double* ms_time;
} ms_ocall_current_time_t;

typedef struct ms_ocall_low_res_time_t {
	int* ms_time;
} ms_ocall_low_res_time_t;

typedef struct ms_ocall_recv_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_send_t {
	size_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

typedef struct ms_ocall_collect_attestation_evidence_t {
	sgx_report_t* ms_p_report;
	ecdsa_attestation_evidence_t* ms_evidence;
} ms_ocall_collect_attestation_evidence_t;

typedef struct ms_ocall_ratls_get_target_info_t {
	sgx_target_info_t* ms_qe_target_info;
} ms_ocall_ratls_get_target_info_t;

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_current_time(void* pms)
{
	ms_ocall_current_time_t* ms = SGX_CAST(ms_ocall_current_time_t*, pms);
	ocall_current_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_low_res_time(void* pms)
{
	ms_ocall_low_res_time_t* ms = SGX_CAST(ms_ocall_low_res_time_t*, pms);
	ocall_low_res_time(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_collect_attestation_evidence(void* pms)
{
	ms_ocall_collect_attestation_evidence_t* ms = SGX_CAST(ms_ocall_collect_attestation_evidence_t*, pms);
	ocall_collect_attestation_evidence(ms->ms_p_report, ms->ms_evidence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Wolfssl_Enclave_ocall_ratls_get_target_info(void* pms)
{
	ms_ocall_ratls_get_target_info_t* ms = SGX_CAST(ms_ocall_ratls_get_target_info_t*, pms);
	ocall_ratls_get_target_info(ms->ms_qe_target_info);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[7];
} ocall_table_Wolfssl_Enclave = {
	7,
	{
		(void*)Wolfssl_Enclave_ocall_print_string,
		(void*)Wolfssl_Enclave_ocall_current_time,
		(void*)Wolfssl_Enclave_ocall_low_res_time,
		(void*)Wolfssl_Enclave_ocall_recv,
		(void*)Wolfssl_Enclave_ocall_send,
		(void*)Wolfssl_Enclave_ocall_collect_attestation_evidence,
		(void*)Wolfssl_Enclave_ocall_ratls_get_target_info,
	}
};
sgx_status_t wc_test(sgx_enclave_id_t eid, int* retval, void* args)
{
	sgx_status_t status;
	ms_wc_test_t ms;
	ms.ms_args = args;
	status = sgx_ecall(eid, 0, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t wc_benchmark_test(sgx_enclave_id_t eid, int* retval, void* args)
{
	sgx_status_t status;
	ms_wc_benchmark_test_t ms;
	ms.ms_args = args;
	status = sgx_ecall(eid, 1, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Init(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Init_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_Debugging_ON(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_Wolfssl_Enclave, NULL);
	return status;
}

sgx_status_t enc_wolfSSL_Debugging_OFF(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Wolfssl_Enclave, NULL);
	return status;
}

sgx_status_t enc_wolfTLSv1_2_client_method(sgx_enclave_id_t eid, WOLFSSL_METHOD** retval)
{
	sgx_status_t status;
	ms_enc_wolfTLSv1_2_client_method_t ms;
	status = sgx_ecall(eid, 5, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfTLSv1_2_server_method(sgx_enclave_id_t eid, WOLFSSL_METHOD** retval)
{
	sgx_status_t status;
	ms_enc_wolfTLSv1_2_server_method_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_new(sgx_enclave_id_t eid, WOLFSSL_CTX** retval, WOLFSSL_METHOD* method)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_new_t ms;
	ms.ms_method = method;
	status = sgx_ecall(eid, 7, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_PrivateKey_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 8, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_load_verify_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_load_verify_buffer_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 9, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_chain_buffer_format(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 10, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_use_certificate_buffer(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_use_certificate_buffer_t ms;
	ms.ms_ctx = ctx;
	ms.ms_buf = buf;
	ms.ms_sz = sz;
	ms.ms_type = type;
	status = sgx_ecall(eid, 11, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_CTX_set_cipher_list(sgx_enclave_id_t eid, int* retval, WOLFSSL_CTX* ctx, const char* list)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_set_cipher_list_t ms;
	ms.ms_ctx = ctx;
	ms.ms_list = list;
	ms.ms_list_len = list ? strlen(list) + 1 : 0;
	status = sgx_ecall(eid, 12, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_new(sgx_enclave_id_t eid, WOLFSSL** retval, WOLFSSL_CTX* ctx)
{
	sgx_status_t status;
	ms_enc_wolfSSL_new_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 13, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_set_fd(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int fd)
{
	sgx_status_t status;
	ms_enc_wolfSSL_set_fd_t ms;
	ms.ms_ssl = ssl;
	ms.ms_fd = fd;
	status = sgx_ecall(eid, 14, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_connect(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl)
{
	sgx_status_t status;
	ms_enc_wolfSSL_connect_t ms;
	ms.ms_ssl = ssl;
	status = sgx_ecall(eid, 15, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_write(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, const void* in, int sz)
{
	sgx_status_t status;
	ms_enc_wolfSSL_write_t ms;
	ms.ms_ssl = ssl;
	ms.ms_in = in;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 16, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_get_error(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, int ret)
{
	sgx_status_t status;
	ms_enc_wolfSSL_get_error_t ms;
	ms.ms_ssl = ssl;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 17, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_read(sgx_enclave_id_t eid, int* retval, WOLFSSL* ssl, void* out, int sz)
{
	sgx_status_t status;
	ms_enc_wolfSSL_read_t ms;
	ms.ms_ssl = ssl;
	ms.ms_out = out;
	ms.ms_sz = sz;
	status = sgx_ecall(eid, 18, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_wolfSSL_free(sgx_enclave_id_t eid, WOLFSSL* ssl)
{
	sgx_status_t status;
	ms_enc_wolfSSL_free_t ms;
	ms.ms_ssl = ssl;
	status = sgx_ecall(eid, 19, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_CTX_free(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_free_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 20, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t enc_wolfSSL_Cleanup(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_enc_wolfSSL_Cleanup_t ms;
	status = sgx_ecall(eid, 21, &ocall_table_Wolfssl_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enc_create_key_and_x509(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx)
{
	sgx_status_t status;
	ms_enc_create_key_and_x509_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 22, &ocall_table_Wolfssl_Enclave, &ms);
	return status;
}

sgx_status_t dummy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 23, &ocall_table_Wolfssl_Enclave, NULL);
	return status;
}

