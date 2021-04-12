#include "Wolfssl_Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_wc_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_wc_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_wc_test_t* ms = SGX_CAST(ms_wc_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_args = ms->ms_args;



	ms->ms_retval = wc_test(_tmp_args);


	return status;
}

static sgx_status_t SGX_CDECL sgx_wc_benchmark_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_wc_benchmark_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_wc_benchmark_test_t* ms = SGX_CAST(ms_wc_benchmark_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_args = ms->ms_args;



	ms->ms_retval = wc_benchmark_test(_tmp_args);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_Init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_Init_t* ms = SGX_CAST(ms_enc_wolfSSL_Init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_Init();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Debugging_ON(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	enc_wolfSSL_Debugging_ON();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Debugging_OFF(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	enc_wolfSSL_Debugging_OFF();
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfTLSv1_2_client_method(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfTLSv1_2_client_method_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfTLSv1_2_client_method_t* ms = SGX_CAST(ms_enc_wolfTLSv1_2_client_method_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfTLSv1_2_client_method();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfTLSv1_2_server_method(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfTLSv1_2_server_method_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfTLSv1_2_server_method_t* ms = SGX_CAST(ms_enc_wolfTLSv1_2_server_method_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfTLSv1_2_server_method();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_new(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_new_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_new_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_new_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_METHOD* _tmp_method = ms->ms_method;



	ms->ms_retval = enc_wolfSSL_CTX_new(_tmp_method);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_PrivateKey_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_PrivateKey_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_use_PrivateKey_buffer(_tmp_ctx, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_load_verify_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_load_verify_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_load_verify_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_load_verify_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_load_verify_buffer(_tmp_ctx, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_certificate_chain_buffer_format(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_certificate_chain_buffer_format_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_use_certificate_chain_buffer_format(_tmp_ctx, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_use_certificate_buffer(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_use_certificate_buffer_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_use_certificate_buffer_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_use_certificate_buffer_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;
	const unsigned char* _tmp_buf = ms->ms_buf;
	long int _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz;
	unsigned char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf = (unsigned char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf, _len_buf, _tmp_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_CTX_use_certificate_buffer(_tmp_ctx, (const unsigned char*)_in_buf, _tmp_sz, ms->ms_type);

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_set_cipher_list(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_set_cipher_list_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_set_cipher_list_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_set_cipher_list_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;
	const char* _tmp_list = ms->ms_list;
	size_t _len_list = ms->ms_list_len ;
	char* _in_list = NULL;

	CHECK_UNIQUE_POINTER(_tmp_list, _len_list);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_list != NULL && _len_list != 0) {
		_in_list = (char*)malloc(_len_list);
		if (_in_list == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_list, _len_list, _tmp_list, _len_list)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_list[_len_list - 1] = '\0';
		if (_len_list != strlen(_in_list) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = enc_wolfSSL_CTX_set_cipher_list(_tmp_ctx, (const char*)_in_list);

err:
	if (_in_list) free(_in_list);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_new(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_new_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_new_t* ms = SGX_CAST(ms_enc_wolfSSL_new_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;



	ms->ms_retval = enc_wolfSSL_new(_tmp_ctx);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_set_fd(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_set_fd_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_set_fd_t* ms = SGX_CAST(ms_enc_wolfSSL_set_fd_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	ms->ms_retval = enc_wolfSSL_set_fd(_tmp_ssl, ms->ms_fd);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_connect(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_connect_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_connect_t* ms = SGX_CAST(ms_enc_wolfSSL_connect_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	ms->ms_retval = enc_wolfSSL_connect(_tmp_ssl);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_write(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_write_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_write_t* ms = SGX_CAST(ms_enc_wolfSSL_write_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;
	const void* _tmp_in = ms->ms_in;
	int _tmp_sz = ms->ms_sz;
	size_t _len_in = _tmp_sz;
	void* _in_in = NULL;

	CHECK_UNIQUE_POINTER(_tmp_in, _len_in);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_in != NULL && _len_in != 0) {
		_in_in = (void*)malloc(_len_in);
		if (_in_in == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_in, _len_in, _tmp_in, _len_in)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = enc_wolfSSL_write(_tmp_ssl, (const void*)_in_in, _tmp_sz);

err:
	if (_in_in) free(_in_in);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_get_error(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_get_error_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_get_error_t* ms = SGX_CAST(ms_enc_wolfSSL_get_error_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	ms->ms_retval = enc_wolfSSL_get_error(_tmp_ssl, ms->ms_ret);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_read(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_read_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_read_t* ms = SGX_CAST(ms_enc_wolfSSL_read_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;
	void* _tmp_out = ms->ms_out;
	int _tmp_sz = ms->ms_sz;
	size_t _len_out = _tmp_sz;
	void* _in_out = NULL;

	CHECK_UNIQUE_POINTER(_tmp_out, _len_out);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_out != NULL && _len_out != 0) {
		if ((_in_out = (void*)malloc(_len_out)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out, 0, _len_out);
	}

	ms->ms_retval = enc_wolfSSL_read(_tmp_ssl, _in_out, _tmp_sz);
	if (_in_out) {
		if (memcpy_s(_tmp_out, _len_out, _in_out, _len_out)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_out) free(_in_out);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_free(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_free_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_free_t* ms = SGX_CAST(ms_enc_wolfSSL_free_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL* _tmp_ssl = ms->ms_ssl;



	enc_wolfSSL_free(_tmp_ssl);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_CTX_free(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_CTX_free_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_CTX_free_t* ms = SGX_CAST(ms_enc_wolfSSL_CTX_free_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;



	enc_wolfSSL_CTX_free(_tmp_ctx);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_wolfSSL_Cleanup(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_wolfSSL_Cleanup_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_wolfSSL_Cleanup_t* ms = SGX_CAST(ms_enc_wolfSSL_Cleanup_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enc_wolfSSL_Cleanup();


	return status;
}

static sgx_status_t SGX_CDECL sgx_enc_create_key_and_x509(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enc_create_key_and_x509_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enc_create_key_and_x509_t* ms = SGX_CAST(ms_enc_create_key_and_x509_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	WOLFSSL_CTX* _tmp_ctx = ms->ms_ctx;



	enc_create_key_and_x509(_tmp_ctx);


	return status;
}

static sgx_status_t SGX_CDECL sgx_dummy(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	dummy();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[24];
} g_ecall_table = {
	24,
	{
		{(void*)(uintptr_t)sgx_wc_test, 0, 0},
		{(void*)(uintptr_t)sgx_wc_benchmark_test, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Init, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Debugging_ON, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Debugging_OFF, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfTLSv1_2_client_method, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfTLSv1_2_server_method, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_new, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_PrivateKey_buffer, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_load_verify_buffer, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_certificate_chain_buffer_format, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_use_certificate_buffer, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_set_cipher_list, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_new, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_set_fd, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_connect, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_write, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_get_error, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_read, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_free, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_CTX_free, 0, 0},
		{(void*)(uintptr_t)sgx_enc_wolfSSL_Cleanup, 0, 0},
		{(void*)(uintptr_t)sgx_enc_create_key_and_x509, 0, 0},
		{(void*)(uintptr_t)sgx_dummy, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[7][24];
} g_dyn_entry_table = {
	7,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_current_time(double* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(double);

	ms_ocall_current_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_current_time_t);
	void *__tmp = NULL;

	void *__tmp_time = NULL;

	CHECK_ENCLAVE_POINTER(time, _len_time);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (time != NULL) ? _len_time : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_current_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_current_time_t));
	ocalloc_size -= sizeof(ms_ocall_current_time_t);

	if (time != NULL) {
		ms->ms_time = (double*)__tmp;
		__tmp_time = __tmp;
		if (_len_time % sizeof(*time) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_time, 0, _len_time);
		__tmp = (void *)((size_t)__tmp + _len_time);
		ocalloc_size -= _len_time;
	} else {
		ms->ms_time = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (time) {
			if (memcpy_s((void*)time, _len_time, __tmp_time, _len_time)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_low_res_time(int* time)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_time = sizeof(int);

	ms_ocall_low_res_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_low_res_time_t);
	void *__tmp = NULL;

	void *__tmp_time = NULL;

	CHECK_ENCLAVE_POINTER(time, _len_time);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (time != NULL) ? _len_time : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_low_res_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_low_res_time_t));
	ocalloc_size -= sizeof(ms_ocall_low_res_time_t);

	if (time != NULL) {
		ms->ms_time = (int*)__tmp;
		__tmp_time = __tmp;
		if (_len_time % sizeof(*time) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_time, 0, _len_time);
		__tmp = (void *)((size_t)__tmp + _len_time);
		ocalloc_size -= _len_time;
	} else {
		ms->ms_time = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (time) {
			if (memcpy_s((void*)time, _len_time, __tmp_time, _len_time)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_recv_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_recv_t));
	ocalloc_size -= sizeof(ms_ocall_recv_t);

	ms->ms_sockfd = sockfd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = len;

	ms_ocall_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_t));
	ocalloc_size -= sizeof(ms_ocall_send_t);

	ms->ms_sockfd = sockfd;
	if (buf != NULL) {
		ms->ms_buf = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_len = len;
	ms->ms_flags = flags;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		errno = ms->ocall_errno;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_collect_attestation_evidence(sgx_report_t* p_report, ecdsa_attestation_evidence_t* evidence)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_report = sizeof(sgx_report_t);
	size_t _len_evidence = sizeof(ecdsa_attestation_evidence_t);

	ms_ocall_collect_attestation_evidence_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_collect_attestation_evidence_t);
	void *__tmp = NULL;

	void *__tmp_evidence = NULL;

	CHECK_ENCLAVE_POINTER(p_report, _len_p_report);
	CHECK_ENCLAVE_POINTER(evidence, _len_evidence);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_report != NULL) ? _len_p_report : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (evidence != NULL) ? _len_evidence : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_collect_attestation_evidence_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_collect_attestation_evidence_t));
	ocalloc_size -= sizeof(ms_ocall_collect_attestation_evidence_t);

	if (p_report != NULL) {
		ms->ms_p_report = (sgx_report_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, p_report, _len_p_report)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_report);
		ocalloc_size -= _len_p_report;
	} else {
		ms->ms_p_report = NULL;
	}
	
	if (evidence != NULL) {
		ms->ms_evidence = (ecdsa_attestation_evidence_t*)__tmp;
		__tmp_evidence = __tmp;
		memset(__tmp_evidence, 0, _len_evidence);
		__tmp = (void *)((size_t)__tmp + _len_evidence);
		ocalloc_size -= _len_evidence;
	} else {
		ms->ms_evidence = NULL;
	}
	
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (evidence) {
			if (memcpy_s((void*)evidence, _len_evidence, __tmp_evidence, _len_evidence)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_ratls_get_target_info(sgx_target_info_t* qe_target_info)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_qe_target_info = sizeof(sgx_target_info_t);

	ms_ocall_ratls_get_target_info_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_ratls_get_target_info_t);
	void *__tmp = NULL;

	void *__tmp_qe_target_info = NULL;

	CHECK_ENCLAVE_POINTER(qe_target_info, _len_qe_target_info);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (qe_target_info != NULL) ? _len_qe_target_info : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_ratls_get_target_info_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_ratls_get_target_info_t));
	ocalloc_size -= sizeof(ms_ocall_ratls_get_target_info_t);

	if (qe_target_info != NULL) {
		ms->ms_qe_target_info = (sgx_target_info_t*)__tmp;
		__tmp_qe_target_info = __tmp;
		memset(__tmp_qe_target_info, 0, _len_qe_target_info);
		__tmp = (void *)((size_t)__tmp + _len_qe_target_info);
		ocalloc_size -= _len_qe_target_info;
	} else {
		ms->ms_qe_target_info = NULL;
	}
	
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (qe_target_info) {
			if (memcpy_s((void*)qe_target_info, _len_qe_target_info, __tmp_qe_target_info, _len_qe_target_info)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

