#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sgx_uae_service.h>
#include <sgx_urts.h>
#include <sgx_report.h>

#include <sgx_dcap_ql_wrapper.h>
#include <sgx_ql_lib_common.h>
#include <sgx_error.h>
#include <sgx_quote_3.h>

#include <ra.h>
#include <ra-attester.h>
#include "ias-ra.h"

void ecdsa_get_quote(sgx_report_t* report, uint8_t* quote, uint32_t* quote_len)
{
	uint32_t quote_size = 0;

	quote3_error_t qe3_ret = sgx_qe_get_quote_size(&quote_size);
	if (SGX_QL_SUCCESS != qe3_ret) {
		fprintf(stderr, "Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
		return;
	}

	qe3_ret = sgx_qe_get_quote(report,
			quote_size,
			quote);
	if (SGX_QL_SUCCESS != qe3_ret) {
		fprintf(stderr, "Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
		return;
	}

	*quote_len = quote_size;
}

void ocall_ratls_get_target_info(sgx_target_info_t* qe_target_info)
{
	int qe3_ret = sgx_qe_get_target_info(qe_target_info);
	if (SGX_QL_SUCCESS != qe3_ret) {
		fprintf(stderr, "Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
	}
}

void ocall_collect_attestation_evidence(sgx_report_t* app_report,
					ecdsa_attestation_evidence_t* evidence)
{
	ecdsa_get_quote(app_report, evidence->quote, &evidence->quote_len);
}




