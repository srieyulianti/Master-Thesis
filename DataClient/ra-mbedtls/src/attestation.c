/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2018-2020 Invisible Things Lab
 *                         Rafal Wojdyla <omeg@invisiblethingslab.com>
 */

#include "attestation.h"

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_report.h>

#include "cJSON.h"
#include "util.h"

// Copied from Graphene's api.h.
// TODO: Remove after Graphene's C utils get refactored into a separate module/header (we can't
// include it here, because these SGX tools should be independent of Graphene).
#define IS_ALIGNED_POW2(val, alignment)     (((val) & ((alignment) - 1)) == 0)
#define IS_ALIGNED_PTR_POW2(val, alignment) IS_ALIGNED_POW2((uintptr_t)(val), alignment)

// TODO: decode some known values (flags etc)
void display_report_body(const sgx_report_body_t* body) {
    INFO(" cpu_svn          : ");
    HEXDUMP(body->cpu_svn);
    INFO(" misc_select      : ");
    HEXDUMP(body->misc_select);
    INFO(" reserved1        : ");
    HEXDUMP(body->reserved1);
    INFO(" isv_ext_prod_id  : ");
    HEXDUMP(body->isv_ext_prod_id);
    INFO(" attributes.flags : ");
    HEXDUMP(body->attributes.flags);
    INFO(" attributes.xfrm  : ");
    HEXDUMP(body->attributes.xfrm);
    INFO(" mr_enclave       : ");
    HEXDUMP(body->mr_enclave);
    INFO(" reserved2        : ");
    HEXDUMP(body->reserved2);
    INFO(" mr_signer        : ");
    HEXDUMP(body->mr_signer);
    INFO(" reserved3        : ");
    HEXDUMP(body->reserved3);
    INFO(" config_id        : ");
    HEXDUMP(body->config_id);
    INFO(" isv_prod_id      : ");
    HEXDUMP(body->isv_prod_id);
    INFO(" isv_svn          : ");
    HEXDUMP(body->isv_svn);
    INFO(" config_svn       : ");
    HEXDUMP(body->config_svn);
    INFO(" reserved4        : ");
    HEXDUMP(body->reserved4);
    INFO(" isv_family_id    : ");
    HEXDUMP(body->isv_family_id);
    INFO(" report_data      : ");
    HEXDUMP(body->report_data);
}

void display_quote(const void* quote_data, size_t quote_size) {
    if (quote_size < offsetof(sgx_quote_t, signature_len)) {
        ERROR("Quote size too small\n");
        return;
    }

    assert(IS_ALIGNED_PTR_POW2(quote_data, alignof(sgx_quote_t)));
    sgx_quote_t* quote = (sgx_quote_t*)quote_data;
    INFO("version           : ");
    HEXDUMP(quote->version);
    INFO("sign_type         : ");
    HEXDUMP(quote->sign_type);
    INFO("epid_group_id     : ");
    HEXDUMP(quote->epid_group_id);
    INFO("qe_svn            : ");
    HEXDUMP(quote->qe_svn);
    INFO("pce_svn           : ");
    HEXDUMP(quote->pce_svn);
    INFO("xeid              : ");
    HEXDUMP(quote->xeid);
    INFO("basename          : ");
    HEXDUMP(quote->basename);
    INFO("report_body       :\n");
    display_report_body(&quote->report_body);

    // quotes from IAS reports are missing signature fields
    if (quote_size >= sizeof(sgx_quote_t)) {
        INFO("signature_len     : %d (0x%x)\n", quote->signature_len, quote->signature_len);
    }

    if (quote_size >= sizeof(sgx_quote_t) + quote->signature_len) {
        INFO("signature         : ");
        hexdump_mem(&quote->signature, quote->signature_len);
        INFO("\n");
    }
}

int verify_quote(const void* quote_data, size_t quote_size, const char* mr_signer,
                 const char* mr_enclave, const char* isv_prod_id, const char* isv_svn,
                 const char* report_data, bool expected_as_str) {
    int ret = -1;

    assert(IS_ALIGNED_PTR_POW2(quote_data, alignof(sgx_quote_t)));
    sgx_quote_t* quote = (sgx_quote_t*)quote_data;

    // Quote contained in the IAS report doesn't contain signature_len and signature fields
    // Reject any smaller quotes as invalid
    size_t ias_quote_size = offsetof(sgx_quote_t, signature_len);
    if (quote_size < ias_quote_size) {
        ERROR("Quote: Bad size %zu < %zu\n", quote_size, ias_quote_size);
        goto out;
    }

    if (get_verbose())
        display_quote(quote_data, quote_size);

    sgx_report_body_t* body = &quote->report_body;

    sgx_measurement_t expected_mr;
    if (mr_signer) {
        if (expected_as_str) {
            if (parse_hex(mr_signer, &expected_mr, sizeof(expected_mr)) != 0)
                goto out;
        } else {
            memcpy(&expected_mr, mr_signer, sizeof(expected_mr));
        }

        if (memcmp(&body->mr_signer, &expected_mr, sizeof(expected_mr)) != 0) {
            ERROR("Quote: mr_signer doesn't match the expected value\n");
            if (get_verbose()) {
                ERROR("Quote mr_signer:\n");
                HEXDUMP(body->mr_signer);
                ERROR("Expected mr_signer:\n");
                HEXDUMP(expected_mr);
            }
            goto out;
        }

        DBG("Quote: mr_signer OK\n");
    }

    if (mr_enclave) {
        if (expected_as_str) {
            if (parse_hex(mr_enclave, &expected_mr, sizeof(expected_mr)) != 0)
                goto out;
        } else {
            memcpy(&expected_mr, mr_enclave, sizeof(expected_mr));
        }

        if (memcmp(&body->mr_enclave, &expected_mr, sizeof(expected_mr)) != 0) {
            ERROR("Quote: mr_enclave doesn't match the expected value\n");
            if (get_verbose()) {
                ERROR("Quote mr_enclave:\n");
                HEXDUMP(body->mr_enclave);
                ERROR("Expected mr_enclave:\n");
                HEXDUMP(expected_mr);
            }
            goto out;
        }

        DBG("Quote: mr_enclave OK\n");
    }

    // Product ID must match, security version must be greater or equal
    if (isv_prod_id) {
        sgx_prod_id_t prod_id;

        if (expected_as_str) {
            prod_id = strtoul(isv_prod_id, NULL, 10);
        } else {
            memcpy(&prod_id, isv_prod_id, sizeof(prod_id));
        }

        if (body->isv_prod_id != prod_id) {
            ERROR("Quote: invalid isv_prod_id (%u, expected %u)\n", body->isv_prod_id, prod_id);
            goto out;
        }

        DBG("Quote: isv_prod_id OK\n");
    }

    if (isv_svn) {
        sgx_isv_svn_t svn;

        if (expected_as_str) {
            svn = strtoul(isv_svn, NULL, 10);
        } else {
            memcpy(&svn, isv_svn, sizeof(svn));
        }

        if (body->isv_svn < svn) {
            ERROR("Quote: invalid isv_svn (%u < expected %u)\n", body->isv_svn, svn);
            goto out;
        }

        DBG("Quote: isv_svn OK\n");
    }

    if (report_data) {
        sgx_report_data_t rd;

        if (expected_as_str) {
            if (parse_hex(report_data, &rd, sizeof(rd)) != 0)
                goto out;
        } else {
            memcpy(&rd, report_data, sizeof(rd));
        }

        if (memcmp(&body->report_data, &rd, sizeof(rd)) != 0) {
            ERROR("Quote: report_data doesn't match the expected value\n");
            if (get_verbose()) {
                ERROR("Quote report_data:\n");
                HEXDUMP(body->report_data);
                ERROR("Expected report_data:\n");
                HEXDUMP(rd);
            }
            goto out;
        }

        DBG("Quote: report_data OK\n");
    }

    ret = 0;
    // TODO: KSS support (isv_ext_prod_id, config_id, config_svn, isv_family_id)
out:
    return ret;
}
