#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "quote_generation.h"

int main() {
    int sgx_fd;
    if ((sgx_fd = open("/dev/sgx", O_RDONLY)) < 0) {
        printf("failed to open /dev/sgx\n");
        return -1;
    }

    uint32_t quote_size = get_quote_size(sgx_fd);
    sgx_quote3_t *p_quote;
    sgx_ql_auth_data_t *p_auth_data;
    sgx_ql_ecdsa_sig_data_t *p_sig_data;
    sgx_ql_certification_data_t *p_cert_data;
    FILE *fptr = NULL;

    uint8_t *quote_buffer = (uint8_t *)malloc(quote_size);
    if (NULL == quote_buffer) {
        printf("Couldn't allocate quote_buffer\n");
        close(sgx_fd);
        return -1;
    }
    memset(quote_buffer, 0, quote_size);

    sgx_report_data_t report_data = { 0 };
    char *data = "ioctl DCAP report data example";
    memcpy(report_data.d, data, strlen(data));

    sgxioc_gen_dcap_quote_arg_t gen_quote_arg = {
        .report_data = &report_data,
        .quote_len = &quote_size,
        .quote_buf = quote_buffer
    };

    if (generate_quote(sgx_fd, &gen_quote_arg) != 0) {
        printf("failed to generate quote\n");
        close(sgx_fd);
        return -1;
    }

    p_quote = (sgx_quote3_t*)p_quote_buffer;
    p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
    p_auth_data = (sgx_ql_auth_data_t*)p_sig_data->auth_certification_data;
    p_cert_data = (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

    printf("cert_key_type = 0x%x\n", p_cert_data->cert_key_type);

    /*Write Quote*/
    fptr = fopen("quote.dat","wb");
    fwrite(p_quote, quote_size, 1, fptr);
    fclose(fptr);

    printf("Succeed to generate the quote!\n");

    