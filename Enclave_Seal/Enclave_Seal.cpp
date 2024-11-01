/* Enclave_Seal.cpp
 * */

#include "sgx_tseal.h"

/* determine how much memory to allocate for the sgx_sealed_data_t structure */
uint32_t ecall_calc_sealed_len(uint32_t data_len)
{
    return sgx_calc_sealed_data_size(0, data_len);
}

void ecall_seal_data(uint32_t data_len, uint8_t *data, uint32_t sealed_len, uint8_t *sealed)
{
    /* seal the data with the MRSIGNER policy */
    sgx_status_t status = sgx_seal_data(0, NULL, data_len, data, sealed_len, (sgx_sealed_data_t *)sealed);

    // ocall_print_error();
}

