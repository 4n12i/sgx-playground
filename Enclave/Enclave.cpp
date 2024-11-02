/* Enclave.cpp
 * inside of enclave (trusted code)
 * */

#include <cstdio>
#include <cstring>

#include <sgx_tseal.h>

#include "Enclave_t.h" /* trusted */

char encrypt_data[BUFSIZ] = "data to encrypt";

/* determine how much memory to allocate for the `sgx_sealed_data_t` structure */
uint32_t ecall_calc_sealed_len()
{
    return sgx_calc_sealed_data_size(0, (uint32_t)strlen(encrypt_data));
}

/* seal the data with the MRSIGNER policy */
void ecall_seal_data(uint32_t sealed_len, uint8_t *sealed)
{
    sgx_status_t ret = sgx_seal_data(0, NULL, (uint32_t)strlen(encrypt_data), (uint8_t *)encrypt_data, sealed_len, (sgx_sealed_data_t *)sealed);

    ocall_print_status(ret);
}

/* ECALL (Enclave CALL)
 * app -> enclave
 * call a function in the enclave from outside the enclave (entering the enclave; EENTER)
 * */
int ecall_example()
{
    ocall_example();
    return 10;
}

