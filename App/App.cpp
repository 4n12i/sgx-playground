/* App.cpp
 * outside of enclave (untrusted code)
 * define the entry point for the concole applcation
 * */

#include <string.h>
#include <iostream>

#include "sgx_urts.h"

#include "Enclave_u.h" // untrusted

#define ENCLAVE_NAME "enclave.signed.so"

/* OCALL (Outside CALL) 
 * enclave -> app
 * temporarily move from inside the enclave to outside the enclave (EEXIT)
 * and call a function outside the enclave
 * */
void ocall_example() 
{
    std::cout << "output from OCALL" << std::endl;
    return;
}

// initialize the enclave 
static sgx_status_t initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid) 
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // create and run the enclave
    // enclave image file, debug flag (macro), launch token (formality), update flag (formality), eclave ID, pointer
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    return SGX_SUCCESS;
}

int main()
{
    // initialize the enclave 
    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME, &eid);
    if (ret != SGX_SUCCESS)
    {
        std::cerr << "failed to run the enclave." << std::endl;
        return -1;
    }

    // start ECALL
    int retval = -9999;
    std::cout << "execute ECALL" << std::endl;
    sgx_status_t status = ecall_example(eid, &retval);
    if (status != SGX_SUCCESS) 
    {
        std::cerr << "failed to execute ECALL" << std::endl;
        return -1;
    }

    // destroy theh enclave
    sgx_destroy_enclave(eid);

    std::cout << "successfully completed" << std::endl;

    return 0;
}

