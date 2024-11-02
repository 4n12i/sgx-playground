/* App.cpp
 * outside of enclave (untrusted code)
 * define the entry point for the concole applcation
 * */

#include <string.h>
#include <iostream>
#include <fstream>

#include "sgx_urts.h"

#include "Enclave_u.h" /* untrusted */

#define ENCLAVE_NAME "enclave.signed.so"
#define SEALED_DATA_FILE "sealed.dat"

sgx_enclave_id_t global_eid = 0;

void ocall_print_status(sgx_status_t ret)
{
    std::cout << "sgx_status_t: " << ret << std::endl;
}

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

static bool write_buf_to_file(const char *filename, uint8_t *sealed, uint32_t sealed_len)
{
    if (filename == NULL)
    {
        return false;
    }
    std::ofstream ofs(filename, std::ios::binary | std::ios::out); /* prepare a file stream */
    if (!ofs.good())
    {
        std::cout << "failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ofs.write((const char*)sealed, sealed_len);
    if (ofs.fail())
    {
        std::cout << "failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}

bool test_seal_data()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t *sealed;
    uint32_t sealed_len = 0;

    ret = ecall_calc_sealed_len(global_eid, &sealed_len);
    sealed = new uint8_t[sealed_len];

    /* encrypt the data in enclave */
    ret = ecall_seal_data(global_eid, sealed_len, sealed);
    if (ret != SGX_SUCCESS)
    {
        std::cerr << "failed to seal the secret" << std::endl;
        return false;
    }

    /* save the sealed blob */
    if (!write_buf_to_file(SEALED_DATA_FILE, sealed, sealed_len)) 
    {
        std::cerr << "failed to save the sealed data blob to \"" << SEALED_DATA_FILE << "\"" << std::endl;
        return false;
    }

    std::cout << "sealing data succeeded" << std::endl;
    return true;
}

bool test_example()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = -9999;
    ret = ecall_example(global_eid, &retval);
    if (ret != SGX_SUCCESS) 
    {
        std::cerr << "failed to execute ECALL" << std::endl;
        return false;
    }

    std::cout << "execute ECALL" << std::endl;
    return true;
}

static sgx_status_t initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid) 
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    /* create and run the enclave */
    /* args: enclave image file, debug flag (macro), launch token (formality), update flag (formality), eclave ID, pointer */
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    return SGX_SUCCESS;
}

int main()
{
    /* initialize the enclave */
    sgx_status_t ret = initialize_enclave(ENCLAVE_NAME, &global_eid);
    if (ret != SGX_SUCCESS)
    {
        std::cerr << "failed to run the enclave." << std::endl;
        return -1;
    }

    /* start ECALL */
    if (!test_example()) 
    {
        std::cerr << "test_example failed" << std::endl;
    }
    if (!test_seal_data())
    {
        std::cerr << "test_seal_data failed" << std::endl;
    }
    /* destroy theh enclave */
    sgx_destroy_enclave(global_eid);

    std::cout << "successfully completed" << std::endl;

    return 0;
}

