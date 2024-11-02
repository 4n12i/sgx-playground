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

static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cerr << "failed to open the file \"" << filename << "\"" << std::endl;
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *sealed, uint32_t sealed_len)
{
    if (filename == NULL)
    {
        return false;
    }
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cerr << "failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ifs.read((char*)sealed, sealed_len);
    if (ifs.fail())
    {
        std::cerr << "failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
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
        std::cerr << "failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ofs.write((const char*)sealed, sealed_len);
    if (ofs.fail())
    {
        std::cerr << "failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
}

/* read the sealed data and decrypt it */
bool test_unseal_data()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint8_t *sealed;
    uint32_t sealed_len;
    uint8_t *unsealed;
    uint32_t unsealed_len;

    /* read the sealed blob from the file */
    sealed_len = (uint32_t)get_file_size(SEALED_DATA_FILE);
    if (sealed_len == (uint32_t)-1)
    {
        std::cerr << "failed to get the file size of \"" << SEALED_DATA_FILE << "\"" << std::endl;
        return false;
    }
    sealed = new uint8_t[sealed_len];
    if (!read_file_to_buf(SEALED_DATA_FILE, sealed, sealed_len))
    {
        std::cerr << "failed to read the sealed data blob from \"" << SEALED_DATA_FILE << "\"" << std::endl;
        return false;
    }

    /* unseal the sealed blob */
    ret = ecall_calc_unsealed_len(global_eid, &unsealed_len, sealed_len, sealed);
    unsealed = new uint8_t[unsealed_len];

    ret = ecall_unseal_data(global_eid, sealed_len, sealed, unsealed_len, unsealed);
    if (ret != SGX_SUCCESS)
    {
        return false;
    }

    std::cout << "unsealed data: " << std::string((char*)unsealed, unsealed_len) << std::endl;

    std::cout << "unseal succeeded" << std::endl;
    return true;
}

/* encrypt the data and save it to the file */
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

/* call ECALL example */
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
    if (!test_unseal_data())
    {
        std::cerr << "test_unseal_data failed" << std::endl;
    }

    /* destroy the enclave */
    sgx_destroy_enclave(global_eid);

    std::cout << "successfully completed" << std::endl;

    return 0;
}

