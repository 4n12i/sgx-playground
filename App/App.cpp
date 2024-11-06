/* App.cpp
 * outside of enclave (untrusted code)
 * define the entry point for the concole applcation
 * */

#include <string.h>
#include <iostream>
#include <fstream>

#include <sgx_urts.h>

#include "Enclave_u.h" /* untrusted */
#include "Initiator_Enclave_u.h"
#include "Responder_Enclave_u.h"

#define ENCLAVE_NAME "enclave.signed.so"
#define SEALED_DATA_FILE "sealed.dat"

#define INITIATOR_ENCLAVE_NAME "initiator_enclave.signed.so"
#define RESPONDER_ENCLAVE_NAME "responder_enclave.signed.so"


sgx_enclave_id_t global_eid = 0;


/* helper functions
 * */
void print_status(sgx_status_t status)
{
    std::cout << "sgx_status_t: ";

    switch(status)
    {
        case 0: 
            std::cerr << "SGX_SUCCESS" << std::endl;
            break;
        case 1: 
            std::cerr << "SGX_ERROR_UNEXPECTED" << std::endl;
            break;
        case 2:
            std::cerr << "SGX_ERROR_INVALID_PARAMETER" << std::endl;
            break;
        default: 
            std::cerr << status << std::endl;
    }

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

static bool read_file_to_buf(const char *filename, uint8_t *buf, uint32_t buf_len)
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
    ifs.read((char*)buf, buf_len);
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
    std::ofstream ofs(filename, std::ios::binary | std::ios::out); 
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


/* OCALL (Outside CALL) implementations 
 * temporarily move from inside the enclave to outside the enclave (EEXIT) and call a function outside the enclave
 * */
void ocall_print(const char *s) 
{
    std::cout << "[OCALL] " << s << std::endl;
    return;
}

void ocall_print_status(sgx_status_t ret)
{
    print_status(ret);
    return;
}

void ocall_example() 
{
    std::cout << "output from OCALL" << std::endl;
    return;
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

    std::cout << "decrypted data is \"" << std::string((char*)unsealed, unsealed_len) << "\"" << std::endl;
    std::cout << "unsealing data succeeded" << std::endl;
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

int initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid) 
{
    /* prepare dummy token and update flag (deprecated parameters) */
    sgx_launch_token_t token = {0};
    int updated = 0;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* create and run the enclave */
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_status(ret);
        return -1;
    }

    return 0;
}

int main()
{
    /* initialize the enclave */
    if (initialize_enclave(ENCLAVE_NAME, &global_eid) != 0)
    {
        std::cerr << "failed to run the enclave" << std::endl;
        return -1;
    }

    /* start ECALLs */
    std::cout << "==============================" << std::endl;
    if (!test_example()) 
    {
        std::cerr << "test_example failed" << std::endl;
    }
    std::cout << "==============================" << std::endl;
    if (!test_seal_data())
    {
        std::cerr << "test_seal_data failed" << std::endl;
    }
    std::cout << "==============================" << std::endl;
    if (!test_unseal_data())
    {
        std::cerr << "test_unseal_data failed" << std::endl;
    }
    std::cout << "==============================" << std::endl;

    /* destroy the enclave */
    sgx_destroy_enclave(global_eid);


    /* LA (Local Attestation)
     * assert that two enclaves running on the same platform can trust each other and exchange information safely
     * see p.94 of the developer reference for more details
     * */
    sgx_enclave_id_t initiator_enclave_eid = 0;
    sgx_enclave_id_t responder_enclave_eid = 0;
    if (initialize_enclave(INITIATOR_ENCLAVE_NAME, &initiator_enclave_eid) != 0)
    {
        std::cerr << "failed to run the enclave" << std::endl;
        return -1;
    }
    if (initialize_enclave(RESPONDER_ENCLAVE_NAME, &responder_enclave_eid) != 0)
    {
        std::cerr << "failed to run the enclave" << std::endl;
        return -1;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int retval = -1;

    /* create ECDH sessions
     * */
    ret = ecall_initiator_init_session(initiator_enclave_eid, &retval);
    // ocall_initiator_request_session(); // to responder app
    // ecall_responder_request_session(); // to responder enclave
    ret = ecall_responder_init_session(responder_enclave_eid, &retval);
    
    /* generate msg1 to get the responder’s public key and target info
     * */
    // ecall_initiator_request_msg1();
    ret = ecall_responder_gen_msg1(responder_enclave_eid, &retval);
    // send msg1 from responder enclave to initiator enclave

    /* process msg1 and generate msg2
     * */
    ret = ecall_initiator_proc_msg1(initiator_enclave_eid, &retval);

    /* send msg2 to responder and verify initiator's REPORT
     * and then, generate msg3 to make initiator to verify responder's REPORT
     * */
    ret = ecall_responder_proc_msg2(responder_enclave_eid, &retval);

    /* send msg3 to initiator and verify responder's REPORT
     * initiator enclave
     * */
    ret = ecall_initiator_proc_msg3(initiator_enclave_eid, &retval);

    /* sample calculation */


    /* close ECDH session */


    ret = ecall_initiator_example(initiator_enclave_eid, &retval);
    print_status(ret);

    ret = ecall_responder_example(responder_enclave_eid, &retval);
    print_status(ret);

    sgx_destroy_enclave(initiator_enclave_eid);
    sgx_destroy_enclave(responder_enclave_eid);

    std::cout << "==============================" << std::endl;
    std::cout << "successfully completed" << std::endl;
    return 0;
}

