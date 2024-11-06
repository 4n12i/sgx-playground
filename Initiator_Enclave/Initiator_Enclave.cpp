#include "Initiator_Enclave_t.h"

int ecall_initiator_proc_msg3()
{
    const char *s = "process msg3";
    ocall_print(s);
    // sgx_dh_session_enclave_identity_t responder_identity;
    // sgx_status_t status;
    // status = sgx_dh_initiator_proc_msg3(msg3, &initiator_session, &initiator_aek, &responder_identity);

    /* MRSIGNER
     * ISV ProdID
     * ISVSVN
     * */
    return 0;
}

int ecall_initiator_proc_msg1()
{
    const char *s = "process msg1 and generate msg2";
    ocall_print(s);
    // sgx_dh_initiator_proc_msg1();
    return 0;
}

int ecall_initiator_init_session() 
{
    const char *s = "initialize initiator's session";
    ocall_print(s);
    // sgx_dh_session_t sgx_dh_session;
    // sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    return 0;
}

int ecall_initiator_example()
{
    return 0;
}

