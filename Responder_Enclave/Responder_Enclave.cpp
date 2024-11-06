#include "Responder_Enclave_t.h"

int ecall_responder_proc_msg2()
{
    ocall_print("exchange REPORTs");
    ocall_print("send msg2 and generate msg3");
    // sgx_dh_session_enclave_identity_t initiator_identity;
    // sgx_status_t status;
    // status = sgx_dh_responder_proc_msg2(msg2, msg3, &responder_session, &responder_aek, &initiator_identity);
    
    /* MRENCLAVE
     * MRSIGNER
     * ISV ProdID
     * ISVSVN
     * */

    return 0;
}

int ecall_responder_gen_msg1()
{
    const char *s = "generate msg1 and get responder's public key and target info";
    ocall_print(s);
    // sgx_dh_responder_gen_msg1();
    return 0;
}

int ecall_responder_init_session()
{
    const char *s = "initialize responder's session";
    ocall_print(s);
    // sgx_dh_session_t sgx_dh_session;
    // sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    return 0;
}

int ecall_responder_example()
{
    return 0;
}

