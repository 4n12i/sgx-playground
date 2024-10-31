/* Enclave.cpp
 * inside of enclave (trusted code)
 * */

#include "sgx_urts.h"
#include "stdio.h"
#include "string.h"

#include "Enclave_t.h" // trusted

/* ECALL (Enclave CALL)
 * app -> enclave
 * call a function in the enclave from outside the enclave (entering the enclave; EENTER)
 * */
int ecall_example()
{
    ocall_example();
    return 10;
}

