#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "httpServer_struct2.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void foo(char* buf, size_t len);
void hendlemessage_enclave_process(struct message* message);

sgx_status_t SGX_CDECL ocall_print_string(const char* fmt, const char* str);
sgx_status_t SGX_CDECL ocall_send(int* retval, int* len, char* buf, size_t buf_siz, int* i, int* t);
sgx_status_t SGX_CDECL ocall_readfile_in_binary(int* flag, size_t buffersize, int* filesize, char* buffer, const char* path);
sgx_status_t SGX_CDECL ocall_readfile_in_binary_test(char* buffer, const char* path);
sgx_status_t SGX_CDECL ocall_set_active_to_false(struct message* message);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
