#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "httpServer_struct2.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* fmt, const char* str));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send, (int* len, char* buf, size_t buf_siz, int* i, int* t));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readfile_in_binary, (int* flag, size_t buffersize, int* filesize, char* buffer, const char* path));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readfile_in_binary_test, (char* buffer, const char* path));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t foo(sgx_enclave_id_t eid, char* buf, size_t len);
sgx_status_t hendlemessage_enclave_process(sgx_enclave_id_t eid, struct message* message);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
