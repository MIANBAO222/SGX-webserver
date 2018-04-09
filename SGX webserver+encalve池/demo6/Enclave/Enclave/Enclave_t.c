#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_foo_t {
	char* ms_buf;
	size_t ms_len;
} ms_foo_t;

typedef struct ms_hendlemessage_enclave_process_t {
	struct message* ms_message;
} ms_hendlemessage_enclave_process_t;

typedef struct ms_ocall_print_string_t {
	char* ms_fmt;
	char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_send_t {
	int ms_retval;
	int* ms_len;
	char* ms_buf;
	size_t ms_buf_siz;
	int* ms_i;
	int* ms_t;
} ms_ocall_send_t;

typedef struct ms_ocall_readfile_in_binary_t {
	int* ms_flag;
	size_t ms_buffersize;
	int* ms_filesize;
	char* ms_buffer;
	char* ms_path;
} ms_ocall_readfile_in_binary_t;

typedef struct ms_ocall_readfile_in_binary_test_t {
	char* ms_buffer;
	char* ms_path;
} ms_ocall_readfile_in_binary_test_t;

typedef struct ms_ocall_set_active_to_false_t {
	struct message* ms_message;
} ms_ocall_set_active_to_false_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_foo(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_foo_t));
	ms_foo_t* ms = SGX_CAST(ms_foo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _len_buf = sizeof(*_tmp_buf);
	char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ((_in_buf = (char*)malloc(_len_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf, 0, _len_buf);
	}
	foo(_in_buf, ms->ms_len);
err:
	if (_in_buf) {
		memcpy(_tmp_buf, _in_buf, _len_buf);
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_hendlemessage_enclave_process(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_hendlemessage_enclave_process_t));
	ms_hendlemessage_enclave_process_t* ms = SGX_CAST(ms_hendlemessage_enclave_process_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct message* _tmp_message = ms->ms_message;
	size_t _len_message = sizeof(*_tmp_message);
	struct message* _in_message = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);

	if (_tmp_message != NULL && _len_message != 0) {
		_in_message = (struct message*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_message, _tmp_message, _len_message);
	}
	hendlemessage_enclave_process(_in_message);
err:
	if (_in_message) {
		memcpy(_tmp_message, _in_message, _len_message);
		free(_in_message);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_foo, 0},
		{(void*)(uintptr_t)sgx_hendlemessage_enclave_process, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[10][2];
} g_dyn_entry_table = {
	10,
	{
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* fmt, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fmt = fmt ? strlen(fmt) + 1 : 0;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (fmt != NULL && sgx_is_within_enclave(fmt, _len_fmt)) ? _len_fmt : 0;
	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (fmt != NULL && sgx_is_within_enclave(fmt, _len_fmt)) {
		ms->ms_fmt = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_fmt);
		memcpy((void*)ms->ms_fmt, fmt, _len_fmt);
	} else if (fmt == NULL) {
		ms->ms_fmt = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send(int* retval, int* len, char* buf, size_t buf_siz, int* i, int* t)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_len = sizeof(*len);
	size_t _len_buf = 100;
	size_t _len_i = sizeof(*i);
	size_t _len_t = sizeof(*t);

	ms_ocall_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_t);
	void *__tmp = NULL;

	ocalloc_size += (len != NULL && sgx_is_within_enclave(len, _len_len)) ? _len_len : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;
	ocalloc_size += (i != NULL && sgx_is_within_enclave(i, _len_i)) ? _len_i : 0;
	ocalloc_size += (t != NULL && sgx_is_within_enclave(t, _len_t)) ? _len_t : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_t));

	if (len != NULL && sgx_is_within_enclave(len, _len_len)) {
		ms->ms_len = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_len);
		memcpy(ms->ms_len, len, _len_len);
	} else if (len == NULL) {
		ms->ms_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy(ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_buf_siz = buf_siz;
	if (i != NULL && sgx_is_within_enclave(i, _len_i)) {
		ms->ms_i = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_i);
		memcpy(ms->ms_i, i, _len_i);
	} else if (i == NULL) {
		ms->ms_i = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (t != NULL && sgx_is_within_enclave(t, _len_t)) {
		ms->ms_t = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_t);
		memcpy(ms->ms_t, t, _len_t);
	} else if (t == NULL) {
		ms->ms_t = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;
	if (len) memcpy((void*)len, ms->ms_len, _len_len);
	if (i) memcpy((void*)i, ms->ms_i, _len_i);
	if (t) memcpy((void*)t, ms->ms_t, _len_t);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_readfile_in_binary(int* flag, size_t buffersize, int* filesize, char* buffer, const char* path)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_flag = sizeof(*flag);
	size_t _len_filesize = sizeof(*filesize);
	size_t _len_buffer = buffersize;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_readfile_in_binary_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readfile_in_binary_t);
	void *__tmp = NULL;

	ocalloc_size += (flag != NULL && sgx_is_within_enclave(flag, _len_flag)) ? _len_flag : 0;
	ocalloc_size += (filesize != NULL && sgx_is_within_enclave(filesize, _len_filesize)) ? _len_filesize : 0;
	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;
	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readfile_in_binary_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readfile_in_binary_t));

	if (flag != NULL && sgx_is_within_enclave(flag, _len_flag)) {
		ms->ms_flag = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_flag);
		memcpy(ms->ms_flag, flag, _len_flag);
	} else if (flag == NULL) {
		ms->ms_flag = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_buffersize = buffersize;
	if (filesize != NULL && sgx_is_within_enclave(filesize, _len_filesize)) {
		ms->ms_filesize = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_filesize);
		memcpy(ms->ms_filesize, filesize, _len_filesize);
	} else if (filesize == NULL) {
		ms->ms_filesize = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		memcpy(ms->ms_buffer, buffer, _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);

	if (flag) memcpy((void*)flag, ms->ms_flag, _len_flag);
	if (filesize) memcpy((void*)filesize, ms->ms_filesize, _len_filesize);
	if (buffer) memcpy((void*)buffer, ms->ms_buffer, _len_buffer);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_readfile_in_binary_test(char* buffer, const char* path)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buffer = 300;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_readfile_in_binary_test_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_readfile_in_binary_test_t);
	void *__tmp = NULL;

	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;
	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_readfile_in_binary_test_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_readfile_in_binary_test_t));

	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		memcpy(ms->ms_buffer, buffer, _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy((void*)ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(3, ms);

	if (buffer) memcpy((void*)buffer, ms->ms_buffer, _len_buffer);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_set_active_to_false(struct message* message)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_message = sizeof(*message);

	ms_ocall_set_active_to_false_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_set_active_to_false_t);
	void *__tmp = NULL;

	ocalloc_size += (message != NULL && sgx_is_within_enclave(message, _len_message)) ? _len_message : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_set_active_to_false_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_set_active_to_false_t));

	if (message != NULL && sgx_is_within_enclave(message, _len_message)) {
		ms->ms_message = (struct message*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_message);
		memcpy(ms->ms_message, message, _len_message);
	} else if (message == NULL) {
		ms->ms_message = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(4, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memset(ms->ms_cpuinfo, 0, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(5, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
