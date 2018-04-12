// App.cpp : �������̨Ӧ�ó������ڵ㡣

#include "stdafx.h"
#include"httpServer.h" 

void ocall_print_string(const char *fmt,const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	* the input string to prevent buffer overflow.
	*/
	printf(fmt, str);
}
int ocall_send(int *len, char* buf, size_t buf_siz,int *i, int *t) {
	//printf("len->%d\n", len);
	//printf("buf->%s\n", buf);
	//printf("i->%d\n", i);
	//printf("t->%d", t);
	int r = send(*len, buf, *i, *t);
	if (r == SOCKET_ERROR) {
		printf("send failed\n");
		//*msg.isActive = false;working in the enclave
		return -1;
	}
	return 0;
}
void ocall_readfile_in_binary_test(char* buffer, const char* path)
{
	FILE *fp;
	fopen_s(&fp, path, "rb");
	int flen;
	if (NULL == fp)
	{
		//*flag = -1;
		return; /* ��ʧ�� */
	}
	else {
		fseek(fp, 0L, SEEK_END); /* ��λ���ļ�ĩβ */
		flen = ftell(fp); /* �õ��ļ���С */
						  //*filesize = flen;
			fseek(fp, 0L, SEEK_SET);
			char buff[200] = { '\0' };
			fread(buff, 1, flen, fp);			
			//printf("%s\n", buff);//test for html
			strncpy_s(buffer, 300, buff,flen );
			fclose(fp);
			//printf("closefilesucess");
			return;
	}
}
void ocall_set_active_to_false(struct message *message)
{
	*message->isActive = false;
	//printf("isactive->%d", message->isActive);
	return;
}
/*
*/
void ocall_readfile_in_binary(int *flag, size_t buffersize,int *filesize,char* buffer, const char* path)
{
	FILE *fp;
	fopen_s(&fp, path, "rb");
	int flen;
	if (NULL == fp)
	{
		*flag = -1;
		return; /* ��ʧ�� */
	}
	else {
		fseek(fp, 0L, SEEK_END); /* ��λ���ļ�ĩβ */
		flen = ftell(fp); /* �õ��ļ���С */
		*filesize = flen;
		if (flen < buffersize) {
			fseek(fp, 0L, SEEK_SET);
			fread(buffer, 1, flen,fp);
			//printf("%s\n", buffer);//test for html
			fclose(fp);
			//printf("closefilesucess");
			return;
		}
		else {
			*flag = -2;/*�ļ�����*/
			return;
		}
	}
	return;
	}
int say_hello(int i) {
	sgx_enclave_id_t eid = 0;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	printf("%d",i);
	char buffer[MAX_BUF_LEN] = "HELLO WORLD";
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("APP:ERROR%#x,fail to create a enclave space", ret);
		return -1;
	}
	else {
		foo(eid, buffer, MAX_BUF_LEN);
		printf("%s\n", buffer);
	}
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;
}
int main()
{
	/*std::thread* th;
	int i = 0;
	for (; i < 10; i++) {
		th = new std::thread(say_hello, i);
	}
	getchar();
	return 0;*/

	httpServer f;
	f.start();
	getchar();
}

