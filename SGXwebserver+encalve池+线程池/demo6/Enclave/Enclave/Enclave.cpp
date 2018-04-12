
#include "sgx_trts.h"
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include <string.h>
/*c++support*/
#include <string>
#include <vector>
#include <iterator>
#include <typeinfo>
#include <functional>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <initializer_list>
#include <tuple>
#include <memory>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <map>
/*file protect support*/
#include<sgx_dh.h>
#include<stdio.h>
/*
* printf:
*   Invokes OCALL to display the enclave buffer to the terminal.
*/
void printf_oversize(int bufsize,const char *fmt, ...)
{	
	int oversize_flag = 0;
	char buf_BUFIZ[BUFSIZ] = { '\0' };
	char *buf;
	if (bufsize >= BUFSIZ) {
		oversize_flag = 1;
		buf = (char*)malloc(sizeof(char)*bufsize);
		memset(buf, 0, sizeof(buf));
	}
	else {
		buf = buf_BUFIZ;
	}
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, bufsize, fmt, ap);
	va_end(ap);
	buf[strlen(buf)] = '\0';
	int i = strlen(buf) / sizeof(char);
	std::string lenth = std::to_string(i);
	ocall_print_string("%d\n", lenth.c_str());
	buf[bufsize - 1] = '\0';
	ocall_print_string(fmt,buf);
	if (oversize_flag == 1) {
		free(buf);
	}
}
void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(fmt,buf);
}
void foo(char *buf, size_t len)
{
	const char *secrect = "HELLO SGX";

	if (len > strlen(secrect))
	{
		memcpy(buf, secrect, strlen(secrect) + 1);
		printf("666");
	}
}
void sendMessage(std::string path, struct message *msg) {
	/*get发送消息方法*/
	char *file_buffer;//文件buffer指针
	char buffer_defult[300]= { '\0' };
	char sending_buffer[1000] = {'\0'};//发送缓冲区
	//默认使用空间为300的栈数组
	file_buffer = buffer_defult;
	//读取文件的参数
	int flag;
	int filesize;
	size_t buffersize = 299 * sizeof(char);//最后一个是\0

	ocall_readfile_in_binary(&flag, buffersize, &filesize, file_buffer, path.c_str());
	/*测试输出传出消息*/
	//printf("%s\n", file_buffer);
	
	//文件过大
	if (flag == -2) {
		file_buffer = (char*)malloc(sizeof(char)*filesize+1);
		memset(file_buffer, 0, sizeof(char) * (filesize + 1));
		file_buffer[filesize] = '\0';
		buffersize = sizeof(char)*filesize + 1;
		ocall_readfile_in_binary(&flag, buffersize, &filesize, file_buffer, path.c_str());
	}
	//找不到文件
	if (flag==-1) {
		char *tmp = "HTTP/1.1 404 Not Found\n";
		strncpy(sending_buffer,tmp,strlen(tmp));
		printf("file no open\n");
	}
	else {
		//完成报头
		char length[20];
		snprintf(length, 20,"%d", filesize);
		char *tmp = "HTTP/1.1 200 OK\n";
		strncpy(sending_buffer,tmp,strlen(tmp));
		tmp = "Content-Type: text/html;charset=ISO-8859-1\nContent-Length: ";
		strncat(sending_buffer, tmp, strlen(tmp));
		strncat(sending_buffer, length, strlen(length));
		tmp = "\n\n";
		strncat(sending_buffer, tmp,strlen(tmp));
		//send参数
		int total_size = 0;
		int r=0;
		int i = strlen(sending_buffer);
		int t = 0;
		size_t msgdatasize = i;
		//测试
		//printf("sending_buffer->%s\n", sending_buffer);
   		ocall_send(&r,&msg->clientSocket, sending_buffer, msgdatasize,&i , &t);
		//发送失败
		if (r == -1) {
			ocall_set_active_to_false(msg);
			//*msg->isActive = false;
			return;
		}
		//发送成功
		else {
			//printf("send success\n");
		}
		char buffer_for_each_message[100] = {'\0'};
		//int s = filesize + strlen(sending_buffer) + 1;未使用
		int len = filesize;
		total_size = 0;
		int message_buffer_size = sizeof(buffer_for_each_message);
		while (len > 0) {
			int size = message_buffer_size < len ? message_buffer_size : len;
			strncpy(buffer_for_each_message, file_buffer + total_size, size);
			total_size += size;
			len -= size;
			int r;
			size_t buffer_siz = message_buffer_size;
			int t = 0;
			ocall_send(&r,&msg->clientSocket, buffer_for_each_message, buffer_siz, &size, &t);
			if (r == -1) {
				printf("send failed\n");
				ocall_set_active_to_false(msg);
				//*msg->isActive = false;
				return;
			}
		}
		//printf("send success\n");
	}
	if (*file_buffer != *buffer_defult) {
		free(file_buffer);
	}
	//todo
	//std::ifstream in(path, std::ios::binary);
	/*std::ifstream in(path, std::ios::binary);
	int sp;
	if (!in) {
		strcpy(msg.data, "HTTP/1.1 404 Not Found\n");
		printf("file no open\n");
	}*/
}
void hendlemessage_enclave_process(struct message *msg) {
	//to do
	//printf_oversize(1000,"%s\n",msg->data);
	int i = 0, cnt = 0;
	bool flag = false;
	bool post_flag = false;
	std::string str = "";
	std::string type = "";
	std::string data = "";
	if (msg->data == "" || msg->data == "\n") {
		ocall_set_active_to_false(msg);
		//*msg->isActive = false;
		return;
	}
	//解析http头部  
	while (1) {
		if (msg->data[i] == '\n' && msg->data[i + 2] == '\n')break;
		if (msg->data[i] == ' ') {
			if (flag) {
				data = str;
				flag = false;
				break;
			}
			else if (str == "GET") {
				type = str;
				flag = true;
			}
			else if (str == "POST") {
				type = str;

			}
			str = "";
		}
		else if (msg->data[i] == '\n');
		else {
			str = str + msg->data[i];
		}
		i++;
	}
	if (type == "POST") {

		bool login_flag = false;
		bool pass_flag = false;
		std::string name = "";
		std::string passwd = "";
		str = "";
		for (int j = i + 3; j <= strlen(msg->data); j++) {
			if (msg->data[j] == '&' || msg->data[j] == '=' || j == strlen(msg->data)) {
				printf("%s\n",str.c_str());
				if (login_flag) {
					if (str == "123") {
						name = str;
						passwd = "123";
					}
					else {
						passwd = "";
					}
					login_flag = false;
				}
				else if (pass_flag) {

					if (str == passwd && str != "") {
						printf("str=");
						printf("%s", str.c_str());
						printf(" paw=");
						printf("%s\n", passwd);
						char response[200];
						char *tmp = "<html><body>欢迎您,";
						strncpy(response, tmp,strlen(tmp));
						strncat(response, name.c_str(),name.size());
						tmp = "!</body></html>\n";
						strncat(response, tmp,strlen(tmp));
						int len = strlen(response);
						char length[20];
						snprintf(length, 20, "%d", len);
						tmp = "HTTP/1.1 200 OK\n";
						strncpy(response, tmp, strlen(tmp));
						tmp = "Content-Type: text/html;charset=gb2312\nContent-Length: ";
						strncat(msg->data, tmp,strlen(tmp));
						strncat(msg->data, length,strlen(length));
						tmp = "\n\n";
						strncat(msg->data, tmp, strlen(tmp));
						strncat(msg->data, response,strlen(response));
						printf("%s\n", msg->data);
						int r;
						int t = 10000;
						size_t buffer_siz = strlen(msg->data) + 1;
						ocall_send(&r,&msg->clientSocket, msg->data, buffer_siz, &t, 0);
						if (r == -1) {
							ocall_set_active_to_false(msg);
							//*msg->isActive = false;
							return;
						}
						printf("send success\n");
						ocall_set_active_to_false(msg);
						//*msg->isActive = false;
						return;
					}
					else {
						printf("str=");
						printf("%s", str.c_str());
						printf(" paw=");
						printf("%s\n", passwd);
						char response[200];
						char *tmp = "<html><body>登录失败</body></html>\n";
						strncpy(response, tmp, strlen(tmp));
						int len = strlen(response);
						char length[20];
						snprintf(length, 20, "%d", len);
						tmp = "HTTP/1.1 200 OK\n";
						strncpy(msg->data, tmp,strlen(tmp));
						tmp = "Content-Type: text/html;charset=gb2312\nContent-Length: ";
						strncpy(msg->data, tmp, strlen(tmp));
						strncat(msg->data, length, strlen(length));
						tmp = "\n\n";
						strncpy(msg->data, tmp, strlen(tmp));
						strncat(msg->data, response,strlen(response));
						printf("%s\n", msg->data);
						int r;
						int t = 10000;
						size_t buffer_siz = strlen(msg->data)+1;
						ocall_send(&r,&msg->clientSocket, msg->data, buffer_siz,&t, 0);
						if (r == -1) {
							ocall_set_active_to_false(msg);
							//*msg->isActive = false;
							return;
						}
						printf("send success\n");
						ocall_set_active_to_false(msg);
						//*msg->isActive = false;
						return;
					}
					pass_flag = false;
				}
				else if (str == "login") {
					login_flag = true;
				}
				else if (str == "pass") {
					pass_flag = true;
				}
				if (j == data.size())break;
				str = "";
			}
			else {
				str = str + msg->data[j];
			}
		}
		return;
	}
		else if (type == "GET" && data != "") {

			memset(msg->data, 0, sizeof(msg->data));
			if (data.substr(0, 5) == "/net/") {
				std::string str = "";
				std::string str1 = "";
				std::string passwd;
				std::string name;
				std::string path;

				bool txt_flag = false;
				for (int i = 5; i < data.size(); i++) {
					if (data[i] == '.') {
						flag = true;
					}
					else if (flag) {
						str = str + data[i];
					}
				}

				if (str == "") {
					ocall_set_active_to_false(msg);
					//*msg->isActive = false;
					return;
				}
				//printf("str=");
				//printf("%s",str.c_str());
				//printf(",");
				if (str == "txt") {
					path = "catalog/txt/" + data.substr(5);
				}
				else if (str == "html") {
					//printf("yes");
					path = "catalog/html/" + data.substr(5);
					//printf("path=");
					//printf("%s\n", path.c_str());
				}
				//printf("str=");
				//printf("%s\n", str.c_str());
				sendMessage(path, msg);
			}
			else if (data.substr(0, 5) == "/img/") {
				int total_size;
				int s;
				std::string path = "catalog/img/" + data.substr(5);
				sendMessage(path, msg);
			}
		}
		ocall_set_active_to_false(msg);
		//*msg->isActive = false;//无法操作
}