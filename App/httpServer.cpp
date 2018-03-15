#include "stdafx.h"
#include"httpserver.h"
#include<cstdio>    
#include<cstdlib>    
#include<fstream>    
#include<cstring>    
#include<string>  
#include<windows.h>  
#include<iostream>
//#include"httpServer_struct.h"
#pragma comment(lib,"ws2_32.lib")
// Global data

int updated = 0;
/*
message 构造函数
unmodified
*/
void message_set(message *msg, char* d, bool* is, int c, int i) 
{ 
	msg->data = d;
	msg->isActive = is;
	msg->clientSocket = c;
	msg->id = i;
}
/*
close_message构造函数
unmodified
*/
void close_message_set(close_message *msg,bool* is, int s) 
{
	msg->isActive = is;
	msg->serverSocket = s;
}
/*
httpserver 构造函数 
unmodified
*/
httpServer::httpServer()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int ret;

	//WinSock初始化：    
	wVersionRequested = MAKEWORD(2, 2);//希望使用的WinSock DLL的版本    
	ret = WSAStartup(wVersionRequested, &wsaData);
	if (ret != 0)
	{
		printf("WSAStartup() failed!\n");
	}
	//确认WinSock DLL支持版本2.2：    
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		WSACleanup();
		printf("Invalid Winsock version!\n");
	}
}
int handleMessage(message msg) 
{
	/*为线程单独声明enclave并创建*/
	//创建enclave空间
	sgx_enclave_id_t eid = 0;
	int retval = 0;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("APP:ERROR%#x,fail to create a enclave space", ret);
		return -1;
	}
	else {
		//进入enclave
		//foo(eid, buffer, MAX_BUF_LEN);
		//C_message enclave_msg;
		//enclave_msg.clientSocket = msg.clientSocket;
		//enclave_msg.data = msg.data;
		//enclave_msg.id = msg.id;
		//enclave_msg.isActive = msg.isActive;
		hendlemessage_enclave_process(eid,&msg);
	}
	printf("%s\n", msg.data);
	free(msg.data);
	closesocket(msg.clientSocket);
	//printf("%s\n", msg.data);
	/*销毁空间*/
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;
}

/*
this part is working in the untursted place
全局函数
listenForClose()
等待键盘输入命令quit并结束程序
do not need to modify
*/
void listenForClose(close_message msg)
{
	std::string str;
	while (1) {
		std::cin >> str;

		if (str == "quit") {
			while (1) {
				bool flag = true;
				for (int i = 0; i < httpServer::MAX; i++) {
					if (msg.isActive[i]) {
						flag = false;
						break;
					}
				}
				if (flag) {
					closesocket(msg.serverSocket);
					exit(0);
				}
			}
		}
		else {
			printf("syntex error!\n");
		}
	}
}
/*
this part is working in the untursted place
httpServer::start()
webserver开启服务
do not need to modify
*/
bool httpServer::start()
{
	int on = 1;
	memset(isActive, false, sizeof(isActive));
	close_message msg ;
	close_message_set(&msg,isActive, serverSocket);
	th = new std::thread(listenForClose, msg);
	//初始化服务器    
	memset(&serverChannel, 0, sizeof(serverChannel));
	serverChannel.sin_family = AF_INET;
	serverChannel.sin_addr.s_addr = htonl(INADDR_ANY);
	serverChannel.sin_port = htons(SERVER_PORT);

	//创建套接字    
	serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket < 0) {
		printf("cannot create socket\n");
		return false;
	}
	else printf("successfully create socket\n");
	setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR,
		(char*)&on, sizeof(on));

	//绑定    
	int b = bind(serverSocket, (sockaddr*)&serverChannel,
		sizeof(serverChannel));
	if (b < 0) {
		printf("bind error\n");
		return false;
	}
	else printf("successfully bind\n");
	//监听    
	int l = listen(serverSocket, 2048);
	if (l < 0) {
		printf("listen failed\n");
		return false;
	}
	else printf("successfully listen\n");
	int len = sizeof(serverChannel);
	//服务器等待连接    

	while (1) {
		printf("waiting for connection...\n");
		//接受一个连接    
		clientSocket = accept(serverSocket, (sockaddr*)&serverChannel, &len);

		if (clientSocket < 0) {
			printf("accept failed\n");
		}
		else {
			printf("successfully connect\n");
			char *buffer = (char*)malloc(1000 * sizeof(char));
			memset(buffer, 0, sizeof(buffer));
			int ret;

			ret = recv(clientSocket, buffer, BUFFER_SIZE, 0);

			if (ret == SOCKET_ERROR) {
				printf("sorry receive failed\n");
			}
			else if (ret == 0) {
				printf("the client socket is closed\n");
			}
			else {
				printf("successfully receive\n");
				for (int i = 0; i < MAX; i++) {
					if (!isActive[i]) {
						isActive[i] = true;
						message msg;
						message_set(&msg,buffer, &isActive[i], clientSocket, i);
						t[i] = new std::thread(handleMessage, msg);
						break;
					}
				}
			}
		}
	}
}