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
message ���캯��
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
close_message���캯��
unmodified
*/
void close_message_set(close_message *msg,bool* is, int s) 
{
	msg->isActive = is;
	msg->serverSocket = s;
}
/*
httpserver ���캯�� 
unmodified
*/
httpServer::httpServer()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int ret;

	//WinSock��ʼ����    
	wVersionRequested = MAKEWORD(2, 2);//ϣ��ʹ�õ�WinSock DLL�İ汾    
	ret = WSAStartup(wVersionRequested, &wsaData);
	if (ret != 0)
	{
		printf("WSAStartup() failed!\n");
	}
	//ȷ��WinSock DLL֧�ְ汾2.2��    
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		WSACleanup();
		printf("Invalid Winsock version!\n");
	}
}
int handleMessage(message msg) 
{
	/*Ϊ�̵߳�������enclave������*/
	//����enclave�ռ�
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
		//����enclave
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
	/*���ٿռ�*/
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;
}

/*
this part is working in the untursted place
ȫ�ֺ���
listenForClose()
�ȴ�������������quit����������
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
webserver��������
do not need to modify
*/
bool httpServer::start()
{
	int on = 1;
	memset(isActive, false, sizeof(isActive));
	close_message msg ;
	close_message_set(&msg,isActive, serverSocket);
	th = new std::thread(listenForClose, msg);
	//��ʼ��������    
	memset(&serverChannel, 0, sizeof(serverChannel));
	serverChannel.sin_family = AF_INET;
	serverChannel.sin_addr.s_addr = htonl(INADDR_ANY);
	serverChannel.sin_port = htons(SERVER_PORT);

	//�����׽���    
	serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket < 0) {
		printf("cannot create socket\n");
		return false;
	}
	else printf("successfully create socket\n");
	setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR,
		(char*)&on, sizeof(on));

	//��    
	int b = bind(serverSocket, (sockaddr*)&serverChannel,
		sizeof(serverChannel));
	if (b < 0) {
		printf("bind error\n");
		return false;
	}
	else printf("successfully bind\n");
	//����    
	int l = listen(serverSocket, 2048);
	if (l < 0) {
		printf("listen failed\n");
		return false;
	}
	else printf("successfully listen\n");
	int len = sizeof(serverChannel);
	//�������ȴ�����    

	while (1) {
		printf("waiting for connection...\n");
		//����һ������    
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