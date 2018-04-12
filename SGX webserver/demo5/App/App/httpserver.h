#pragma once


#include<winsock.h>    
#include<thread>  
#include"httpserver_struct2.h"
#include<cstdio>
#define QUEUE_SIZE 2048
extern sgx_enclave_id_t eidcount[QUEUE_SIZE];
class httpServer
{
private:
	enum {
		SERVER_PORT = 4547,
		BUFFER_SIZE = 1000,
		MAX = QUEUE_SIZE
	};
	//char buffer[BUFFER_SIZE];
	sockaddr_in serverChannel;
	std::thread* t[MAX];
	std::thread* th;
	char rootDir[50];
	char name[50];
	bool isActive[MAX];
	
	int serverSocket; //socket    
	int clientSocket;
	friend int handleMessage(message msg);
	friend void listenForClose(close_message msg);
public:
	httpServer();
	bool start();//¿ªÆô·þÎñÆ÷    
};