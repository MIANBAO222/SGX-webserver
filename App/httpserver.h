#pragma once


#include<winsock.h>    
#include<thread>  
#include"httpserver_struct2.h"
#include<cstdio>
class httpServer
{
private:
	enum {
		SERVER_PORT = 4548,
		BUFFER_SIZE = 1300,
		QUEUE_SIZE = 10,
		MAX = 1000
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