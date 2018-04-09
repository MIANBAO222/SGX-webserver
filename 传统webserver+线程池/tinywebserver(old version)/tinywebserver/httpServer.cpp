  #include "stdafx.h"
#include"httpServer.h"    
#include<cstdio>    
#include<cstdlib>    
#include<fstream>    
#include<cstring>    
#include<string>  
#include<windows.h>  
#include<iostream>  
#include <time.h>
#pragma comment(lib,"ws2_32.lib")
std::mutex mt;
int threadcount = 0;
int position = 0;
message::message(char* d, bool* is, int c, int i) :data(d), isActive(is), clientSocket(c), id(i) { }
close_message::close_message(bool* is, int s) : isActive(is), serverSocket(s) { }
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

void sendMessage(std::string path, message msg)
{
	//std::string test = "catalog/html/test.html";
	//std::ifstream in;
/*	if (path.compare(test)==0 ) {
	}
	else {
		std::ifstream in(path, std::ios::binary);
	}*/

	std::ifstream in(path, std::ios::binary);
	int sp;
	if (!in) {
		strcpy(msg.data, "HTTP/1.1 404 Not Found\n");
		printf("file no open\n");
	}
	else {
		in.seekg(0, std::ios_base::end);
		sp = in.tellg();
		char length[20];
		sprintf(length, "%d", sp);
		strcpy(msg.data, "HTTP/1.1 200 OK\n");
		strcat(msg.data, "Content-Type: text/html;charset=ISO-8859-1\nContent-Length: ");
		strcat(msg.data, length);
		strcat(msg.data, "\n\n");
		int total_size = 0;
		//printf("%s\n", msg.data);
		int r = send(msg.clientSocket, msg.data, strlen(msg.data), 0);
		if (r == SOCKET_ERROR) {
			printf("send failed\n");
			*msg.isActive = false;;
			return;
		}
		else {
			//printf("send success%d\n",msg.clientSocket);
		}
		char buffer[100];
		int s = sp + strlen(msg.data) + 1;

		int len = sp;
		total_size = 0;
		in.clear();
		in.seekg(0, std::ios_base::beg);

		while (len > 0) {
			memset(buffer, 0, sizeof(buffer));
			int size = sizeof(buffer) < len ? sizeof(buffer) : len;
			total_size += size;
			len -= size;
			in.read(buffer, size);
			//printf("%s\n", buffer);
			int r = send(msg.clientSocket, buffer, size, 0);

			if (r == SOCKET_ERROR) {
				printf("send failed\n");
				*msg.isActive = false;
				return;
			}
		}
	}
}

void httpServer::handleMessage(message msg)
{
	/*mt.lock();
	threadcount++;
	mt.unlock();*/
	int i = 0, cnt = 0;
	bool flag = false;
	bool post_flag = false;
	std::string str = "";
	std::string type = "";
	std::string data = "";
	//printf("你好呀！我是线程%d\ndata = %s\n", msg.id, msg.data);
	if (msg.data == "" || msg.data == "\n") {
		*msg.isActive = false;
		return;
	}
	//解析http头部  
	while (1) {
		if (msg.data[i] == '\n' && msg.data[i + 2] == '\n')break;
		if (msg.data[i] == ' ') {
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
		else if (msg.data[i] == '\n');
		else {
			str = str + msg.data[i];
		}
		i++;
	}

	if (type == "POST") {

		bool login_flag = false;
		bool pass_flag = false;
		std::string name = "";
		std::string passwd = "";
		str = "";
		for (int j = i + 3; j <= strlen(msg.data); j++) {
			if (msg.data[j] == '&' || msg.data[j] == '=' || j == strlen(msg.data)) {
				std::cout << str << std::endl;
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
						std::cout << "str=" << str << " " << "paw=" << passwd << std::endl;
						char response[200];
						strcpy(response, "<html><body>欢迎您,");
						strcat(response, name.c_str());
						strcat(response, "!</body></html>\n");
						int len = strlen(response);
						char length[20];
						sprintf(length, "%d", len);
						strcpy(msg.data, "HTTP/1.1 200 OK\n");
						strcat(msg.data, "Content-Type: text/html;charset=gb2312\nContent-Length: ");
						strcat(msg.data, length);
						strcat(msg.data, "\n\n");
						strcat(msg.data, response);
						//printf("%s\n", msg.data);
						int r = send(msg.clientSocket, msg.data, 10000, 0);

						if (r == SOCKET_ERROR) {
							printf("send failed\n");
							*msg.isActive = false;
							return;
						}
						printf("send success\n");
						*msg.isActive = false;
						return;
					}
					else {
						std::cout << "str=" << str << " " << "paw=" << passwd << std::endl;
						char response[200];
						strcpy(response, "<html><body>登录失败</body></html>\n");
						int len = strlen(response);
						char length[20];
						sprintf(length, "%d", len);
						strcpy(msg.data, "HTTP/1.1 200 OK\n");
						strcat(msg.data, "Content-Type: text/html;charset=gb2312\nContent-Length: ");
						strcat(msg.data, length);
						strcat(msg.data, "\n\n");
						strcat(msg.data, response);
						//printf("%s\n", msg.data);
						int r = send(msg.clientSocket, msg.data, 10000, 0);

						if (r == SOCKET_ERROR) {
							printf("send failed\n");
							*msg.isActive = false;
							return;
						}
						//printf("send success\n");
						*msg.isActive = false;
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
				str = str + msg.data[j];
			}
		}
		*msg.isActive = false;
		return;
	}
	else if (type == "GET" && data != "") {

		memset(msg.data, 0, sizeof(msg.data));
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
				*msg.isActive = false;
				return;
			}
			//std::cout << "str=" << str << "," << std::endl;
			if (str == "txt") {
				path = "catalog/txt/" + data.substr(5);
			}
			else if (str == "html") {
				//std::cout << "yes" << std::endl;
				path = "catalog/html/" + data.substr(5);
				//std::cout << "path=" << path << std::endl;
			}
			//std::cout << "str=" << str << std::endl;
			sendMessage(path, msg);
		}
		else if (data.substr(0, 5) == "/img/") {
			int total_size;
			int s;
			std::string path = "catalog/img/" + data.substr(5);
			sendMessage(path, msg);
		}

	}
	closesocket(msg.clientSocket);
	*msg.isActive = false;
	free(msg.data);
	/*mt.lock();
	//threadcount--;
	mt.unlock();*/
}
void thread_prinft()
{
	while (true)
	{
		std::cout << "------------------------->" <<threadcount<<std::endl;
		Sleep(100);
	}

}
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

bool httpServer::start()
{
	int on = 1;
	threadcount = 0;
	Actioncount = 0;
	memset(isActive, false, sizeof(isActive));
	close_message msg(isActive, serverSocket);
	th = new std::thread(listenForClose, msg);
	cpp11_thread_pool threadpool(MAX);
	//初始化服务器    
	memset(&serverChannel, 0, sizeof(serverChannel));
	serverChannel.sin_family = AF_INET;
	serverChannel.sin_addr.s_addr = htonl(INADDR_ANY);
	serverChannel.sin_port = htons(SERVER_PORT);
	//初始化线程计数器
	//count = new std::thread(thread_prinft);
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
	int l = listen(serverSocket, QUEUE_SIZE);
	if (l < 0) {
		printf("listen failed\n");
		return false;
	}
	else printf("successfully listen\n");
	int len = sizeof(serverChannel);
	//服务器等待连接    

	while (1) {
		//printf("waiting for connection...\n");
		//接受一个连接   
		//DWORD startTime = GetTickCount();
		clientSocket = accept(serverSocket, (sockaddr*)&serverChannel, &len);
		//DWORD totalTime = GetTickCount() - startTime;
		
		//printf("accput%d---waitting for%d\n", clientSocket, totalTime);
		if (clientSocket < 0) {
			//printf("accept failed\n");
		}
		else {
			//printf("successfully connect\n");
			char *buffer = (char*)malloc(BUFFER_SIZE*sizeof(char));
			memset(buffer, 0, sizeof(buffer));
			int ret;

			ret = recv(clientSocket, buffer, BUFFER_SIZE, 0);

			if (ret == SOCKET_ERROR) {
				printf("！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！sorry receive failed\n");
			}
			else if (ret == 0) {
				printf("！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！the client socket is closed\n");
			}
			else {
				//printf("successfully receive\n");
				if (position == MAX)position = 0;
				for (int i = position; i < MAX; i++) {
					if (i == MAX - 1)i = 0;
					if (!isActive[i]) {
						position = i+1;
						isActive[i] = true;
						//printf("position->%d", position);
						
						//被测试的代码 
						
						message msg(buffer, &isActive[i], clientSocket, i);
						//printf("new thread for%d\n",clientSocket);
						//t[i] = new std::thread(handleMessage, msg);
						threadpool.append(std::bind(&httpServer::handleMessage,this, msg));
						break;
					}
				}
			}
		}
	}
}