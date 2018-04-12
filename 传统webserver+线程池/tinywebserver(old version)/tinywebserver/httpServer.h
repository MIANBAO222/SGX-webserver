#pragma once  
#include<winsock.h>    
#include<thread> 
#include"thread_pool.h"
#include <mutex>  
extern int threadcount;
extern std::mutex mt;
struct message  
{  
    char* data;  
    bool* isActive;  
    int clientSocket;  
    int id;  
    message(char* d, bool* is, int c, int i);  
};  
  
struct close_message  
{  
    bool* isActive;  
    int serverSocket;  
    close_message(bool* is, int s);  
};  
  
class httpServer  
{  
private:  
    enum {  
        SERVER_PORT = 4548,  
        BUFFER_SIZE = 1000,  
        QUEUE_SIZE = 2048,  
        MAX =100,
    };  
    //char buffer[BUFFER_SIZE];
    sockaddr_in serverChannel;  
	//int Max_num = MAX;
	
    std::thread* t[MAX];  
    std::thread* th;  
	//std::thread* count;
    char rootDir[50];  
    char name[50];  
    bool isActive[MAX]; 
	int Actioncount; //活动计算
    int serverSocket; //socket    
    int clientSocket;  
    void handleMessage(message msg);  
    friend void listenForClose(close_message msg);  
public:  
    httpServer();  
    bool start();//开启服务器    
};  