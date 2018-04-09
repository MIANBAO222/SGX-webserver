#pragma once
#include<stdbool.h>
struct message
{
	char* data;
	bool* isActive;
	int clientSocket;
	int id;
};

struct close_message
{
	bool* isActive;
	int serverSocket;
};
