// tinywebserver.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include"httpServer.h" 
int main()
{
	httpServer f;
	f.start();
	system("pause");
}

