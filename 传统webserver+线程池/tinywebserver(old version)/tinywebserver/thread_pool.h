#pragma once
#include "stdafx.h"

#include <iostream>  
//#include <boost/thread/thread.hpp>  
//#include <boost/thread/mutex.hpp>  
#include<thread>
#include<mutex>
#include <functional>  
#include <list>  
#include <atomic>  
#include <vector>  
#include <stdlib.h>  
#include <time.h>  
#include <assert.h>  
#include <memory>  
#include <windows.h>  
#include <algorithm> 
//This class defines a class contains a thread, a task queue  
class cpp11_thread
{
public:
	cpp11_thread()
		:m_b_is_finish(false)
		, m_pthread(nullptr)
	{

	}
	~cpp11_thread()
	{
		if (m_pthread != nullptr)
			delete m_pthread;
		m_list_tasks.clear();
	}
public:
	//wait until this thread is terminated;  
	void join() {
		terminate();
		if (m_pthread != nullptr)
			m_pthread->join();
	}
	//wait until this thread has no tasks pending.  
	void wait_for_idle()
	{
		while (load())
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	//set the mask to termminiate  
	void terminate() { m_b_is_finish = true; m_cond_incoming_task.notify_one(); }
	//return the current load of this thread  
	size_t load()
	{
		size_t sz = 0;
		m_list_tasks_mutex.lock();
		sz = m_list_tasks.size();
		m_list_tasks_mutex.unlock();
		return sz;
	}
	//Append a task to do  
	size_t append(std::function< void(void) > func)
	{
		if (m_pthread == nullptr)
			m_pthread = new std::thread(std::bind(&cpp11_thread::run, this));
		size_t sz = 0;
		m_list_tasks_mutex.lock();
		m_list_tasks.push_back(func);
		sz = m_list_tasks.size();
		//if there were no tasks before, we should notidy the thread to do next job.  
		if (sz == 1)
			m_cond_incoming_task.notify_one();
		m_list_tasks_mutex.unlock();
		return sz;
	}
protected:
	std::atomic< bool>                            m_b_is_finish;          //atomic bool var to mark the thread the next loop will be terminated.  
	std::list<std::function< void(void)> >     m_list_tasks;           //The Task List contains function objects  

	std::mutex                                m_list_tasks_mutex;     //The mutex with which we protect task list  
	std::thread                               *m_pthread;             //inside the thread, a task queue will be maintained.  
	std::mutex                                m_cond_mutex;           //condition mutex used by m_cond_locker  
	std::condition_variable                   m_cond_incoming_task;   //condition var with which we notify the thread for incoming tasks  
	SYSTEMTIME systime;
protected:
	void run()
	{
		// loop wait  
		while (!m_b_is_finish)
		{
			std::function< void(void)> curr_task;
			bool bHasTasks = false;
			m_list_tasks_mutex.lock();
			if (m_list_tasks.empty() == false)
			{
				bHasTasks = true;
				curr_task = *m_list_tasks.begin();
			}
			m_list_tasks_mutex.unlock();
			//doing task  
			if (bHasTasks)
			{
				curr_task();
				m_list_tasks_mutex.lock();
				m_list_tasks.pop_front();
				m_list_tasks_mutex.unlock();
			}
			if (!load())
			{
				std::unique_lock< std::mutex> m_cond_locker(m_cond_mutex);
				//std::chrono::milliseconds const timeout = GetSystemTime(&systime) + std::chrono::milliseconds(5000);
				if (m_cond_locker.mutex())
					m_cond_incoming_task.wait(m_cond_locker);
			}
		}
	}
};

//the thread pool class  
class cpp11_thread_pool
{
public:
	cpp11_thread_pool(int nThreads)
		:m_n_threads(nThreads)
	{
		assert(nThreads>0 && nThreads <= 512);
		for (int i = 0; i< nThreads; i++)
			m_vec_threads.push_back(std::shared_ptr<cpp11_thread>(new cpp11_thread()));
	}
	~cpp11_thread_pool()
	{

	}
public:
	//total threads;  
	size_t count() { return m_vec_threads.size(); }
	//wait until all threads is terminated;  
	void join()
	{
		std::for_each(m_vec_threads.begin(), m_vec_threads.end(), [this](std::shared_ptr<cpp11_thread> & item)
		{
			item->terminate();
			item->join();
		});
	}
	//wait until this thread has no tasks pending.  
	void wait_for_idle()
	{
		int n_tasks = 0;
		do
		{
			if (n_tasks)
				std::this_thread::sleep_for(std::chrono::milliseconds(20));
			n_tasks = 0;
			std::for_each(m_vec_threads.begin(), m_vec_threads.end(), [this, &n_tasks](std::shared_ptr<cpp11_thread> & item)
			{
				n_tasks += item->load();
			});
		} while (n_tasks);

	}
	//set the mask to termminiate  
	void terminate()
	{
		for_each(m_vec_threads.begin(), m_vec_threads.end(), [this](std::shared_ptr<cpp11_thread> & item)
		{
			item->terminate();
		});
	}
	//return the current load of this thread  
	size_t load(int n)
	{
		return (n >= m_vec_threads.size()) ? 0 : m_vec_threads[n]->load();
	}
	//Append a task to do  
	void append(std::function< void(void) > func)
	{
		int nIdx = -1;
		unsigned int nMinLoad = -1;
		for (unsigned int i = 0; i<m_n_threads; i++)
		{
			if (nMinLoad> m_vec_threads[i]->load())
			{
				nMinLoad = m_vec_threads[i]->load();
				nIdx = i;
			}
		}

		assert(nIdx >= 0 && nIdx<m_n_threads);
		m_vec_threads[nIdx]->append(func);
	}
protected:
	//NO. threads  
	int m_n_threads;
	//vector contains all the threads  
	std::vector<std::shared_ptr<cpp11_thread> > m_vec_threads;
};