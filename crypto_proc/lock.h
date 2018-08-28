#ifndef THREADLOCK_H
#define THREADLOCK_H
 
#include <exception>
#include <pthread.h>
#include <semaphore.h>

class CSemaphore
{
    public:
        CSemaphore()
        {
            if( sem_init( &m_sem, 0, 0 ) != 0 )
            {
                throw std::exception();
            }
        }
        ~CSemaphore()
        {
            sem_destroy( &m_sem );
        }
        bool wait()
        {
            return sem_wait( &m_sem ) == 0;
        }
        bool post()
        {
            return sem_post( &m_sem ) == 0;
        }

    private:
        sem_t m_sem;
};


class CCondition   
{
    public:
        CCondition()
        {
            if( pthread_mutex_init( &m_mutex, NULL ) != 0)
            {
                throw std::exception();
            }
            if ( pthread_cond_init( &m_cond, NULL ) != 0 )
            {
                pthread_mutex_destroy( &m_mutex );
                throw std::exception();
            }
        }
        ~CCondition()
        {
            pthread_mutex_destroy( &m_mutex );
            pthread_cond_destroy( &m_cond );
        }
        bool wait()
        {
            int ret = 0;
            pthread_mutex_lock( &m_mutex );
            ret = pthread_cond_wait( &m_cond, &m_mutex );
            pthread_mutex_unlock( &m_mutex );
            return ret == 0;
        }
        bool signal()
        {
            return pthread_cond_signal( &m_cond ) == 0;
        }

    private:
        pthread_mutex_t m_mutex;
        pthread_cond_t m_cond;
};

class CThreadMutex 
{
    public:
        CThreadMutex()
        {
            if( pthread_mutex_init( &m_mutex, NULL ) != 0)
            {
                throw std::exception();
            }
        }
        ~CThreadMutex()
        {
            pthread_mutex_destroy( &m_mutex );
        }
        bool lock()
        {
            return pthread_mutex_lock( &m_mutex ) == 0;
        }
        bool unlock()
        {
            return pthread_mutex_unlock( &m_mutex ) == 0;
        }

    private:
        pthread_mutex_t m_mutex;
};

#endif
