#ifndef _LINUX_SEMAPHORE_H
#define _LINUX_SEMAPHORE_H

#include <pthread.h>

struct semaphore
{
    pthread_mutex_t mutex;
};

#define sema_init(SEM, N) \
    ((void) (void (*)(int[N == 1 ? 1 : -1])) NULL,  /* we only support N == 1 */ \
     pthread_mutex_init(&(SEM)->mutex, NULL))
#define down(SEM) pthread_mutex_lock(&(SEM)->mutex)
#define down_interruptible(SEM) (down(SEM), 0)
#define up(SEM) pthread_mutex_unlock(&(SEM)->mutex)

typedef pthread_mutex_t spinlock_t;
#define SPIN_LOCK_UNLOCKED (spinlock_t) PTHREAD_MUTEX_INITIALIZER
#define spin_lock_bh pthread_mutex_lock
#define spin_unlock_bh pthread_mutex_unlock

#endif
