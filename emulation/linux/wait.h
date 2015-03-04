#ifndef _LINUX_WAIT_H
#define _LINUX_WAIT_H

#include <pthread.h>

struct __wait_queue_head 
{
    pthread_cond_t cond;
    pthread_mutex_t mutex;
};
typedef struct __wait_queue_head wait_queue_head_t;

static inline void init_waitqueue_head(wait_queue_head_t *queue)
{
    pthread_cond_init(&queue->cond, NULL);
    pthread_mutex_init(&queue->mutex, NULL);
}

#define wait_event_interruptible wait_event
#define wait_event(QUEUE, COND) \
({ \
    pthread_mutex_lock(&(QUEUE).mutex); \
    while (!(COND)) \
        pthread_cond_wait(&(QUEUE).cond, &(QUEUE).mutex); \
    pthread_mutex_unlock(&(QUEUE).mutex); \
    0; \
})

#define wake_up_interruptible wake_up
static inline void wake_up (wait_queue_head_t *queue)
{
    pthread_mutex_lock(&queue->mutex);
    pthread_cond_broadcast(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);
};

#endif
