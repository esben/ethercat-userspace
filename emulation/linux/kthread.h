#ifndef _LINUX_KTHREAD_H
#define _LINUX_KTHREAD_H

#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/err.h>

struct task_struct
{
    pthread_t thread;
    int (*thread_func)(void *);
    void *data;
    char name[16];
    int should_stop;
};

static __thread struct task_struct *current_task;

static inline void dummy_signal_handler(int sig)
{
    (void) sig;
}

static inline void *task_run(void *arg)
{
    current_task = (struct task_struct *) arg;
    prctl(PR_SET_NAME, current_task->name);
    struct sigaction a;
    memset(&a, 0, sizeof (a));
    a.sa_handler = dummy_signal_handler;
    sigemptyset(&a.sa_mask);
    sigaction(SIGUSR1, &a, NULL);
    current_task->thread_func(current_task->data);
    return NULL;
}

static inline struct task_struct *kthread_run(int (*thread_func)(void *), void *data, const char *namefmt, ...)
{
    struct task_struct *task = malloc(sizeof(struct task_struct));
    if (!task)
        return ERR_PTR(-ENOMEM);
    task->thread_func = thread_func;
    task->data = data;
    va_list args;
    va_start(args, namefmt);
    vsnprintf(task->name, sizeof(task->name), namefmt, args);
    va_end(args);
    task->should_stop = 0;
    int ret = pthread_create(&task->thread, NULL, task_run, task);
    if (ret == 0)
        return task;
    free(task);
    return ERR_PTR(-ret);
}

static inline void kthread_stop(struct task_struct *task)
{
    pthread_kill(task->thread, SIGUSR1);  // interrupt blocking system calls
    task->should_stop = 1;
    pthread_join(task->thread, NULL);
    free(task);
}

#define kthread_should_stop() (current_task->should_stop)

#endif
