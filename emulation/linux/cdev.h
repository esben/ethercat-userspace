#ifndef _LINUX_CDEV_H
#define _LINUX_CDEV_H

#include <linux/err.h>

struct cdev
{
    void *owner;
};

#define cdev_init(CDEV, FOPS)
#define cdev_add(CDEV, DEV, COUNT) 0
#define cdev_del(CDEV)

#endif
