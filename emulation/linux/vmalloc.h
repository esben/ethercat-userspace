#ifndef _LINUX_VMALLOC_H
#define _LINUX_VMALLOC_H

#include <linux/err.h>
#include <linux/printk.h>
#include <stdlib.h>
#include <string.h>

#define kmalloc(SIZE, MODE) malloc(SIZE)
#define kfree free
#define vmalloc malloc
#define vfree free

#define __user

#define put_user(x, ptr) ((*ptr) = (x), 0)
#define get_user(x, ptr) ((x) = (*ptr), 0)

#endif
