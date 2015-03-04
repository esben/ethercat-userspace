#ifndef _LINUX_PRINTK_H
#define _LINUX_PRINTK_H

#include <stdio.h>

#define KERN_ERR	"[ERROR] "
#define KERN_WARNING	"[WARNING] "
#define KERN_INFO	"[INFO] "
#define KERN_DEBUG	"[DEBUG] "

#define printk(...) fprintf(stderr, __VA_ARGS__)

#define printk_ratelimit() 1

#endif
