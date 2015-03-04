#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H

#include <stdint.h>
#include <errno.h>

#define likely(X) (X)
#define unlikely(X) (X)

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(X) ((X) >= (unsigned long) -MAX_ERRNO)
#define IS_ERR(PTR) IS_ERR_VALUE((unsigned long)(PTR))
#define ERR_PTR(ERR) ((void *) (intptr_t) (ERR))
#define PTR_ERR(PTR) ((long) (PTR))

#endif
