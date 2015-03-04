#ifndef _LINUX_JIFFIES_H
#define _LINUX_JIFFIES_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <linux/types.h>

typedef _Bool bool;
#define false 0
#define true 1

typedef __s8  s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;
typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define min(x,y) ({ \
    typeof(x) _x = (x);     \
    typeof(y) _y = (y);     \
    (void) (&_x == &_y);    \
    _x < _y ? _x : _y; })

#define max(x,y) ({ \
    typeof(x) _x = (x);     \
    typeof(y) _y = (y);     \
    (void) (&_x == &_y);    \
    _x > _y ? _x : _y; })

static inline u32 do_div(u64 x, u32 y) { return x / y; }

typedef u64 cycles_t;

static const unsigned int cpu_khz = 1000;  // unit of get_cycles()

static inline cycles_t get_cycles(void)
{
    struct timeval TVal;
    // thanks to VDSO, gettimeofday() does not require a system call
    if (gettimeofday (&TVal, NULL) < 0)
        return -1;
    return (cycles_t) TVal.tv_sec * 1000000 + TVal.tv_usec;
}

#define HZ 1000

#define jiffies ((unsigned long) (get_cycles () / (cpu_khz * 1000 / HZ)))

#endif
