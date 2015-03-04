#ifndef _LINUX_MODULE_H
#define _LINUX_MODULE_H

#include <string.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>

#define simple_strtoul strtoul

#define THIS_MODULE NULL
#define MODULE_AUTHOR(AUTHOR)
#define MODULE_DESCRIPTION(DESCRIPTION)
#define MODULE_LICENSE(LICENSE)
#define MODULE_VERSION(VERSION)
#define module_param_named(NAME, VALUE, TPYE, PERM)
#define module_param_array(NAME, TYPE, NUMP, PERM)
#define MODULE_PARM_DESC(PARM, DESC)
#define __init
#define __exit
#define module_init(FUNC)
#define module_exit(FUNC)
#define EXPORT_SYMBOL(SYMBOL)

struct module;

#define try_module_get(MODULE) 1
#define module_put(MODULE)

#endif
