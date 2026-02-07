#ifndef __KSU_H_KLOG
#define __KSU_H_KLOG

#include <linux/printk.h>
#include <linux/task_work.h>
/* Kernel 5.4 task_work_add takes bool; later kernels use enum TWA_RESUME */
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "KernelSU: " fmt
#endif

#endif
