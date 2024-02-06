#ifndef _LINUX_IGLOO_H
#define _LINUX_IGLOO_H

extern unsigned long igloo_task_size; // mmap.c
extern bool igloo_do_hc; // mmap.c

#define IGLOO_IOCTL_ENOTTY 105

#define IGLOO_HYP_TASK_ARGV 597
#define IGLOO_HYP_TASK_ARGC 598
#define IGLOO_HYP_TASK_ENVV 599
#define IGLOO_HYP_TASK_ENVC 600
#define IGLOO_HYP_TASK_EUID 601
#define IGLOO_HYP_TASK_EGID 602

#define IGLOO_HYP_VMA_REPORT_UPDATE 5910
#define IGLOO_HYP_VMA_VM_START 5911
#define IGLOO_HYP_VMA_VM_END 5912
#define IGLOO_HYP_VMA_NAME 5913
#define IGLOO_HYP_VMA_SPECIAL 5914

#endif /* _LINUX_IGLOO_H */


