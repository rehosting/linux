#ifndef _LINUX_IGLOO_H
#define _LINUX_IGLOO_H

extern unsigned long igloo_task_size; // mmap.c
extern bool igloo_do_hc; // mmap.c
extern bool igloo_log_cov; // mmap.c
extern bool igloo_block_halt; // reboot.c

#define IGLOO_OPEN         100
#define IGLOO_IOCTL_ENOTTY 105
#define IGLOO_IPV4_SETUP   200
#define IGLOO_IPV4_BIND    201
#define IGLOO_IPV6_SETUP   202
#define IGLOO_IPV6_BIND    203

#define IGLOO_HYP_TASK_COMM 590
#define IGLOO_HYP_TASK_TGID 591
#define IGLOO_HYP_TASK_PTGID 592
#define IGLOO_HYP_TASK_STIME 593
#define IGLOO_HYP_TASK_KTHREAD 594
#define IGLOO_HYP_KTHREAD_CHANGE 595
#define IGLOO_HYP_THREAD_CHANGE 596
#define IGLOO_HYP_TASK_ARGV 597
#define IGLOO_HYP_TASK_ARGC 598
#define IGLOO_HYP_TASK_ENVV 599
#define IGLOO_HYP_TASK_ENVC 600
#define IGLOO_HYP_TASK_EUID 601
#define IGLOO_HYP_TASK_EGID 602

#define IGLOO_HYP_TASK_PSTIME 1595

#define IGLOO_HYP_VMA_REPORT_UPDATE 5910
#define IGLOO_HYP_VMA_VM_START 5911
#define IGLOO_HYP_VMA_VM_END 5912
#define IGLOO_HYP_VMA_NAME 5913
#define IGLOO_HYP_VMA_SPECIAL 5914

#endif /* _LINUX_IGLOO_H */


