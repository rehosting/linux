#ifndef _LINUX_IGLOO_SIGNAL_H
#define _LINUX_IGLOO_SIGNAL_H

#include <linux/types.h>

struct task_struct;

typedef bool (*igloo_signal_deliver_hook_t)(int sig, struct task_struct *task);

extern igloo_signal_deliver_hook_t igloo_signal_deliver_hook;

#endif /* _LINUX_IGLOO_SIGNAL_H */
