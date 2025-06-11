#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/socket.h>
#include "syscall_macros.h"
#include "igloo.h"

/* Global variables */
unsigned long __weak igloo_task_size = 0x80000000;
bool __weak igloo_do_hc = false;
bool __weak igloo_log_cov = false;
bool __weak igloo_block_halt = false;

/* from fs/exec.c */
struct user_arg_ptr {
#ifdef CONFIG_COMPAT
  bool is_compat;
#endif
  union {
    const char __user *const __user *native;
#ifdef CONFIG_COMPAT
    const compat_uptr_t __user *compat;
#endif
  } ptr;
};

#ifdef CONFIG_IGLOO
/* Syscall hooks */
igloo_syscall_enter_t __weak igloo_syscall_enter_hook = NULL;
igloo_syscall_return_t __weak igloo_syscall_return_hook = NULL;

/* File system related functions */
int __weak igloo_hc_open(int dfd, struct filename *tmp, int fd)
{
    return 0;
}

void __weak igloo_exec_succeeded(struct filename *filename,
    struct user_arg_ptr argv, struct user_arg_ptr envp, struct linux_binprm *bprm) {}

void __weak igloo_ioctl(int error, struct file *filp, unsigned int cmd) {}

bool __weak igloo_should_block_mount(struct path *path)
{
    return false;
}

void __weak igloo_sock_release(struct socket *sock) { }

int __weak igloo_sock_bind(struct socket *sock, struct sockaddr_storage *address)
{
    return 0;
}

void __weak igloo_hc_newuname(struct new_utsname *name) {}
#endif
