#ifndef _LINUX_IGLOO_H
#define _LINUX_IGLOO_H
#include <linux/utsname.h>
#include <linux/socket.h>
#include <linux/binfmts.h>

extern unsigned long igloo_task_size; // mmap.c
extern bool igloo_do_hc; // mmap.c
extern bool igloo_log_cov; // mmap.c
extern bool igloo_block_halt; // reboot.c
struct user_arg_ptr;  // Forward declaration

void igloo_hc_open(int dfd, struct filename *tmp, int fd);
void igloo_exec_succeeded(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, struct linux_binprm *bprm);
void igloo_ioctl(int error, struct file *filp, unsigned int cmd);
bool igloo_should_block_mount(struct path *path);
void igloo_sock_release(struct socket *sock);
void igloo_sock_bind(struct socket *sock, struct sockaddr_storage *address);
void igloo_hc_newuname(struct new_utsname *name);
unsigned long igloo_arch_syscall_addr(int nr);

#include "igloo_hypercall_consts.h"

#endif /* _LINUX_IGLOO_H */
