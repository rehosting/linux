#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/syscall.h>
#include "igloo_syscall_macros.h"
#include "igloo.h"

/* Syscall hooks */
igloo_syscall_enter_t igloo_syscall_enter_hook = NULL;
igloo_syscall_return_t igloo_syscall_return_hook = NULL;
EXPORT_SYMBOL(igloo_syscall_enter_hook);
EXPORT_SYMBOL(igloo_syscall_return_hook);

bool igloo_should_block_mount(struct path *path);

bool __weak igloo_should_block_mount(struct path *path)
{
    return false;
}
EXPORT_SYMBOL(igloo_should_block_mount);

void __weak igloo_sock_release(struct socket *sock) { }
EXPORT_SYMBOL(igloo_sock_release);

void __weak igloo_sock_bind(struct socket *sock, struct sockaddr_storage *address) {}
EXPORT_SYMBOL(igloo_sock_bind);

void __weak igloo_hc_newuname(struct new_utsname *name) {}
EXPORT_SYMBOL(igloo_hc_newuname);


/* Export internal symbols needed for introspection research */

// Symbol lookup functions - now pulled in by trace/syscall.h
EXPORT_SYMBOL(kallsyms_lookup);

extern unsigned long kallsyms_lookup_name(const char *name);
EXPORT_SYMBOL(kallsyms_lookup_name);

// Architecture-specific functions
extern const char *arch_vma_name(struct vm_area_struct *vma);
EXPORT_SYMBOL(arch_vma_name);

// Process management
extern pid_t kernel_clone(struct kernel_clone_args *args);
EXPORT_SYMBOL(kernel_clone);

extern int kill_pid_info(int sig, struct kernel_siginfo *info, struct pid *pid);
EXPORT_SYMBOL(kill_pid_info);

// Memory access
extern int access_remote_vm(struct mm_struct *mm, unsigned long addr,
                           void *buf, int len, unsigned int gup_flags);
EXPORT_SYMBOL(access_remote_vm);
