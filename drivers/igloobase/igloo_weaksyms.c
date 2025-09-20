#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <asm/unistd.h>
#include <asm/syscall.h>
#include "igloo_syscall_macros.h"
#include "igloo.h"

/* Syscall hooks */
igloo_syscall_enter_t igloo_syscall_enter_hook = NULL;
igloo_syscall_return_t igloo_syscall_return_hook = NULL;
EXPORT_SYMBOL(igloo_syscall_enter_hook);
EXPORT_SYMBOL(igloo_syscall_return_hook);

// Function pointer for override
bool (*igloo_should_block_mount_module)(struct path *path);
bool igloo_should_block_mount(struct path *path);
bool igloo_should_block_mount(struct path *path)
{
    if (igloo_should_block_mount_module) {
        return igloo_should_block_mount_module(path);
    } else {
        // printk(KERN_INFO "igloo_should_block_mount: default implementation called\n");
        return false;
    }
}
EXPORT_SYMBOL(igloo_should_block_mount);

void (*igloo_sock_release_module)(struct socket *sock);
void igloo_sock_release(struct socket *sock)
{
    if (igloo_sock_release_module) {
        igloo_sock_release_module(sock);
    } else {
        // printk(KERN_EMERG "igloo_sock_release: unimplemented\n");
    }
}
EXPORT_SYMBOL(igloo_sock_release);

void (*igloo_sock_bind_module)(struct socket *sock, struct sockaddr_storage *address);
void igloo_sock_bind(struct socket *sock, struct sockaddr_storage *address)
{
    if (igloo_sock_bind_module) {
        igloo_sock_bind_module(sock, address);
    } else {
        // printk(KERN_EMERG "igloo_sock_bind: unimplemented\n");
    }
}
EXPORT_SYMBOL(igloo_sock_bind);

void (*igloo_hc_newuname_module)(struct new_utsname *name) = NULL;
void igloo_hc_newuname(struct new_utsname *name)
{
    if (igloo_hc_newuname_module) {
        igloo_hc_newuname_module(name);
    } else {
        // printk(KERN_EMERG "igloo_hc_newuname: unimplemented\n");
    }
}
EXPORT_SYMBOL(igloo_hc_newuname);

void (*igloo_hc_open_module)(int dfd, struct filename *tmp, int fd);
void igloo_hc_open(int dfd, struct filename *tmp, int fd)
{
    if (igloo_hc_open_module) {
        igloo_hc_open_module(dfd, tmp, fd);
    } else {
        // printk(KERN_EMERG "igloo_hc_open: unimplemented\n");
    }
}
EXPORT_SYMBOL(igloo_hc_open);

void (*igloo_ioctl_module)(int error, struct inode *inode, struct file *filp, unsigned int cmd, void __user *argp);
void igloo_ioctl(int error, struct inode *inode, struct file *filp, unsigned int cmd, void __user *argp);
void igloo_ioctl(int error, struct inode *inode, struct file *filp, unsigned int cmd, void __user *argp)
{
    if (igloo_ioctl_module) {
        igloo_ioctl_module(error, inode, filp, cmd, argp);
    } else {
        // printk(KERN_EMERG "igloo_ioctl: unimplemented\n");
    }
}
EXPORT_SYMBOL(igloo_ioctl);

/* Export internal symbols needed for introspection research */

// Symbol lookup functions - now pulled in by trace/syscall.h
EXPORT_SYMBOL(kallsyms_lookup);


// version not confirmed
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
extern unsigned long kallsyms_lookup_name(const char *name);
EXPORT_SYMBOL(kallsyms_lookup_name);
#endif

// Architecture-specific functions
extern const char *arch_vma_name(struct vm_area_struct *vma);
EXPORT_SYMBOL(arch_vma_name);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
// Process management
extern pid_t kernel_clone(struct kernel_clone_args *args);
EXPORT_SYMBOL(kernel_clone);
#else
// we will need another version here
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
extern int kill_pid_info(int sig, struct kernel_siginfo *info, struct pid *pid);
#else
extern int kill_pid_info(int sig, struct siginfo *info, struct pid *pid); 
#endif
EXPORT_SYMBOL(kill_pid_info);

// Memory access
extern int access_remote_vm(struct mm_struct *mm, unsigned long addr,
                           void *buf, int len, unsigned int gup_flags);
EXPORT_SYMBOL(access_remote_vm);