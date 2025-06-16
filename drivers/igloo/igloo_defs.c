#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/module.h>
#include <linux/init.h>
#include "syscall_macros.h"
#include "igloo.h"

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
EXPORT_SYMBOL(igloo_syscall_enter_hook);
EXPORT_SYMBOL(igloo_syscall_return_hook);

/* File system related functions */
void __weak igloo_hc_open(int dfd, struct filename *tmp, int fd) { }
EXPORT_SYMBOL(igloo_hc_open);

void __weak igloo_exec_succeeded(struct filename *filename,
    struct user_arg_ptr argv, struct user_arg_ptr envp, struct linux_binprm *bprm) {}
EXPORT_SYMBOL(igloo_exec_succeeded);

void __weak igloo_ioctl(int error, struct file *filp, unsigned int cmd) {}
EXPORT_SYMBOL(igloo_ioctl);

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

// arch_syscall_addr wasn't available in module, even with init
#ifdef CONFIG_MIPS
#ifdef CONFIG_MIPS32_N32
extern const unsigned long sysn32_call_table[];
#endif
#ifdef CONFIG_MIPS32_O32
extern const unsigned long sys32_call_table[];
#endif
extern unsigned long sys_ni_syscall;
#else
extern const unsigned long sys_call_table[];
#endif

unsigned long igloo_arch_syscall_addr(int nr) {
    #ifdef CONFIG_MIPS
    #ifdef CONFIG_32BIT
    return (unsigned long)sys_call_table[nr - __NR_O32_Linux];
    #endif

    #ifdef CONFIG_64BIT
    #ifdef CONFIG_MIPS32_N32
    if (nr >= __NR_N32_Linux && nr < __NR_N32_Linux + __NR_N32_Linux_syscalls)
        return (unsigned long)sysn32_call_table[nr - __NR_N32_Linux];
    #endif
    if (nr >= __NR_64_Linux  && nr < __NR_64_Linux + __NR_64_Linux_syscalls)
        return (unsigned long)sys_call_table[nr - __NR_64_Linux];
    #ifdef CONFIG_MIPS32_O32
    if (nr >= __NR_O32_Linux && nr < __NR_O32_Linux + __NR_O32_Linux_syscalls)
        return (unsigned long)sys32_call_table[nr - __NR_O32_Linux];
    #endif

    return (unsigned long) &sys_ni_syscall;
    #endif
    #endif // CONFIG_MIPS
    return (unsigned long)sys_call_table[nr];
}
EXPORT_SYMBOL(igloo_arch_syscall_addr);

/**
 * Early params originally from igloo_hc.c in the module
 */
unsigned long igloo_task_size = 0;
static int __init early_igloo_task_size(char *p)
{
    unsigned long task_size;
    if (kstrtoul(p, 0, &task_size) < 0 ) {
        pr_warn("Could not parse igloo_task_size parameter %s\n", p);
        return -1;
    }
    igloo_task_size = task_size;
    pr_warn_once("Using igloo_task_size: 0x%lx\n", igloo_task_size);
    return 0;
}
early_param("igloo_task_size", early_igloo_task_size);
EXPORT_SYMBOL(igloo_task_size);

bool igloo_do_hc = true;
static int __init early_igloo_do_hc(char *p)
{
    unsigned long do_hc;
    if (kstrtoul(p, 0, &do_hc) < 0 ) {
        pr_warn("Could not parse igloo_do_hc parameter %s\n", p);
        return -1;
    }
    igloo_do_hc = (do_hc > 0);
    pr_warn_once("Using igloo_do_hc: %d\n", igloo_do_hc);
    return 0;
}
early_param("igloo_do_hc", early_igloo_do_hc);
EXPORT_SYMBOL(igloo_do_hc);

bool igloo_log_cov = false;
static int __init early_igloo_log_cov(char *p)
{
    unsigned long log_cov;
    if (kstrtoul(p, 0, &log_cov) < 0 ) {
        pr_warn("Could not parse igloo_log_cov parameter %s\n", p);
        return -1;
    }
    igloo_log_cov = (log_cov > 0);
    pr_warn_once("Using igloo_log_cov: %d\n", igloo_log_cov);
    return 0;
}
early_param("igloo_log_cov", early_igloo_log_cov);
EXPORT_SYMBOL(igloo_log_cov);

bool igloo_block_halt=false;

static int __init early_igloo_block_halt(char *p)
{
    unsigned long block_halt;
    if (kstrtoul(p, 0, &block_halt) < 0 ) {
        pr_warn("Could not parse igloo_block_halt parameter %s. Set to 0 (default) or 1\n", p);
        return -1;
    }
    igloo_block_halt = (block_halt > 0);
    pr_warn_once("Using igloo_block_halt: %d\n", igloo_block_halt);
    return 0;
}

early_param("igloo_block_halt", early_igloo_block_halt);
EXPORT_SYMBOL(igloo_block_halt);

// Debug logging configuration for each module
struct igloo_debug_config {
    bool portal;       // Enable debug for portal module
    bool uprobe;       // Enable debug for uprobe module
    bool vma;          // Enable debug for VMA tracking
    bool syscall;      // Enable debug for syscall tracking
    bool osi;          // Enable debug for OSI features
};

// Global debug configuration
struct igloo_debug_config igloo_debug = {
    .portal = false,
    .uprobe = false,
    .vma = false,
    .syscall = false,
    .osi = false,
};

// Parse comma-separated list of modules to enable debug logging for
static int __init early_igloo_debug_modules(char *p)
{
    char *token;

    // By default, all modules have debug disabled
    memset(&igloo_debug, 0, sizeof(igloo_debug));

    // Special case: "all" enables all modules
    if (!strcmp(p, "all")) {
        memset(&igloo_debug, 1, sizeof(igloo_debug));
        pr_warn_once("IGLOO: Debug enabled for all modules\n");
        return 0;
    }

    // Special case: "none" disables all modules (default)
    if (!strcmp(p, "none")) {
        memset(&igloo_debug, 0, sizeof(igloo_debug));
        pr_warn_once("IGLOO: Debug disabled for all modules\n");
        return 0;
    }

    // Parse comma-separated module list
    while ((token = strsep(&p, ",")) != NULL) {
        if (!strcmp(token, "portal"))
            igloo_debug.portal = true;
        else if (!strcmp(token, "uprobe"))
            igloo_debug.uprobe = true;
        else if (!strcmp(token, "vma"))
            igloo_debug.vma = true;
        else if (!strcmp(token, "syscall"))
            igloo_debug.syscall = true;
        else if (!strcmp(token, "osi"))
            igloo_debug.osi = true;
        else if (!strcmp(token, "all")){
            memset(&igloo_debug, 1, sizeof(igloo_debug));
            pr_warn_once("IGLOO: Debug enabled for all modules\n");
            return 0;
        }
        else
            pr_warn("IGLOO: Unknown debug module: %s\n", token);
    }

    pr_warn_once("IGLOO: Debug modules - portal:%d uprobe:%d vma:%d syscall:%d osi:%d\n",
               igloo_debug.portal, igloo_debug.uprobe, igloo_debug.vma,
               igloo_debug.syscall, igloo_debug.osi);

    return 0;
}

early_param("igloo_debug", early_igloo_debug_modules);
EXPORT_SYMBOL(igloo_debug);

/* Export internal symbols needed for introspection research */

// Tracepoint symbols
extern struct tracepoint __tracepoint_sched_switch;
EXPORT_SYMBOL(__tracepoint_sched_switch);

// Symbol lookup functions
extern int kallsyms_lookup(unsigned long addr, unsigned long *symbolsize,
                          unsigned long *offset, char **modname, char *namebuf);
EXPORT_SYMBOL(kallsyms_lookup);

extern unsigned long kallsyms_lookup_name(const char *name);
EXPORT_SYMBOL(kallsyms_lookup_name);

// Syscall table
extern const unsigned long sys_call_table[];
EXPORT_SYMBOL(sys_call_table);

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

// Syscall metadata (linker symbols)
extern char __start_syscalls_metadata[];
extern char __stop_syscalls_metadata[];
EXPORT_SYMBOL(__start_syscalls_metadata);
EXPORT_SYMBOL(__stop_syscalls_metadata);

#endif /* CONFIG_IGLOO */
