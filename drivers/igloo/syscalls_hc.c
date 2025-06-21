#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <asm/ftrace.h>
#include "hypercall.h" // Content is now included directly below
#include "igloo.h"
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include "syscalls_hc.h"
#include "args.h"
#include "kprobe_syscalls.h"
#include "portal/portal.h"

// Use the syscall_event structure from syscalls_hc.h

igloo_syscall_enter_t igloo_syscall_enter_hook;
igloo_syscall_return_t igloo_syscall_return_hook;

/* Global hash tables for organizing hooks */
struct hlist_head syscall_hook_table[1024];                /* Main table indexed by hook pointer */
struct hlist_head syscall_name_table[1024];                /* Table indexed by syscall name hash */
struct hlist_head syscall_all_hooks;                       /* Special list for "match all syscalls" hooks */
DEFINE_SPINLOCK(syscall_hook_lock);

/* Export symbols for use by other modules */
EXPORT_SYMBOL(syscall_hook_table);
EXPORT_SYMBOL(syscall_name_table);
EXPORT_SYMBOL(syscall_all_hooks);
EXPORT_SYMBOL(syscall_hook_lock);

// syscall_name_hash is now defined in syscalls_hc.h

// Define IGLOO_DEBUG=1 during compilation to enable debug prints
#ifdef IGLOO_DEBUG
#define DBG_PRINTK(fmt, ...) printk(KERN_EMERG "IGLOO_DBG: " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINTK(fmt, ...) do {} while (0)
#endif

extern struct syscall_metadata *__start_syscalls_metadata[];
extern struct syscall_metadata *__stop_syscalls_metadata[];

// Replace mutex with spinlock which is safe for atomic contexts
DEFINE_SPINLOCK(syscall_hc_lock); // Keep commented out unless hypercall needs external locking

/* Function to print syscall information */
void print_syscall_info(const struct syscall_event *sc, const char *prefix);
void print_syscall_info(const struct syscall_event *sc, const char *prefix) {
    if (!sc) {
        DBG_PRINTK( "IGLOO: %s NULL syscall structure\n", prefix ? prefix : "");
        return;
    }
    
    printk(KERN_INFO "IGLOO: %s Syscall Info --------\n", prefix ? prefix : "");
    printk(KERN_INFO "  Hook Ptr: %p\n", sc->hook);
    printk(KERN_INFO "  Syscall Name: %s\n", sc->syscall_name);
    printk(KERN_INFO "  PC: 0x%llx\n", sc->pc);
    printk(KERN_INFO "  Return Val: %ld\n", sc->retval);
    printk(KERN_INFO "  Skip: %d\n", sc->skip_syscall);
    printk(KERN_INFO "  Task: %p\n", sc->task);
    printk(KERN_INFO "  Regs: %p\n", sc->regs);
    
    printk(KERN_INFO "  Arguments (%u):\n", sc->argc);
    for (int i = 0; i < sc->argc && i < IGLOO_SYSCALL_MAXARGS; i++) {
        printk(KERN_INFO "    arg[%d]: 0x%llx\n", i, sc->args[i]);
    }
    printk(KERN_INFO "IGLOO: ------------------------\n");
}

static inline void fill_handler(struct syscall_event *args, int argc, const unsigned long args_ptrs[], const char* syscall_name) {
    struct pt_regs *regs;
    
    // Fill the syscall structure with arguments
    args->skip_syscall = false;
    args->argc = argc;
    
    // Copy syscall name into the structure (with bounds checking)
    if (syscall_name) {
        strncpy(args->syscall_name, syscall_name, SYSCALL_NAME_MAX_LEN - 1);
        args->syscall_name[SYSCALL_NAME_MAX_LEN - 1] = '\0';
    } else {
        args->syscall_name[0] = '\0';
    }

    // Copy arguments safely - add proper NULL checks before dereferencing
    for (int i = 0; i < IGLOO_SYSCALL_MAXARGS; i++) {
        if (i < argc && args_ptrs && args_ptrs[i]) {
            // Safely copy argument value - verify valid pointer first
            unsigned long arg_ptr = args_ptrs[i];
            if (arg_ptr && !IS_ERR_VALUE(arg_ptr)) {
                args->args[i] = *(unsigned long*)arg_ptr;
            } else {
                args->args[i] = 0;
                DBG_PRINTK("IGLOO: Invalid argument pointer at index %d\n", i);
            }
        } else {
            args->args[i] = 0; // Initialize unused args to 0
        }
    }
    
    args->task = current;
    args->retval = 0; // Initialize to 0, will be set by hypercall
    
    regs = task_pt_regs(current);
    args->regs = regs;
    
    if (regs != NULL) {
        // Use safe way to get instruction pointer that works across architectures
        args->pc = instruction_pointer(regs);
    } else {
        DBG_PRINTK("IGLOO: Failed to get pt_regs\n");
        args->pc = 0;
    }
}

static inline void do_hyp(bool is_enter, struct syscall_event* args) {
    // Add the hook_id and metadata to the call so the hypervisor knows which hook was triggered
    // and has access to syscall metadata - pass the hook_id as third argument
    igloo_portal(is_enter ? IGLOO_HYP_SYSCALL_ENTER : IGLOO_HYP_SYSCALL_RETURN,
                (unsigned long)args, 0);
}

/* Check if a value matches a filter that is assumed to be enabled */
static inline bool value_matches_filter(long value, const struct value_filter *filter)
{
    switch (filter->type) {
        case SYSCALLS_HC_FILTER_EXACT:
            return value == filter->value;
            
        case SYSCALLS_HC_FILTER_GREATER:
            return value > filter->value;
            
        case SYSCALLS_HC_FILTER_GREATER_EQUAL:
            return value >= filter->value;
            
        case SYSCALLS_HC_FILTER_LESS:
            return value < filter->value;
            
        case SYSCALLS_HC_FILTER_LESS_EQUAL:
            return value <= filter->value;
            
        case SYSCALLS_HC_FILTER_NOT_EQUAL:
            return value != filter->value;
            
        case SYSCALLS_HC_FILTER_RANGE:
            return value >= filter->min_value && value <= filter->max_value;
            
        case SYSCALLS_HC_FILTER_SUCCESS:
            return value >= 0;
            
        case SYSCALLS_HC_FILTER_ERROR:
            return value < 0;
            
        case SYSCALLS_HC_FILTER_BITMASK_SET:
            return (value & filter->bitmask) == filter->bitmask;
            
        case SYSCALLS_HC_FILTER_BITMASK_CLEAR:
            return (value & filter->bitmask) == 0;
            
        default:
            // Unknown filter type, assume no match
            return false;
    }
}

// Change hook_matches_syscall and hook_matches_syscall_return to take struct kernel_syscall_hook *
static inline bool hook_matches_syscall(struct kernel_syscall_hook *hook, const char *syscall_name, 
                         int argc, const unsigned long args[])
{
    if (!hook->hook.enabled){
        return false;
    }
    if (hook->hook.on_all){
        return true;
    }
    if (syscall_name && hook->hook.name[0] != '\0') {
        const char *normalized_syscall = normalize_syscall_name(syscall_name);
        if (strcmp(hook->normalized_name, normalized_syscall) != 0) {
            return false;
        }
    } else if (hook->hook.name[0] != '\0') {
        return false;
    }
    if (hook->hook.comm_filter_enabled) {
        if (strncmp(current->comm, hook->hook.comm_filter, TASK_COMM_LEN) != 0){
            return false;
        }
    }
    if (hook->hook.pid_filter_enabled) {
        if (task_pid_nr(current) != hook->hook.filter_pid){
            return false;
        }
    }
    for (int i = 0; i < IGLOO_SYSCALL_MAXARGS && i < argc; i++) {
        struct value_filter *f = &hook->hook.arg_filters[i];
        if (!f->enabled){
		    continue;
	    }
        unsigned long arg_ptr = args[i];
        long arg_val = *(long *)arg_ptr;
        if (f->type == SYSCALLS_HC_FILTER_EXACT){
            if (arg_val != f->value){
		    return false;
	    }
	    }else{
            if (!value_matches_filter(arg_val, f)) {
                return false;
            }
        }
    }
    return true;
}

static inline bool hook_matches_syscall_return(struct kernel_syscall_hook *hook, const char *syscall_name, 
                                 int argc, const unsigned long args[], long retval)
{
    if (!hook_matches_syscall(hook, syscall_name, argc, args)) {
        return false;
    }
    struct value_filter *f = &hook->hook.retval_filter;
    if (!f->enabled) {
        return true;
    }
    if (f->type == SYSCALLS_HC_FILTER_EXACT) {
        return retval == f->value;
    }
    return value_matches_filter(retval, f);
}

// Unified syscall hook processing function
static long process_syscall_hooks(
    bool is_entry,
    const char *syscall_name,
    int argc,
    const unsigned long args[],
    igloo_syscall_setter_t setter_func,
    long *skip_ret_val, // Only used for entry
    long orig_ret // Only used for return
) {
    struct syscall_event syscall_args_holder, original_info;
    bool skip_syscall = false;
    long skip_ret_val_local = 0;
    long modified_ret = orig_ret;
    struct kernel_syscall_hook *hook;
    rcu_read_lock();
    fill_handler(&original_info, argc, args, syscall_name);
    // 1. Check the "match all syscalls" list first
    if (!hlist_empty(&syscall_all_hooks)) {
        hlist_for_each_entry_rcu(hook, &syscall_all_hooks, name_hlist) {
            bool matches = false;
            if (is_entry) {
                matches = hook->hook.on_enter && hook_matches_syscall(hook, syscall_name, argc, args);
            } else {
                matches = hook->hook.on_return && hook_matches_syscall_return(hook, syscall_name, argc, args, modified_ret);
            }
            if (matches) {
                memcpy(&syscall_args_holder, &original_info, sizeof(struct syscall_event));
                syscall_args_holder.hook = &hook->hook;
                if (!is_entry) syscall_args_holder.retval = modified_ret;
                do_hyp(is_entry, &syscall_args_holder);
                if (is_entry) {
                    bool was_modified = false;
                    for (int i = 0; i < IGLOO_SYSCALL_MAXARGS && i < argc; i++) {
                        if (syscall_args_holder.args[i] != original_info.args[i]) {
                            DBG_PRINTK("Hypercall modified arg[%d]: old=0x%lx, new=0x%lx\n", i, original_info.args[i], syscall_args_holder.args[i]);
                            was_modified = true;
                            break;
                        }
                    }
                    if (was_modified && setter_func && args) {
                        setter_func(args, (const __le64 *)&syscall_args_holder.args[0]);
                    }
                    if (syscall_args_holder.skip_syscall) {
                        skip_syscall = true;
                        skip_ret_val_local = syscall_args_holder.retval;
                        DBG_PRINTK("IGLOO: Hook %p requested to skip syscall %s with return value %lx\n", hook, syscall_name, skip_ret_val_local);
                        break;
                    }
                } else {
                    long new_ret = syscall_args_holder.retval;
                    if (new_ret != modified_ret) {
                        DBG_PRINTK("Hypercall modified return value: old=%ld, new=%ld\n", modified_ret, new_ret);
                        modified_ret = new_ret;
                    }
                }
            }
        }
    }
    // 2. Check hooks specific to this syscall name
    if (syscall_name) {
        u32 name_hash = syscall_name_hash(syscall_name);
        hash_for_each_possible_rcu(syscall_name_table, hook, name_hlist, name_hash) {
            bool matches = false;
            if (is_entry) {
                matches = hook->hook.on_enter && hook_matches_syscall(hook, syscall_name, argc, args);
            } else {
                matches = hook->hook.on_return && hook_matches_syscall_return(hook, syscall_name, argc, args, modified_ret);
            }
            if (matches) {
                memcpy(&syscall_args_holder, &original_info, sizeof(struct syscall_event));
                syscall_args_holder.hook = &hook->hook;
                if (!is_entry) syscall_args_holder.retval = modified_ret;
                do_hyp(is_entry, &syscall_args_holder);
                if (is_entry) {
                    bool was_modified = false;
                    for (int i = 0; i < IGLOO_SYSCALL_MAXARGS && i < argc; i++) {
                        if (syscall_args_holder.args[i] != original_info.args[i]) {
                            DBG_PRINTK("Hypercall modified arg[%d]: old=0x%lx, new=0x%lx\n", i, original_info.args[i], syscall_args_holder.args[i]);
                            was_modified = true;
                            break;
                        }
                    }
                    if (was_modified && setter_func && args) {
                        setter_func(args, (const __le64 *)&syscall_args_holder.args[0]);
                    }
                    if (syscall_args_holder.skip_syscall) {
                        skip_syscall = true;
                        skip_ret_val_local = syscall_args_holder.retval;
                        DBG_PRINTK("IGLOO: Hook %p requested to skip syscall %s with return value %lx\n", hook, syscall_name, skip_ret_val_local);
                        break;
                    }
                } else {
                    long new_ret = syscall_args_holder.retval;
                    if (new_ret != modified_ret) {
                        DBG_PRINTK("Hypercall modified return value: old=%ld, new=%ld\n", modified_ret, new_ret);
                        modified_ret = new_ret;
                    }
                }
            }
        }
    }
    rcu_read_unlock();
    if (is_entry) {
        if (skip_syscall) {
            *skip_ret_val = skip_ret_val_local;
            return 1;
        }
        return 0;
    } else {
        return modified_ret;
    }
}

//Entry handler for system calls
static bool syscall_entry_handler(const char *syscall_name, long *skip_ret_val, int argc, const unsigned long args[], igloo_syscall_setter_t setter_func)
{
    check_portal_interrupt();
    if (!igloo_do_hc || !args || !skip_ret_val) {
        return 0;
    }
    if (current->flags & PF_KTHREAD) {
        return 0;
    }
    unsigned long safe_args[IGLOO_SYSCALL_MAXARGS] = {0};
    for (int i = 0; i < IGLOO_SYSCALL_MAXARGS && i < argc; i++) {
        safe_args[i] = args[i];
    }
    return process_syscall_hooks(true, syscall_name, argc, safe_args, setter_func, skip_ret_val, 0);
}

// Return handler for system calls
static long syscall_ret_handler(const char *syscall_name, long orig_ret, int argc, const unsigned long args[]){
    check_portal_interrupt();
    if (!igloo_do_hc || !args) {
        return orig_ret;
    }
    if (current->flags & PF_KTHREAD) {
        return orig_ret;
    }
    return process_syscall_hooks(false, syscall_name, argc, args, NULL, NULL, orig_ret);
}

#ifndef ARCH_HAS_SYSCALL_MATCH_SYM_NAME
static inline bool arch_syscall_match_sym_name(const char *sym, const char *name)
{
	/*
	 * Only compare after the "sys" prefix. Archs that use
	 * syscall wrappers may have syscalls symbols aliases prefixed
	 * with ".SyS" or ".sys" instead of "sys", leading to an unwanted
	 * mismatch.
	 */
	return !strcmp(sym + 3, name + 3);
}
#endif

// copied from trace_syscalls.c
static struct syscall_metadata *
find_syscall_meta_copy(unsigned long syscall);
static struct syscall_metadata *
find_syscall_meta_copy(unsigned long syscall)
{
	struct syscall_metadata **start;
	struct syscall_metadata **stop;
	char str[KSYM_SYMBOL_LEN];


	start = __start_syscalls_metadata;
	stop = __stop_syscalls_metadata;
	kallsyms_lookup(syscall, NULL, NULL, NULL, str);

	if (arch_syscall_match_sym_name(str, "sys_ni_syscall"))
		return NULL;

	for ( ; start < stop; start++) {
		if ((*start)->name && arch_syscall_match_sym_name(str, (*start)->name))
			return *start;
	}
	return NULL;
}

static void report_syscall(char * buffer, struct syscall_metadata *meta){
    if (!meta || !meta->name) {
        return; // Skip invalid metadata
    }
    // Prepare JSON metadata for hypercall (ensure buffer is large enough)
    int x = snprintf(buffer, PAGE_SIZE,
                   "{\"name\": \"%s\", \"args\":[",
                    normalize_syscall_name(meta->name));

    for (int j = 0; j < meta->nb_args && x > 0 && x < PAGE_SIZE; j++) {
        // Append args safely, checking remaining buffer space
        x += snprintf((char*)buffer + x, PAGE_SIZE - x, "[\"%s\", \"%s\"]%s",
                      meta->types[j] ? meta->types[j] : "?", // Handle potential NULL type/arg names
                      meta->args[j] ? meta->args[j] : "?",
                      j + 1 < meta->nb_args ? ", " : "");
    }

    if (x > 0 && x < PAGE_SIZE) {
         x += snprintf((char*)buffer + x, PAGE_SIZE - x, "]}");
    }

    if (x <= 0 || x >= PAGE_SIZE) {
         DBG_PRINTK( "IGLOO: Failed to format JSON for syscall %s (nr %d) - buffer overflow or snprintf error.\n", meta->name, meta->syscall_nr);
         // Decide how to handle: skip this probe or abort? Skipping for now.
         return;
    }
    // Send metadata via hypercall (call returns value, but it's ignored here)
    igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, (unsigned long)buffer);
}

// normalize_syscall_name is now defined in syscalls_hc.h

#ifdef CONFIG_COMPAT
/* For ARM64 */
#if defined(CONFIG_ARM64)
extern const syscall_fn_t compat_sys_call_table[];
/* Don't redeclare sys_call_table as it's already in syscall.h with correct type */
#define COMPAT_TABLE_SIZE __NR_compat32_syscalls

/* For x86_64 */
// #elif defined(CONFIG_X86_64)
// /* Use void* instead of syscall_fn_t for broader compatibility */
// extern const void * const ia32_sys_call_table[];
// #define compat_sys_call_table ia32_sys_call_table
// #define COMPAT_TABLE_SIZE IA32_NR_syscalls

/* For MIPS64 */
#elif defined(CONFIG_MIPS) && defined(CONFIG_64BIT)
/* Use the correct declaration that matches what's in syscall.h */
#include <asm/syscall.h>  /* Ensure we get the right declaration */
#define compat_sys_call_table sys32_call_table 
#define COMPAT_TABLE_SIZE NR_syscalls  /* Use NR_syscalls instead of __NR_syscalls */

/* For PPC64 */
// #elif defined(CONFIG_PPC64)
// extern void *sys32_call_table[];
// #define compat_sys_call_table sys32_call_table
// #define COMPAT_TABLE_SIZE __NR_syscalls

/* For RISC-V64 */
#elif defined(CONFIG_RISCV) && defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
/* Use the correct declaration for RISC-V - it's already properly declared in syscall.h */
#define COMPAT_TABLE_SIZE __NR_syscalls
#endif
#endif

/* Get syscall name from a function pointer */
#ifdef CONFIG_COMPAT
static const char *get_syscall_name_from_func(void *func_ptr) {
    char sym[KSYM_SYMBOL_LEN];
    
    if (!func_ptr || IS_ERR(func_ptr))
        return NULL;
        
    kallsyms_lookup((unsigned long)func_ptr, NULL, NULL, NULL, sym);
    
    /* Skip if we couldn't identify the symbol */
    if (!sym[0])
        return NULL;
    
    /* Skip the "sys_" or similar prefix */
    if (strncmp(sym, "sys_", 4) == 0)
        return kstrdup(sym, GFP_KERNEL);
    else if (strncmp(sym, "compat_sys_", 11) == 0) 
        return kstrdup(sym + 7, GFP_KERNEL); /* Return without the "compat_" prefix */
    else if (strncmp(sym, "__arm64_", 8) == 0)
        return kstrdup(sym + 8, GFP_KERNEL); /* Return without the "__arm64_" prefix */
    else if (strncmp(sym, "__loongarch_", 12) == 0)
        return kstrdup(sym + 12, GFP_KERNEL); /* Return without the "__loongarch_" prefix */
    else if (strncmp(sym, "__riscv_", 8) == 0)
        return kstrdup(sym + 8, GFP_KERNEL); /* Return without the "__riscv_" prefix */
    else if (strncmp(sym, "__se_", 5) == 0)
        return kstrdup(sym + 5, GFP_KERNEL); /* Return without the "__se_" prefix */
    
    return kstrdup(sym, GFP_KERNEL);
}

static void report_syscall_from_func(char *buffer, void *func_ptr, int syscall_nr) {
    const char *name;
    int x;
    
    if (!func_ptr || IS_ERR(func_ptr))
        return;
    
    name = get_syscall_name_from_func(func_ptr);
    if (!name)
        return;
    
    /* Create a simplified metadata report for compat syscalls */
    x = snprintf(buffer, PAGE_SIZE, "{\"name\": \"%s\", \"compat\": true, \"args\":\"unknown\"}", 
                normalize_syscall_name(name));
    
    if (x > 0 && x < PAGE_SIZE) {
        /* Send this metadata via hypercall */
        igloo_hypercall(IGLOO_HYP_SETUP_SYSCALL, (unsigned long)buffer);
    }
    
    kfree(name);
}
#endif

int syscalls_hc_init(void) {
    printk(KERN_EMERG "IGLOO: Initializing syscall hypercalls\n");
    if (!igloo_do_hc) {
        printk(KERN_INFO "IGLOO: Hypercalls disabled, syscalls tracing not activated\n");
        return 0;
    }
    struct syscall_metadata **p = __start_syscalls_metadata;
    struct syscall_metadata **end = __stop_syscalls_metadata;

    igloo_syscall_enter_hook = syscall_entry_handler;
    igloo_syscall_return_hook = syscall_ret_handler;

    void *buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
    
    if (!buffer) {
        printk(KERN_ERR "IGLOO: Failed to allocate memory for syscall metadata buffer\n");
        return -ENOMEM;
    }

    // Count the number of syscalls
    int num_syscall_probes = end - p;
    if (num_syscall_probes <= 0) {
        printk(KERN_WARNING "IGLOO: No syscall metadata found.\n");
        return -EINVAL;
    }

    // Process regular syscalls first
    int i;
    for (i = 0; i < NR_syscalls+1000; i++) {
        struct syscall_metadata *meta;
        unsigned long addr;
        addr = arch_syscall_addr(i);
        meta = find_syscall_meta_copy(addr);
        if (!meta)
            continue;
        meta->syscall_nr = i;
        report_syscall(buffer, meta);
    }

    for (p = __start_syscalls_metadata; p < end; p++) {
        struct syscall_metadata *meta = *p;
        if (!meta) {
            continue; // Skip invalid metadata
        }
        report_syscall(buffer, meta);
    }
    
    // Process compat syscalls
#ifdef CONFIG_COMPAT
#ifdef COMPAT_TABLE_SIZE
    printk(KERN_INFO "IGLOO: Processing compat syscall table with %d entries\n", COMPAT_TABLE_SIZE);
    
    for (i = 0; i < COMPAT_TABLE_SIZE; i++) {
#if defined(CONFIG_RISCV) && defined(CONFIG_64BIT) && defined(CONFIG_COMPAT)
        /* For RISC-V, use the already declared variable without casting */
        void *func_ptr = compat_sys_call_table[i];
#elif defined(CONFIG_MIPS) && defined(CONFIG_64BIT)
        /* For MIPS64, handle the unsigned long array correctly */
        void *func_ptr = (void *)(unsigned long)compat_sys_call_table[i];
#else
        /* For other architectures, use proper casting based on architecture pointer size */
        void *func_ptr = (void *)(uintptr_t)compat_sys_call_table[i];
#endif
        
        /* Skip non-existent syscalls (usually NULL) */
        if (!func_ptr || IS_ERR(func_ptr)) {
            continue;
        }
            
        report_syscall_from_func(buffer, func_ptr, i);
    }
#else
    printk(KERN_INFO "IGLOO: No compat syscall table found for this architecture\n");
#endif
#endif

    kfree(buffer);
    /* Initialize the hash table */
    hash_init(syscall_hook_table);
    return 0;
}

/* Unregister a syscall hook */
int unregister_syscall_hook(struct kernel_syscall_hook *hook_ptr)
{
    if (!hook_ptr)
        return -EINVAL;
    
    spin_lock(&syscall_hook_lock);
    
    // Remove from main hash table
    hash_del(&hook_ptr->hlist);
    
    // Remove from name-based hash table if it was added
    if (hook_ptr->hook.on_all) {
        hlist_del_rcu(&hook_ptr->name_hlist);
    } else if (hook_ptr->hook.name[0] != '\0') {
        hlist_del_rcu(&hook_ptr->name_hlist);
    }
    
    spin_unlock(&syscall_hook_lock);
    
    // Free the hook after RCU grace period
    kfree_rcu(hook_ptr, rcu);
    return 0;
}
