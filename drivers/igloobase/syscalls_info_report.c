#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/ftrace.h>
#include <asm/ftrace.h>
#include <linux/binfmts.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <trace/syscall.h>
#include <asm/syscall.h>
#include "hypercall.h" // Content is now included directly below
#include "igloo.h"
#include "igloobase.h"
#include "igloobasehypercalls.h"

extern struct syscall_metadata *__start_syscalls_metadata[];
extern struct syscall_metadata *__stop_syscalls_metadata[];

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

/* Normalize syscall names by removing common prefixes like 'sys_', '_sys_', 'compat_sys_' */
static inline const char *normalize_syscall_name(const char *name)
{
    if (!name)
        return NULL;
        
    /* Skip leading underscores (e.g. _sys_) */
    while (*name == '_')
        name++;
        
    /* Check for 'sys_' prefix */
    if (strncmp(name, "sys_", 4) == 0)
        return name + 4;
        
    /* Check for 'compat_sys_' prefix */
    if (strncmp(name, "compat_sys_", 11) == 0)
        return name + 11;
    
    /* Check for other arch-specific prefixes */
    if (strncmp(name, "arm64_sys_", 10) == 0)
        return name + 10;
    
    if (strncmp(name, "riscv_sys_", 10) == 0)
        return name + 10;
        
    return name;
}

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
        //  DBG_PRINTK( "IGLOO: Failed to format JSON for syscall %s (nr %d) - buffer overflow or snprintf error.\n", meta->name, meta->syscall_nr);
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

int syscalls_info_report(void) {
    printk(KERN_EMERG "IGLOO: Initializing syscall hypercalls\n");
    if (!igloo_do_hc) {
        printk(KERN_INFO "IGLOO: Hypercalls disabled, syscalls tracing not activated\n");
        return 0;
    }
    struct syscall_metadata **p = __start_syscalls_metadata;
    struct syscall_metadata **end = __stop_syscalls_metadata;

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
    return 0;
}