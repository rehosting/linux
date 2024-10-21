#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hypercall.h>
#include <linux/igloo.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrew");
MODULE_DESCRIPTION("Kretprobe-based VMA change logging");
MODULE_VERSION("0.1");

#define MAX_PROBES 20
#define HC_TASK_CHANGE 590
#define HC_VMA_UPDATE 591
// #define DEBUG_PRINT

// Enum for types of VMA updates - insert, remove, update
typedef enum {
    VMA_INSERT,
    VMA_REMOVE,
    VMA_UPDATE
} vma_update_type_t;

// Struct to hold VMA update information
typedef struct {
    vma_update_type_t type;      // Type of update
    uint64_t start_addr;         // Start of the VMA
    uint64_t end_addr;           // End of the VMA
    char name[256];              // Name (or NULL for anonymous mappings)

    // Optional old value for VMA_UPDATE
    uint64_t old_start_addr;     // Old start (for VMA_UPDATE only)
} vma_update_t;

// Stuct to hold task information, shared via hypercall
typedef struct {
    uint32_t tgid; // TGID for userspace tasks, PID for kernel threads
    uint32_t start_time;
    uint32_t parent_tgid;
    uint32_t parent_start_time;
    uint32_t is_kernel;  // Flag to indicate if it's a kernel thread
    char comm[TASK_COMM_LEN]; // 16 bytes for task name
} task_info_t;

/* Define kprobe and kretprobe structures */
static struct kretprobe mmap_retprobe;
static struct kretprobe munmap_retprobe;
static struct kretprobe mremap_retprobe;
static struct kretprobe brk_retprobe;
static struct kprobe exit_probe;
static struct kprobe switch_probe;

/* Passing data between entrance and exit of target functions */
struct munmap_data {
    unsigned long start_addr;
    unsigned long length;
};

struct mremap_data {
    unsigned long old_addr;  // Old start address
};

struct brk_data {
    unsigned long requested_brk;  // Requested brk address
    unsigned long old_brk;  // Old brk address
};

/* Architecture-specific function to retrieve syscall number */
static inline int get_syscall_number(struct pt_regs *regs) {
#ifdef CONFIG_X86_64
    return regs->orig_ax;
#elif defined(CONFIG_ARM) || defined(CONFIG_ARMEB)
    #if defined(__thumb__) || defined(__thumb2__) || defined(CONFIG_THUMB2_KERNEL)
        return regs->uregs[7];  // Syscall number is in r7 in Thumb mode
    #else
        return regs->ARM_r7;    // Syscall number is in r7 in ARM mode
    #endif
#elif defined(CONFIG_ARM64)
    return regs->regs[8];  // Syscall number is stored in x8 in ARM64
#elif defined(CONFIG_MIPS) || defined(CONFIG_MIPS64)
    return regs->regs[2];  // Syscall number is in v0 for MIPS
#else
    #error "Unsupported architecture"
#endif
}

static inline unsigned long get_first_syscall_arg(struct pt_regs *regs) {
#ifdef CONFIG_X86_64
    return regs->di;  // 1st argument in di
#elif defined(CONFIG_ARM) || defined(CONFIG_ARMEB)
    return regs->ARM_r0;  // 1st argument in r0
#elif defined(CONFIG_ARM64)
    return regs->regs[0];  // 1st argument in x0
#elif defined(CONFIG_MIPS) || defined(CONFIG_MIPS64)
    return regs->regs[4];  // 1st argument in a0 (regs[4])
#else
    #error "Unsupported architecture"
#endif
}

static inline unsigned long get_second_syscall_arg(struct pt_regs *regs) {
#ifdef CONFIG_X86_64
    return regs->si;  // 2nd argument in si
#elif defined(CONFIG_ARM) || defined(CONFIG_ARMEB)
    return regs->ARM_r1;  // 2nd argument in r1
#elif defined(CONFIG_ARM64)
    return regs->regs[1];  // 2nd argument in x1
#elif defined(CONFIG_MIPS) || defined(CONFIG_MIPS64)
    return regs->regs[5];  // 2nd argument in a1 (regs[5])
#else
    #error "Unsupported architecture"
#endif
}

static inline unsigned long get_return_value(struct pt_regs *regs) {
#ifdef CONFIG_X86_64
    return regs->ax;  // Return value in ax
#elif defined(CONFIG_ARM) || defined(CONFIG_ARMEB)
    return regs->ARM_r0;  // Return value in r0
#elif defined(CONFIG_ARM64)
    return regs->regs[0];  // Return value in x0
#elif defined(CONFIG_MIPS) || defined(CONFIG_MIPS64)
    return regs->regs[2];  // Return value in v0 (regs[2])
#else
    #error "Unsupported architecture"
#endif
}

// Check if an mmap return value is an error based on TASK_SIZE
static inline int is_mmap_error(unsigned long addr) {
    return addr >= TASK_SIZE;
}

/* Post-mmap handler (after mmap completes) */
// Log a VMA_insert event with the new VMA information
static int mmap_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct task_struct *task = current;
    struct mm_struct *mm = task->mm;
    struct vm_area_struct *vma;
    vma_update_t vma_update = {0};
    unsigned long mmap_start = get_return_value(regs); // New start address

    if (is_mmap_error(mmap_start) || mmap_start == (unsigned long)-ENOMEM || mmap_start == (unsigned long)-1) {
        // MMAP failed - ignore it
#ifdef DEBUG_PRINT
        printk(KERN_ERR "Invalid mmap return value for task %s (pid: %d): 0x%lx\n",
            current->comm, current->pid, mmap_start);
#endif
    return 0;
}


    /* Find the VMA corresponding to the mmap_start address */
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_start == mmap_start) {
            /* Found the newly mapped VMA */
            break;
        }
    }

    if (!vma) {
        // Did not find the VMA - unexpected. Maybe mmap failed?
#ifdef DEBUG_PRINT
        printk(KERN_INFO "No VMA found for task %s (pid: %d) at address 0x%lx\n",
               current->comm, current->pid, mmap_start);
#endif
        return 0;
    }

    /* Populate the vma_update */
    vma_update.type = cpu_to_le32(VMA_INSERT);
    vma_update.start_addr = cpu_to_le64(vma->vm_start);
    vma_update.end_addr = cpu_to_le64(vma->vm_end);

    if (vma->vm_file && vma->vm_file->f_path.dentry) {
        snprintf(vma_update.name, 256, "%s", vma->vm_file->f_path.dentry->d_iname);
    }

    igloo_hypercall(HC_VMA_UPDATE, (uintptr_t)&vma_update);

    /* Log the newly created VMA */
#ifdef DEBUG_PRINT
    printk(KERN_ERR "New VMA: Name: %s Start: 0x%llx, End: 0x%llx\n",
            vma_update.name, (uint64_t)vma->vm_start, (uint64_t)vma->vm_end);
#endif
    return 0;
}

/* Entry handler for the kretprobe to capture the arguments */
static int munmap_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct munmap_data data;

    /* Capture the first and second arguments */
    data.start_addr = get_first_syscall_arg(regs);  // Start address of the region to unmap
    data.length = get_second_syscall_arg(regs);             // Length of the region

    /* Copy the data into the kretprobe's data field */
    memcpy(ri->data, &data, sizeof(struct munmap_data));

    return 0;
}

/* Post-munmap handler (after munmap completes) */
static int munmap_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct munmap_data *data = (struct munmap_data *)ri->data;

    vma_update_t vma_update = {0};
    vma_update.type = cpu_to_le32(VMA_REMOVE);
    vma_update.start_addr = cpu_to_le64(data->start_addr);
    vma_update.end_addr = cpu_to_le64(data->start_addr + data->length);

    igloo_hypercall(HC_VMA_UPDATE, (uintptr_t)&vma_update);

#ifdef DEBUG_PRINT
    printk(KERN_ERR "VMA unmapped for task %s (pid: %d) - Start: 0x%lx, Length: %lu\n",
            current->comm, current->pid, data->start_addr, data->length);
#endif

    return 0;
}

/* Entry handler for the kretprobe to capture the old address and length */
static int mremap_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct mremap_data data;

    /* Capture the old start address (first argument) and length (second argument) */
    data.old_addr = get_first_syscall_arg(regs);

    /* Store the data in the kretprobe's data field */
    memcpy(ri->data, &data, sizeof(struct mremap_data));

    return 0;
}

/* Post-mremap handler (after mremap completes) */
static int mremap_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct mremap_data *data = (struct mremap_data *)ri->data;
    unsigned long new_addr = get_return_value(regs);  // New address from the return value

    vma_update_t vma_update = {0};
    vma_update.type = cpu_to_le32(VMA_UPDATE);
    vma_update.old_start_addr = cpu_to_le64(data->old_addr);
    vma_update.start_addr = cpu_to_le64(new_addr);

    igloo_hypercall(HC_VMA_UPDATE, (uintptr_t)&vma_update);

    /* Log the remap operation */
#ifdef DEBUG_PRINT
    printk(KERN_ERR "VMA remapped for task %s (pid: %d) - Old Start: 0x%lx, New Start: 0x%lx\n",
        current->comm, current->pid, data->old_addr, new_addr);
#endif

    return 0;
}

/* Pre-brk handler */
static int brk_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct brk_data data;

    /* Capture the old brk address */
    data.old_brk = current->mm->brk;

    /* Capture the requested brk address */
    data.requested_brk = get_first_syscall_arg(regs);

    /* Store the data in the kretprobe's data field */
    memcpy(ri->data, &data, sizeof(struct brk_data));

    return 0;
}

/* Post-brk handler (after brk completes) */
static int brk_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    unsigned long result = get_return_value(regs);
    vma_update_t vma_update = {0};

    if (IS_ERR_VALUE(result)) {
        return 0;
    }

    // Update vma information
    vma_update.type = cpu_to_le32(VMA_UPDATE);
    vma_update.old_start_addr = cpu_to_le64(((struct brk_data *)ri->data)->old_brk);
    vma_update.start_addr = cpu_to_le64(((struct brk_data *)ri->data)->requested_brk);

    igloo_hypercall(HC_VMA_UPDATE, (uintptr_t)&vma_update);

#ifdef DEBUG_PRINT
    printk(KERN_ERR "brk successful for task %s (pid: %d) - New End: 0x%lx\n",
            current->comm, current->pid, ((struct brk_data *)ri->data)->requested_brk);
#endif

    return 0;
}

/* Pre-exit handler (*before* exit completes) */
static int exit_handler(struct kprobe *kp, struct pt_regs *regs) {
    // Hypercall to clear VMAs for the current process clear all
    igloo_hypercall(HC_VMA_UPDATE, 0);

#ifdef DEBUG_PRINT
    printk(KERN_ERR "Process exiting: %s (pid: %d)\n", current->comm, current->pid);
#endif

    return 0;
}


/* Hooking process context switches */
static int finish_task_switch_hook(struct kprobe *kp, struct pt_regs *regs) {
    struct task_struct *next = (struct task_struct *)current;
    unsigned int next_flags;

    task_info_t task_info = {0};

    if (IS_ERR_OR_NULL(next)) {
        igloo_hypercall(HC_TASK_CHANGE, 0);
        return 0;
    }

    next_flags = READ_ONCE(next->flags);

    if (!(next_flags & (PF_KTHREAD | PF_EXITING | PF_EXITPIDONE))) {
        // For user-space tasks, set tgid and start_time
        struct task_struct *parent;

        strncpy(task_info.comm, next->comm, sizeof(task_info.comm) - 1);
        task_info.comm[sizeof(task_info.comm) - 1] = '\0';  // Ensure null-termination

        // Safely access parent process information only for non-kernel, non-exiting threads
        rcu_read_lock();
        parent = rcu_dereference(next->real_parent);
        if (!IS_ERR_OR_NULL(parent) && parent != next && !(READ_ONCE(parent->flags) & PF_KTHREAD)) {
            // Only dereference parent fields if parent is not a kernel thread and not self-referencing
            task_info.parent_tgid = cpu_to_le32(READ_ONCE(parent->tgid));
            task_info.start_time = cpu_to_le32(READ_ONCE(parent->start_time));
        }
        rcu_read_unlock();

        // For user-space tasks, set tgid and start_time
        task_info.tgid = cpu_to_le32(READ_ONCE(next->tgid));
        task_info.start_time = cpu_to_le32(READ_ONCE(next->start_time));
    } else {
        // Otherwise set the kernel thread (we'll ignore these in our coverage analysis)
        // Might actually be exiting, not just kernel. Oh well
        task_info.comm[0] = '\0';
        task_info.is_kernel = cpu_to_le32(1);
        task_info.tgid = cpu_to_le32(next->pid);  // Use pid for kernel threads
    }

    // Hypercall with struct
    igloo_hypercall(HC_TASK_CHANGE, (uintptr_t)&task_info);

    // Print debug information
#ifdef DEBUG_PRINT
    printk(KERN_ERR "Context switch: next_pid=%d, next_comm=%s, tgid=%d, parent_tgid=%d, start_time=%d, parent_start_time=%d, is_kernel=%d\n",
        task_info.tgid, task_info.comm, task_info.tgid, task_info.parent_tgid, task_info.start_time, task_info.parent_start_time, task_info.is_kernel);
#endif


    return 0;
}

/* Register probes for mmap and munmap */
int __init gva_hc_init(void) {
    int ret = 0;
    if (!igloo_log_cov) {
        return 0;
    }


    mmap_retprobe.handler = mmap_ret_handler;
    mmap_retprobe.maxactive = MAX_PROBES;
    mmap_retprobe.kp.symbol_name = "do_mmap";

    munmap_retprobe.handler = munmap_ret_handler;
    munmap_retprobe.entry_handler = munmap_entry_handler;
    munmap_retprobe.data_size = sizeof(struct munmap_data);
    munmap_retprobe.maxactive = MAX_PROBES;
    munmap_retprobe.kp.symbol_name = "sys_munmap";

    mremap_retprobe.handler = mremap_ret_handler;
    mremap_retprobe.entry_handler = mremap_entry_handler;
    mremap_retprobe.data_size = sizeof(struct mremap_data);
    mremap_retprobe.maxactive = MAX_PROBES;
    mremap_retprobe.kp.symbol_name = "sys_mremap";

    brk_retprobe.handler = brk_ret_handler;
    brk_retprobe.entry_handler = brk_entry_handler;
    brk_retprobe.data_size = sizeof(struct brk_data);
    brk_retprobe.maxactive = MAX_PROBES;
    brk_retprobe.kp.symbol_name = "sys_brk";

    switch_probe.pre_handler = finish_task_switch_hook;
    switch_probe.symbol_name = "finish_task_switch";

    exit_probe.pre_handler = exit_handler;
    exit_probe.symbol_name = "do_exit";

    ret = register_kprobe(&switch_probe);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kprobe switch_probe\n");
        return ret;
    }

    ret = register_kprobe(&exit_probe);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kprobe exit_retprobe\n");
        return ret;
    }

    ret = register_kretprobe(&mmap_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kretprobe mmap_retprobe\n");
        return ret;
    }

    ret = register_kretprobe(&munmap_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kretprobe munmap_retprobe\n");
        return ret;
    }

    ret = register_kretprobe(&mremap_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kretprobe mremap_retprobe\n");
        return ret;
    }

    ret = register_kretprobe(&brk_retprobe);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kretprobe brk_retprobe\n");
        return ret;
    }

    printk(KERN_ERR "Kprobes registered\n");
    return 0;
}

/* Unregister probes */
static void __exit gva_hc_exit(void) {
    // Unreachable, module is built in
    printk(KERN_ERR "TODO\n");
}

module_init(gva_hc_init);
module_exit(gva_hc_exit);
