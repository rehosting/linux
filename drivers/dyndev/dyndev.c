#include <asm/uaccess.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <linux/mm_types.h>
#include <linux/pagemap.h>
#include <asm/pgtable.h>

#include <linux/proc_fs.h>

#include <linux/hypercall.h>
#include <linux/dyndev.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrew");
MODULE_DESCRIPTION("Dynamic devices");

bool hook_mtd=false; // Set by dyndev, checked by mtdpart
EXPORT_SYMBOL(hook_mtd);

static char *devnames = "";
module_param(devnames, charp, 0000);
MODULE_PARM_DESC(devnames, "A comma-separated list of device names");

static char *procnames = "";
module_param(procnames, charp, 0000);
MODULE_PARM_DESC(procnames, "A comma-separated list of proc names");

static char **device_name;
static int *device_major;
static int num_devices = 0;

static char **proc_name;
static int num_procs = 0;

static struct class* my_class  = NULL; // The device-driver class struct pointer

// Unified read function for hypervisor interaction
ssize_t hypervisor_read(const char *device_name, char *buffer, size_t len, loff_t *offset) {
    char *kernel_buffer;
    struct hyper_file_op hyper_op;
    ssize_t ret;
    //printk(KERN_INFO "dyndev: read for device %s\n", device_name);

    kernel_buffer = kmalloc(len, GFP_KERNEL);
    if (!kernel_buffer) {
        return -ENOMEM;
    }

    hyper_op.type = HYPER_READ;
    strncpy(hyper_op.device_name, device_name, 127);
    hyper_op.args.read_args.buffer = kernel_buffer;
    hyper_op.args.read_args.length = len;
    hyper_op.args.read_args.offset = *offset;

    sync_struct(&hyper_op);

    if (copy_to_user(buffer, kernel_buffer, len)) {
        ret = -EFAULT;
    } else {
        if (hyper_op.rv > 0) {
            *offset += hyper_op.rv;
        }
        ret = hyper_op.rv;
    }

    kfree(kernel_buffer);
    return ret;
}

// Unified write function for hypervisor interaction
ssize_t hypervisor_write(const char *device_name, const char *buffer, size_t len, loff_t *offset) {
    char *kernel_buffer;
    struct hyper_file_op hyper_op;
    ssize_t ret;
    //printk(KERN_INFO "dyndev: write for device %s\n", device_name);

    kernel_buffer = kmalloc(len, GFP_KERNEL);
    if (!kernel_buffer) {
        return -ENOMEM;
    }

    if (copy_from_user(kernel_buffer, buffer, len)) {
        kfree(kernel_buffer);
        return -EFAULT;
    }

    hyper_op.type = HYPER_WRITE;
    strncpy(hyper_op.device_name, device_name, 127);
    hyper_op.args.write_args.buffer = kernel_buffer;
    hyper_op.args.write_args.length = len;
    hyper_op.args.write_args.offset = *offset;

    sync_struct(&hyper_op);

    if (hyper_op.rv > 0) {
        *offset += hyper_op.rv;
    }
    ret = hyper_op.rv;

    kfree(kernel_buffer);
    return ret;
}

static int dev_open(struct inode *inodep, struct file *filep) {
    return 0;
}

static int dev_release(struct inode *inodep, struct file *filep) {
    return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    // We need to prepend the filename with /dev/ to get the full path
    char full_path[128];
    snprintf(full_path, 128, "/dev/%s", filep->f_path.dentry->d_iname);
    return hypervisor_read(full_path, buffer, len, offset);
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    char full_path[128];
    snprintf(full_path, 128, "/dev/%s", filep->f_path.dentry->d_iname);
    return hypervisor_write(full_path, buffer, len, offset);
}

static void my_vm_open(struct vm_area_struct *vma) {
    struct hyper_file_op* old_hyper_op = vma->vm_private_data;
    //printk(KERN_INFO "dyndev open: virt %lx for hyper_file at %p\n", vma->vm_start, old_hyper_op);

    // Increment reference count to prevent premature free in case of fork
    if (old_hyper_op) {
        atomic_inc(&old_hyper_op->refcount);
    }
}

static void my_vm_close(struct vm_area_struct *vma) {
    struct hyper_file_op* hyper_op = vma->vm_private_data;

    printk(KERN_INFO "dyndev close: virt %lx for hyper_file at %p\n", vma->vm_start, hyper_op);

    if (hyper_op && atomic_dec_and_test(&hyper_op->refcount)) {
        kfree(hyper_op);
        vma->vm_private_data = NULL;
    }

    #if 0
    if (hyper_op && atomic_dec_and_test(&hyper_op->refcount)) {
        // Execute the hypercall for write
        //printk(KERN_INFO "\t: writing back to device %s\n", hyper_op->device_name);
        //printk(KERN_INFO "\t: kbuf is at %p\n", hyper_op->args.read_args.buffer);

        hyper_op->type = HYPER_WRITE;
        sync_struct(hyper_op);
        //printk(KERN_INFO "\t: rv is %ld\n", hyper_op->rv);

        // Free the buffer and hyper op struct
        if (hyper_op->args.read_args.buffer) {
            //printk(KERN_INFO "\t: free_pages for kernel buf at %p\n", hyper_op->args.read_args.buffer);
            free_pages((unsigned long)hyper_op->args.read_args.buffer, get_order(vma->vm_end - vma->vm_start));
        }

        //printk(KERN_INFO "\t: kfreeing hyper op struct %p\n", hyper_op);
        kfree(hyper_op);

        vma->vm_private_data = NULL;
    }
    #endif
}

static int my_fault_handler(struct vm_area_struct *vma, struct vm_fault *vmf) {
    struct page *page;
    char *kernel_buffer;
    struct hyper_file_op *hyper_op = vmf->vma->vm_private_data;
    ssize_t ret;
    unsigned long address = (unsigned long)vmf->address;
    void *page_ptr;
    bool is_write = vmf->flags & FAULT_FLAG_WRITE;
    unsigned long pfn;

    printk(KERN_INFO "dyndev: page fault at address %lx. Write=%d\n", address, is_write);

    // Allocate a temporary kernel buffer
    kernel_buffer = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!kernel_buffer) {
        return VM_FAULT_OOM;
    }

    if (is_write) {
        // Handle write fault: Copy data from user space to kernel buffer
        if (copy_from_user(kernel_buffer, (char *)vmf->address, PAGE_SIZE)) {
            kfree(kernel_buffer);
            return VM_FAULT_SIGBUS;
        }

        // TODO: Add your write handling logic here
        hyper_op->type = HYPER_WRITE;
        hyper_op->args.write_args.buffer = kernel_buffer;
        sync_struct(hyper_op);
    } else {
        // Handle read fault: Populate kernel buffer with data for user space
        if (copy_to_user((char *)vmf->address, kernel_buffer, PAGE_SIZE)) {
            kfree(kernel_buffer);
            return VM_FAULT_SIGBUS;
        }
        hyper_op->type = HYPER_READ;
        hyper_op->args.read_args.buffer = kernel_buffer;
        sync_struct(hyper_op);
    }

    // Allocate a new page and copy data to it
    page = alloc_page(GFP_KERNEL);
    if (!page) {
        kfree(kernel_buffer);
        return VM_FAULT_OOM;
    }
    page_ptr = kmap(page);
    memcpy(page_ptr, kernel_buffer, PAGE_SIZE);
    kunmap(page);

    // Convert the page to a PFN
    pfn = page_to_pfn(page);

    // Unmap the page to ensure the next access traps
    zap_vma_ptes(vma, address & PAGE_MASK, PAGE_SIZE);

    // Insert the page into the user space
    ret = vm_insert_pfn(vma, address & PAGE_MASK, pfn);
    if (ret) {
        __free_page(page);
        kfree(kernel_buffer);
        return ret;
    }

    kfree(kernel_buffer);
    return VM_FAULT_NOPAGE; // Indicate that the fault has been handled
}

static const struct vm_operations_struct my_vm_ops = {
    .open = my_vm_open,
    .close = my_vm_close,
    .fault = my_fault_handler,
};

static int dev_mmap(struct file *filp, struct vm_area_struct *vma) {
    struct hyper_file_op* hyper_op;
    size_t len = vma->vm_end - vma->vm_start;

    hyper_op = kmalloc(sizeof(struct hyper_file_op), GFP_KERNEL);
    if (!hyper_op) {
        pr_err("Failed to allocate memory for hyper_op\n");
        return -ENOMEM;
    }

    atomic_set(&hyper_op->refcount, 1); // Initialize reference count

    hyper_op->type = HYPER_READ; // Initialize for read, can be changed in fault handler
    snprintf(hyper_op->device_name, 128, "/dev/%s", filp->f_path.dentry->d_iname);
    hyper_op->args.read_args.length = len;
    hyper_op->args.read_args.offset = 0;
    //hyper_op->args.read_args.offset = vma->vm_pgoff << PAGE_SHIFT; // ???

    printk(KERN_ERR "dyndev: MMAPing device %s\n", hyper_op->device_name);

    // Set up the VMA
    vma->vm_ops = &my_vm_ops; // Set the custom vm_ops
    vma->vm_private_data = hyper_op;
    vma->vm_flags |= VM_MIXEDMAP; // Indicate custom page fault handling

    // Do not map any pages here. Let the fault handler take care of it.
    return 0;
}



static long dev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    struct hyper_file_op hyper_op;
    hyper_op.type = HYPER_IOCTL;
    snprintf(hyper_op.device_name, 128, "/dev/%s", filep->f_path.dentry->d_iname);
    hyper_op.args.ioctl_args.cmd = cmd;
    hyper_op.args.ioctl_args.arg = arg;

    sync_struct(&hyper_op);

    return hyper_op.rv; // Return the value fetched from the emulator
}

static struct file_operations fops = {
	.owner =	  THIS_MODULE,
    .open = dev_open,
    .read = dev_read,
    .mmap = dev_mmap,
    .release = dev_release,
    .write = dev_write,
    .unlocked_ioctl = dev_ioctl,
};

static char *rw_devnode(struct device *dev, umode_t *mode) {
    if (mode) {
        *mode = 0666; // read-write permissions for user, group, and others
    }
    return NULL;
}

int init_devices(void) {
    char *str, *token;
    dev_t current_dev;
    int i=0;

    if (!devnames || !(*devnames)) {
        return 0;
    }

    // First, count the number of devices to allocate memory
    for (str = devnames; *str; str++) {
        if (*str == ',') {
            num_devices++;
        }
    }
    num_devices++; // Add one more for the last (or only) device name

    my_class = class_create(THIS_MODULE, "dyndev");
    if (IS_ERR(my_class)) {
        printk(KERN_ALERT "Dyndev: Failed to create class.\n");
        return -EINVAL;
    }

    // Ensure device is can be read & written by all users
    my_class->devnode = rw_devnode;


    // Allocate memory with error checking for device names and major numbers
    device_name = kmalloc(sizeof(char*) * num_devices, GFP_KERNEL);
    if (!device_name) {
        pr_err("Failed to allocate memory for device_name\n");
        return -ENOMEM;
    }
    device_major = kmalloc(sizeof(int) * num_devices, GFP_KERNEL);
    if (!device_major) {
        pr_err("Failed to allocate memory for device_major\n");
        kfree(device_name);
        return -ENOMEM;
    }

    // Now actually tokenize the string
    str = kstrdup(devnames, GFP_KERNEL);
    if (!str) {
        pr_err("Failed to duplicate devnames\n");
        kfree(device_name);
        kfree(device_major);
        return -ENOMEM;
    }

    while ((token = strsep(&str, ",")) != NULL) {
        if (!(*token)) {  // Check if the token is empty
            // We'll hit this if no device name is provided at all
            continue;
        }

        // If this token is 'mtd' we set a flag and skip
        if (strncmp(token, "mtd", 3) == 0) {
            // MTD is a special device that we handle with custom code in mtdpart.c
            // We'll set the static bool in our header so it knows to do special stuff
            hook_mtd = true;
            continue;
        }

        device_name[i] = kstrdup(token, GFP_KERNEL);
        // Initialize device_major[i] appropriately
        device_major[i] = register_chrdev(0, device_name[i], &fops);
        if (device_major[i] < 0) {
            printk(KERN_ALERT "Could not register device %s: %d\n", device_name[i], device_major[i]);
            return device_major[i];
        } else { 
            printk(KERN_ALERT "Registered device %s: %d\n", device_name[i], device_major[i]);
            current_dev = MKDEV(device_major[i], 0);
            device_create(my_class, NULL, current_dev, NULL, "%s", device_name[i]);
        }
        i++;
    }
    return 0;
}

void free_devices(void) {
    int i;
    dev_t current_dev;
    for (i = 0; i < num_devices; i++) {
        current_dev = MKDEV(device_major[i], 0);
        device_destroy(my_class, current_dev);

        unregister_chrdev(device_major[i], device_name[i]);
        printk(KERN_INFO "Unregistered device %s\n", device_name[i]);
    }

    // Destroy the class
    class_destroy(my_class);
    kfree(device_major);
}

//////////////// Proc files ///////////////
static struct proc_dir_entry **proc_files;

static void get_full_proc_path(struct file *file, char *path, size_t path_len) {
    struct dentry *dentry;
    struct path f_path;
    char* p;
    char *buf = (char *)__get_free_page(GFP_TEMPORARY);

    if (!buf) {
        path[0] = '\0';
        return;
    }

    f_path = file->f_path;
    dentry = f_path.dentry;

    /* Get the full path. This will put the path in reverse order */
    p = dentry_path_raw(dentry, buf, PAGE_SIZE);

    if (IS_ERR(p)) {
        path[0] = '\0';
    } else {
        /* Reverse the path to get it in the correct order */
        snprintf(path, path_len, "/proc%s", p);
    }

    free_page((unsigned long)buf);
}

static ssize_t proc_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
    char full_path[128];

    get_full_proc_path(file, full_path, sizeof(full_path));
    if (strlen(full_path) == 0) {
        return -EINVAL;
    }

    printk(KERN_INFO "dyndev: proc read for %s\n", full_path);
    return hypervisor_read(full_path, ubuf, count, ppos);
}

static ssize_t proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char full_path[128];

    get_full_proc_path(file, full_path, sizeof(full_path));
    if (strlen(full_path) == 0) {
        return -EINVAL;
    }

    printk(KERN_INFO "dyndev: proc write for %s\n", full_path);
    return hypervisor_write(full_path, ubuf, count, ppos);
}


// File operations for our proc file
static struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read = proc_read,
    .write = proc_write,
};

static struct proc_dir_entry *create_procfs_dir(const char *path) {
    const char *relative_path = path;
    const char *residual;
    char *token, *dup_path, *next_token, *delimiter = "/";
    struct proc_dir_entry *parent = NULL, *entry;
    int result;

    //printk(KERN_INFO "dyndev: create_procfs_dir called with path: %s\n", path);

    // Skip the "/proc/" part if present
    if (strncmp(path, "/proc/", 6) == 0) {
        relative_path += 6;
    }

    //printk(KERN_INFO "dyndev: Relative path for xlate_proc_name: %s\n", relative_path);

    // Use xlate_proc_name to find the deepest existing directory
    result = xlate_proc_name(relative_path, &parent, &residual);
    if (result != 0) {
        //printk(KERN_INFO "dyndev: Path does not exist at all, creating entire path\n");
        residual = relative_path;
        parent = NULL;
    }

    dup_path = kstrdup(residual, GFP_KERNEL);
    if (!dup_path) {
        //printk(KERN_WARNING "dyndev: Memory allocation failed for residual path\n");
        return ERR_PTR(-ENOMEM);
    }

    token = strsep(&dup_path, delimiter);
    next_token = strsep(&dup_path, delimiter);
    while (next_token != NULL) {
        //printk(KERN_INFO "dyndev: Creating directory: %s under parent\n", token);
        entry = proc_mkdir(token, parent);
        if (!entry) {
            printk(KERN_WARNING "dyndev: Failed to create directory: %s\n", token);
            kfree(dup_path);
            return ERR_PTR(-ENOMEM);
        }
        parent = entry;

        token = next_token;
        next_token = strsep(&dup_path, delimiter); // Move to next token
    }

    // Create the proc file with the name of the last token
    if (token != NULL) {
        //printk(KERN_INFO "dyndev: Creating proc file: %s\n", token);
        parent = proc_create(token, 0666, parent, &proc_fops);
        if (!parent) {
            printk(KERN_WARNING "dyndev: Failed to create proc file: %s\n", token);
            kfree(dup_path);
            return ERR_PTR(-ENOMEM);
        }
    }

    kfree(dup_path);
    //printk(KERN_INFO "dyndev: Directory and file creation successful, returning entry\n");
    return parent;
}

int init_procs(void) {
    char *str, *token;
    int i = 0;
    struct proc_dir_entry *entry = NULL;

    if (!procnames || !(*procnames)) {
        printk(KERN_INFO "dyndev: no proc names provided\n");
        return 0;
    }
    str = procnames; 

    // Count the number of devices to allocate memory
    num_procs = 1; // Start from 1 for at least one device
    for (; *str; str++) {
        if (*str == ',') {
            num_procs++;
        }
    }

    printk(KERN_INFO "dyndev: found %d proc names\n", num_procs);

    // Allocate memory for proc names and proc files
    proc_name = kmalloc(sizeof(char*) * num_procs, GFP_KERNEL);
    proc_files = kmalloc(sizeof(struct proc_dir_entry*) * num_procs, GFP_KERNEL);
    if (!proc_name || !proc_files) {
        pr_err("dyndev: failed to allocate memory for proc structures\n");
        kfree(proc_name);
        kfree(proc_files);
        return -ENOMEM;
    }

    str = procnames; // Reset str to start of procnames
    while ((token = strsep(&str, ",")) != NULL) {
        if (!(*token)) {
            continue;
        }
        entry = create_procfs_dir(token);
        // Check if the entry is an error pointer
        if (IS_ERR(entry)) {
            printk(KERN_WARNING "dyndev: Failed to create proc file for %s\n", token);
            proc_files[i] = NULL;
        } else {
            proc_files[i] =  entry;
        }
        i++;
    }
    return 0;
}

void free_procs(void) {
    int i;
    for (i = 0; i < num_procs; i++) {
        if (proc_files[i]) {
            remove_proc_entry(proc_name[i], NULL);
            kfree(proc_name[i]);
        }
    }
    kfree(proc_name);
    kfree(proc_files);
}


static int __init hyperdev_init(void) {
    int rv;
    pr_emerg("dyndev: Initializing the dyndev module\n");

    rv = init_devices();
    if (rv < 0) {
        return rv;
    }

    rv = init_procs();
    if (rv < 0) {
        return rv;
    }

    printk(KERN_INFO "Module loaded.\n");
    return 0;
}

static void __exit hyperdev_exit(void) {
    free_devices();
    free_procs();
}

module_init(hyperdev_init);
module_exit(hyperdev_exit);
