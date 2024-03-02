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
#include <linux/cdev.h>
#include <linux/netdevice.h>

#include <linux/mm_types.h>
#include <linux/pagemap.h>
#include <asm/pgtable.h>

#include <linux/proc_fs.h>

#include <linux/hypercall.h>
#include <linux/dyndev.h>

#include "hyperutils.h"
#include <linux/mount.h>
#include <linux/fs.h>

static int minor;
static int num_devices = 0;
static struct class *my_class;
static struct cdev *my_cdevs; // Array of cdev structures
static int my_major;
static struct class* my_class  = NULL; // The device-driver class struct pointer

bool hook_mtd=false; // Set by dyndev, checked by mtdpart
EXPORT_SYMBOL(hook_mtd);

#define MAX_BUFFER_SIZE 0x100000 // Large buffer size for mmap

struct dyndev_private_info {
    char *path;
    char *buffer; // Pointer to the allocated memory for mmap
    size_t size;  // Size of the buffer
};

static int dyndev_open(struct inode *inode, struct file *file) {
    struct dyndev_private_info *info = kmalloc(sizeof(struct dyndev_private_info), GFP_KERNEL);
    char* path_buffer, *path_ptr;
    struct path path;

    if (!info)
        return -ENOMEM;

    // Initialize the buffer or defer its allocation to mmap
    info->buffer = NULL;
    info->size = 0; // Or your default size

    // Also update info to store our filename (observed path name
    // resolution fail with directories later during execution?)
    path_buffer = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!path_buffer) {
        kfree(info);
        return -ENOMEM;
    }

    // Resolve path
    path.dentry = file->f_path.dentry;
    path.mnt = file->f_path.mnt;
    path_ptr = d_path(&path, path_buffer, PATH_MAX);
    if (IS_ERR(path_ptr)) {
        kfree(path_buffer);
        kfree(info);
        return PTR_ERR(info->path);
    }

    info->path = kmalloc(strlen(path_ptr) + 1, GFP_KERNEL);
    if (!info->path) {
        kfree(path_buffer);
        kfree(info);
        return -ENOMEM;
    }
    strcpy(info->path, path_ptr);

    file->private_data = info;
    return 0;
}

static ssize_t dyndev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    struct dyndev_private_info *data = filep->private_data;
    //printk(KERN_ERR "READ from %s\n", data->path);
    return hypervisor_read(data->path, buffer, len, offset);
}

static ssize_t dyndev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    struct dyndev_private_info *data = filep->private_data;
    //printk(KERN_ERR "WRITE to %s\n", data->path);
    return hypervisor_write(data->path, buffer, len, offset);
}

static long dyndev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    struct dyndev_private_info *data = filep->private_data;
    //struct hyper_file_op hyper_op;
    //hyper_op.type = HYPER_IOCTL;
    //hyper_op.args.ioctl_args.cmd = cmd;
    //hyper_op.args.ioctl_args.arg = arg;
    struct hyper_file_op hyper_op = {
        .type = HYPER_IOCTL,
        .args.ioctl_args.cmd = cmd,
        .args.ioctl_args.arg = arg,
    };

    //printk(KERN_ERR "IOCTL on %s\n", data->path);
    //hyper_op.device_name = path_buffer; // Can we do this?
    snprintf(hyper_op.device_name, 128, "%s", data->path);

    sync_struct(&hyper_op);
    return hyper_op.rv; // Return the value fetched from the emulator
}

#if 0
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


static int dyndev_mmap(struct file *filp, struct vm_area_struct *vma) {
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
#endif

static int simple_mmap(struct file *file, struct vm_area_struct *vma) {
    size_t size = vma->vm_end - vma->vm_start;
    struct dyndev_private_info *info = file->private_data;

    // Check if size exceeds your maximum buffer size limit
    if (size > MAX_BUFFER_SIZE) // Define MAX_BUFFER_SIZE as needed
        return -EINVAL;

    // Allocate buffer if not already done, adjusted for larger sizes
    if (!info->buffer) {
        info->buffer = vmalloc_user(size); // Adjusted for the requested size
        if (!info->buffer)
            return -ENOMEM;
    }

    // Ensure the VMA is suitable for the mapping
    vma->vm_flags |= VM_LOCKED | VM_DONTEXPAND | VM_DONTDUMP;

    // Zero out the memory
    memset(info->buffer, 0, size);

    // Map the buffer to user space, handling larger sizes appropriately
    if (remap_vmalloc_range(vma, info->buffer, 0))
        return -EAGAIN;

    return 0;
}

static int simple_release(struct inode *inode, struct file *file) {
    struct dyndev_private_info *info = file->private_data;

    if (info) {
        // Free the allocated buffer, if it exists
        kfree(info->path);
        if (info->buffer) {
            vfree(info->buffer);
            info->buffer = NULL;
        }

        kfree(info);
        file->private_data = NULL;
    }
    return 0;
}

static struct file_operations fops = {
	.owner =	  THIS_MODULE,
    .open = dyndev_open,
    .read = dyndev_read,
    .mmap = simple_mmap,
    .release = simple_release,
    .write = dyndev_write,
    .unlocked_ioctl = dyndev_ioctl,
};

static char *rw_devnode(struct device *dev, umode_t *mode) {
    if (mode) {
        *mode = 0666; // read-write permissions for user, group, and others
    }
    return NULL;
}

int dyndev_init_devfs(char *devnames) {
    char *str, *token;
    int i=0;

    if (!devnames || !(*devnames)) {
        printk(KERN_INFO "dyndev: no dev names provided\n");
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
        unregister_chrdev(my_major, "dyndev");
        printk(KERN_ALERT "Dyndev: Failed to create class.\n");
        return PTR_ERR(my_class);
    }

    // Ensure device is can be read & written by all users
    my_class->devnode = rw_devnode;

    // Allocate array of cdev structures
    my_cdevs = kmalloc(sizeof(struct cdev) * num_devices, GFP_KERNEL);
    if (!my_cdevs) {
        printk(KERN_ERR "dyndev: Failed to allocate cdevs\n");
        return -ENOMEM;
    }

    // Allocate and register a single major number for all devices
    my_major = register_chrdev(0, "dyndev", &fops);
    if (my_major < 0) {
        printk(KERN_ERR "dyndev: Failed to register a major number\n");
        return my_major;
    }

    // Now actually tokenize the string
    str = kstrdup(devnames, GFP_KERNEL);
    if (!str) {
        pr_err("Failed to duplicate devnames\n");
        return -ENOMEM;
    }

    // Tokenize and create devices
    while ((token = strsep(&str, ",")) != NULL && i < num_devices) {
        dev_t devnum;
        if (!(*token)) {  // Check if the token is empty
            // We'll hit this if no device name is provided at all
            continue;
        }

        if (strncmp(token, "mtd", 3) == 0) {
            // MTD is a special device that we handle with custom code in mtdpart.c
            // We'll set the static bool in our header so it knows to do special stuff
            hook_mtd = true;
        }
        devnum = MKDEV(my_major, minor++);
        cdev_init(&my_cdevs[i], &fops);
        if (cdev_add(&my_cdevs[i], devnum, 1) < 0) {
            printk(KERN_ERR "dyndev: Failed to add cdev: %s\n", token);
            continue;
        }
        device_create(my_class, NULL, devnum, NULL, "%s", token);
        i++;
    }
    return 0;
}

void dyndev_free_devfs(void) {
    int i;
    for (i = 0; i < num_devices; i++) {
        dev_t devnum = MKDEV(my_major, i);
        device_destroy(my_class, devnum);
        cdev_del(&my_cdevs[i]);
    }
    class_destroy(my_class);
    unregister_chrdev(my_major, "dyndev");
    kfree(my_cdevs);
}