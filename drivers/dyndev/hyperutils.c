#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/hypercall.h>
#include <linux/dyndev.h>
#include "hyperutils.h"

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