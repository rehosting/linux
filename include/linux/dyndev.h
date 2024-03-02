#ifndef DYNDEV_H
#define DYNDEV_H
#include <linux/hypercall.h>
#include <linux/atomic.h>
#include <linux/printk.h>
#define HYPER_FILE_OP 0x100200
#define MAX_DEVICES 250
#define MAX_MTD_DEVICES 64  // Maximum number of MTD devices?

enum request_type {
    HYPER_READ,
    HYPER_WRITE,
    HYPER_IOCTL,
    // Add other operation types as needed
};

struct hyper_read_args {
    char *buffer;
    size_t length;
    loff_t offset;
} __packed;

struct hyper_write_args {
    const char *buffer;
    size_t length;
    loff_t offset;
} __packed;

struct hyper_ioctl_args {
    unsigned int cmd;
    unsigned long arg;
} __packed;

struct hyper_file_op {
    enum request_type type;
    unsigned long rv;
    char device_name[128];
    union {
        struct hyper_read_args read_args;
        struct hyper_write_args write_args;
        struct hyper_ioctl_args ioctl_args;
    } args;
    atomic_t refcount;
} __packed;


static inline void sync_struct(struct hyper_file_op* struct_instance) {
    int i;
    volatile char junk = 0;
    int max_tries = 100;
    while (max_tries-- > 0) {
        if (igloo_hypercall2(HYPER_FILE_OP, (unsigned long)struct_instance, (unsigned long)sizeof(struct hyper_file_op)) == 0)
            break;
        if (max_tries < 98) {
            printk(KERN_INFO "Dyndev: multiple retrying in sync struct: %d\n", 100-max_tries);
        }
        for (i = 0; i < sizeof(struct hyper_file_op); i++) {
            // Ensure we read the entire structure just to make sure it's paged in
            junk += ((char*)struct_instance)[i];
        }

        // Check if it's of type HYPER_READ and if so, copy the data back
        if (struct_instance->type == HYPER_READ) {
            // page in the buffer - read up to length bytes
            for (i = 0; i < struct_instance->args.read_args.length; i++) {
                junk += (struct_instance->args.read_args.buffer + struct_instance->args.read_args.offset)[i];
            }
        } else if (struct_instance->type == HYPER_WRITE) {
            // page in the buffer - read up to length bytes
            for (i = 0; i < struct_instance->args.write_args.length; i++) {
                junk += (struct_instance->args.write_args.buffer + struct_instance->args.write_args.offset)[i];
            }
        }
    }
    (void)junk;  // Suppress possible unused variable warning
    if (max_tries == 0) {
        pr_emerg("dyndev: failed to sync struct\n");
    }
}
#endif