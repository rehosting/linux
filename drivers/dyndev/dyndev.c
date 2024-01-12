#include <linux/uaccess.h>
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
#include <linux/netdevice.h>
#include <linux/mm_types.h>
#include <linux/pagemap.h>
#include <asm/pgtable.h>
#include <linux/proc_fs.h>
#include <linux/hypercall.h>
#include <linux/dyndev.h>

#include "dyndev_devfs.h"
#include "dyndev_procfs.h"
#include "dyndev_netdev.h"
#include "dyndev_sysfs.h"
#include "hyperutils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrew");
MODULE_DESCRIPTION("Dynamic devices");

#define ARG_SIZE 4096

static int __init hyperdev_init(void) {
    int rv;
    pr_emerg("dyndev: Initializing the dyndev module\n");
    char *devnames = kmalloc(ARG_SIZE, GFP_KERNEL);
    char *procnames = kmalloc(ARG_SIZE, GFP_KERNEL);
    char *netdevnames = kmalloc(ARG_SIZE, GFP_KERNEL);
    char *sysfs = kmalloc(ARG_SIZE, GFP_KERNEL);
    loff_t offset = 0;
    hypervisor_read("dyndev.devnames", devnames, ARG_SIZE, &offset);
    offset = 0;
    hypervisor_read("dyndev.procnames", procnames, ARG_SIZE, &offset);
    offset = 0;
    hypervisor_read("dyndev.netdevnames", netdevnames, ARG_SIZE, &offset);
    offset = 0;
    hypervisor_read("dyndev.sysfs", sysfs, ARG_SIZE, &offset);

    printk(KERN_EMERG "dyndev: devnames: %s\n", devnames);
    printk(KERN_EMERG "dyndev: procnames: %s\n", procnames);
    printk(KERN_EMERG "dyndev: netdevnames: %s\n", netdevnames);
    printk(KERN_EMERG "dyndev: sysfs: %s\n", sysfs);

    rv = dyndev_init_devfs(devnames);
    if (rv < 0) {
        printk(KERN_ERR "dyndev: Failed to initialize devfs\n");
        return rv;
    }

    rv = dyndev_init_procfs(procnames);
    if (rv < 0) {
        printk(KERN_ERR "dyndev: Failed to initialize procfs\n");
        return rv;
    }

    rv = dyndev_init_netdevs(netdevnames);
    if (rv < 0) {
        printk(KERN_ERR "dyndev: Failed to initialize netdevs\n");
        return rv;
    }

    rv = dyndev_init_sysfs(sysfs);
    if (rv < 0) {
        printk(KERN_ERR "dyndev: Failed to initialize sysfs\n");
        return rv;
    }

    printk(KERN_ERR "dyndev module loaded.\n");
    return 0;
}

static void __exit hyperdev_exit(void) {
    dyndev_free_devfs();
    dyndev_free_procfs();
    dyndev_free_netdevs();
    dyndev_free_sysfs();
    printk(KERN_ERR "dyndev module exited.\n");
}

module_init(hyperdev_init);
module_exit(hyperdev_exit);
