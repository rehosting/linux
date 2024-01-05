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
#include <linux/netdevice.h>
#include <linux/mm_types.h>
#include <linux/pagemap.h>
#include <asm/pgtable.h>
#include <linux/proc_fs.h>
#include <linux/hypercall.h>
#include <linux/dyndev.h>

#include "dyndev_devfs.h"
#include "dyndev_procfs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrew");
MODULE_DESCRIPTION("Dynamic devices");

static char *devnames = "";
module_param(devnames, charp, 0000);
MODULE_PARM_DESC(devnames, "A comma-separated list of device names");

static char *procnames = "";
module_param(procnames, charp, 0000);
MODULE_PARM_DESC(procnames, "A comma-separated list of proc names");

static char *netdevnames = "";
module_param(netdevnames, charp, 0000);
MODULE_PARM_DESC(netdevnames, "A comma-separated list of network device names");


static int __init hyperdev_init(void) {
    int rv;
    pr_emerg("dyndev: Initializing the dyndev module\n");

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

    //rv = dyndev_init_netdevs(netdevnames);
    //if (rv < 0) {
    //    printk(KERN_ERR "dyndev: Failed to initialize netdevs\n");
    //    return rv;
    //}

    printk(KERN_ERR "dyndev module loaded.\n");
    return 0;
}

static void __exit hyperdev_exit(void) {
    dyndev_free_devfs();
    dyndev_free_procfs();
    dyndev_free_netdevs();
    printk(KERN_ERR "dyndev module exited.\n");
}

module_init(hyperdev_init);
module_exit(hyperdev_exit);