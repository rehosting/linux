#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "igloo.h"
#include "igloobase.h"


/* Register probes for mmap and munmap */
static int __init igloo_base_init(void) {
	int ret;
	printk(KERN_EMERG "IGLOOBase: Initializing\n");
    if ((ret = osi_notifier_init()) != 0) {
        printk(KERN_ERR "Failed to register osi_notifier_init\n");
    }
    if ((ret = syscalls_info_report()) != 0) {
		printk(KERN_ERR "Failed to register syscalls_hc returning %d\n", ret);
	}
	return 0;
}

/* Unregister probes */
static void __exit igloo_base_exit(void) {
    // Unreachable, module is built in
    printk(KERN_ERR "TODO\n");
}

module_init(igloo_base_init);
module_exit(igloo_base_exit);