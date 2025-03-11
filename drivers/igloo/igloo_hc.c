#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hypercall.h>
#include <linux/igloo.h>
#include "vma_hc.h"
#include "exec_hc.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("IGLOO Kernel Inspection/Interventions");
MODULE_VERSION("0.1");

/* Register probes for mmap and munmap */
static int __init igloo_hc_init(void) {
	int ret = 0;
	if ((ret = vma_hc_init()) != 0) {
        printk(KERN_ERR "Failed to register vma_hc\n");
		return ret;
	}
	// if ((ret = exec_hc_init()) != 0) {
    //     printk(KERN_ERR "Failed to register exec_hc\n");
	// 	return ret;
	// }
	return 0;
}

/* Unregister probes */
static void __exit igloo_hc_exit(void) {
    // Unreachable, module is built in
    printk(KERN_ERR "TODO\n");
}

module_init(igloo_hc_init);
module_exit(igloo_hc_exit);
