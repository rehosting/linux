#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/syscall.h>
#include "igloo_syscall_macros.h"
#include "igloo.h"


/**
 * Early params originally from igloo_hc.c in the module
 */
unsigned long igloo_task_size = 0;
static int __init early_igloo_task_size(char *p)
{
    unsigned long task_size;
    if (kstrtoul(p, 0, &task_size) < 0 ) {
        pr_warn("Could not parse igloo_task_size parameter %s\n", p);
        return -1;
    }
    igloo_task_size = task_size;
    pr_warn_once("Using igloo_task_size: 0x%lx\n", igloo_task_size);
    return 0;
}
early_param("igloo_task_size", early_igloo_task_size);
EXPORT_SYMBOL(igloo_task_size);

bool igloo_block_halt=false;

static int __init early_igloo_block_halt(char *p)
{
    unsigned long block_halt;
    if (kstrtoul(p, 0, &block_halt) < 0 ) {
        pr_warn("Could not parse igloo_block_halt parameter %s. Set to 0 (default) or 1\n", p);
        return -1;
    }
    igloo_block_halt = (block_halt > 0);
    pr_warn_once("Using igloo_block_halt: %d\n", igloo_block_halt);
    return 0;
}

early_param("igloo_block_halt", early_igloo_block_halt);
EXPORT_SYMBOL(igloo_block_halt);

// Debug logging configuration for each module
struct igloo_debug_config {
    bool portal;       // Enable debug for portal module
    bool uprobe;       // Enable debug for uprobe module
    bool vma;          // Enable debug for VMA tracking
    bool syscall;      // Enable debug for syscall tracking
    bool osi;          // Enable debug for OSI features
};

// Global debug configuration
struct igloo_debug_config igloo_debug = {
    .portal = false,
    .uprobe = false,
    .vma = false,
    .syscall = false,
    .osi = false,
};

// Parse comma-separated list of modules to enable debug logging for
static int __init early_igloo_debug_modules(char *p)
{
    char *token;

    // By default, all modules have debug disabled
    memset(&igloo_debug, 0, sizeof(igloo_debug));

    // Special case: "all" enables all modules
    if (!strcmp(p, "all")) {
        memset(&igloo_debug, 1, sizeof(igloo_debug));
        pr_emerg_once("IGLOO: Debug enabled for all modules\n");
        return 0;
    }

    // Special case: "none" disables all modules (default)
    if (!strcmp(p, "none")) {
        memset(&igloo_debug, 0, sizeof(igloo_debug));
        pr_emerg_once("IGLOO: Debug disabled for all modules\n");
        return 0;
    }

    // Parse comma-separated module list
    while ((token = strsep(&p, ",")) != NULL) {
        if (!strcmp(token, "portal"))
            igloo_debug.portal = true;
        else if (!strcmp(token, "uprobe"))
            igloo_debug.uprobe = true;
        else if (!strcmp(token, "vma"))
            igloo_debug.vma = true;
        else if (!strcmp(token, "syscall"))
            igloo_debug.syscall = true;
        else if (!strcmp(token, "osi"))
            igloo_debug.osi = true;
        else if (!strcmp(token, "all")){
            memset(&igloo_debug, 1, sizeof(igloo_debug));
            pr_emerg_once("IGLOO: Debug enabled for all modules\n");
            return 0;
        }
        else
            pr_emerg("IGLOO: Unknown debug module: %s\n", token);
    }

    pr_emerg_once("IGLOO: Debug modules - portal:%d uprobe:%d vma:%d syscall:%d osi:%d\n",
               igloo_debug.portal, igloo_debug.uprobe, igloo_debug.vma,
               igloo_debug.syscall, igloo_debug.osi);

    return 0;
}

early_param("igloo_debug", early_igloo_debug_modules);
EXPORT_SYMBOL(igloo_debug);
