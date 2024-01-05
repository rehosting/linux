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
#include "hyperutils.h"

static char **proc_name;
static int num_procs = 0;
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

int dyndev_init_procfs(char *procnames) {
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
            proc_files[i] = entry;
        }
        i++;
    }
    return 0;
}

void dyndev_free_procfs(void) {
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
