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
#include <net/net_namespace.h> // init_net
#include "../fs/proc/internal.h" // struct proc_dir_entry

static char **proc_name;
static int num_procs = 0;
static struct proc_dir_entry **proc_files;

extern struct proc_dir_entry proc_root;

int my_sysctl_value = 0; // Fake placeholder for sysctl value
struct dynamic_sysctl_entry {
    struct ctl_table_header *header;
    struct ctl_table *table;
};

int my_sysctl_read_write_handler(struct ctl_table *table, int write,
                                 void __user *buffer, size_t *lenp, loff_t *ppos) {
    const char *full_path = (const char*)table->extra1;
    ssize_t rv;

    if (write) {
        // Handle write operation
        rv = hypervisor_write(full_path, buffer, *lenp, ppos);
        if (rv < 0) {
            return rv; // Return error code if write failed
        }
        // For write operations, rv typically indicates the number of bytes written.
        // Update *ppos if necessary, similar to read handling.
        *ppos += rv;
        return 0;
    } else {
        // Handle read operation
        rv = hypervisor_read(full_path, buffer, *lenp, ppos);
        if (rv < 0) {
            return rv; // Return error code if read failed
        }
        // Update *lenp to reflect the actual number of bytes read.
        *lenp = rv;
        if (rv > 0) {
            *ppos += rv; // Increment *ppos by the number of bytes read.
        }
        return 0;
    }
}

struct dynamic_sysctl_entry *create_dynamic_sysctl_net_entry(const char *full_path) {
    struct dynamic_sysctl_entry *entry;
    struct ctl_table *table;
    char *path_copy, *last_slash;
    char *entry_name, *dir_path, *prefixed_full_path;

    // Duplicate the full path to manipulate it
    path_copy = kstrdup(full_path, GFP_KERNEL);
    if (!path_copy) return NULL;

    // Find the last slash to separate directory path from entry name
    last_slash = strrchr(path_copy, '/');
    if (last_slash) {
        *last_slash = '\0'; // Cut the string to get the directory path
        entry_name = last_slash + 1;
        dir_path = path_copy;
    } else {
        printk(KERN_WARNING "dyndev: No directory path found in sysctl path\n");
        return NULL;
    }

    // Allocate memory for the dynamic entry structure
    entry = kzalloc(sizeof(struct dynamic_sysctl_entry), GFP_KERNEL);
    if (!entry) {
        kfree(path_copy);
        return NULL;
    }

    // Allocate and set up the sysctl table
    table = kzalloc(2 * sizeof(struct ctl_table), GFP_KERNEL); // Extra entry for termination
    if (!table) {
        kfree(path_copy);
        kfree(entry);
        return NULL;
    }

    // Set up the sysctl table entry
    table[0].procname = entry_name; // Use the entry name as the proc name
    table[0].data = &my_sysctl_value;
    table[0].maxlen = sizeof(int);
    table[0].mode = 0644;
    table[0].proc_handler = my_sysctl_read_write_handler;

    // We want to write "/proc/sys/" before full_path into prefixed_full_path
    prefixed_full_path = kmalloc(strlen(full_path) + strlen("/proc/sys/") + 1, GFP_KERNEL);
    snprintf(prefixed_full_path, strlen(full_path) + strlen("/proc/sys/") + 1, "/proc/sys/%s", full_path);
    table[0].extra1 = (void*)prefixed_full_path; // Store the prefixed full path as extra1


    // Register the sysctl table
    printk(KERN_WARNING "dyndev: Registering sysctl net table for /proc/sys/%s\n", full_path);
    entry->table = table;
    entry->header = register_net_sysctl(&init_net, dir_path, &table[0]); // XXX inet_net is a global variable pointing to the root of /proc/sys/net

    if (!entry->header) {
        printk(KERN_WARNING "dyndev: Failed to register sysctl table for %s\n", full_path);
        kfree(table);
        kfree(entry);
        entry = NULL;
    }

    kfree(path_copy); // Clean up the duplicated path
    return entry;
}

void cleanup_dynamic_sysctl_entry(struct dynamic_sysctl_entry *entry) {
    if (!entry) return;

    if (entry->header) {
        unregister_net_sysctl_table(entry->header);
    }

    if (entry->table) {
        kfree(entry->table[0].procname);
        kfree(entry->table[0].extra1);
        kfree(entry->table); // Free the table
    }

    kfree(entry); // Free the entry structure
}


static int proc_match(unsigned int len, const char *name, struct proc_dir_entry *de)
{
	if (len < de->namelen)
		return -1;
	if (len > de->namelen)
		return 1;

	return memcmp(name, de->name, len);
}

static struct proc_dir_entry *pde_subdir_find(struct proc_dir_entry *dir,
					      const char *name,
					      unsigned int len)
{
	struct rb_node *node = dir->subdir.rb_node;

	while (node) {
		struct proc_dir_entry *de = container_of(node,
							 struct proc_dir_entry,
							 subdir_node);
		int result = proc_match(len, name, de);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return de;
	}
	return NULL;
}

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

    //printk(KERN_INFO "dyndev: proc read for %s\n", full_path);
    return hypervisor_read(full_path, ubuf, count, ppos);
}

static ssize_t proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
    char full_path[128];

    get_full_proc_path(file, full_path, sizeof(full_path));
    if (strlen(full_path) == 0) {
        return -EINVAL;
    }

    //printk(KERN_INFO "dyndev: proc write for %s\n", full_path);
    return hypervisor_write(full_path, ubuf, count, ppos);
}


// File operations for our proc file
static struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read = proc_read,
    .write = proc_write,
};

static struct proc_dir_entry *create_procfs_entry(const char *path, const struct file_operations *proc_fops) {
    struct proc_dir_entry *parent = &proc_root; // Start from the root of /proc
    char *dup_path, *token, *next_token, *delimiter = "/";
    const char *residual_path = path; // Assume the whole path might need creation initially

    // Duplication of the residual path for safe tokenization
    dup_path = kstrdup(residual_path, GFP_KERNEL);
    if (!dup_path) {
        return ERR_PTR(-ENOMEM);
    }

    if (strncmp(dup_path, "sys/", strlen("sys/")) == 0) {
        if (strncmp(dup_path, "sys/net/", strlen("sys/net/")) == 0) {
            struct dynamic_sysctl_entry *dyn_entry;

            // Strip sys/ prefix from dup_path
            dup_path += strlen("sys/");

            printk(KERN_INFO "Creating dynamic sysctl entry for /proc/sys/%s\n", dup_path);
            dyn_entry = create_dynamic_sysctl_net_entry(dup_path);
            if (!dyn_entry) {
                printk(KERN_WARNING "Failed to create sysctl entry for %s\n", dup_path);
            }
            return dyn_entry ? NULL : ERR_PTR(-ENOMEM); // Doesn't quite match our standard signature
        } else {
            printk(KERN_WARNING "UNSUPPORTED dyndev path: /proc/sys is special and we only have support for /proc/sys/net/ but you provided %s\n", path);
        }
        return NULL;
    }

    // If no specific starting point is needed, consider the entire path for creation from /proc root

    // Tokenize and process each segment of the path
    for (token = strsep(&dup_path, delimiter); token && *token; token = next_token) {
        next_token = strsep(&dup_path, delimiter); // Peek ahead to see if there's more

        if (next_token) {
            // More segments follow, so this should be a directory
            if (!parent || !pde_subdir_find(parent, token, strlen(token))) {
                printk(KERN_INFO "Creating directory: %s under parent\n", token);
                // Directory doesn't exist, so create it
                parent = proc_mkdir(token, parent);
                if (!parent) {
                    printk(KERN_WARNING "Failed to create directory: %s\n", token);
                    kfree(dup_path);
                    return ERR_PTR(-ENOMEM);
                }
            } // If directory exists, parent is already set to move into it for the next iteration
        } else {
            // This is the last segment; decide based on the context if it's a file or directory
            struct proc_dir_entry *entry = proc_create(token, 0666, parent, proc_fops);
            if (entry) {
                printk(KERN_INFO "Created proc file: %s\n", token);
            } else {
                printk(KERN_WARNING "Failed to create proc file: %s\n", token);
            }
            kfree(dup_path);
            return entry ? entry : ERR_PTR(-ENOMEM);
        }
    }

    kfree(dup_path); // Clean up if we didn't return earlier
    return parent; // Return the last created or found directory entry if no file was specified
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
        entry = create_procfs_entry(token, &proc_fops);
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
    //cleanup_dynamic_sysctl_entry(); // XXX needs specific entries, we're not tracking those
}
