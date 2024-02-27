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
#include <linux/stat.h>
#include <linux/pagemap.h>
#include <asm/pgtable.h>
#include <linux/proc_fs.h>
#include <linux/hypercall.h>
#include <linux/dyndev.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "hyperutils.h"

static char **sysfs_names;
static int num_sysfs = 0;
struct kobject **sys_files;

extern struct kernfs_node *sysfs_root_kn;

static ssize_t sysfs_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf){

    ssize_t ret = 0;
    const char *path;
    const char *full_path;
    loff_t off = 0;
    char tmpbuf[512];

    path = kobject_get_path(kobj, GFP_KERNEL);
    if (!path) {
        printk(KERN_EMERG "Failed to get kobject path\n");
        return -ENOMEM;
    }

    full_path = kmalloc(strlen(path) + strlen(attr->attr.name) + 7, GFP_KERNEL); // +7 for slash and null terminator + /sys/
    if (!full_path) {
        printk(KERN_EMERG "Failed to allocate memory for full_path\n");
        kfree(path);
        return -ENOMEM;
    }
    sprintf(full_path, "/sys%s/%s", path, attr->attr.name);

    ret = hypervisor_read_kernel(full_path, tmpbuf, sizeof(tmpbuf), &off);
    if (ret < 0) {
        //printk(KERN_EMERG "Failed to read from hypervisor for %s\n", full_path);
        kfree(path);
        kfree(full_path);
        return ret;
    }
    tmpbuf[ret] = (char)0;
    strncpy(buf, tmpbuf, ret);
    kfree(path);
    kfree(full_path);
    return ret;
}
static ssize_t sysfs_store(struct kobject *kobj,
                struct kobj_attribute *attr, const char *buf, size_t count)
{
    ssize_t ret = 0;
    const char *path;
    const char *full_path;
    loff_t off = 0;

    path = kobject_get_path(kobj, GFP_KERNEL);

    full_path = kmalloc(strlen(path) + strlen(attr->attr.name) + 7, GFP_KERNEL); // +7 for slash and null terminator + /sys/
    if (!full_path) {
        printk(KERN_EMERG "Failed to allocate memory for full_path\n");
        kfree(path);
        return -ENOMEM;
    }
    sprintf(full_path, "/sys%s/%s", path, attr->attr.name);

    //printk(KERN_EMERG "dyndev: sysfs storing %s for path %s\n", buf, full_path);
    ret =  hypervisor_write_kernel(full_path, buf, count, &off);

    kfree(path);
    kfree(full_path);
    return ret;
}

struct kobj_attribute sysfs_entry = __ATTR(sysfs_attr, S_IRUGO|S_IWUSR, sysfs_show, sysfs_store);

struct kernfs_node* create_sysfs_dir(struct kernfs_node *parent, char* dir_path) {
    char *next_token, *delimiter = "/";

    next_token = strsep(&dir_path, delimiter);
    //printk(KERN_WARNING "dyndev: Processing directory: %s\n", next_token);

    while (next_token != NULL) {
        struct kernfs_node *kn;
        //printk(KERN_EMERG "dyndev: Creating directory: %s under parent\n", next_token);
        kn = kernfs_find_and_get(parent, next_token);

        if (!kn){
            struct kobject *kpar;
            //printk(KERN_EMERG "Did not find parent directory");
            kpar = kobject_create_and_add(next_token, (struct kobject *)parent->priv);
            if (!kpar) {
                printk(KERN_WARNING "dyndev: Failed to create directory: %s\n", next_token);
                return ERR_PTR(-ENOMEM);
            }
            kn = kernfs_find_and_get(parent, next_token);
        }
        parent = kn;
        next_token = strsep(&dir_path, delimiter); // Correctly update next_token
    }
    return parent;
}


int create_sysfs_dir_and_file(const char *path) {
    const char *relative_path = path;
    char *token, *dup_path;
    struct kernfs_node *parent = sysfs_root_kn;
    const char *file_name, *dir_path;
    int ret = 0;

    dup_path = kstrdup(relative_path, GFP_KERNEL);
    if (!dup_path) {
        printk(KERN_WARNING "dyndev: Memory allocation failed for residual path\n");
        return -ENOMEM;
    }

    // Split the path into directory path and file name
    token = dup_path;
    file_name = strrchr(token, '/');
    if (file_name) {
        dir_path = kstrndup(dup_path, file_name - dup_path, GFP_KERNEL);
        file_name++; // Move past the last '/' to get the file name

        //printk(KERN_EMERG "dyndev: Creating directory %s for file %s\n", dir_path, file_name);

        parent = create_sysfs_dir(parent, (char*)dir_path);
        kfree(dir_path); // Free the allocated directory path after use
        if (IS_ERR(parent)) {
            kfree(dup_path);
            return PTR_ERR(parent);
        }
    } else {
        printk(KERN_EMERG "Dyndev: UNSUPPORTED bare sysfs file created. This doesn't seem to work! TODO: Debug and fix this");
        file_name = token;
    }

    // Create file_name
    if (file_name != NULL) {
        sysfs_entry.attr.name = kstrdup(file_name, GFP_KERNEL);
        ret = sysfs_create_file((struct kobject *)parent->priv , &sysfs_entry.attr);
        if (ret) {
            printk(KERN_WARNING "dyndev: Failed to create sysfs file: %s\n", file_name);
            kfree(dup_path);
            return -ENOMEM;
        }
    }

    kfree(dup_path);
    //printk(KERN_EMERG "dyndev: Directory and file creation successful, returning\n");
    return 0;
}

int dyndev_init_sysfs(char *sysfs) {
    char *str, *token;
    int i = 0;
    struct kobject *entry = NULL;

    if (!sysfs || !(*sysfs)) {
        printk(KERN_EMERG "dyndev: no proc names provided\n");
        return 0;
    }
    str = sysfs; 

    // Count the number of devices to allocate memory
    num_sysfs = 1; // Start from 1 for at least one device
    for (; *str; str++) {
        if (*str == ',') {
            num_sysfs++;
        }
    }

    printk(KERN_EMERG "dyndev: found %d sysfs names\n", num_sysfs);

    // Allocate memory for proc names and proc files
    sysfs_names = kmalloc(sizeof(char*) * num_sysfs, GFP_KERNEL);
    sys_files = kmalloc(sizeof(struct kobject*) * num_sysfs, GFP_KERNEL);
    if (!sysfs_names || !sys_files) {
        pr_err("dyndev: failed to allocate memory for sysfs structures\n");
        kfree(sysfs_names);
        kfree(sys_files);
        return -ENOMEM;
    }

    str = sysfs; // Reset str to start of procnames
    while ((token = strsep(&str, ",")) != NULL) {
        int err;
        if (!(*token)) {
            continue;
        }
        err = create_sysfs_dir_and_file(token);
        // Check if the entry is an error pointer
        if (err < 0) {
            printk(KERN_WARNING "dyndev: Failed to create sysfs file for %s: %d\n", token, err);
            sys_files[i] = NULL;
        } else {
            sys_files[i] = entry;
        }
        i++;
    }
    return 0;
}

void dyndev_free_sysfs(void) {
    // int i;
    // for (i = 0; i < num_syss; i++) {
    //     if (sys_files[i]) {
    //         remove_sys_entry(sys_name[i], NULL);
    //         kfree(sys_name[i]);
    //     }
    // }
    // kfree(sysfs_names);
    // kfree(sys_files);
}

