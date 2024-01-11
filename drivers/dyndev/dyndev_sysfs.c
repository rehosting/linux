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
    char tmpbuf[128];

    path = kobject_get_path(kobj, GFP_KERNEL);
    
    full_path = kmalloc(strlen(path) + strlen(attr->attr.name) + 7, GFP_KERNEL);
    sprintf(full_path, "/sys%s/%s", path, attr->attr.name);

    // printk(KERN_EMERG "dyndev: sysfs show %p %s\n", kobj, full_path);
    ret = hypervisor_read(full_path, tmpbuf, 100, &off);
    kfree(path);
    kfree(full_path);
    return ret;
}
static ssize_t sysfs_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
    ssize_t ret = 0;
    const char *path;
    const char *full_path;
    loff_t off = 0;

    path = kobject_get_path(kobj, GFP_KERNEL);
    
    full_path = kmalloc(strlen(path) + strlen(attr->attr.name) + 7, GFP_KERNEL);
    sprintf(full_path, "/sys%s/%s", path, attr->attr.name);

    // printk(KERN_EMERG "dyndev: sysfs store %p %s\n", kobj, full_path);
    ret =  hypervisor_write(full_path, buf, PAGE_SIZE, &off);
    kfree(path);
    kfree(full_path);
    return ret;
}

struct kobj_attribute sysfs_entry = __ATTR(sysfs_attr, S_IRUGO|S_IWUSR, sysfs_show, sysfs_store);


static struct kobject *create_sysfs_dir(const char *path) {
    const char *relative_path = path;
    const char *residual;
    char *token, *dup_path, *next_token, *delimiter = "/";
    struct kobject *head = NULL;
    struct kernfs_node *parent = sysfs_root_kn;

    printk(KERN_EMERG "dyndev: create_sysfs_dir called with path: %s\n", path);

    // Skip the "/sys/" part if present
    // if (strncmp(path, "/sys/", 5) == 0) {
    //     relative_path += 5;
    // }
    // // check starting kobjects
    // if (strncmp(path, "module/", 7) == 0) {
    //     relative_path += 7;
    //     head = module_kset;
    // }else if (strncmp(path, "mm/",3) == 0){
    //     relative_path += 3;
    //     head = mm_kobj;
    // }else if (strncmp(path, "hypervisor/",11) == 0){
    //     relative_path += 11;
    //     head = hypervisor_kobj;
    // }else if (strncmp(path, "firmware/",9) == 0){
    //     relative_path += 9;
    //     head = firmware_kobj;
    // }else{
    //     printk(KERN_EMERG "dyndev: No starting kobject found\n");
    //     return;
    // }
    // parent = head->sd;

    dup_path = kstrdup(relative_path, GFP_KERNEL);
    if (!dup_path) {
        //printk(KERN_WARNING "dyndev: Memory allocation failed for residual path\n");
        return ERR_PTR(-ENOMEM);
    }

    token = strsep(&dup_path, delimiter);
    next_token = strsep(&dup_path, delimiter);
    while (next_token != NULL && strlen(token) > 0) {
        printk(KERN_EMERG "dyndev: Creating directory: %s under parent\n", token);
        struct kernfs_node *kn = kernfs_find_and_get(parent, token);

        if (!kn){
            printk(KERN_EMERG "Did not find parent directory");
            struct kobject *kpar;
            kpar = kobject_create_and_add(token, (struct kobject *)parent->priv);
            if (!kpar) {
                printk(KERN_WARNING "dyndev: Failed to create directory: %s\n", token);
                kfree(dup_path);
                return ERR_PTR(-ENOMEM);
            }
            kn = kernfs_find_and_get(parent, token);
            if (!kn) {
                printk(KERN_WARNING "dyndev: Failed to find directory: %s\n", token);
                kfree(dup_path);
                return ERR_PTR(-ENOMEM);
            }
        }
        parent = kn;
        token = next_token;
        next_token = strsep(&dup_path, delimiter); // Move to next token
    }

    struct kobject *par = NULL;
  
    par = (struct kobject *)parent->priv;
    int ret = 0;
    // Create the sysfs file with the name of the last token
    if (token != NULL) {
        printk(KERN_EMERG "dyndev: Creating sysfs file: %s\n", token);
        sysfs_entry.attr.name = token;
        ret = sysfs_create_file(par, &sysfs_entry.attr);
        if (ret) {
            printk(KERN_WARNING "dyndev: Failed to create sysfs file: %s\n", token);
            kfree(dup_path);
            return ERR_PTR(-ENOMEM);
        }
        struct kernfs_node *kfsn = kernfs_find_and_get(parent, token);
        if (kfsn) {
            printk(KERN_WARNING "dyndev: Failed to find sysfs file: %s\n", token);
            kfree(dup_path);
            return ERR_PTR(-ENOMEM);
        }
        par = (struct kobject *)kfsn->priv;
    }

    kfree(dup_path);
    printk(KERN_EMERG "dyndev: Directory and file creation successful, returning entry\n");
    return par;
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
        if (!(*token)) {
            continue;
        }
        entry = create_sysfs_dir(token);
        // Check if the entry is an error pointer
        if (IS_ERR(entry)) {
            printk(KERN_WARNING "dyndev: Failed to create sysfs file for %s\n", token);
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

