/*
 * container.c
 *
 * Android Container Subsystem
 *
 * Copyright (C) 2015-2017 ICL/ITRI
 * All rights reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of ICL/ITRI and its suppliers, if any.
 * The intellectual and technical concepts contained
 * herein are proprietary to ICL/ITRI and its suppliers and
 * may be covered by Taiwan and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from ICL/ITRI.
 *
 */

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/rwsem.h>
#include <linux/string.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include "container.h"

#define BINDER_ULONG_TO_ULONG(x) ((unsigned long)(x))

enum {
        CONTAINER_DEBUG_INIT                   = 1U << 0,
	CONTAINER_DEBUG_IOCTL                  = 1U << 1,
        CONTAINER_DEBUG_OPEN_CLOSE             = 1U << 2,
        CONTAINER_DEBUG_READ_WRITE             = 1U << 3,
};

#ifdef DEBUG_CONTAINER
static uint32_t container_debug_mask = CONTAINER_DEBUG_INIT |
                                       CONTAINER_DEBUG_IOCTL | 
                                       CONTAINER_DEBUG_READ_WRITE;
#else
static uint32_t container_debug_mask = 0 ;
#endif

module_param_named(debug_mask, container_debug_mask, uint, S_IWUSR | S_IRUGO);

#define container_debug(mask, x...) \
        do { \
		if (container_debug_mask & mask) \
			printk(KERN_INFO x); \
	} while (0)

#define container_error(x...) \
	do { \
		printk(KERN_ERR x); \
	} while (0)

/* proc entries */
static struct proc_dir_entry *container_proc_root;
static struct proc_dir_entry *container_proc_active;
static struct proc_dir_entry *container_proc_ready;


/* proc buffer related data */
static struct rw_semaphore proc_rw_sem;

static struct miscdevice container_miscdev;

#if 1

static int active_container = 0;
static int ready_container = 0;


static int container_send_uevent(int event_id)
{
  char event_string[32];
  char *envp[] = { event_string, NULL };

  snprintf(event_string, sizeof(event_string), "ACTIVE_CONTAINER_CHANGED=%d", event_id);

  container_debug(CONTAINER_DEBUG_READ_WRITE, " container_send_uevent %s \n", event_string);

  return kobject_uevent_env(&container_miscdev.this_device->kobj, KOBJ_CHANGE, envp);
}

static int container_send_uevent_ready(int event_id)
{
  char event_string[32];
  char *envp[] = { event_string, NULL };

  snprintf(event_string, sizeof(event_string), "CONTAINER_READY=%d", event_id);

  container_debug(CONTAINER_DEBUG_READ_WRITE, " container_send_uevent %s \n", event_string);

  return kobject_uevent_env(&container_miscdev.this_device->kobj, KOBJ_CHANGE, envp);
}

/* 
 * write callback function for /proc/container/active
 */
static ssize_t container_active_proc_write(struct file *filp, const char __user *buffer,
                                           size_t count, loff_t *pos)
{
    int ret = 0;
    int active = 0;
    char buf[32];
    size_t len = min_t(size_t, sizeof(buf) - 1, count);

    container_debug(CONTAINER_DEBUG_READ_WRITE,
                    "container: proc entry active write, "
                    "f_pos=%lld, len=%lu\n",
                    filp->f_pos, len);

    down_write(&proc_rw_sem);

    if (copy_from_user(buf, buffer, len)) {
        ret = -EFAULT;
        goto out_unlock; 
    }

    buf[len] = 0;

    ret = kstrtoint(buf, 10, &active);

    if(ret) 
        goto out_unlock;

    if(active > MAX_CONTAINER)    {
        ret = -EINVAL;
        goto out_unlock;
    }

    ret = strnlen(buf, count);

    if(active_container != active)    {
        /* 
         * raise uevent here
	 */
        active_container = active;
        container_send_uevent(active);
    }

out_unlock:
    up_write(&proc_rw_sem);
    return ret;
}


/* 
 * read callback function for /proc/container/active
 */
static int container_active_proc_show(struct seq_file *m, void *v)
{
    down_read(&proc_rw_sem);

    seq_printf(m, "%d", active_container);

    up_read(&proc_rw_sem);

    return 0;
}

/* 
 * write callback function for /proc/container/ready
 */
static ssize_t container_ready_proc_write(struct file *filp, const char __user *buffer,
                                           size_t count, loff_t *pos)
{
    int ret = 0;
    int ready = 0;
    char buf[32];
    size_t len = min_t(size_t, sizeof(buf) - 1, count);

    container_debug(CONTAINER_DEBUG_READ_WRITE,
                    "container: proc entry ready write, "
                    "f_pos=%lld, len=%lu\n",
                    filp->f_pos, len);

    down_write(&proc_rw_sem);

    if (copy_from_user(buf, buffer, len)) {
        ret = -EFAULT;
        goto out_unlock;
    }

    buf[len] = 0;

    ret = kstrtoint(buf, 10, &ready);

    if(ret)
        goto out_unlock;

    if(ready > MAX_CONTAINER)    {
        ret = -EINVAL;
        goto out_unlock;
    }

    ret = strnlen(buf, count);

    /* 
     * raise uevent here
    */
    ready_container = ready;
    container_send_uevent_ready(ready);

out_unlock:
    up_write(&proc_rw_sem);
    return ret;
}

/* 
 * read callback function for /proc/container/ready
 */
static int container_ready_proc_show(struct seq_file *m, void *v)
{
    down_read(&proc_rw_sem);

    seq_printf(m, "%d", ready_container);

    up_read(&proc_rw_sem);

    return 0;
}

#endif

/*
 * ioctl function for container driver
 */
static long container_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return 0;
}


static const struct file_operations container_fops = {
    .owner = THIS_MODULE,
    .poll = NULL,
    .unlocked_ioctl = container_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = container_ioctl,
#endif
    .mmap = NULL,
    .open = NULL,
    .flush = NULL,
    .release = NULL,
};

/*
 *   initialize container device structures
 */
static void init_device(void) 
{
    container_miscdev.minor = MISC_DYNAMIC_MINOR;
    container_miscdev.name  = "container";
    container_miscdev.fops  = &container_fops;
    container_miscdev.mode  = S_IRUGO | S_IWUGO;
}

/*
 *   register container device structures
 */
static int register_dev(void) 
{
    int ret;

    ret = misc_register(&container_miscdev);

    if (ret) {
        container_error("container error: "
	                "cannot register container device driver\n");
    }

    return ret;
}

static int container_active_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, container_active_proc_show, NULL);
}

static const struct file_operations container_active_proc_fops = {
        .owner          = THIS_MODULE,
        .open           = container_active_proc_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
        .write          = container_active_proc_write,
};


static int container_ready_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, container_ready_proc_show, NULL);
}

static const struct file_operations container_ready_proc_fops = {
        .owner          = THIS_MODULE,
        .open           = container_ready_proc_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
        .write          = container_ready_proc_write,
};



static int __init container_init(void)
{
    int ret;

    init_device();
    ret = register_dev();

    if(ret)    return ret;

    init_rwsem(&proc_rw_sem);

    container_debug(CONTAINER_DEBUG_INIT,
                    "container: initializing container driver\n");

    container_proc_root = proc_mkdir("container", NULL);
    if(container_proc_root == NULL) {
        ret = -ENOMEM;
        container_error("container error: cannot create proc dir /proc/container\n");
    } else {
        container_proc_active = proc_create("active", 0666, container_proc_root, &container_active_proc_fops) ;

        if (container_proc_active == NULL) {
            container_error("container error: cannot create proc entry /proc/container/active\n");
            ret = -ENOMEM;
        } else {
            container_debug(CONTAINER_DEBUG_INIT,
			    "container: /proc/container/active created\n");
        }
        container_proc_ready = proc_create("ready", 0666, container_proc_root, &container_ready_proc_fops);

        if (container_proc_ready == NULL) {
            container_error("container error: cannot create proc entry /proc/container/ready\n");
            ret = -ENOMEM;
        } else {
            container_debug(CONTAINER_DEBUG_INIT,
                            "container: /proc/container/ready created\n");
        }

    }

    return ret;
}

static void __exit container_exit(void)
{
        if (container_proc_root) {
                remove_proc_entry("active", container_proc_root);
                remove_proc_entry("ready", container_proc_root);
                remove_proc_entry("container", NULL);
                container_proc_root = NULL;
        }

        misc_deregister(&container_miscdev);
}

module_exit(container_exit);
module_init(container_init);

MODULE_LICENSE("GPL v2");
