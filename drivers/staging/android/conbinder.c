/*
 * conbinder.h
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


#include "conbinder.h"
#include <linux/proc_fs.h>
#include <linux/rwsem.h>
#include <linux/string.h>
#include "container.h"

#define MAX_CONBINDER MAX_CONTAINER
#define MAX_LEN_CONBINDER_NAME 15
#define CONBINDER_DEF_NAME_LENGTH 11
#define CONBINDER_NAME_PREFIX_LENGTH (CONBINDER_DEF_NAME_LENGTH - 2)
#define PROC_BUFFER_SS_CAPACITY PAGE_SIZE

#define BINDER_ULONG_TO_ULONG(x) ((unsigned long)(x))

enum {
        CONBINDER_DEBUG_INIT                   = 1U << 0,
	CONBINDER_DEBUG_IOCTL                  = 1U << 0,
        CONBINDER_DEBUG_OPEN_CLOSE             = 1U << 3,
        CONBINDER_DEBUG_READ_WRITE             = 1U << 6,
	CONBINDER_DEBUG_NONE_READ_WRITE        = 1U << 7,
	CONBINDER_DEBUG_TRANSACTION            = 1U << 8,
	CONBINDER_DEBUG_FILTER                 = 1U << 9,
	CONBINDER_DEBUG_SHARED_SERVICE         = 1U << 10,
};

#define DEBUG_CONBINDER 0

#if DEBUG_CONBINDER
static uint32_t conbinder_debug_mask = CONBINDER_DEBUG_INIT |
                                       CONBINDER_DEBUG_IOCTL |
                                       CONBINDER_DEBUG_OPEN_CLOSE |
                                       CONBINDER_DEBUG_READ_WRITE |
                                       CONBINDER_DEBUG_NONE_READ_WRITE |
                                       CONBINDER_DEBUG_TRANSACTION |
				       CONBINDER_DEBUG_FILTER |
				       CONBINDER_DEBUG_SHARED_SERVICE;
#else
static uint32_t conbinder_debug_mask = 0; 
#endif

module_param_named(debug_mask, conbinder_debug_mask, uint, S_IWUSR | S_IRUGO);

#define conbinder_debug(mask, x...) \
        do { \
		if (conbinder_debug_mask & mask) \
			printk(KERN_INFO x); \
	} while (0)

#define conbinder_error(x...) \
	do { \
		printk(KERN_ERR x); \
	} while (0)

/*
 * copied from service_manager
 */
enum {
    SVC_MGR_GET_SERVICE = 1,
    SVC_MGR_CHECK_SERVICE,
    SVC_MGR_ADD_SERVICE,
    SVC_MGR_LIST_SERVICES,
};

struct conbinder_service {
    char *name;
    struct rb_node rb_node;
};

/* proc entries */
static struct proc_dir_entry *conbinder_proc_root;
static struct proc_dir_entry *conbinder_proc_sharedservices;

/* proc buffer related data */
static struct rb_root services_tree;
static char   *proc_buffer_ss;
static char   *proc_buffer_ss_wptr;
static char   *proc_buffer_ss_pptr;
static struct rw_semaphore proc_ss_rw_sem;

#define proc_buffer_ss_size ((size_t)(proc_buffer_ss_wptr - proc_buffer_ss))

static char default_conbinder_name[CONBINDER_DEF_NAME_LENGTH] = "conbinder1";

static char *default_shared_services[] = {
	"ServiceManager",
//	"SurfaceFlinger",
};

#define default_shared_services_size  (sizeof (default_shared_services) / sizeof (const char *))

/*
 * add new service
 */
static int add_shared_service(char *svc_name, size_t len)
{
    struct conbinder_service *new_service;
    struct rb_node **p = &services_tree.rb_node;
    struct rb_node *parent = NULL;
    struct conbinder_service *svc;
    int cmp;

    /* do not add empty service name */
    if (len <= 1)
        return 0;

    conbinder_debug(CONBINDER_DEBUG_SHARED_SERVICE,
                    "conbinder: adding shared service %s\n", svc_name);

    /* find the service in the tree */
    while (*p) {
        parent = *p;
        svc = rb_entry(parent, struct conbinder_service, rb_node);
        cmp = strcmp(svc_name, svc->name);

        if (cmp < 0)
            p = &(*p)->rb_left;
        else if(cmp > 0)
            p = &(*p)->rb_right;
        else {
	    conbinder_debug(CONBINDER_DEBUG_SHARED_SERVICE,
                            "conbinder: service %s is already added\n", svc_name);
            return 0; /* if already in the tree, abort */
        }
    }

    /* create a new shared ervice */
    new_service = (struct conbinder_service *)kzalloc(sizeof(*new_service), GFP_KERNEL);
    if (new_service == NULL) {
	conbinder_error("conbinder error: failed to allocate service node for proc fs\n");
        return -EINVAL;
    }
    new_service->name = svc_name;   /* set service name */

    /* insert service to the tree */
    rb_link_node(&new_service->rb_node, parent, p);
    rb_insert_color(&new_service->rb_node, &services_tree);

    conbinder_debug(CONBINDER_DEBUG_SHARED_SERVICE,
                    "conbinder: shared service %s added\n", svc_name);

    return 0;
}


/*
 *   parse data written to /proc/conbinder/sharedservices
 *   return the last position parsed
 */
static long conbinder_proc_ss_parse(char *start, size_t len)
{
    long ret = 0;
    char *ptr = start;
    char *end = start + len;
    char *line_start = start;

    /* scan through the data, add services */
    while (ptr < end) {
        if (*ptr == '\n') {     /* end of line found */
            *ptr = 0;           /* set end flag for service name */

            ret = add_shared_service(line_start, (size_t)(ptr - line_start + 1));
            if (ret) 
                break;

            line_start = ptr + 1;   /* new line */
        }

        ++ ptr;
    }

    proc_buffer_ss_pptr = line_start;
    
    return ret;
}

/* 
 * write callback function for /proc/conbinder/sharedservices
 */
static ssize_t conbinder_proc_ss_write(struct file *filp, const char __user *buff,
                                       size_t len, loff_t *pos)
{
    ssize_t ret = len;

    /* check whether the buffer is empty */
    if (proc_buffer_ss == NULL) {
        pr_err("conbinder error: no proc buffer\n");
        return -ENOMEM;
    }

    down_write(&proc_ss_rw_sem);

    conbinder_debug(CONBINDER_DEBUG_SHARED_SERVICE,
                    "conbinder: proc entry sharedservices write, "
		    "f_pos=%lld, len=%lu\n", 
                    filp->f_pos, len);
    conbinder_debug(CONBINDER_DEBUG_SHARED_SERVICE,
                    "conbinder: %lu bytes of data already written\n",
		    proc_buffer_ss_size);

    /* check whether buffer can hold data */
    if (proc_buffer_ss_size + len > PROC_BUFFER_SS_CAPACITY) {
        conbinder_error("conbinder error: cannot write data to sharedservices, full buffer\n");
        ret = -ENOSPC;
        goto out_unlock;
    }

    /* copy data from user space */
    if (copy_from_user(proc_buffer_ss_wptr, buff, len)) {
        conbinder_error("conbinder error: failed to copy data from user space to proc fs\n");
        ret = -EFAULT;
        goto out_unlock;
    }
    proc_buffer_ss_wptr += len;

    /* parse written data */
    ret = conbinder_proc_ss_parse(proc_buffer_ss_pptr, 
        (size_t)(proc_buffer_ss_wptr - proc_buffer_ss_pptr));
    if (ret) {
        conbinder_error("conbinder error: error occured when parsing written data\n");
        goto out_unlock;
    }

    ret = len;

out_unlock:
    up_write(&proc_ss_rw_sem);
    return ret;
}

/* 
 *   read callback function for /proc/conbinder/sharedservices
 */
#if 0
static int conbinder_proc_ss_read(char *buffer, char **start, off_t offset,
                   int count, int *eof, void *data)
{
    size_t actual_count = offset + count;
    char *ptr;

    /*
    pr_info("conbinder: proc entry sharedservices read, offset=%ld, count=%d\n", 
        offset, count);
    pr_info("conbinder: %u bytes of data available\n", proc_buffer_ss_size);
    */

    /* set start as NULL to match 0) (see fs/proc/generic.c) */
    *start = NULL;

    /* check whether the buffer is empty */
    if (proc_buffer_ss == NULL) {
        conbinder_error("conbinder error: no proc buffer\n");
        *eof = 1;
        return offset;
    }

    down_read(&proc_ss_rw_sem);

    /* check whether trying to read data out of boundary */
    if (offset > proc_buffer_ss_size) {
        *eof = 1;
        up_read(&proc_ss_rw_sem);
        return -EINVAL;
    }
    
    /* check whether there is enough data */
    if (actual_count >= proc_buffer_ss_size) {
        actual_count = proc_buffer_ss_size;
        *eof = 1;
    }

    /* copy data to buffer */
    memcpy(buffer, proc_buffer_ss, actual_count);
    for (ptr = buffer; ptr < buffer + actual_count; ++ ptr) {
        if (*ptr == 0)
            *ptr = '\n'; /* change it back */
    }

    up_read(&proc_ss_rw_sem);

    return actual_count; /* return data available in buffer */
}
#endif

static int conbinder_proc_ss_show(struct seq_file *m, void *v)
{
    char *ptr;

    /* check whether the buffer is empty */
    if (proc_buffer_ss == NULL) {
        conbinder_error("conbinder error: no proc buffer\n");
        return -ENOMEM;
    }

    down_read(&proc_ss_rw_sem);

    /* copy data to buffer */
    seq_write(m, proc_buffer_ss, proc_buffer_ss_size);

    for (ptr = m->buf + m->count - proc_buffer_ss_size; ptr < m->buf + m->count; ++ ptr) {
        if (*ptr == 0)
            *ptr = '\n'; /* change it back */
    }

    up_read(&proc_ss_rw_sem);

    return 0;
}

/*
 * compare a UTF-16 string with a ASCII string
 */
static int strcmp16(uint16_t *s16, char *s8)
{
    unsigned char c1, c2;

//#if DEBUG_CONBINDER 
#if 0
    uint16_t *tmp = s16;
    //conbinder_debug(CONBINDER_DEBUG_SHARED_SERVICE, "conbinder : service name : ");
    printk("conbinder : service name : ");
    while(1) {
    c1 = (char)(*tmp++);
    printk("%c",c1);
    if(!c1) 
      break;
    }
    printk("\n");
#endif

    while (1) {
        c1 = (char)(*s16++);
        c2 = *s8++;
        if(c1 != c2)
            return c1 < c2 ? -1 : 1;
         if (!c1)
            break;
    }
    return 0;
}

/* 
 * replace the service name 
 */
static void replace_name(uint16_t *str, size_t len, char magic, unsigned int trcode) {
    struct rb_node **p = &services_tree.rb_node;
    struct rb_node *parent = NULL;
    struct conbinder_service *svc;
    int cmp;
#if 0
    int i;
#endif
    /* find the service in the tree */
    if(trcode != SVC_MGR_ADD_SERVICE ) {
        while (*p) {
            parent = *p;
            svc = rb_entry(parent, struct conbinder_service, rb_node);
            cmp = strcmp16(str, svc->name);

            //VICTOR TEST
            //printk("conbinder : service_name %s \n", svc->name);

            if (cmp < 0)
                p = &(*p)->rb_left;
            else if(cmp > 0)
                p = &(*p)->rb_right;
            else {
	        conbinder_debug(CONBINDER_DEBUG_FILTER,
                            "conbinder: service %s found in shared services list\n",
			    svc->name);
                return; /* if service is in the tree, abort */
            }
        }
    }
#if 0
    for (i = 0; i < len-1; ++i)
        str[i] = str[i+1];
    str[len - 1] = (uint16_t)magic;
#else 
    str[0] = (uint16_t)magic;
#endif

//printk("conbinder : replace_name %s \n", (char*)str);

}

/* 
 * skip a string of type String16
 */
static void *skip_string16(void *buffer) {
    size_t string_size;
    int32_t len = *((int32_t*)buffer);

    if (len < 0)
        return buffer + sizeof(len);

    string_size = (len + 1) * sizeof(uint16_t);
    string_size = (string_size + 3) & (~3);

    return buffer + sizeof(len) + string_size;
}

/*
    skip an interface token
*/
static void *skip_interface_token(void *buffer) {
    void *ptr = buffer;

    if (!ptr)
        return 0;

    ptr += sizeof(int32_t);     /* skip strict policy */
    ptr = skip_string16(ptr);

    return ptr;
}

/*
    get the # of conbinder device
*/
static char get_conbinder_number_c(struct file *filp) 
{
    const char *node_name = filp->f_dentry->d_name.name;

    return node_name[CONBINDER_NAME_PREFIX_LENGTH];
}

/*
 *   filter transaction from container to service manager
 */
static long conbinder_filter_transaction_smgr(struct file *filp, struct binder_transaction_data *tr) 
{
    void *buffer = NULL;
    void *ptr = NULL;
    int32_t name_len = 0;
    void __user *ubuf = NULL;

    /* check function code of Service Manager */
    if (tr->code != SVC_MGR_ADD_SERVICE &&
        tr->code != SVC_MGR_CHECK_SERVICE &&
        tr->code != SVC_MGR_GET_SERVICE) {
        return 0;
    }

    //DEBUG
#if 0
    switch(tr->code) {
        case SVC_MGR_ADD_SERVICE :
            printk("conbinder : SVC_MGR_ADD_SERVICE \n");
            break;
        
        case SVC_MGR_CHECK_SERVICE :
            printk("conbinder : SVC_MGR_CHECK_SERVICE \n");
            break;
        
        case SVC_MGR_GET_SERVICE :
            printk("conbinder : SVC_MGR_GET_SERVICE \n");
            break;
        default :
            printk("conbinder : tr->code %d \n ", tr->code);
            break;
    }
#endif

    /* allocate buffer */
    buffer = kzalloc(tr->data_size, GFP_KERNEL);
    if (!buffer) {
        conbinder_error("conbinder error: failed to allocate buffer for filter\n");
        return -ENOMEM;
    }

    /* copy transaction data from user space */
    //ubuf = (void __user *)(unsigned long)(tr->data.ptr.buffer);
    ubuf = (void __user *)(uintptr_t)tr->data.ptr.buffer;
    if (copy_from_user(buffer, ubuf, tr->data_size)) {
        kfree(buffer);
        return -EFAULT;
    }

    /* read the interface token */
    ptr = skip_interface_token(buffer);

    /* get length of service name */
    name_len = *((int32_t*)ptr);
    ptr += sizeof(name_len);

    if (name_len < 0) {
        pr_err("conbinder error: invalid service name\n");
    }

    conbinder_debug(CONBINDER_DEBUG_FILTER,
                    "conbinder: filtering transaction for function code %d\n", tr->code);
    conbinder_debug(CONBINDER_DEBUG_FILTER,
		    "conbinder: length of service name: %d\n", name_len);

    /* modify service name */
    replace_name((uint16_t *)ptr, (size_t)name_len, get_conbinder_number_c(filp), tr->code);

    /* copy back to user space */
    if(copy_to_user(ubuf, buffer, tr->data_size)) {
        kfree(buffer);
        return -EFAULT;
    }
    
    /* free buffer */
    kfree(buffer);

    return 0;
}

/*
 * filter transaction data from container
 */
static long conbinder_filter_transaction(struct file *filp, struct binder_transaction_data *tr) 
{
    conbinder_debug(CONBINDER_DEBUG_FILTER,
                    "conbinder: filtering transaction with buffer 0x%lx\n",
		    (unsigned long)(tr->data.ptr.buffer));
    
    if(tr->target.handle == 0) {
        return conbinder_filter_transaction_smgr(filp, tr);
    }

    return 0;
}

/*
 * ioctl function for conbinder driver
 */
static long conbinder_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct binder_write_read bwr;
    unsigned int size = _IOC_SIZE(cmd);
    long ret = 0;
    void __user *ubuf = (void __user *)arg;
    uint32_t binder_cmd;

    conbinder_debug(CONBINDER_DEBUG_IOCTL,
                    "conbinder: conbinder_ioctl called with node name: %s\n",
		    filp->f_dentry->d_name.name);

    if (cmd == CONBINDER_GET_CURRENT_CONTAINER) {
        char container_c = get_conbinder_number_c(filp);
        int container = container_c - '0';

        conbinder_debug(CONBINDER_DEBUG_IOCTL,
			"conbinder: getting current container in container\n");

        if (copy_to_user(ubuf, &container, sizeof(container))) {
            conbinder_error("conbinder err: error getting current container in container\n");
            ret = -EINVAL;
            goto err;
        }
        
        return 0;
    }

    conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : CHECK COMMAND , cmd=%x START \n", cmd);

    switch(cmd) {
    case BINDER_WRITE_READ :    
        conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : cmd = %x BINDER_WRITE_READ \n", cmd);
        break;
    case BINDER_SET_IDLE_TIMEOUT :
        conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : cmd = %x BINDER_SET_IDLE_TIMEOUT \n", cmd);
        break;
    case BINDER_SET_MAX_THREADS :
        conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : cmd = %x BINDER_SET_MAX_THREADS \n", cmd);
        break;
    case BINDER_SET_IDLE_PRIORITY :
        conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : cmd = %x BINDER_SET_IDLE_PRIORITY \n", cmd);
        break;
    case BINDER_SET_CONTEXT_MGR :
        conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : cmd = %x BINDER_SET_CONTEXT_MGR \n", cmd);
        break;
    case BINDER_THREAD_EXIT :
        conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : cmd = %x BINDER_THREAD_EXIT \n", cmd);
        break;
    case BINDER_VERSION :
        conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : cmd = %x BINDER_VERSION \n", cmd);
        break;
    }

    conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : CHECK COMMAND , cmd=%x END \n", cmd);

    /* check command */
    if (cmd != BINDER_WRITE_READ) {
	conbinder_debug(CONBINDER_DEBUG_NONE_READ_WRITE,
                        "conbinder: command %x do not require filtering\n", cmd);
        return binder_ioctl(filp, cmd, arg);
    }

    conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : CHECK SIZE , size=%u sizeof(struct binder_write_read) = %lu \n", size, sizeof(struct binder_write_read));
    /* check size */
    if (size != sizeof(struct binder_write_read)) {
        ret = -EINVAL;
        goto err;
    }

    
    conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : copy binder_write_read struct from user space \n");
    /* copy binder_write_read struct from user space */
    if (copy_from_user(&bwr, ubuf, sizeof(bwr))) {
        ret = -EFAULT;
        goto err;
    }

    if (bwr.write_size > 0) {
        void __user *wb_ptr = (void __user *) (uintptr_t)bwr.write_buffer;
        void __user *wb_end = wb_ptr + bwr.write_size;

        while (wb_ptr < wb_end) {
            if (get_user(binder_cmd, (uint32_t __user *)wb_ptr))    /* get command */
                return -EFAULT;
            wb_ptr += sizeof(uint32_t);

            conbinder_debug(CONBINDER_DEBUG_IOCTL, "conbinder : binder_cmd = %d \n", binder_cmd);
            switch (binder_cmd) {
            case BC_TRANSACTION: { /* only BC_TRANSACTION commands are filtered */
                struct binder_transaction_data tr;

                conbinder_debug(CONBINDER_DEBUG_TRANSACTION,
			        "conbinder: BC_TRANSACTION got with write buffer 0x%lx\n",
				(unsigned long)(bwr.write_buffer));

                if (copy_from_user(&tr, wb_ptr, sizeof(tr)))
                    return -EFAULT;
                wb_ptr += sizeof(tr);
                ret = conbinder_filter_transaction(filp, &tr); /* filter transaction */
                break;
            }

            /*
            case BC_REPLY:
            case BC_ACQUIRE_RESULT:
            case BC_ATTEMPT_ACQUIRE:
            case BC_FREE_BUFFER:
            case BC_INCREFS:
            case BC_ACQUIRE:
            case BC_RELEASE:
            case BC_DECREFS:
            case BC_INCREFS_DONE:
            case BC_ACQUIRE_DONE:
            case BC_REGISTER_LOOPER:
            case BC_ENTER_LOOPER:
            case BC_EXIT_LOOPER:
            case BC_REQUEST_DEATH_NOTIFICATION:
            case BC_DEAD_BINDER_DONE:
            case BC_CLEAR_DEATH_NOTIFICATION:
            */

            default:
                wb_ptr += _IOC_SIZE(binder_cmd);
                break;
            }
        }
    }

    if (ret)
        return ret;

    /* call original driver function */
    return binder_ioctl(filp, cmd, arg);

err:
    return ret;
}

static const struct file_operations conbinder_fops = {
    .owner = THIS_MODULE,
    .poll = binder_poll,
    .unlocked_ioctl = conbinder_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = conbinder_ioctl,
#endif
    .mmap = binder_mmap,
    .open = binder_open,
    .flush = binder_flush,
    .release = binder_release,
};

/* device data */
static struct miscdevice conbinder_miscdevs[MAX_CONBINDER];
static char conbinder_names[MAX_CONBINDER][MAX_LEN_CONBINDER_NAME];

/*
 *   initialize conbinder device structures
 */
static void init_devs(int nr_devs) 
{
    int i;

    /* initialize the first one */
    memcpy(conbinder_names[0], default_conbinder_name, sizeof(default_conbinder_name));
    conbinder_miscdevs[0].minor = MISC_DYNAMIC_MINOR;
    conbinder_miscdevs[0].name = conbinder_names[0];
    conbinder_miscdevs[0].fops = &conbinder_fops;
    conbinder_miscdevs[0].mode = S_IRUGO | S_IWUGO;

    /* initialize the rest structures */
    for (i = 1; i < nr_devs; i++) {
        memcpy(conbinder_miscdevs + i, conbinder_miscdevs, sizeof(conbinder_miscdevs[0]));

        memcpy(conbinder_names[i], conbinder_names[0], sizeof(conbinder_names[0]));
        conbinder_names[i][sizeof(default_conbinder_name) - 2] = (char)(i) + '1';

        conbinder_miscdevs[i].name = conbinder_names[i];
    }
}

/*
 *   register conbinder device structures
 */
static int register_devs(int nr_devs) 
{
    int i;
    int ret;

    for (i = 0; i < nr_devs; i++) {
        ret = misc_register(conbinder_miscdevs + i);

        if (ret) {
            conbinder_error("conbinder error: "
			    "cannot register conbinder device driver for conbinder%d\n", i+1);
            return ret;
        }
    }

    return ret;
}


static void init_default_shared_services(void)
{
    int i; 

    for(i = 0; i < default_shared_services_size; i++)    {
        add_shared_service(default_shared_services[i],
			   strlen(default_shared_services[i]));
    }
}




static int conbinder_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, conbinder_proc_ss_show, NULL);
}

static const struct file_operations conbinder_proc_fops = {
        .owner          = THIS_MODULE,
        .open           = conbinder_proc_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
        .write          = conbinder_proc_ss_write,
};

static int __init conbinder_init(void)
{
    int ret;

    init_devs(MAX_CONBINDER);
    ret = register_devs(9);
    init_default_shared_services();

    conbinder_debug(CONBINDER_DEBUG_INIT,
                    "conbinder: initializing conbinder driver\n");

    conbinder_proc_root = proc_mkdir("conbinder", NULL);
    if(conbinder_proc_root == NULL) {
        ret = -ENOMEM;
        conbinder_error("conbinder error: cannot create proc dir /proc/conbinder\n");
    } else {
        conbinder_proc_sharedservices = proc_create("sharedservices", 0666, conbinder_proc_root, &conbinder_proc_fops);

        if (conbinder_proc_sharedservices == NULL) {
            conbinder_error("conbinder error: cannot create proc entry /proc/conbinder/sharedservices\n");
            ret = -ENOMEM;
        } else {
            conbinder_debug(CONBINDER_DEBUG_INIT,
			    "conbinder: /proc/conbinder/sharedservices created\n");
        
            proc_buffer_ss = (char*)get_zeroed_page(GFP_KERNEL);
            if (proc_buffer_ss == NULL) {
                conbinder_error("conbinder error: failed to allocate proc buffer for shared services\n");
                return -ENOMEM;
            }

            proc_buffer_ss_wptr = proc_buffer_ss;
            proc_buffer_ss_pptr = proc_buffer_ss;

            init_rwsem(&proc_ss_rw_sem);
        }
    }

    return ret;
}

module_init(conbinder_init);

MODULE_LICENSE("GPL v2");
