#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>

#include "file.h"
#include "dir.h"



#define MAGIC 0x5C12EEC8
#define DEFAULT_MODE 0755

#define CACHE_PREFIX ".screech-cache."

#define LOG(...) printk(KERN_INFO "SCREECH " __VA_ARGS__)

struct mount_args {
    char *container_path;
    char *key;
};


/*
static struct fs_info *get_fs_info(struct super_block *sb) {
    return sb->s_fs_info;
}*/


static struct file_system_type fs_type;
static struct super_operations s_op;
static struct inode_operations dir_i_op;
static struct file_operations dir_f_op;
static struct inode_operations reg_i_op;
static struct file_operations reg_f_op;

static struct inode *make_inode(struct super_block *sb, const struct inode *parent, int mode) {
    struct inode *child = new_inode(sb);
    if (!child)
        return ERR_PTR(-ENOMEM);

    child->i_ino = get_next_ino();

    inode_init_owner(child, parent, mode);

    struct timespec ct = CURRENT_TIME;
    child->i_ctime = ct;
    child->i_mtime = ct;        
    child->i_atime = ct;

    switch (mode & S_IFMT) {
    case S_IFREG:
        child->i_op = &reg_i_op;
        child->i_fop = &reg_f_op;
        break;
    case S_IFDIR:
        child->i_op = &dir_i_op;
        child->i_fop = &dir_f_op;
            // directory inodes start off with i_nlink == 2 (for "." entry)
        inc_nlink(child); 
        break;
    }

    child->i_private = NULL;
    
    return child;
}




static char *get_dentry_path(struct dentry *dentry) {
    int len = 256;
    for (;;) {
        char *buf = kmalloc(len, GFP_KERNEL);
        if (!buf)
            return ERR_PTR(-ENOMEM);
        char *res = dentry_path_raw(dentry, buf, len);
        if (IS_ERR(res)) {
            kfree(buf);
            if (PTR_ERR(res) == -ENAMETOOLONG) {
                len *= 2;
                continue;
            }
            return res;
        }
        memmove(buf, res, strlen(res) + 1);
        return buf;
    }
}


//static struct dentry *lookup(struct inode *parent, struct dentry *dentry, struct nameidata *nd) {
//    //struct fs_node *parent_node = parent->i_private;
//
//    char *path = get_dentry_path(dentry);
//    if (IS_ERR(path)) {
//        LOG("lookup get_dentry_path() failed");
//    } else {
//        LOG("lookup %s", path);
//        kfree(path);
//    }
//
//    //if (/* name in parent*/) {
//     //   d_add(dentry, /* get inode for file name */);
//    //} else {
//        d_add(dentry, NULL);
//    //}
//
//    return NULL;
//}



static int mkdir(struct inode *parent, struct dentry *dentry, int mode) {
    struct inode *child = make_inode(parent->i_sb, parent, S_IFDIR | mode);
    if (IS_ERR(child))
        return PTR_ERR(child);
    
    d_instantiate(dentry, child);

    dget(dentry);

    struct timespec current_time = CURRENT_TIME;
    parent->i_ctime = current_time;    
    parent->i_mtime = current_time;    

    inc_nlink(parent);
    
    char *path = get_dentry_path(dentry);
    if (IS_ERR(path)) {
        LOG("mkdir get_dentry_path() failed");
        return PTR_ERR(path);
    } else {
        LOG("mkdir %s", path);
        kfree(path);
    }

    return 0;
}

static int rmdir(struct inode *dir, struct dentry *dentry) {
    int error = simple_rmdir(dir, dentry);

    if (!error) {
        char *path = get_dentry_path(dentry);
        if (IS_ERR(path)) {
            LOG("rmdir get_dentry_path(dentry) failed");
            error = PTR_ERR(path);
            goto exit;
        }
        LOG("rmdir %s", path);
    exit:
        if (path)
            kfree(path);
    }

    return error;
}

static int rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry) {
    int error = simple_rename(old_dir, old_dentry, new_dir, new_dentry);

    if (!error) {
        char* old_path = get_dentry_path(old_dentry);
        if (IS_ERR(old_path)) {
            LOG("rename get_dentry_path(old_dentry) failed");
            error = PTR_ERR(old_path);
            old_path = 0;
            goto exit_old;
        }
        char* new_path = get_dentry_path(new_dentry);
        if (IS_ERR(new_path)) {
            LOG("rename get_dentry_path(new_dentry) failed");
            error = PTR_ERR(new_path);
            new_path = 0;
            goto exit_new;
        }
        LOG("rename %s %s", old_path, new_path);
    exit_new:
        if (new_path)
            kfree(new_path);
    exit_old:
        if (old_path)
            kfree(old_path);
    }

    return error;
}

static struct file_operations dir_f_op = {
    .open = dcache_dir_open,
    .release = dcache_dir_close,
    .llseek = dcache_dir_lseek,
    .read = generic_read_dir,
    .readdir = dcache_readdir,
    .fsync = noop_fsync,
};

static struct inode_operations dir_i_op = {
    .lookup = simple_lookup,
    .mkdir = mkdir,
    .rmdir = rmdir,
    .rename = rename,
};




static struct super_operations s_op = {
    //.statfs = simple_statfs,
    //.drop_inode = generic_delete_inode,
    //.show_options = generic_show_options,
};



static int fill_super(struct super_block *sb, void *data, int silent) {
    struct mount_args *mount_args = data;
    
    sb->s_magic = MAGIC;    
    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_blocksize = PAGE_CACHE_SIZE;
    sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
    sb->s_time_gran = 1;
    sb->s_op = &s_op;
    sb->s_fs_info = mount_args;

    struct inode *iroot = make_inode(sb, NULL, S_IFDIR | 0755);
    if (IS_ERR(iroot))
        return PTR_ERR(iroot);
        
    sb->s_root = d_alloc_root(iroot);
    if (!sb->s_root) {
        iput(iroot);
        return -ENOMEM;
    }

    return 0;
}


static struct dentry *mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *options) {
    int error = 0;
    
    struct mount_args *mount_args = kzalloc(sizeof(struct mount_args), GFP_KERNEL);
    if (!mount_args) {
        error = -ENOMEM;
        goto failure;
    }

    mount_args->container_path = kmalloc(strlen(dev_name) + 1, GFP_KERNEL);
    if (!mount_args->container_path) {
        error = -ENOMEM;
        goto failure;
    }
    strcpy(mount_args->container_path, dev_name);

    if (!options)
        options = "";
    mount_args->key = kmalloc(strlen(options) + 1, GFP_KERNEL);
    if (!mount_args->key) {
        error = -ENOMEM;
        goto failure;
    }
    strcpy(mount_args->key, options);
    
    struct dentry *droot = mount_nodev(fs_type, flags, mount_args, &fill_super);
    if (IS_ERR(droot)) {
        error = PTR_ERR(droot);
        goto failure;
    }
        
    return droot;

failure:
    if (mount_args) {
        if (mount_args->container_path) {
            kfree(mount_args->container_path);
        }
        if (mount_args->key) {
            kfree(mount_args->key);
        }
        kfree(mount_args);
    }
    return ERR_PTR(error);
}

static void kill_sb(struct super_block *sb) {
    struct mount_args *mount_args = sb->s_fs_info;

    kfree(mount_args->container_path);
    kfree(mount_args->key);
    kfree(mount_args);

    kill_litter_super(sb);
}

static struct file_system_type fs_type = {
    .name = "screech",
    .mount = mount,
    .kill_sb = kill_sb,
};

static int startup(void) {
    return register_filesystem(&fs_type);
}

static void shutdown(void) {
    unregister_filesystem(&fs_type);
}

module_init(startup);
module_exit(shutdown);

MODULE_AUTHOR("Yuri Kilochek <yuri.kilochek@gmail.com>");
MODULE_DESCRIPTION("Encrypted file system");
MODULE_LICENSE("GPL");
