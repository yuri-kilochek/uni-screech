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
static struct inode_operations dir_iop;
static struct file_operations dir_op;
static struct inode_operations reg_iop;
static struct file_operations reg_op;

static int open(struct inode *inode, struct file *file) {
    file->private_data = inode->i_private;
    LOG("open %s", (char*)inode->i_private);
    return 0;
}

static ssize_t read(struct file *file, char __user *buffer, size_t size, loff_t *offset) {
    LOG("read %s %d %d", (char*)file->private_data, (int)size, (int)*offset);
    return 0;
}

static ssize_t write(struct file *file, const char __user *buffer, size_t size, loff_t *offset) {
    LOG("write %s %d %d", (char*)file->private_data, (int)size, (int)*offset);
    *offset += size;
    return size;
}

static int release (struct inode *inode, struct file *file) {
    LOG("release %s", (char*)inode->i_private);
    return 0;
}

static struct file_operations reg_op = {
    .open = open,
    .read = read,
    .write = write,
    .release = release,
//    .fsync = noop_fsync,
};

static struct inode_operations reg_iop = {
//    .setattr = simple_setattr,
//    .getattr = simple_getattr,
};

static char *get_path(struct dentry *dentry) {
    int len = 256;
    for (;;) {
        char *buf = kmalloc(len, GFP_KERNEL);
        if (!buf)
            return ERR_PTR(-ENOMEM);
        char *res = dentry ? dentry_path_raw(dentry, buf, len) : strcpy(buf, "/");
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

static struct inode *make_inode(struct super_block *sb, struct inode *parent, struct dentry *dentry, int mode) {
    char *path = get_path(dentry);
    if (IS_ERR(path)) {
        LOG("make_inode get_path() failed");
        return ERR_CAST(path);
    }

    struct inode *inode = new_inode(sb);
    if (!inode) {
        if (path)
            kfree(path);
        return ERR_PTR(-ENOMEM);
    }

    inode->i_ino = get_next_ino();
    if (dentry) {
        d_instantiate(dentry, inode);
        dget(dentry);
    }
    if (parent)
        inc_nlink(parent);

    struct timespec ct = CURRENT_TIME;
    inode->i_ctime = ct;
    inode->i_mtime = ct;
    inode->i_atime = ct;

    inode_init_owner(inode, parent, mode);

    switch (mode & S_IFMT) {
    case S_IFREG:
        inode->i_op = &reg_iop;
        inode->i_fop = &reg_op;
        break;
    case S_IFDIR:
        inode->i_op = &dir_iop;
        inode->i_fop = &dir_op;
            // directory inodes start off with i_nlink == 2 (for "." entry)
        inc_nlink(inode);
        break;
    }

    inode->i_private = path;
    
    return inode;
}

static int create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd) {
    struct inode *inode = make_inode(dir->i_sb, dir, dentry, S_IFREG | mode);
    if (IS_ERR(inode))
        return PTR_ERR(inode);

    LOG("create %s", (char*)inode->i_private);

    return 0;
}

static int unlink(struct inode *dir, struct dentry *dentry) {
    LOG("unlink %s", (char*)dentry->d_inode->i_private);
    return simple_unlink(dir, dentry);
}


static int mkdir(struct inode *dir, struct dentry *dentry, int mode) {
    struct inode *inode = make_inode(dir->i_sb, dir, dentry, S_IFDIR | mode);
    if (IS_ERR(inode))
        return PTR_ERR(inode);

    LOG("mkdir %s", (char*)inode->i_private);

    return 0;
}

static int rmdir(struct inode *dir, struct dentry *dentry) {
    LOG("rmdir %s", (char*)dentry->d_inode->i_private);
    return simple_rmdir(dir, dentry);
}

static int rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry) {
    LOG("rename %s %s", (char*)old_dentry->d_inode->i_private, (char*)new_dentry->d_inode->i_private);
    return simple_rename(old_dir, old_dentry, new_dir, new_dentry);
}

static struct file_operations dir_op = {
    .open = dcache_dir_open,
    .release = dcache_dir_close,
    .llseek = dcache_dir_lseek,
    .read = generic_read_dir,
    .readdir = dcache_readdir,
//    .fsync = noop_fsync,
};

static struct inode_operations dir_iop = {
    .lookup = simple_lookup,
    .create = create,
    .unlink = unlink,
    .mkdir = mkdir,
    .rmdir = rmdir,
    .rename = rename,
};

static struct super_operations s_op = {
//    .statfs = simple_statfs,
//    .drop_inode = generic_delete_inode,
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

    struct inode *iroot = make_inode(sb, NULL, NULL, S_IFDIR | 0755);
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
