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

#define MAGIC 0x5C12EEC8
#define DEFAULT_MODE 0755

#define CACHE_PREFIX "screech-cache."

#define LOG(...) printk(KERN_INFO "SCREECH " __VA_ARGS__)

struct fs_data {
    char *container_path;
    char *crypt_key;
};

static struct file_system_type fs_type;
static struct super_operations s_op;
static struct inode_operations dir_iop;
static struct file_operations dir_op;
static struct inode_operations reg_iop;
static struct file_operations reg_op;

static int open(struct inode *inode, struct file *file) {
    LOG("open %s", (char*)inode->i_private);
    file->private_data = inode->i_private;
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
};

static struct inode_operations reg_iop = {};

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

static struct inode *make_inode(struct super_block *sb, struct inode *dir, struct dentry *dentry, int mode) {
    char *path = get_path(dentry);
    if (IS_ERR(path)) {
        LOG("make_inode get_path(dentry) failed");
        return ERR_CAST(path);
    }

    struct inode *inode = new_inode(sb);
    if (!inode) {
        kfree(path);
        return ERR_PTR(-ENOMEM);
    }

    inode->i_ino = get_next_ino();
    inode->i_ctime = inode->i_mtime = inode->i_atime = CURRENT_TIME;
    inode->i_mode = mode;
    inode->i_private = path;

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

    if (dentry) {
        d_instantiate(dentry, inode);
        dget(dentry);
    }

    if (dir) {
        inc_nlink(dir);
    }

    return inode;
}

static int drop_inode(struct inode *inode) {
    kfree(inode->i_private);
    return generic_delete_inode(inode);
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
    LOG("rmdir %s", (char *) dentry->d_inode->i_private);
    return simple_rmdir(dir, dentry);
}

static int rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry) {
    struct inode *inode = old_dentry->d_inode;

    char* tmp = get_path(new_dentry);
    if (IS_ERR(tmp)) {
        LOG("rename get_path(new_dentry) failed");
        return PTR_ERR(tmp);
    }

    int error = simple_rename(old_dir, old_dentry, new_dir, new_dentry);
    if (error) {
        kfree(tmp);
        return error;
    }

    LOG("rename %s %s", (char*)inode->i_private, tmp);
    kfree(inode->i_private);
    inode->i_private = tmp;

    return 0;
}

static struct file_operations dir_op = {
    .open = dcache_dir_open,
    .release = dcache_dir_close,
    .llseek = dcache_dir_lseek,
    .read = generic_read_dir,
    .readdir = dcache_readdir,
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
    .drop_inode = drop_inode,
};

static void unpack(struct dentry *root) {
    LOG("unpack");

    struct super_block *sb = root->d_inode->i_sb;

    struct dentry *a = d_alloc_name(root, "a"); d_rehash(a); make_inode(sb, root->d_inode, a, S_IFDIR | 0755); dput(a);
        struct dentry *a_1 = d_alloc_name(a, "1"); d_rehash(a_1); make_inode(sb, a->d_inode, a_1, S_IFREG | 0644); dput(a_1);
        struct dentry *a_2 = d_alloc_name(a, "2"); d_rehash(a_2); make_inode(sb, a->d_inode, a_2, S_IFREG | 0644); dput(a_2);
    struct dentry *b = d_alloc_name(root, "b"); d_rehash(b); make_inode(sb, root->d_inode, b, S_IFDIR | 0755); dput(b);
        struct dentry *b_3 = d_alloc_name(b, "3"); d_rehash(b_3); make_inode(sb, b->d_inode, b_3, S_IFREG | 0644); dput(b_3);
        struct dentry *b_4 = d_alloc_name(b, "4"); d_rehash(b_4); make_inode(sb, b->d_inode, b_4, S_IFREG | 0644); dput(b_4);
}

static void save(struct file *container, struct dentry *dentry, long long *offset) {
    offset = offset ? offset : &(long long){0};

    struct qstr *name = &dentry->d_name;
    *offset += file_write(container, *offset, name->name, name->len);
    *offset += file_write(container, *offset, "\n", strlen("\n"));

    struct list_head *i;
    list_for_each(i, &dentry->d_subdirs) {
        struct dentry *subdentry = list_entry(i, struct dentry, d_u.d_child);
        save(container, subdentry, offset);
    }
}

static int repack(struct dentry *root) {
    LOG("repack");

    struct fs_data *fs_data = root->d_sb->s_fs_info;

    struct file *container = file_open(fs_data->container_path, O_WRONLY | O_TRUNC, 0000);
    if (IS_ERR(container)) {
        LOG("repack file_open(fs_data->container_path, O_WRONLY | O_TRUNC, 0000) failed");
        return PTR_ERR(container);
    }

    save(container, root, NULL);

    file_close(container);

    return 0;
}

static int fill_super(struct super_block *sb, void *data, int silent) {
    sb->s_magic = MAGIC;    
    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_blocksize = PAGE_CACHE_SIZE;
    sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
    sb->s_time_gran = 1;
    sb->s_op = &s_op;
    sb->s_fs_info = data;

    struct inode *iroot = make_inode(sb, NULL, NULL, S_IFDIR | 0755);
    if (IS_ERR(iroot))
        return PTR_ERR(iroot);
        
    sb->s_root = d_alloc_root(iroot);
    if (!sb->s_root) {
        iput(iroot);
        return -ENOMEM;
    }

    unpack(sb->s_root);

    return 0;
}

static struct dentry *mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *options) {
    int error = 0;

    if (!options)
        options = "";

    struct fs_data *fs_data = kmalloc(sizeof(struct fs_data), GFP_KERNEL);
    if (!fs_data) {
        error = -ENOMEM;
        goto failure;
    }
    memset(fs_data, 0, sizeof(struct fs_data));

    fs_data->container_path = kmalloc(strlen(dev_name) + 1, GFP_KERNEL);
    if (!fs_data->container_path) {
        error = -ENOMEM;
        goto failure;
    }
    strcpy(fs_data->container_path, dev_name);

    fs_data->crypt_key = kmalloc(strlen(options) + 1, GFP_KERNEL);
    if (!fs_data->crypt_key) {
        error = -ENOMEM;
        goto failure;
    }
    strcpy(fs_data->crypt_key, options);
    
    struct dentry *droot = mount_nodev(fs_type, flags, fs_data, fill_super);
    if (IS_ERR(droot)) {
        error = PTR_ERR(droot);
        goto failure;
    }
        
    return droot;

failure:
    if (fs_data) {
        if (!fs_data->container_path) {
            kfree(fs_data->container_path);
        }
        if (fs_data->crypt_key) {
            kfree(fs_data->crypt_key);
        }
        kfree(fs_data);
    }

    return ERR_PTR(error);
}

static void kill_sb(struct super_block *sb) {
    repack(sb->s_root);

    struct fs_data *fs_data = sb->s_fs_info;

    kfree(fs_data->container_path);
    kfree(fs_data->crypt_key);
    kfree(fs_data);

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
MODULE_DESCRIPTION("\"Encrypted\" file system");
MODULE_LICENSE("GPL");
