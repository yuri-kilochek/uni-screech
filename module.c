#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>

#include "kernel_read_write.h"

#define MAGIC 0x5C12EEC8

#define LOG(...) printk(KERN_INFO "SCREECH " __VA_ARGS__)

#define CACHE_PREFIX "/tmp/screech-cache-"

#define CACHE_PATH_SIZE (sizeof(CACHE_PREFIX) + sizeof(unsigned long) * 2)

void make_cache_path(char *cache_path, unsigned long no) {
    snprintf(cache_path, CACHE_PATH_SIZE, "%s%0*lX", CACHE_PREFIX, (int)(sizeof(unsigned long) * 2), no);
}

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
    LOG("open %s", file->f_dentry->d_name.name);

    char cache_path[CACHE_PATH_SIZE];
    make_cache_path(cache_path, inode->i_ino);

    file->private_data = filp_open(cache_path, file->f_flags, 0600);
    if (IS_ERR(file->private_data)) {
        return PTR_ERR(file->private_data);
    }

    return 0;
}

static loff_t llseek(struct file *file, loff_t offset, int whence) {
    LOG("llseek %d %s", (int)offset, (whence == SEEK_SET) ? "SEEK_SET" : (whence == SEEK_CUR) ? "SEEK_CUR" : (whence == SEEK_END) ? "SEEK_END" : "???");
    return vfs_llseek(file->private_data, offset, whence);
}

static ssize_t read(struct file *file, char __user *buffer, size_t size, loff_t *offset) {
    LOG("read %s %d %d", file->f_dentry->d_name.name, (int)size, (int)*offset);
    return vfs_read(file->private_data, buffer, size, offset);
}

static ssize_t write(struct file *file, const char __user *buffer, size_t size, loff_t *offset) {
    LOG("write %s %d %d", file->f_dentry->d_name.name, (int)size, (int)*offset);
    return vfs_write(file->private_data, buffer, size, offset);
}

static int release(struct inode *inode, struct file *file) {
    LOG("release %s", file->f_dentry->d_name.name);
    return filp_close(file->private_data, NULL);
}

static struct file_operations reg_op = {
    .open = open,
    .llseek = llseek,
    .read = read,
    .write = write,
    .release = release,
};

static struct inode_operations reg_iop = {};

//static char *get_path(struct dentry *dentry) {
//    int len = 256;
//    for (;;) {
//        char *buf = kmalloc(len, GFP_KERNEL);
//        if (!buf)
//            return ERR_PTR(-ENOMEM);
//        char *res = dentry ? dentry_path_raw(dentry, buf, len) : strcpy(buf, "/");
//        if (IS_ERR(res)) {
//            kfree(buf);
//            if (PTR_ERR(res) == -ENAMETOOLONG) {
//                len *= 2;
//                continue;
//            }
//            return res;
//        }
//        memmove(buf, res, strlen(res) + 1);
//        return buf;
//    }
//}

static struct inode *make_inode(struct super_block *sb, struct inode *dir, struct dentry *dentry, int mode) {
    struct inode *inode = new_inode(sb);
    if (!inode) {
        return ERR_PTR(-ENOMEM);
    }

    inode->i_ino = get_next_ino();
    inode->i_ctime = inode->i_mtime = inode->i_atime = CURRENT_TIME;
    inode->i_mode = mode;

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
    return generic_delete_inode(inode);
}

static int create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd) {
    LOG("create %s", dentry->d_name.name);

    struct inode *inode = make_inode(dir->i_sb, dir, dentry, S_IFREG | mode);
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    return 0;
}

static int unlink(struct inode *dir, struct dentry *dentry) {
    LOG("unlink %s", dentry->d_name.name);
    return simple_unlink(dir, dentry);
}

static int mkdir(struct inode *dir, struct dentry *dentry, int mode) {
    LOG("mkdir %s", dentry->d_name.name);

    struct inode *inode = make_inode(dir->i_sb, dir, dentry, S_IFDIR | mode);
    if (IS_ERR(inode))
        return PTR_ERR(inode);
    return 0;
}

static int rmdir(struct inode *dir, struct dentry *dentry) {
    LOG("rmdir %s", dentry->d_name.name);
    return simple_rmdir(dir, dentry);
}

static int rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry) {
    LOG("rename %s %s", old_dentry->d_name.name, new_dentry->d_name.name);
    return simple_rename(old_dir, old_dentry, new_dir, new_dentry);
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

static void load_reg_content(struct file *container, struct dentry *dentry, loff_t *offset) {
    struct inode *inode = dentry->d_inode;

    char cache_path[CACHE_PATH_SIZE];
    make_cache_path(cache_path, inode->i_ino);

    struct file* cache = filp_open(cache_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (IS_ERR(cache)) {
        LOG("save_reg_content filp_open(cache_path, O_CREAT | O_TRUNC | O_WRONLY, 0600) failed");
        return;
    }

    uint32_t cache_size;
    vfs_read_to_kernel(container, (char *)&cache_size, sizeof(cache_size), offset);

    loff_t cache_offset = 0;
    while (cache_offset < cache_size) {
        char buffer[1024];
        loff_t amount_to_read = cache_size - cache_offset;
        if (amount_to_read > sizeof(buffer)) {
            amount_to_read = sizeof(buffer);
        }
        ssize_t amount_read = vfs_read_to_kernel(container, buffer, amount_to_read, offset);
        vfs_write_from_kernel(cache, buffer, amount_read, &cache_offset);
    }

    filp_close(cache, NULL);
}

static void load_dir_content(struct file *container, struct dentry *dentry, loff_t *offset) {
    struct super_block *sb = dentry->d_sb;

    uint32_t count;
    vfs_read_to_kernel(container, (char *)&count, sizeof(count), offset);

    for (int i = 0; i < count; ++i) {
        uint32_t name_size;
        vfs_read_to_kernel(container, (char *)&name_size, sizeof(name_size), offset);

        char name[name_size + 1];
        vfs_read_to_kernel(container, name, name_size, offset);
        name[name_size] = '\0';

        char type;
        vfs_read_to_kernel(container, &type, 1, offset);

        struct dentry *subdentry = d_alloc_name(dentry, name);
        d_rehash(subdentry);

        switch (type) {
            case 'R':
                make_inode(sb, dentry->d_inode, subdentry, S_IFREG | 0644);
                load_reg_content(container, subdentry, offset);
                break;
            case 'D':
                make_inode(sb, dentry->d_inode, subdentry, S_IFDIR | 0755);
                load_dir_content(container, subdentry, offset);
                break;
        }

        dput(subdentry);
    }
}

static int unpack(struct dentry *root) {
    LOG("unpack");

    struct fs_data *fs_data = root->d_sb->s_fs_info;

    struct file *container = filp_open(fs_data->container_path, O_RDONLY, 0000);
    if (IS_ERR(container)) {
        LOG("unpack file_open(fs_data->container_path, O_RDONLY, 0000) failed");
        return PTR_ERR(container);
    }

    load_dir_content(container, root, &(loff_t){0});

    filp_close(container, NULL);

    return 0;
}

static void save_reg_content(struct file *container, struct dentry *dentry, loff_t *offset) {
    struct inode *inode = dentry->d_inode;

    char cache_path[CACHE_PATH_SIZE];
    make_cache_path(cache_path, inode->i_ino);

    struct file* cache = filp_open(cache_path, O_CREAT | O_RDONLY, 0600);
    if (IS_ERR(cache)) {
        LOG("save_reg_content filp_open(cache_path, O_CREAT | O_RDONLY, 0600) failed");
        return;
    }

    uint32_t cache_size = vfs_llseek(cache, 0, SEEK_END);
    vfs_write_from_kernel(container, (char const *)&cache_size, sizeof(cache_size), offset);

    loff_t cache_offset = 0;
    while (cache_offset < cache_size) {
        char buffer[1024];
        ssize_t amount_read = vfs_read_to_kernel(cache, buffer, sizeof(buffer), &cache_offset);
        vfs_write_from_kernel(container, buffer, amount_read, offset);
    }

    filp_close(cache, NULL);
}

static void save_dir_content(struct file *container, struct dentry *dentry, loff_t *offset) {
    LOG("save_dir_content");

    struct dentry *subdentry;

    uint32_t count = 0;
    list_for_each_entry(subdentry, &dentry->d_subdirs, d_u.d_child) {
        ++count;
    }
    vfs_write_from_kernel(container, (char const *)&count, sizeof(count), offset);

    list_for_each_entry(subdentry, &dentry->d_subdirs, d_u.d_child) {
        uint32_t name_size = subdentry->d_name.len;
        vfs_write_from_kernel(container, (char const*)&name_size, sizeof(name_size), offset);

        char const* name = subdentry->d_name.name;
        vfs_write_from_kernel(container, name, name_size, offset);

        switch (subdentry->d_inode->i_mode & S_IFMT) {
            case S_IFREG:
                vfs_write_from_kernel(container, &(char){'R'}, 1, offset);
                save_reg_content(container, subdentry, offset);
                break;
            case S_IFDIR:
                vfs_write_from_kernel(container, &(char){'D'}, 1, offset);
                save_dir_content(container, subdentry, offset);
                break;
        };
    }
}

static int repack(struct dentry *root) {
    LOG("repack");

    struct fs_data *fs_data = root->d_sb->s_fs_info;

    struct file *container = filp_open(fs_data->container_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (IS_ERR(container)) {
        LOG("repack filp_open(fs_data->container_path, O_CREAT | O_TRUNC | O_WRONLY, 0644) failed");
        return PTR_ERR(container);
    }

    save_dir_content(container, root, &(loff_t){0});

    filp_close(container, NULL);

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
