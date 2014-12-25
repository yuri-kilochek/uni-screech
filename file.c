#include "file.h"

#include <linux/slab.h>
#include <asm/uaccess.h>

struct file *file_open(char const *path, int flags, int rights) {
    mm_segment_t fs = get_fs();
    set_fs(get_ds());
    struct file *file = filp_open(path, flags, rights);
    set_fs(fs);
    return file;
}

ssize_t file_read(struct file *file, char __user *buffer, size_t size, loff_t *offset) {
    mm_segment_t fs = get_fs();
    set_fs(get_ds());
    ssize_t result = vfs_read(file, buffer, size, offset);
    set_fs(fs);
    return result;
}

ssize_t file_write(struct file *file, const char __user *buffer, size_t size, loff_t *offset) {
    mm_segment_t fs = get_fs();
    set_fs(get_ds());
    ssize_t result = vfs_write(file, buffer, size, &offset);
    set_fs(fs);
    return result;
}

int file_close(struct file *file) {
    return filp_close(file, NULL);
}
