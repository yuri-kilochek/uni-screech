#include "file.h"

#include <asm/uaccess.h>

ssize_t vfs_read_to_kernel(struct file *file, char *buffer, size_t size, loff_t *offset) {
    mm_segment_t fs = get_fs();
    set_fs(get_ds());
    ssize_t result = vfs_read(file, buffer, size, offset);
    set_fs(fs);
    return result;
}

ssize_t vfs_write_from_kernel(struct file *file, const char *buffer, size_t size, loff_t *offset) {
    mm_segment_t fs = get_fs();
    set_fs(get_ds());
    ssize_t result = vfs_write(file, buffer, size, offset);
    set_fs(fs);
    return result;
}
