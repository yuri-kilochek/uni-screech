#include "file.h"

#include <asm/uaccess.h>

struct file *file_open(char const *path, int flags, int rights) {
    mm_segment_t fs = get_fs();
    set_fs(get_ds());
    struct file *file = filp_open(path, flags, rights);
    set_fs(fs);
    return file;
}

int file_read(struct file *file, long long offset, void* data, int size) {
    mm_segment_t fs = get_fs();
    set_fs(get_ds());
    int result = vfs_read(file, data, size, &offset);
    set_fs(fs);
    return result;
}  

int file_write(struct file *file, long long offset, void const* data, int size) {
    mm_segment_t fs = get_fs();
    set_fs(get_ds());
    int result = vfs_write(file, data, size, &offset);
    set_fs(fs);
    return result;
}

int file_close(struct file *file) {
    return filp_close(file, NULL);
}
