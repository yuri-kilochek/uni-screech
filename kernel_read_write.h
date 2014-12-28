#ifndef FILE_HEADER
#define FILE_HEADER

#include <linux/fs.h>

ssize_t vfs_read_to_kernel(struct file *file, char *buffer, size_t size, loff_t *offset);
ssize_t vfs_write_from_kernel(struct file *file, const char *buffer, size_t size, loff_t *offset);

#endif

