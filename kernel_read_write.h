#ifndef KERNEL_READ_WRITE_HEADER
#define KERNEL_READ_WRITE_HEADER

#include <linux/fs.h>

ssize_t vfs_read_to_kernel(struct file *file, char *buffer, size_t size, loff_t *offset);
ssize_t vfs_write_from_kernel(struct file *file, const char *buffer, size_t size, loff_t *offset);

ssize_t vfs_read_to_kernel_decrypted(struct file *file, char *buffer, size_t size, loff_t *offset, char const* key);
ssize_t vfs_write_from_kernel_encrypted(struct file *file, const char *buffer, size_t size, loff_t *offset, char const* key);

#endif

