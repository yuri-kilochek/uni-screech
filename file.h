#ifndef FILE_HEADER
#define FILE_HEADER

#include <linux/fs.h>

struct file *file_open(char const *path, int flags, int rights);
ssize_t file_read(struct file *file, char __user *buffer, size_t size, loff_t *offset);
ssize_t file_write(struct file *file, const char __user *buffer, size_t size, loff_t *offset);
int file_close(struct file *file);

#endif

