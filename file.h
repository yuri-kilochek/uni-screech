#ifndef FILE_HEADER
#define FILE_HEADER

#include <linux/fs.h>

struct file *file_open(char const *path, int flags, int rights);
int file_read(struct file *file, long long offset, void *data, int size);
int file_write(struct file *file, long long offset, void const *data, int size);
int file_close(struct file *file);

#endif

