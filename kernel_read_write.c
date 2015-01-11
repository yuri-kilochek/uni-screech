#include "kernel_read_write.h"

#include <asm/uaccess.h>
#include <linux/string.h>

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

static void crypt(char *buffer, ssize_t buffer_len, char const* key, ssize_t key_len, ssize_t offset) {
    if (key_len == 0) {
        return;
    }

    for (ssize_t i = 0; i < buffer_len; ++i) {
        ssize_t j = offset + i;
        buffer[i] ^= key[j % key_len] ^ (j % 256);
    }
}

ssize_t vfs_read_to_kernel_decrypted(struct file *file, char *buffer, size_t size, loff_t *offset, char const* key) {
    ssize_t result = vfs_read_to_kernel(file, buffer, size, offset);
    crypt(buffer, result, key, strlen(key), *offset - result);
    return result;
}

ssize_t vfs_write_from_kernel_encrypted(struct file *file, const char *buffer, size_t size, loff_t *offset, char const* key) {
    ssize_t i = 0;

    while (i < size) {
        char subbuffer[512];
        ssize_t subsize = size - i;
        if (subsize > sizeof(subbuffer)) {
            subsize = sizeof(subbuffer);
        }
        memcpy(subbuffer, buffer + i, subsize);
        crypt(subbuffer, subsize, key, strlen(key), *offset);
        i += vfs_write_from_kernel(file, subbuffer, subsize, offset);
    }

    return i;
}