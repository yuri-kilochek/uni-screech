#include "dir.h"

#include "file.h"

struct box {
    char const *dir_path;
    void (*report)(char const *dir_path, char const *name, void *ctx);
    void *ctx;
};

static int filldir(void *buf, char const *name, int _0, loff_t _1, u64 _2, unsigned _3) {
    struct box* box = buf;
    box->report(box->dir_path, name, box->ctx);
    return 0;
}

int dir_iterate(char const *path, void (*report)(char const *dir_path, char const *name, void *ctx), void *ctx) {
    struct file *dir = file_open(path, O_DIRECTORY, 0);
    if (IS_ERR(dir))
        return PTR_ERR(dir);
    int result = vfs_readdir(dir, filldir, &(struct box){path, report, ctx});
    file_close(dir);
    return result;
}
