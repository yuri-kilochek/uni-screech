#ifndef DIR_HEADER
#define DIR_HEADER

int dir_iterate(char const *path, void (*report)(char const *dir_path, char const *name, void *ctx), void *ctx);

#endif
