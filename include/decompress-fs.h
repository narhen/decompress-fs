#ifndef __DECOMPRESS_FS_H
#define __DECOMPRESS_FS_H
#define FUSE_USE_VERSION 31

#include <fuse.h>

struct data {
    int root;
    int file_buf_size; // number of buffer-bytes to allocate for each open file
    const char *root_path;
};

extern int do_open(const char *path, struct fuse_file_info *fi);
extern int do_release(const char *path, struct fuse_file_info *fi);
extern int do_read(
    const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
extern int do_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size, off_t offset,
    struct fuse_file_info *fi);
extern int do_opendir(const char *path, struct fuse_file_info *fi);
extern int do_releasedir(const char *path, struct fuse_file_info *fi);
extern int do_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
    struct fuse_file_info *fi, enum fuse_readdir_flags flags);
extern int do_getattr(const char *path, struct stat *info, struct fuse_file_info *fi);

#endif
