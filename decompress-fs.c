#define _GNU_SOURCE
#define FUSE_USE_VERSION 31

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fuse.h>

struct dir {
    DIR *dp;
};

struct data {
    int root;
};

static inline struct data *get_data(void)
{
    return (struct data *)fuse_get_context()->private_data;
}

static inline int root_fd(void)
{
    return get_data()->root;
}

static inline struct file *get_file(struct fuse_file_info *fi)
{
    return (struct file *)(uintptr_t)fi->fh;
}


static const char *get_path(const char *path)
{
    if (!strcmp(path, "/"))
        return ".";
    else if (path[0] == '/')
        return path + 1;

    return path;
}

static int open_file(const char *path, int flags)
{
    int fd;
    const char *p = get_path(path);

    fd = openat(root_fd(), p, flags);
    if (fd == -1)
        return -1;

    return fd;
}

int do_open(const char *path, struct fuse_file_info *fi)
{
    int fd;

    fd = open_file(path, fi->flags);
    fprintf(stderr, "OPEN %s, %d\n", path, fd);
    if (fd == -1)
        return -errno;
    fi->fh = (uintptr_t)fd;

    return 0;
}

int do_release(const char *path, struct fuse_file_info *fi)
{
    fprintf(stderr, "release %s, %d\n", path, (int)fi->fh);
    close((int)fi->fh);

    return 0;
}

int do_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int res, fd;

    fd = (int)fi->fh;
    res = pread(fd, buf, size, offset);
    if (res == -1)
        return -errno;
    return res;
}

int do_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size, 
        off_t offset, struct fuse_file_info *fi)
{
    struct fuse_bufvec *buf;
    int fd;

    fd = (int)fi->fh;

    buf = malloc(sizeof(struct fuse_bufvec));
    if (!buf)
        return -ENOMEM;

    *buf = FUSE_BUFVEC_INIT(size);
    buf->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    buf->buf[0].fd = fd;
    buf->buf[0].pos = offset;

    *bufp = buf;
    return 0;
}

int do_opendir(const char *path, struct fuse_file_info *fi)
{
    int fd;
    DIR *dp;
    
    fd = open_file(path, fi->flags);
    fprintf(stderr, "   opendir %d, %p, %s, %p\n", getpid(), fi, path, (DIR *)fi->fh);
    if (fd == -1)
        return -errno;

    dp = fdopendir(fd);
    if (dp == NULL)
        perror("fdopendir");

    fi->fh = (uintptr_t)dp;

    return 0;
}

int do_releasedir(const char *path, struct fuse_file_info *fi)
{
    fprintf(stderr, "releasedir %d, %p, %s, %p\n", getpid(), fi, path, (DIR *)fi->fh);

    closedir((DIR *)fi->fh);

    return 0;
}

int do_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, 
        struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
    DIR *dp = (DIR *)fi->fh;
    struct dirent *de;
    struct stat st;

    fprintf(stderr, "readdir %d, %p, %s, %p\n", getpid(), fi, path, dp);

    while ((de = readdir(dp))) {
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0))
            return 0;
    }
    return 0;
}

int do_getattr(const char *path, struct stat *info, struct fuse_file_info *fi)
{
    fprintf(stderr, "getattr %p, %s, %s\n", fi, path, get_path(path));

    if (fi)
        return fstat(fi->fh, info);
    return fstatat(root_fd(), get_path(path), info, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
}

static struct fuse_operations ops = {
    .opendir = do_opendir,
    .readdir = do_readdir,
    .releasedir = do_releasedir,
    .open = do_open,
    .release = do_release,
    .read = do_read,
    .read_buf = do_read_buf,
    .getattr = do_getattr,
};

int main(int argc, char *argv[])
{
    struct data d;
    char *root = "/home/narhen/";

    d.root = open(root, O_PATH);

    return fuse_main(argc, argv, &ops, &d);
}
