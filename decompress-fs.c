#define _GNU_SOURCE
#define FUSE_USE_VERSION 31

#include "utils.h"
#include <archive.h>
#include <archive_entry.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ROOT "/home/narhen/tmp"

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

static inline int root_fd(void) { return get_data()->root; }

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

int do_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size, off_t offset,
    struct fuse_file_info *fi)
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

static struct archive *_get_archive(const char *abspath)
{
    struct archive *a;

    a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    if (archive_read_open_filename(a, abspath, 1024) != ARCHIVE_OK) {
        archive_read_free(a);
        return NULL;
    }

    return a;
}

static struct archive *get_archive(const char *root, const char *path, const char *name)
{
    char filename[strlen(ROOT) + strlen(path) + strlen(name) + 3];

    sprintf(filename, "%s/%s/%s", root, path, name);
    return _get_archive(filename);
}

static int fill_compressed_files(
    void *buf, fuse_fill_dir_t filler, const char *path, struct dirent *dirents, int num_dirents)
{
    int i, dirent_size;
    struct dirent *curr_ent = dirents;
    struct archive *a;
    struct archive_entry *ent;
    char filename[1024];

    dirent_size = struct_dirent_size(path);

    for (i = 0; i < num_dirents; ++i, curr_ent = dirent_array_next(curr_ent, dirent_size)) {
        a = get_archive(ROOT, path, curr_ent->d_name);
        if (a == NULL)
            return -errno;
        while (archive_read_next_header(a, &ent) == ARCHIVE_OK) {
            sprintf(filename, "%s:%s", curr_ent->d_name, archive_entry_pathname(ent));
            if (filler(buf, filename, NULL, 0, 0)) {
                archive_read_free(a);
                return 0;
            }
        }
    }

    archive_read_free(a);
    return 0;
}

int do_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
    struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
    DIR *dp = (DIR *)fi->fh;
    int num_dirents = 8, curr_dirent = 0;
    int ret = 0, dirent_size = struct_dirent_size(get_path(path));
    struct dirent *curr, *result, *dirents = calloc(num_dirents, dirent_size);
    struct stat st;

    fprintf(stderr, "readdir %d, %p, %s, %p\n", getpid(), fi, path, dp);

    for (result = curr = dirents; readdir_r(dp, curr, &result) == 0 && result != NULL;
         curr = dirent_array_entry(dirents, dirent_size, curr_dirent)) {
        memset(&st, 0, sizeof(st));
        st.st_ino = curr->d_ino;
        st.st_mode = curr->d_type << 12;
        if (filler(buf, curr->d_name, &st, 0, 0))
            goto done;

        if (!endswith(curr->d_name, ".tar.bz2"))
            continue;

        if (++curr_dirent < num_dirents)
            continue;

        num_dirents *= 2;
        dirents = realloc(dirents, num_dirents * dirent_size);
    }

    ret = fill_compressed_files(buf, filler, get_path(path), dirents, curr_dirent);

done:
    free(dirents);
    return ret;
}

static const char *find_filename_in_archive(const char *filename)
{
    const char *ret = strrchr(filename, ':');

    if (!ret)
        return NULL;
    return ret + 1;
}

static char *find_archive_for_file(const char *filename)
{
    struct stat info;
    char *p;
    char abspath[strlen(ROOT) + strlen(filename) + 2];

    sprintf(abspath, "%s/%s", ROOT, filename);

    while ((p = strrchr(abspath, ':'))) {
        *p = 0;
        if (!lstat(abspath, &info))
            return strdup(abspath);
    }

    return NULL;
}

static int archive_stat(const char *archive_filename, struct stat *info)
{
    char *archive_name = find_archive_for_file(archive_filename);
    const char *filename = find_filename_in_archive(archive_filename);
    struct archive *archive;
    struct archive_entry *ent_iter, *correct_ent = NULL;
    int ret = 0;

    if (!archive_name)
        return -EACCES;

    archive = _get_archive(archive_name);
    while (archive_read_next_header(archive, &ent_iter) == ARCHIVE_OK) {
        if (!strcmp(filename, archive_entry_pathname(ent_iter))) {
            correct_ent = ent_iter;
            break;
        }
    }

    if (correct_ent) {
        memcpy(info, archive_entry_stat(correct_ent), sizeof(*info));
        ret = 0;
    } else
        ret = -EACCES;

    free(archive_name);
    archive_read_free(archive);
    return ret;
}

int do_getattr(const char *path, struct stat *info, struct fuse_file_info *fi)
{
    int ret;
    fprintf(stderr, "getattr %p, %s, %s\n", fi, path, get_path(path));

    if (fi)
        return fstat(fi->fh, info);

    ret = fstatat(root_fd(), get_path(path), info, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
    if (!ret)
        return ret;

    return archive_stat(path, info);
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

    d.root = open(ROOT, O_PATH);

    return fuse_main(argc, argv, &ops, &d);
}
