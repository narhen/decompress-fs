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

struct file {
    int fd;
    DIR *dp;
    struct archive *archive;
    struct archive_entry *archive_entry;
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

static const char *get_virtual_archive_file_name(const char *filename)
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

static struct archive_entry *find_archive_entry(struct archive *a, const char *filename)
{
    struct archive_entry *ent;

    while (archive_read_next_header(a, &ent) == ARCHIVE_OK)
        if (!strcmp(filename, archive_entry_pathname(ent)))
            return ent;

    return NULL;
}

static void free_file(struct file *f)
{
    if (f->archive)
        archive_read_free(f->archive);

    if (f->dp)
        closedir(f->dp);
    else if (f->fd >= 0)
        close(f->fd);

    free(f);
}

static struct file *open_file(const char *path, int flags)
{
    const char *filename, *p = get_path(path);
    char *archive_name;
    struct file *file;

    file = calloc(1, sizeof(struct file));
    if (!file)
        return NULL;

    file->fd = openat(root_fd(), p, flags);
    if (file->fd >= 0)
        return file;

    archive_name = find_archive_for_file(path);
    if (!archive_name) {
        free(file);
        return NULL;
    }

    file->archive = _get_archive(archive_name);
    free(archive_name);

    if (!file->archive) {
        free(file);
        return NULL;
    }

    filename = get_virtual_archive_file_name(p);
    file->archive_entry = find_archive_entry(file->archive, filename);

    return file;
}

int do_open(const char *path, struct fuse_file_info *fi)
{
    struct file *file;

    fprintf(stderr, "open '%s'\n", path);

    file = open_file(path, fi->flags);
    if (!file)
        return -errno;

    fprintf(stderr, "\tfd = %d\n", file->fd);

    fi->fh = (uintptr_t)file;

    return 0;
}

int do_release(const char *path, struct fuse_file_info *fi)
{
    struct file *f = (struct file *)fi->fh;

    fprintf(stderr, "release %s, %p, %d\n", path, f, f->fd);
    free_file(f);

    return 0;
}

int do_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int res;
    struct file *file;

    file = (struct file *)fi->fh;
    fprintf(stderr, "read %lu, from %d\n", size, file->fd);

    res = pread(file->fd, buf, size, offset);
    if (res == -1)
        return -errno;
    return res;
}

int do_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size, off_t offset,
    struct fuse_file_info *fi)
{
    struct fuse_bufvec *buf;
    struct file *file;

    file = (struct file *)fi->fh;
    fprintf(stderr, "read_buf %lu, from %d\n", size, file->fd);

    buf = malloc(sizeof(struct fuse_bufvec));
    if (!buf)
        return -ENOMEM;

    *buf = FUSE_BUFVEC_INIT(size);
    buf->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
    buf->buf[0].fd = file->fd;
    buf->buf[0].pos = offset;

    *bufp = buf;
    return 0;
}

// TODO: opendir where dir is virtual (not actually on the file system)
int do_opendir(const char *path, struct fuse_file_info *fi)
{
    struct file *file;

    fprintf(stderr, "   opendir %d, %p, %s\n", getpid(), fi, path);

    file = open_file(path, fi->flags);
    if (!file)
        return -errno;

    if (file->fd == -1) {
        free_file(file);
        return -errno;
    }

    file->dp = fdopendir(file->fd);
    if (file->dp == NULL)
        perror("fdopendir");

    fi->fh = (uintptr_t)file;

    return 0;
}

int do_releasedir(const char *path, struct fuse_file_info *fi)
{
    struct file *f = (struct file *)fi->fh;
    fprintf(stderr, "releasedir %d, %p, %s, %p, %d\n", getpid(), fi, path, f, f->fd);

    free_file(f);

    return 0;
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
    DIR *dp = ((struct file *)fi->fh)->dp;
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

static int archive_stat(const char *archive_filename, struct stat *info)
{
    char *archive_name = find_archive_for_file(archive_filename);
    const char *filename = get_virtual_archive_file_name(archive_filename);
    struct archive *archive;
    struct archive_entry *correct_ent = NULL;
    int ret = 0;

    if (!archive_name)
        return -EACCES;

    archive = _get_archive(archive_name);
    correct_ent = find_archive_entry(archive, filename);

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

    if (fi) {
        return fstat(((struct file *)fi->fh)->fd, info);
    }

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
