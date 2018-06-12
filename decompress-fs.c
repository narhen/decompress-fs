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

const char *supported_formats[] = {
    "tar.bz2", "tar.gz", "tar", "rar",
};

struct virtual_file {
    struct archive *archive;
    struct archive_entry *archive_entry;

    uint8_t *next_mem;
    size_t next_mem_size;
    off_t next_mem_off;
};

struct file {
    int fd;
    DIR *dp;

    struct virtual_file *vfile;
};

struct data {
    int root;
};

static inline int supported_format(const char *filename)
{
    return endswith_list(
        filename, supported_formats, sizeof(supported_formats) / sizeof(const char *));
}

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

static int cmpstringp(const void *p1, const void *p2)
{
    return strcmp(*(const char **)p1, *(const char **)p2);
}

static struct archive *_get_rar_archive(const char *abspath, struct archive *a)
{
    struct dirent *ent;
    char *dir, *filename;
    DIR *dp;
    int i, j, dirlen;
    char *multipart_archive_entries[2048]; // dynalloc pls

    if (archive_read_open_filename(a, abspath, 1024) != ARCHIVE_OK) {
        archive_read_free(a);
        return NULL;
    }
    return a;

    filename = basename(strdupa(abspath));
    dir = dirname(strdupa(abspath));
    dirlen = strlen(dir);
    dp = opendir(dir);
    if (!dp)
        return a;

    filename[strlen(filename) - 2] = 0; // cut off the "ar" part of "...rar"

    i = 0;
    while ((ent = readdir(dp)) != NULL) {
        if (!startswith(ent->d_name, filename))
            continue;
        char buf[dirlen + strlen(ent->d_name) + 2];
        sprintf(buf, "%s/%s", dir, ent->d_name);
        multipart_archive_entries[i++] = strdup(buf);
    }
    multipart_archive_entries[i] = NULL;

    qsort(multipart_archive_entries, i, sizeof(char *), cmpstringp);

    if (archive_read_open_filenames(a, (const char **)multipart_archive_entries, 4096)
        != ARCHIVE_OK) {
        fprintf(stderr, "FAIL!!!!\n");
        archive_read_free(a);
        return NULL;
    }

    for (j = 0; j < i; j++) {
        fprintf(stderr, "added '%s'\n", multipart_archive_entries[j]);
        free(multipart_archive_entries[j]);
    }

    return a;
}

static struct archive *_get_archive(const char *abspath)
{
    struct archive *a;

    a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    if (endswith(abspath, ".rar"))
        return _get_rar_archive(abspath, a);

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
    if (f->vfile) {
        if (archive_read_free(f->vfile->archive) != ARCHIVE_OK)
            perror("archive_read_free");
        if (f->vfile->next_mem)
            free(f->vfile->next_mem);
        free(f->vfile);
    }

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
    struct virtual_file *vfile;

    file = calloc(1, sizeof(struct file));
    if (!file)
        return NULL;

    file->fd = openat(root_fd(), p, flags);
    if (file->fd >= 0)
        return file;

    archive_name = find_archive_for_file(path);
    if (!archive_name) {
        free_file(file);
        return NULL;
    }

    vfile = calloc(1, sizeof(struct virtual_file));
    if (!vfile) {
        free_file(file);
        return NULL;
    }

    vfile->archive = _get_archive(archive_name);
    free(archive_name);

    if (!vfile->archive) {
        free(file);
        return NULL;
    }

    filename = get_virtual_archive_file_name(p);
    vfile->archive_entry = find_archive_entry(vfile->archive, filename);

    file->vfile = vfile;

    return file;
}

int do_open(const char *path, struct fuse_file_info *fi)
{
    struct file *file;

    fprintf(stderr, "open '%s'\n", path);

    file = open_file(path, fi->flags);
    if (!file)
        return -errno;

    fprintf(stderr, "\tfd = %d, vfile = %p\n", file->fd, file->vfile);

    fi->fh = (uintptr_t)file;

    return 0;
}

int do_release(const char *path, struct fuse_file_info *fi)
{
    struct file *f = (struct file *)fi->fh;

    fprintf(stderr, "release %s, %p, %d, %p\n", path, f, f->fd, f->vfile);
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

static int fill_buffer_from_memory(
    struct fuse_buf *target, size_t max_size, struct virtual_file *file)
{
    int unread_memory = file->next_mem_size - file->next_mem_off;

    fprintf(stderr, "%s: %lu, unread memory: %d\n", __func__, max_size, unread_memory);

    if (unread_memory > max_size) {
        target->mem = malloc(max_size);
        if (!target->mem)
            return -ENOMEM;
        target->size = max_size;
        memcpy(target->mem, file->next_mem + file->next_mem_off, max_size);
        file->next_mem_off += max_size;

        return max_size;
    }

    if (file->next_mem_off == 0) {
        target->mem = file->next_mem;
        target->size = file->next_mem_size;
    } else {
        target->mem = malloc(unread_memory);
        if (!target->mem)
            return -ENOMEM;
        target->size = unread_memory;
        memcpy(target->mem, file->next_mem + file->next_mem_off, unread_memory);
        free(file->next_mem);
    }

    file->next_mem = NULL;
    file->next_mem_off = file->next_mem_size = 0;
    return unread_memory;
}

static int read_vfile_buf(
    struct fuse_bufvec **bufp, size_t size, off_t offset, struct virtual_file *file)
{
    struct fuse_bufvec *bufs;
    struct fuse_buf *ptr;
    int ret = 0, res, num_bufs = 1;
    int bytes_read = 0, curr_buf = 0;
    off_t off;
    size_t block_size;
    void *mem;

    fprintf(stderr, "read_vfile_buf: size: %lu, offset: %lu, file: %p\n", size, offset, file);

    bufs = calloc(1, sizeof(struct fuse_bufvec));
    if (!bufs)
        return -1;

    if (file->next_mem) {
        if ((bytes_read = fill_buffer_from_memory(bufs->buf, size, file)) < 0)
            return bytes_read;
        fprintf(stderr, "read %d bytes from memory. size = %lu\n", bytes_read, size);
        curr_buf = 1;
    }

    while (bytes_read < size) {
        res = archive_read_data_block(file->archive, (const void **)&mem, &block_size, &off);
        if (res == ARCHIVE_EOF) {
            ret = 0;
            break;
        } else if (res == ARCHIVE_WARN)
            perror("archive_read_data_block");
        else if (res == ARCHIVE_FATAL)
            return -errno;

        if (!block_size || !mem)
            continue;

        if (curr_buf >= num_bufs) {
            num_bufs *= 2;
            bufs = realloc(
                bufs, sizeof(struct fuse_bufvec) + ((num_bufs - 1) * sizeof(struct fuse_buf)));
            if (!bufs)
                return -ENOMEM;
        }

        fprintf(stderr, "read %lu byte block\n", block_size);
        ptr = &bufs->buf[curr_buf++];

        if (bytes_read + block_size <= size) {
            ptr->size = block_size;
            ptr->mem = malloc(ptr->size);
            if (!ptr->mem)
                return -ENOMEM;
            memcpy(ptr->mem, mem, ptr->size);
        } else {
            ptr->size = size - bytes_read;
            ptr->mem = malloc(ptr->size);
            if (!ptr->mem)
                return -ENOMEM;
            memcpy(ptr->mem, mem, ptr->size);

            file->next_mem_size = block_size - ptr->size;
            file->next_mem = malloc(file->next_mem_size);
            if (!file->next_mem)
                return -ENOMEM;
            memcpy(file->next_mem, ((uint8_t *)mem) + ptr->size, file->next_mem_size);
            file->next_mem_off = 0;

            fprintf(stderr, "this boi is full. storing next chunk for next read. next_mem: %p, "
                            "next_mem_size: %lu\n",
                file->next_mem, file->next_mem_size);
        }

        bytes_read += ptr->size;
        fprintf(stderr, "read %d/%lu bytes\n", bytes_read, size);
    }

    bufs->count = num_bufs;
    *bufp = bufs;

    return ret;
}

int do_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size, off_t offset,
    struct fuse_file_info *fi)
{
    struct fuse_bufvec *buf;
    struct file *file;

    file = (struct file *)fi->fh;

    if (file->vfile)
        return read_vfile_buf(bufp, size, offset, file->vfile);

    fprintf(stderr, "read_buf %lu, from fd %d\n", size, file->fd);
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

    file = open_file(path, fi->flags);

    fprintf(stderr, "   opendir %d, %p, %s, %p\n", getpid(), fi, path, file);

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
        archive_read_free(a);
    }

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

    fprintf(stderr, "readdir %d, %p, %s, %p\n", getpid(), fi, path, (void *)fi->fh);

    for (result = curr = dirents; readdir_r(dp, curr, &result) == 0 && result != NULL;
         curr = dirent_array_entry(dirents, dirent_size, curr_dirent)) {
        memset(&st, 0, sizeof(st));
        st.st_ino = curr->d_ino;
        st.st_mode = curr->d_type << 12;
        if (filler(buf, curr->d_name, &st, 0, 0))
            goto done;

        if (!supported_format(curr->d_name))
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

static int _archive_stat(struct stat *info, struct archive_entry *ent)
{
    if (!ent)
        return -EACCES;

    memcpy(info, archive_entry_stat(ent), sizeof(*info));
    return 0;
}

static int archive_stat(const char *archive_filename, struct stat *info)
{
    char *archive_name = find_archive_for_file(archive_filename);
    const char *filename = get_virtual_archive_file_name(archive_filename);
    struct archive *archive;
    struct archive_entry *correct_ent = NULL;
    int ret = 0;

    fprintf(stderr, "archvie_stat %s\n", archive_filename);

    if (!archive_name)
        return -EACCES;

    archive = _get_archive(archive_name);
    correct_ent = find_archive_entry(archive, filename);

    ret = _archive_stat(info, correct_ent);

    free(archive_name);
    archive_read_free(archive);
    return ret;
}

int do_getattr(const char *path, struct stat *info, struct fuse_file_info *fi)
{
    struct file *file;

    fprintf(stderr, "getattr %p, %s, %s\n", fi, path, get_path(path));

    if (fi) {
        file = (struct file *)fi->fh;
        if (!file->vfile)
            return fstat(file->fd, info);
        return _archive_stat(info, file->vfile->archive_entry);
    }

    if (!fstatat(root_fd(), get_path(path), info, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
        return 0;

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
