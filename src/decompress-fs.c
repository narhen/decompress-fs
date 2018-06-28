#define _GNU_SOURCE
#include "mem.h"
#include "utils.h"
#include "decompress-fs.h"
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
#include <pthread.h>

#define fuse_bufvec_size(num_bufs)                                                                 \
    (num_bufs) > 1 ? sizeof(struct fuse_bufvec) + (sizeof(struct fuse_buf) * ((num_bufs)-1))       \
                   : sizeof(struct fuse_bufvec)

const char *supported_formats[] = {
    "tar.bz2", "tar.gz", "tar", "rar",
};

struct virtual_file {
    struct archive *archive;
    struct archive_entry *archive_entry;

    pthread_mutex_t lock;

    struct fifo_buf *buf;
    char *archive_path, *archive_filename;
};

struct file {
    int fd;
    DIR *dp;

    struct virtual_file *vfile;
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

static int _archive_stat(struct stat *info, struct archive_entry *ent)
{
    if (!ent)
        return -EACCES;

    memcpy(info, archive_entry_stat(ent), sizeof(*info));
    return 0;
}

static inline int root_fd(void)
{
    return get_data()->root;
}

static inline const char *root_path(void)
{
    return get_data()->root_path;
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
    char abspath[strlen(root_path()) + strlen(filename) + 2];

    sprintf(abspath, "%s/%s", root_path(), filename);

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

    if (i == 1) {
        if (archive_read_open_filename(a, multipart_archive_entries[0], 10240) != ARCHIVE_OK) {
            archive_read_free(a);
            return NULL;
        }
        return a;
    }

    qsort(multipart_archive_entries, i, sizeof(char *), cmpstringp);

    multipart_archive_entries[i] = NULL;
    if (archive_read_open_filenames(a, (const char **)multipart_archive_entries, 10240)
        != ARCHIVE_OK) {
        archive_read_free(a);
        return NULL;
    }

    for (j = 0; j < i; j++)
        free(multipart_archive_entries[j]);

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

    if (archive_read_open_filename(a, abspath, 10240) != ARCHIVE_OK) {
        archive_read_free(a);
        return NULL;
    }

    return a;
}

static struct archive *get_archive(const char *root, const char *path, const char *name)
{
    char filename[strlen(root_path()) + strlen(path) + strlen(name) + 3];

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

static inline void free_archive(struct archive *a)
{
    if (archive_read_free(a) != ARCHIVE_OK)
        perror("archive_read_free");
}

static void free_virtual_file(struct virtual_file *vfile)
{
    free_archive(vfile->archive);
    fifo_free(vfile->buf);
    free(vfile->archive_path);
    free(vfile->archive_filename);
    pthread_mutex_destroy(&vfile->lock);
    free(vfile);
}

static void free_file(struct file *f)
{
    if (f->vfile)
        free_virtual_file(f->vfile);

    if (f->dp)
        closedir(f->dp);
    else if (f->fd >= 0)
        close(f->fd);

    free(f);
}

static int _open_archive(struct virtual_file *vfile)
{
    vfile->archive = _get_archive(vfile->archive_path);
    if (!vfile->archive)
        return 0;

    vfile->archive_entry = find_archive_entry(vfile->archive, vfile->archive_filename);

    return 1;
}

static struct virtual_file *open_archive(const char *path)
{
    struct virtual_file *vfile;

    vfile = calloc(1, sizeof(struct virtual_file));
    if (!vfile)
        return NULL;

    vfile->archive_path = find_archive_for_file(path);
    if (!vfile->archive_path) {
        free(vfile);
        return NULL;
    }

    vfile->archive_filename = strdup(get_virtual_archive_file_name(path));
    if (!vfile->archive_filename) {
        free(vfile->archive_path);
        free(vfile);
        return NULL;
    }

    if (!_open_archive(vfile)) {
        free(vfile->archive_path);
        free(vfile->archive_filename);
        free(vfile);
        return NULL;
    }

    vfile->buf = fifo_init(get_data()->file_buf_size);
    pthread_mutex_init(&vfile->lock, NULL);

    return vfile;
}

static struct file *open_file(const char *path, int flags)
{
    const char *p = get_path(path);
    struct file *file;

    file = calloc(1, sizeof(struct file));
    if (!file)
        return NULL;

    file->fd = openat(root_fd(), p, flags);
    if (file->fd >= 0)
        return file;

    file->vfile = open_archive(p);
    if (!file->vfile) {
        free_file(file);
        return NULL;
    }

    return file;
}

int do_open(const char *path, struct fuse_file_info *fi)
{
    struct file *file;

    file = open_file(path, fi->flags);
    debug("%p '%s'\n", file->vfile, path);

    if (!file)
        return -errno;

    fi->fh = (uintptr_t)file;

    return 0;
}

int do_release(const char *path, struct fuse_file_info *fi)
{
    struct file *f = (struct file *)fi->fh;

    debug("%s, %p, %d, %p\n", path, f, f->fd, f->vfile);
    free_file(f);

    return 0;
}

static int vfile_read(struct virtual_file *vfile, size_t size, char *dest_buf)
{
    int bytes_read, mem_size;
    long res;
    uint8_t *mem;

    mem_size = fifo_buffer_size(vfile->buf);
    mem = calloc(1, mem_size);
    if (!mem)
        return -ENOMEM;

    bytes_read = 0;
    while (bytes_read < size) {
        res = archive_read_data(vfile->archive, mem, mem_size);
        if (!res || res == ARCHIVE_EOF)
            break;
        else if (res < 0) {
            debug("archive_read_data_block: %s\n", archive_error_string(vfile->archive));
            bytes_read = -EOF;
            goto done;
        }


        if (dest_buf) {
            int max_copy = min(res, size - bytes_read);
            memcpy(dest_buf + bytes_read, mem, max_copy);

            bytes_read += max_copy;
        }

        res = fifo_write(vfile->buf, mem, res);

        if (!dest_buf)
            bytes_read += res;
    }

done:
    free(mem);
    return bytes_read;
}

static int vfile_seek(struct virtual_file *vfile, off_t offset)
{
    struct stat info;

    debug("seeking from %lu to %lu\n", fifo_curr_pos(vfile->buf), offset);

    if (_archive_stat(&info, vfile->archive_entry) != 0)
        return -EINVAL;

    if (offset < 0 || offset > info.st_size)
        return -EINVAL;

    if (offset > fifo_max_pos(vfile->buf))
        vfile_read(vfile, offset - fifo_max_pos(vfile->buf), NULL);
    else if (offset < fifo_min_pos(vfile->buf)) {
        free_archive(vfile->archive);
        _open_archive(vfile);
        fifo_reset(vfile->buf);
        vfile_read(vfile, offset, NULL);
    }

    return fifo_set_pos(vfile->buf, offset);
}

static int read_vfile_buf(
    struct fuse_bufvec **bufp, size_t size, off_t offset, struct virtual_file *file)
{
    int available_data, num_bufs = 2, ret = 0;
    struct fuse_bufvec *bufs;
    struct fuse_buf *buf;

    pthread_mutex_lock(&file->lock);

    debug("size: %lu, offset: %lu, file: %p\n", size, offset, file);

    bufs = calloc(1, fuse_bufvec_size(num_bufs));
    if (!bufs) {
        ret = -ENOMEM;
        goto done;
    }

    if (fifo_curr_pos(file->buf) != offset)
        if ((ret = vfile_seek(file, offset)) < 0)
            goto done;

    buf = bufs->buf;
    available_data = fifo_available_data(file->buf);
    if (available_data > 0) {
        buf->mem = calloc(1, available_data);
        if (!buf->mem) {
            ret = -ENOMEM;
            free(bufs);
            goto done;
        }

        buf->size = fifo_read(file->buf, buf->mem, size);
        size -= buf->size;
        buf++;
    }

    buf->mem = calloc(1, size);
    if (!buf->mem) {
        ret = -ENOMEM;
        free((buf - 1)->mem);
        free(bufs);
        goto done;
    }

    buf->size = vfile_read(file, size, buf->mem);

    bufs->count = num_bufs;
    *bufp = bufs;

    debug("read %d bytes from %d buffers\n", bufs->buf[0].size + bufs->buf[1].size, num_bufs);

done:
    pthread_mutex_unlock(&file->lock);

    return ret;
}

static int read_vfile(struct virtual_file *vfile, void *buf, size_t size, off_t offset)
{
    int bytes_read;
    int8_t *bufptr = buf;
    debug("reading at most %lu bytes into %p from offset %lu\n", size, buf, offset);

    if (fifo_curr_pos(vfile->buf) != offset)
        if (!vfile_seek(vfile, offset))
            return -1;

    bytes_read = fifo_read(vfile->buf, bufptr, size);
    size -= bytes_read;

    if (size > fifo_available_data(vfile->buf))
        bytes_read += vfile_read(vfile, size, (char *)bufptr + bytes_read);

    return bytes_read;
}

int do_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int res;
    struct file *file;

    file = (struct file *)fi->fh;
    if (file->vfile)
        return read_vfile(file->vfile, buf, size, offset);

    debug("read %lu, from %d\n", size, file->fd);
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

    if (file->vfile)
        return read_vfile_buf(bufp, size, offset, file->vfile);

    debug("read_buf %lu, from fd %d\n", size, file->fd);
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
    struct file *file = NULL;

    debug("%d, %p, %s, %p\n", getpid(), fi, path, file);

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
    debug("%d, %p, %s, %p, %d\n", getpid(), fi, path, f, f->fd);

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
        a = get_archive(root_path(), path, curr_ent->d_name);
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

    debug("%d, %p, %s, %p\n", getpid(), fi, path, (void *)fi->fh);

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

    ret = _archive_stat(info, correct_ent);

    free(archive_name);
    archive_read_free(archive);
    return ret;
}

int do_getattr(const char *path, struct stat *info, struct fuse_file_info *fi)
{
    struct file *file;

    debug("%p, %s, %s\n", fi, path, get_path(path));

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
