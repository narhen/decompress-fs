#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fuse_opt.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "decompress-fs.h"
#include "config.h"

struct decompressfs {
    char *source_dir;
    char *mountpoint;
    int file_buf_size;
    int foreground;
    int singlethreaded;
    int help;
    int version;
} decompressfs = {.file_buf_size = 512 * 1024 * 1024 }; // default to 512 MiB

struct fuse_operations ops = {
    .opendir = do_opendir,
    .readdir = do_readdir,
    .releasedir = do_releasedir,
    .open = do_open,
    .release = do_release,
    .read_buf = do_read_buf,
    .getattr = do_getattr,
    .access = do_access,
};

enum { KEY_BUFFER_SIZE };

#define DECOMFS_OPT(t, p, v)                                                                       \
    {                                                                                              \
        t, offsetof(struct decompressfs, p), v                                                     \
    }

static struct fuse_opt decompressfs_opts[] = {
    DECOMFS_OPT("-h", help, 1),
    DECOMFS_OPT("-v", version, 1),
    DECOMFS_OPT("-f", foreground, 1),
    DECOMFS_OPT("-S", singlethreaded, 1),
    FUSE_OPT_KEY("-s ", KEY_BUFFER_SIZE),
    FUSE_OPT_KEY("rw", FUSE_OPT_KEY_DISCARD),
    FUSE_OPT_END
};

static void help(int argc, char **argv)
{
    printf("USAGE: %s <options> [SOURCE DIRECTORY] [MOUNTPOINT]\n",
        argc > 0 ? argv[0] : "decompressfs");
    printf("Available options:\n");
    printf("    -h      - Show this help help\n");
    printf("    -v      - Print version then exit\n");
    printf("    -f      - Run in foreground\n");
    printf("    -S      - Run one single thread\n");
    printf("    -s      - File Buffer size. Default is 512 MiB\n");
}

static int fuse_opt_process(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    switch (key) {
    case FUSE_OPT_KEY_OPT:
        return 1;
    case FUSE_OPT_KEY_NONOPT:
        if (!decompressfs.source_dir) {
            decompressfs.source_dir = strdup(arg);
            return 0;
        } else if (!decompressfs.mountpoint) {
            decompressfs.mountpoint = strdup(arg);
            return 0;
        }
        fprintf(stderr, "decompressfs: invalid argument '%s'\n", arg);
        return -1;
    case KEY_BUFFER_SIZE:
        sscanf(arg, "-s%d", &decompressfs.file_buf_size);
        if (decompressfs.file_buf_size < 4096) {
            fprintf(stderr, "Buffer size cannot be less than 4 KiB\n");
            exit(1);
        }
        return 0;
    default:
        fprintf(stderr, "hmm, something is wrong..\n");
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    int ret;
    struct data d;
    struct fuse *f;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (fuse_opt_parse(&args, &decompressfs, decompressfs_opts, fuse_opt_process) == -1)
        return 1;

    if (decompressfs.help) {
        help(argc, argv);
        return 0;
    }

    if (decompressfs.version) {
        puts(VERSION_STR);
        return 0;
    }

    if (!decompressfs.source_dir || !decompressfs.mountpoint) {
        fprintf(stderr, "Error: source and/or mountpoint was not specified\n");
        help(argc, argv);
        return 1;
    }

    if (fuse_opt_add_arg(&args, "-oro") == -1)
        return 1;

    d.root = open(decompressfs.source_dir, O_PATH);
    d.root_path = decompressfs.source_dir;
    d.file_buf_size = decompressfs.file_buf_size;

    if (!d.root) {
        fprintf(stderr, "failed to open source directory '%s'\n", decompressfs.source_dir);
        return 1;
    }

    f = fuse_new(&args, &ops, sizeof(ops), &d);
    fuse_mount(f, (const char *)decompressfs.mountpoint);
    fuse_daemonize(decompressfs.foreground);
    fuse_set_signal_handlers(fuse_get_session(f));

    if (decompressfs.singlethreaded)
        ret = fuse_loop(f);
    else
        ret = fuse_loop_mt(f, 1);

    fuse_remove_signal_handlers(fuse_get_session(f));
    fuse_unmount(f);
    fuse_destroy(f);

    return ret;
}
