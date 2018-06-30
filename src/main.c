#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "decompress-fs.h"

struct {
    char *source_dir, *mountpoint;

    char *fuse_args[32];
    int num_fuse_args;

    int file_buf_size; // defaults to 512 MiB
    int foreground;
} options = {.source_dir = NULL,
    .mountpoint = NULL,
    .num_fuse_args = 0,
    .file_buf_size = 512 * 1024 * 1024,
    .foreground = 0};

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

void usage(char **argv, struct option *options)
{
    int i;

    printf("USAGE: %s <options> [SOURCE DIRECTORY] [MOUNTPOINT]\n", argv[0]);
    printf("Available options:\n");
    for (i = 0; options[i].name; i++)
        printf("    -%c, --%s %s\n", options[i].val, options[i].name,
            options[i].has_arg == required_argument ? "<argument>" : "");
}

void parse_args(int argc, char **argv)
{
    int c, i, option_index;
    struct option long_options[] = {
        {"foreground", no_argument, NULL, 'f'},
        {"buffer-size", required_argument, NULL, 's'},
        {NULL, 0, NULL, 0},
    };

    options.fuse_args[options.num_fuse_args++] = argv[0];

    while ((c = getopt_long(argc, argv, "fs:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'f':
                options.foreground = 1;
                break;
            case 's':
                options.file_buf_size = atoi(optarg);
                if (options.file_buf_size < 1024) {
                    fprintf(stderr, "Buffer size cant be less than 1024 bytes!\n");
                    exit(1);
                }
            default:
                usage(argv, long_options);
                exit(0);
        }
    }

    for (i = optind; i < argc; ++i)
        if (!options.source_dir)
            options.source_dir = argv[i];
        else
            options.mountpoint = argv[i];

    if (!options.source_dir || !options.mountpoint) {
        usage(argv, long_options);
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    int ret;
    struct data d;
    struct fuse *f;
    struct fuse_args args;

    parse_args(argc, argv);

    d.root = open(options.source_dir, O_PATH);
    d.root_path = options.source_dir;
    d.file_buf_size = options.file_buf_size;

    if (!d.root) {
        fprintf(stderr, "failed to open source directory '%s'\n", options.source_dir);
        return 1;
    }

    args.argv = options.fuse_args;
    args.argc = options.num_fuse_args;
    args.allocated = 0;

    f = fuse_new(&args, &ops, sizeof(ops), &d);
    fuse_mount(f, (const char *)options.mountpoint);
    fuse_daemonize(options.foreground);
    fuse_set_signal_handlers(fuse_get_session(f));

    ret = fuse_loop_mt_31(f, 1);

    fuse_remove_signal_handlers(fuse_get_session(f));
    fuse_unmount(f);
    fuse_destroy(f);

    return ret;
}
