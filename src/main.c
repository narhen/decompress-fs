#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "decompress-fs.h"

#define ROOT "/home/narhen/tmp"

static struct fuse_operations ops = {
    .opendir = do_opendir,
    .readdir = do_readdir,
    .releasedir = do_releasedir,
    .open = do_open,
    .release = do_release,
    //.read = do_read,
    .read_buf = do_read_buf,
    .getattr = do_getattr,
};

int main(int argc, char *argv[])
{
    struct data d;

    d.root = open(ROOT, O_PATH);
    d.root_path = ROOT;

    return fuse_main(argc, argv, &ops, &d);
}
