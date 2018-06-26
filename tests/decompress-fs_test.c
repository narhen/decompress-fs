#define _GNU_SOURCE
#include "decompress-fs.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fuse.h>

#define ROOT "../tests/data"
#define MOUNTPOINT "../tests/mnt"
#define FIFO_BUF_SIZE 1024
char root_dir[PATH_MAX];
char mountpoint[PATH_MAX];

struct fuse_operations ops = {
    .opendir = do_opendir,
    .readdir = do_readdir,
    .releasedir = do_releasedir,
    .open = do_open,
    .release = do_release,
    .read_buf = do_read_buf,
    .getattr = do_getattr,
};

static struct fuse *setup(int *fs_pid)
{
    struct fuse *f;
    struct fuse_args args;
    struct data d;
    char *argv[] = { "integration_test" };

    realpath(ROOT, root_dir);
    realpath(MOUNTPOINT, mountpoint);

    mkdir(mountpoint, 0777);

    d.root_path = root_dir;
    d.root = open(d.root_path, O_PATH);
    d.file_buf_size = FIFO_BUF_SIZE;

    args.argv = argv;
    args.argc = sizeof(argv) / sizeof(argv[0]);
    args.allocated = 0;

    f = fuse_new(&args, &ops, sizeof(ops), &d);
    fuse_set_signal_handlers(fuse_get_session(f));

    fuse_mount(f, (const char *)mountpoint);

    if (!(*fs_pid = fork()))
        exit(fuse_loop(f));

    return f;
}

static int teardown(struct fuse *f, int fs_pid)
{
    kill(fs_pid, SIGTERM);
    waitpid(fs_pid, NULL, 0);

    fuse_unmount(f);
    rmdir(mountpoint);

    return 0;
}

static int str_list_contains(char **str_list, int str_list_len, char *str)
{
    int i;

    for (i = 0; i < str_list_len; i++)
        if (!strcmp(str_list[i], str))
            return 1;
    return 0;
}

static void readdir__should_list_expected_files(void **state)
{
    DIR *dp;
    int expected_ent, total_ents_found, expected_ents_found;
    struct dirent *dent;
    char *expected_entries[] = {
        ".", "..", "lorem.txt.tar.bz2", "lorem.txt", "lorem.txt.tar.bz2:lorem.txt",
    };
    int expected_entries_len = sizeof(expected_entries) / sizeof(expected_entries[0]);

    dp = opendir(mountpoint);
    assert_non_null(dp);

    for (expected_ents_found = total_ents_found = 0; (dent = readdir(dp)) != NULL;
         ++total_ents_found) {
        expected_ent = str_list_contains(expected_entries, expected_entries_len, dent->d_name);
        assert_int_not_equal(0, expected_ent);
        if (expected_ent)
            ++expected_ents_found;
    }

    assert_int_equal(expected_entries_len, expected_ents_found);
    assert_int_equal(expected_ents_found, total_ents_found);
}

static void stat__should_provide_correct_meta_data(void **state)
{
    char buf[PATH_MAX];
    struct stat mounted, original;

    sprintf(buf, "%s/lorem.txt.tar.bz2:lorem.txt", mountpoint);
    stat(buf, &mounted);

    sprintf(buf, "%s/lorem.txt", root_dir);
    stat(buf, &original);

    assert_int_equal(mounted.st_size, original.st_size);
    assert_int_equal(mounted.st_mode, original.st_mode);
}

static void read__should_read_the_entire_file_without_errors(void **state)
{
    char buf[PATH_MAX];
    char original_content[4096], fs_content[4096];
    struct stat info;
    int fd, ret;

    memset(original_content, 0, sizeof(original_content));
    memset(fs_content, 0, sizeof(original_content));

    sprintf(buf, "%s/lorem.txt", root_dir);
    fd = open(buf, O_RDONLY);
    assert_int_not_equal(fd, -1);

    stat(buf, &info);
    ret = read(fd, original_content, sizeof(original_content));
    assert_int_equal(ret, info.st_size);

    sprintf(buf, "%s/lorem.txt.tar.bz2:lorem.txt", mountpoint);
    fd = open(buf, O_RDONLY);
    assert_int_not_equal(fd, -1);

    stat(buf, &info);
    ret = read(fd, fs_content, sizeof(fs_content));
    assert_int_equal(ret, info.st_size);

    assert_memory_equal(original_content, fs_content, info.st_size);
}

int main(void)
{
    int ret, fs_pid;
    struct fuse *f;
    const struct CMUnitTest tests[] = { cmocka_unit_test(readdir__should_list_expected_files),
        cmocka_unit_test(stat__should_provide_correct_meta_data),
        cmocka_unit_test(read__should_read_the_entire_file_without_errors) };

    f = setup(&fs_pid);
    ret = cmocka_run_group_tests(tests, NULL, NULL);
    teardown(f, fs_pid);

    return ret;
}
