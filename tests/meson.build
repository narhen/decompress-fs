test_dependencies = [dependency('cmocka'), dependency('fuse3'), dependency('libarchive')]
test_sources += files('mem_test.c', 'decompress-fs_test.c')

mem_test = executable('mem_test',
    ['mem_test.c', mem],
    include_directories: inc,
    dependencies: test_dependencies,
    c_args: ['-DUNIT_TEST'])

decompress_fs_test = executable('decompress_fs_test',
    ['decompress-fs_test.c', sources],
    include_directories: inc,
    dependencies: test_dependencies,
    c_args: ['-DINTEGRATION_TEST'])

test('mem test', mem_test)
test('decompress-fs test', decompress_fs_test)
