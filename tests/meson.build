test_dependencies = [dependency('cmocka')]
test_sources += files('mem_test.c')

mem_test = executable('mem_test',
    ['mem_test.c', mem],
    include_directories: inc,
    dependencies: test_dependencies,
    c_args: ['-DUNIT_TEST'])

test('mem test', mem_test)
