project('decompress-fs', 'c')
add_global_arguments('-g', '-Werror', language: 'c')

inc = [include_directories('include')]
sources = []
header_files = []
test_sources = []

subdir('src')
subdir('tests')

dependencies = [dependency('fuse3'), dependency('libarchive')]

executable('decompressfs', sources, include_directories: inc, dependencies: dependencies)


configure_file(input : '.clang-format',
               output : '.clang-format',
               configuration : configuration_data())
run_target('format', command: [
    'clang-format',
    '-i',
    '-style=file',
    sources,
    header_files,
    test_sources])
