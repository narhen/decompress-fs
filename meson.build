project('decompress-fs', 'c')
add_global_arguments('-g', '-Werror', language: 'c')

inc = [include_directories('include')]
sources = []
header_files = []
test_sources = []

subdir('src')
subdir('include')
subdir('tests')

dependencies = [dependency('fuse3'), dependency('libarchive')]

executable('decompressfs',
           sources + [main],
           include_directories: inc,
           dependencies: dependencies,
           c_args: ['-DDEBUG'])


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
