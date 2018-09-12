project('decompress-fs', 'c')
add_global_arguments('-Werror', language: 'c')

inc = [include_directories('include')]
sources = []
header_files = []
test_sources = []

subdir('src')
subdir('include')
subdir('tests')

dependencies = [dependency('fuse3'), dependency('libarchive')]

conf_data = configuration_data()
conf_data.set('version', '0.1')
configure_file(input: 'config.h.in',
                   output: 'config.h',
                   configuration: conf_data)

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
