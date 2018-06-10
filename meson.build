project('decompress-fs', 'c')
add_global_arguments('-g', '-Werror', language: 'c')

fuse3 = dependency('fuse3')
libarchive = dependency('libarchive')
sources = ['decompress-fs.c', 'utils.c']
executable('decompressfs', sources, dependencies : [fuse3, libarchive])
