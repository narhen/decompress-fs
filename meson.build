project('decompress-fs', 'c')
add_global_arguments('-g', language: 'c')
fuse3 = dependency('fuse3')
executable('decompressfs', 'decompress-fs.c', dependencies : fuse3)
