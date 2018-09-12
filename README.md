# decompress-fs
[![Build Status](https://travis-ci.org/narhen/decompress-fs.svg?branch=master)](https://travis-ci.org/narhen/decompress-fs)

## Howto

First:
```bash
$ meson builddir
$ cd builddir
builddir/ $ # Make sure you have libfuse 3 installed. For me libfuse3.so is located in `/usr/local/lib/x86_64-linux-gnu`
builddir/ $ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/x86_64-linux-gnu
```

### Build
```bash
builddir/ $ ninja
[13/13] Linking target decompressfs
builddir/ $ ls -l decompressfs
-rwxr-xr-x 1 narhen narhen 58624 Sep 12 18:31 decompressfs*
```

### Run
```bash
builddir/ $ ninja
[13/13] Linking target tests/decompress_fs_test
$ # Mount a source folder at mountpoint
builddir/ $ ./decompressfs ~/source_directory ~/mountpoint
$ # Unmount the way you usually would
$ sudo umount ~/mountpoint
```

### Run tests
```bash
builddir/ $ ninja test
[0/1] Running all tests.
...
```
