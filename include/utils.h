#ifndef __UTILS_H
#define __UTILS_H

#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define dirent_array_entry(dent_array, dent_size, entry_num)                                       \
    ((struct dirent *)(((uint8_t *)(dent_array)) + ((dent_size) * (entry_num))))

#define dirent_array_next(dent_array, dent_size)                                                   \
    ((struct dirent *)(((uint8_t *)(dent_array)) + ((dent_size)*1)))

#define min(a, b) ((a) < (b) ? (a) : (b))

extern int endswith(const char *str, const char *p);
extern int endswith_list(const char *str, const char *ps[], size_t ps_len);
extern int startswith(const char *str, const char *p);

static inline int struct_dirent_size(const char *path)
{
    int filename_max = pathconf(path, _PC_NAME_MAX);
    if (filename_max == -1)
        filename_max = 255;
    return offsetof(struct dirent, d_name) + filename_max + 1;
}

#endif
