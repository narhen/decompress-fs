#ifndef __UTILS_H
#define __UTILS_H

#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define dirent_array_entry(dent_array, dent_size, entry_num)                                       \
    ((struct dirent *)(((uint8_t *)(dent_array)) + ((dent_size) * (entry_num))))

#define dirent_array_next(dent_array, dent_size)                                                   \
    ((struct dirent *)(((uint8_t *)(dent_array)) + ((dent_size)*1)))

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define MOD(a, b) ((((a) % (b)) + (b)) % (b))

#ifdef DEBUG
void _debug_print(const char *function, int line, char *fmt, ...);
#define debug(fmt, ...) _debug_print(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

extern bool endswith(const char *str, const char *p);
extern bool endswith_list(const char *str, const char *ps[], size_t ps_len);
extern bool startswith(const char *str, const char *p);

static inline int struct_dirent_size(const char *path)
{
    int filename_max = pathconf(path, _PC_NAME_MAX);
    if (filename_max == -1)
        filename_max = 255;
    return offsetof(struct dirent, d_name) + filename_max + 1;
}

#endif
