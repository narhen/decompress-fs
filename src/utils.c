#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

bool endswith(const char *str, const char *p)
{
    int str_off = strlen(str) - strlen(p);

    if (str + str_off < str)
        return 0;
    return strcmp(str + str_off, p) == 0;
}

bool endswith_list(const char *str, const char *ps[], size_t ps_len)
{
    int i;

    for (i = 0; i < ps_len; i++)
        if (endswith(str, ps[i]))
            return true;
    return false;
}

bool startswith(const char *str, const char *p)
{
    int plen = strlen(p);

    if (plen > strlen(str))
        return false;

    return strncmp(str, p, plen) == 0;
}

void _debug_print(const char *function, int line, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    fprintf(stderr, "[DEBUG] %s:%d ", function, line);
    vfprintf(stderr, fmt, ap);

    va_end(ap);
}
