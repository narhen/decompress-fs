#include <string.h>
#include <stdarg.h>
#include <stdio.h>

int endswith(const char *str, const char *p)
{
    int str_off = strlen(str) - strlen(p);

    if (str + str_off < str)
        return 0;
    return !strcmp(str + str_off, p);
}

int endswith_list(const char *str, const char *ps[], size_t ps_len)
{
    int i;

    for (i = 0; i < ps_len; i++)
        if (endswith(str, ps[i]))
            return 1;
    return 0;
}

int startswith(const char *str, const char *p)
{
    int plen = strlen(p);

    if (plen > strlen(str))
        return 0;

    return !strncmp(str, p, plen);
}

void _debug_print(const char *function, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", function);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
