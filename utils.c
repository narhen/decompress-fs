#include <string.h>

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
