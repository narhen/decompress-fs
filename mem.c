#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define min(a, b) ((a) < (b) ? (a) : (b))

struct fifo_buf {
    uint8_t *mem;
    uint8_t *head, *tail;

    size_t pos;
    size_t size;
};

void fifo_free(struct fifo_buf *buf)
{
    free(buf->mem);
    free(buf);
}

struct fifo_buf *fifo_init(size_t size)
{
    struct fifo_buf *buf;
    uint8_t *mem;

    mem = malloc(size);
    if (!mem)
        return NULL;

    buf = calloc(1, sizeof(struct fifo_buf));
    if (!buf) {
        free(mem);
        return NULL;
    }

    buf->size = size;
    buf->mem = buf->head = buf->tail = mem;
    return buf;
}

static int free_space(struct fifo_buf *buf)
{
    if (buf->head == buf->tail)
        return buf->size;

    if (buf->tail > buf->head)
        return buf->size - (int)(buf->tail - buf->head);

    return (long)(buf->head - buf->tail);
}

// len must be <= buf->size
static void copy_to(struct fifo_buf *to, uint8_t *from, size_t len)
{
    int fs = free_space(to);
    uint8_t *buf_end = to->mem + to->size;
    int positive_mem_left = (int)(buf_end - to->tail);

    int tmp = min(positive_mem_left, len);
    memcpy(to->tail, from, tmp);

    if (tmp != len) {
        memcpy(to->mem, from + tmp, len - tmp);
        to->tail = to->mem + len - tmp;
    } else
        to->tail += len;

    if (len > fs) {
        int to_add = len - fs;
        uint8_t *head_end = to->head + to_add;

        if (head_end > buf_end)
            to->head = to->mem + (long)(head_end - buf_end);
        else
            to->head = head_end;
    }
}

int fifo_write(struct fifo_buf *buf, void *data, size_t len)
{
    uint8_t *data_ptr = data;
    size_t seek = len > buf->size ? len - buf->size : 0;

    copy_to(buf, data_ptr + seek, min(len, buf->size));

    buf->pos += len;
    return len;
}

// size bust be <= from->size
static int copy_from(struct fifo_buf *from, uint8_t *to, size_t size)
{
    int to_read = min(from->size - free_space(from), size);
    uint8_t *from_end = from->mem + from->size;
    int positive_mem_left = (int)(from_end - from->head);

    int tmp = min(positive_mem_left, to_read);
    memcpy(to, from->head, tmp);
    from->head += tmp;

    if (tmp != to_read) {
        memcpy(to + tmp, from->mem, to_read - tmp);
        from->head = from->mem + to_read - tmp;
    }

    return to_read;
}

int fifo_read(struct fifo_buf *src, void *dest, size_t size)
{
    size = min(src->size, size);
    return copy_from(src, (uint8_t *)dest, size);
}
