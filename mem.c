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

static int used_space(struct fifo_buf *buf)
{
    return buf->size - free_space(buf);
}

static int data_left_from_pos(struct fifo_buf *buf, size_t pos)
{
    return used_space(buf) - (pos - buf->pos);
}

size_t curr_pos(struct fifo_buf *buf)
{
    return buf->pos;
}

size_t min_pos(struct fifo_buf *buf)
{
    if (buf->tail > buf->head)
        return buf->pos - (size_t)(buf->head - buf->mem);
    return buf->pos - (size_t)(buf->head - buf->tail);
}

size_t max_pos(struct fifo_buf *buf)
{
    return buf->pos + used_space(buf);
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

static uint8_t *pos_to_ptr(struct fifo_buf *from, size_t pos)
{
    int head_offset = pos - from->pos;
    int head_mem_offset = (int)(from->head - from->mem);

    if (pos < min_pos(from) || pos > max_pos(from))
        return NULL;

    return from->mem + ((head_offset + head_mem_offset) % from->size);
}

static int copy_from_pos(
    struct fifo_buf *from, uint8_t *to, size_t size, size_t pos, uint8_t **end_ptr_loc)
{
    uint8_t *ptr = pos_to_ptr(from, pos);
    int to_read = min(data_left_from_pos(from, pos), size);

    int positive_mem_left = from->size - (int)(ptr - from->mem);
    int tmp = min(positive_mem_left, to_read);

    memcpy(to, ptr, tmp);
    ptr += tmp;

    if (tmp != to_read) {
        memcpy(to + tmp, from->mem, to_read - tmp);
        ptr = from->mem + to_read - tmp;
    }

    if (end_ptr_loc)
        *end_ptr_loc = ptr;

    return to_read;
}

// size bust be <= from->size
static int copy_from(struct fifo_buf *from, uint8_t *to, size_t size)
{
    return copy_from_pos(from, to, size, from->pos, &from->head);
}

int fifo_read(struct fifo_buf *src, void *dest, size_t size)
{
    size = min(src->size, size);
    return copy_from(src, (uint8_t *)dest, size);
}

int fifo_peak(struct fifo_buf *src, void *dest, size_t size, size_t pos)
{
    size_t end_pos = src->pos + used_space(src);

    if (pos < src->pos || pos >= end_pos)
        return 0;

    return copy_from_pos(src, dest, size, pos, NULL);
}
