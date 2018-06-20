#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef UNIT_TEST
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#define malloc(size) test_malloc((size))
#define realloc(ptr, size) test_realloc((ptr), (size))
#define calloc(nmemb, size) test_calloc((nmemb), (size))
#define free(ptr) test_free((ptr))
#endif

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define MOD(a, b) ((((a) % (b)) + (b)) % (b))

struct fifo_buf {
    uint8_t *mem;
    uint8_t *head, *tail;

    size_t head_pos, tail_pos;
    size_t size;
};

void fifo_free(struct fifo_buf *buf)
{
    free(buf->mem);
    free(buf);
}

void fifo_reset(struct fifo_buf *buf)
{
    buf->head = buf->tail = buf->mem;
    buf->head_pos = buf->tail_pos = 0;
}

struct fifo_buf *fifo_init(size_t size)
{
    struct fifo_buf *buf;
    uint8_t *mem;

    mem = malloc(size);
    if (!mem)
        return NULL;

    buf = malloc(sizeof(struct fifo_buf));
    if (!buf) {
        free(mem);
        return NULL;
    }

    buf->mem = mem;
    buf->size = size;
    fifo_reset(buf);

    return buf;
}

static inline uint64_t ptr_distance(struct fifo_buf *buf, uint8_t *from, uint8_t *to)
{
    int64_t dist;

    dist = (int64_t)(to - from);
    return MOD(dist, buf->size);
}

int fifo_available_data(struct fifo_buf *buf)
{
    return buf->tail_pos - buf->head_pos;
}

static int available_data_from_pos(struct fifo_buf *buf, size_t pos)
{
    return fifo_available_data(buf) - (pos - buf->head_pos);
}

size_t fifo_curr_pos(struct fifo_buf *buf)
{
    return buf->head_pos;
}

long fifo_min_pos(struct fifo_buf *buf)
{
    long min_pos = buf->head_pos - ptr_distance(buf, buf->tail, buf->head);
    return max(0, min_pos);
}

size_t fifo_max_pos(struct fifo_buf *buf)
{
    return buf->tail_pos;
}

static uint8_t *ptr_add_offset(struct fifo_buf *buf, uint8_t *ptr, int offset)
{
    int64_t new_off, ptr_off;

    if (ptr < buf->mem || ptr > buf->mem + buf->size)
        return NULL;

    ptr_off = (int64_t)(ptr - buf->mem);
    new_off = MOD(ptr_off + offset, buf->size);

    return buf->mem + new_off;
}

// len must be <= buf->size
static void copy_to(struct fifo_buf *to, uint8_t *dest, uint8_t *src, size_t len)
{
    uint8_t *buf_end = to->mem + to->size;
    int positive_mem_left = (int)(buf_end - dest);
    int tmp = min(positive_mem_left, len);

    memcpy(dest, src, tmp);
    if (tmp != len)
        memcpy(to->mem, src + tmp, len - tmp);
}

int fifo_write(struct fifo_buf *buf, void *data, size_t len)
{
    uint8_t *data_ptr = data;
    size_t seek = len > buf->size ? len - buf->size : 0;
    size_t to_copy = min(len, buf->size);
    long dist_from_head_to_tail;

    copy_to(buf, buf->tail, data_ptr + seek, to_copy);

    buf->tail = ptr_add_offset(buf, buf->tail, to_copy);
    buf->tail_pos += len;

    if (fifo_available_data(buf) > buf->size) {
        dist_from_head_to_tail = ptr_distance(buf, buf->head, buf->tail);
        buf->head = ptr_add_offset(buf, buf->head, dist_from_head_to_tail);
        buf->head_pos += dist_from_head_to_tail + (((len - 1) / buf->size) * buf->size);
    }

    return len;
}

static uint8_t *pos_to_ptr(struct fifo_buf *from, size_t pos)
{
    int head_offset = pos - from->head_pos;
    int head_mem_offset = (int)(from->head - from->mem);

    if (pos < fifo_min_pos(from) || pos > fifo_max_pos(from))
        return NULL;

    return from->mem + ((head_offset + head_mem_offset) % from->size);
}

int fifo_set_pos(struct fifo_buf *buf, size_t pos)
{
    if (pos < fifo_min_pos(buf) || pos > fifo_max_pos(buf))
        return 0;

    buf->head = pos_to_ptr(buf, pos);
    buf->head_pos = pos;

    return 1;
}

static int copy_from_pos(
    struct fifo_buf *from, uint8_t *to, size_t size, size_t pos, uint8_t **end_ptr_loc)
{
    uint8_t *ptr = pos_to_ptr(from, pos);
    int to_read = min(available_data_from_pos(from, pos), size);

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
    return copy_from_pos(from, to, size, from->head_pos, &from->head);
}

int fifo_read(struct fifo_buf *src, void *dest, size_t size)
{
    int bytes_read;

    size = min(src->size, size);
    bytes_read = copy_from(src, (uint8_t *)dest, size);
    src->head_pos += bytes_read;

    return bytes_read;
}

int fifo_peek_pos(struct fifo_buf *src, void *dest, size_t size, size_t pos)
{
    size_t end_pos = src->head_pos + fifo_available_data(src);

    if (pos < src->head_pos || pos >= end_pos)
        return 0;

    return copy_from_pos(src, dest, size, pos, NULL);
}

int fifo_peek(struct fifo_buf *src, void *dest, size_t size)
{
    return fifo_peek_pos(src, dest, size, fifo_curr_pos(src));
}
