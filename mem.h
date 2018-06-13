#ifndef __MEM_H
#define __MEM_H

struct fifo_buf;
extern void fifo_free(struct fifo_buf *buf);
extern void fifo_reset(struct fifo_buf *buf);
extern struct fifo_buf *fifo_init(size_t size);
extern int fifo_write(struct fifo_buf *buf, void *data, size_t len);
extern int fifo_read(struct fifo_buf *src, void *dest, size_t size);
extern int fifo_peak(struct fifo_buf *src, void *dest, size_t size, size_t pos);
extern size_t fifo_curr_pos(struct fifo_buf *buf);
extern size_t fifo_min_pos(struct fifo_buf *buf);
extern size_t fifo_max_pos(struct fifo_buf *buf);
extern int fifo_set_pos(struct fifo_buf *buf, size_t pos);

#endif
