#pragma once

/* A dma-buf from the pool fds/dmabuf.c makes at init, or -1 when it made
 * none. */
int get_rand_dmabuf_fd(void);
