//
// Created by Wihy on 10/5/26.
//

#ifndef SECUREMALLOC_MMAP_HELPER_H
#define SECUREMALLOC_MMAP_HELPER_H
#include <stddef.h>

#define MMAP_THRESHOLD (128 * 1024)
#define IS_MMAPED(sz) ((sz) & CHUNK_MMAPED)

typedef struct mmap_header {
    size_t cookie;
    size_t size;
} mmap_header;

void * mmap_allocate(size_t page_aligned_size, size_t secret);
void mmap_free(void *ptr, size_t total_size, size_t secret);

#endif //SECUREMALLOC_MMAP_HELPER_H
