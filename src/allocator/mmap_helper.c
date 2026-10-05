//
// Created by Wihy on 10/5/26.
//

#include "mmap_helper.h"

#include <stdio.h>
#include <sys/mman.h>
#include "secure_malloc.h"

void * mmap_allocate(const size_t page_aligned_size, const size_t secret) {
    mmap_header *chunk = mmap(NULL, page_aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    chunk->size = page_aligned_size | CHUNK_MMAPED;
    chunk->cookie = secret ^ page_aligned_size;

    return (char *) chunk + sizeof(mmap_header);
}


void mmap_free(void *ptr, const size_t total_size, const size_t secret) {
    const size_t cookie = ((size_t *) ptr - 2)[0];

    if ((secret ^ total_size) != cookie) {
        printf("\nINCORRECT COOKIE! Refusing free\n");
        return;
    }

    const int result = munmap(ptr - sizeof(mmap_header), total_size);
    printf("(%d) Unmapped %p \n", result, ptr);
}