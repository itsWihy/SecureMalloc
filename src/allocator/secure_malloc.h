//
// Created by Wihy on 9/20/26.
//

#ifndef SECUREMALLOC_SECURE_MALLOC_H
#define SECUREMALLOC_SECURE_MALLOC_H
#include <stddef.h>

#define CHUNK_HEADER_SIZE 0x10

#define FLAG_MASK    0xFUL
#define CHUNK_MMAPED    0x2UL
#define CHUNK_PREVINUSE 0x1

#define IS_PREVINUSE(size)    ((size) & CHUNK_PREVINUSE)
#define SET_PREVINUSE(chunk)  ((chunk)->size |= CHUNK_PREVINUSE)
#define ZERO_PREVINUSE(chunk) ((chunk)->size &= ~CHUNK_PREVINUSE)

typedef struct {
    size_t prev_size;
    size_t size;
    size_t cookie;
    //prev is at size/2
    //next is at size/2+1
} chunk_entry;

void *secure_malloc(size_t size);
void secure_free(void *ptr);
void validate_heap();

#endif //SECUREMALLOC_SECURE_MALLOC_H
