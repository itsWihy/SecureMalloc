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

void *secure_malloc(size_t size);
void secure_free(void *ptr);

#endif //SECUREMALLOC_SECURE_MALLOC_H
