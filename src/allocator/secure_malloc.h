//
// Created by Wihy on 9/20/26.
//

#ifndef SECUREMALLOC_SECURE_MALLOC_H
#define SECUREMALLOC_SECURE_MALLOC_H
#include <stddef.h>

#define FLAG_MASK    0xFUL
#define CHUNK_MMAPED    0x2UL
#define CHUNK_PREVINUSE 0x1

void *secure_malloc(size_t size);
void secure_free(void *ptr);

#endif //SECUREMALLOC_SECURE_MALLOC_H
