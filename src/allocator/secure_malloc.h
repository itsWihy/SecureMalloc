//
// Created by Wihy on 9/20/26.
//

#ifndef SECUREMALLOC_SECURE_MALLOC_H
#define SECUREMALLOC_SECURE_MALLOC_H
#include <stddef.h>


void *secure_malloc(size_t size);
void secure_free(void *ptr);

#endif //SECUREMALLOC_SECURE_MALLOC_H
