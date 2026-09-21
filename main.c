#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secure_malloc.h"
#include <pthread.h>
#include <unistd.h>

size_t* alloc_struct[100];

int main(void) {
    char input_buffer[100];
    int idx;

    //[*] Function (malloc/free/puts/read/quit):
    while (1) {
        printf("\n[*] Function (malloc/free/puts/read/quit): \n");
        fscanf(stdin, "%99s", input_buffer);
        scanf("%d", &idx);

        if (strstr(input_buffer, "malloc") != 0) {
            size_t alloc_size;
            scanf("%d", &alloc_size);

            void* ptr = secure_malloc(alloc_size);
            alloc_struct[idx] = ptr;

            printf("allocation[%d] of size 0x%lx\n", idx, alloc_size);
            printf("allocation[%d] = %p\n", idx, ptr);

            //mallloc idx size..
            continue;
        }

        //https://elixir.bootlin.com/glibc/glibc-2.44.9000/source/malloc/malloc.c

        if (strstr(input_buffer, "free") != 0) {
            void* ptr = alloc_struct[idx];
            secure_free(ptr);

            printf("allocation[%d] = %p freed.\n", idx, ptr);
        }

        if (strstr(input_buffer, "malloc") != 0) {

        }
    }
    return 0;
}
