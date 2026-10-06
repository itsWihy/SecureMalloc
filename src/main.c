#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "allocator/secure_malloc.h"
#include <pthread.h>
#include <unistd.h>

#include "utils/utils.h"

size_t* secure_alloc_struct[100];
size_t* alloc_struct[100];

void secure_malloc_demo();
void normal_malloc_demo();

void interactive_repl();

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0); //so printf in allocator doesnt cause issues.

    // printf("Free leak: %llx", sbrk(0));

    interactive_repl();

    // secure_malloc_demo();
    // interactive_repl();
    int tests = 10000;
    int first_sizes = 100000;
    int second_sizes = 4096;
    size_t* ptr_array[tests];

    for (int i = 0; i < tests; ++i) {
        ptr_array[i] = secure_malloc(random() % first_sizes);
    }
    for (int i = 0; i < tests; ++i) {
        secure_free(ptr_array[i]);
    }
    for (int i = 0; i < tests; ++i) {
        ptr_array[i] = secure_malloc(random() % second_sizes);
    }
    for (int i = 0; i < tests; ++i) {
        secure_free(ptr_array[i]);
    }

    validate_heap();
}




void secure_malloc_demo() {
    void* uaf = malloc(0x100);
    free(uaf);

    write(STDOUT_FILENO, uaf, 100);
}

void normal_malloc_demo() {
    void* uaf = malloc(0x100);
    free(uaf);

    write(STDOUT_FILENO, uaf, 100);

}

void interactive_repl() {
    char input_buffer[100];
    int idx = 0;

    //[*] Function (malloc/free/puts/read/quit):

    while (1) {
        printf("\n[*] Function (malloc/free/write/read/secure_malloc/secure_free/secure_write/secure_read): \n");
        fscanf(stdin, "%99s", input_buffer);

        //All cmds read an index
        scanf("%zu", &idx);

        if (strstr(input_buffer, "secure_malloc") != 0) {
            size_t alloc_size = 0;
            scanf("%zu", &alloc_size);

            void* ptr = secure_malloc(alloc_size);
            secure_alloc_struct[idx] = ptr;
            printf("secure_allocation[%d] of size 0x%lx\n", idx, alloc_size);
            printf("secure_allocation[%d] = %p\n", idx, ptr);
            continue;
        }

        if (strstr(input_buffer, "secure_free") != 0) {
            void* ptr = secure_alloc_struct[idx];
            secure_free(ptr);
            printf("secure_allocation[%d] = %p freed.\n", idx, ptr);
            continue;
        }

        if (strstr(input_buffer, "secure_write") != 0) {
            void* ptr = secure_alloc_struct[idx];
            write(STDOUT_FILENO, ptr, 0x100);
            hexdump(ptr, 0x100);
            continue;
        }

        if (strstr(input_buffer, "secure_read") != 0) {
            void* ptr = secure_alloc_struct[idx];
            ssize_t read_bytes = read(STDIN_FILENO, ptr, 1000);
            printf("Read %zu bytes into secure allocation [%d].", read_bytes, idx);
            continue;
        }

        //-------------------------
        if (strstr(input_buffer, "malloc") != 0) {
            size_t alloc_size = 0;
            scanf("%zu", &alloc_size);
            void* ptr = malloc(alloc_size);
            alloc_struct[idx] = ptr;
            printf("allocation[%d] of size 0x%lx\n", idx, alloc_size);
            printf("allocation[%d] = %p\n", idx, ptr);
            continue;
        }

        if (strstr(input_buffer, "free") != 0) {
            void* ptr = alloc_struct[idx];
            free(ptr);
            printf("allocation[%d] = %p freed.\n", idx, ptr);
            continue;
        }

        if (strstr(input_buffer, "write") != 0) {
            void* ptr = alloc_struct[idx];
            write(STDOUT_FILENO, ptr, 0x100);
            hexdump(ptr-0x10, 0x100);
            continue;
        }

        if (strstr(input_buffer, "read") != 0) {
            void* ptr = alloc_struct[idx];
            ssize_t read_bytes = read(STDIN_FILENO, ptr, 1000);
            printf("Read %zu bytes into allocation [%d].", read_bytes, idx);
            continue;
        }
    }
}


//TODO:
// - fix writing over heap break on free.... check if over heap_next bro V
// - add chunk splitting when allocating very big chunk to avoid fragmentation V
// - coalescing V
// - thread safety V

// - safe linking, safe unlink FULL checks, avoid fragmentation when last chunk is freed- move sbrk backwards!
// Heap checker & testing
// Write workflow, show how can not be exploited while nomral CAN.

// - heap checker maybe?
// - workflow sheet & DONE!

// afterwards: -safelinking.

//https://elixir.bootlin.com/glibc/glibc-2.44.9000/source/malloc/malloc.c


// - SHOW that isn't vulnerable in UAF.
// - main hardenings:
//      Put PTRs at middle of chunk, vary by length.
//      Zero out next and prev on malloc.
//      Heap cookie (MMAP, ADD ON TCACHE TOO) <-- ovewrite harder.