//
// Created by Wihy on 9/20/26.
//
#include "secure_malloc.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils/utils.h"
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE       (4096)
#define MMAP_THRESHOLD (128 * 1024)

#define FLAG_MASK    0xFUL
#define CHUNK_MMAPED    0x2UL
#define CHUNK_PREVINUSE 0x1

#define IS_MMAPED(sz) ((sz) & CHUNK_MMAPED)
#define IS_PREVINUSE(sz) ((sz) & CHUNK_PREVINUSE)

//TCACHE STUFF
#define TCACHE_BINS 64
#define MAX_CHUNKS_PER_BIN 10
#define TCACHE_CHUNK_MAX_SIZE ((TCACHE_BINS-1) * 0x10 + 0x20)

typedef struct mmap_header {
    size_t cookie;
    size_t size;
} mmap_header;

typedef struct tcache_entry tcache_entry;


//TCACHE FORAMTTING:
//-------- PREV SIZE, SIZE  ....... NEXT FD  KEY .....
struct tcache_entry {
    tcache_entry* next; //stores PTR TO HEADER!!
    size_t key;
};

typedef struct { //bins store ACTUAL SIZE. meaning HEADER + bin.
    uint16_t bin_counts[TCACHE_BINS];
    tcache_entry* entries[TCACHE_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct tcache;

size_t secret = 0;

void *secure_malloc(const size_t size) {
    if (secret == 0)
        secret = random();

    const size_t aligned_size = max(size + 8 + 15 & ~15, 0x20); //Round to next 0x10. min of 0x20.

    if (aligned_size > MMAP_THRESHOLD) {
        const size_t page_aligned_size = (aligned_size + sizeof(mmap_header) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        mmap_header *ptr = mmap(NULL, page_aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        ptr->size = page_aligned_size | CHUNK_MMAPED;
        ptr->cookie = secret ^ page_aligned_size;
        return (char*)ptr + sizeof(mmap_header);
    }

    //Let's do tcache (!)
    if (aligned_size <= TCACHE_CHUNK_MAX_SIZE) {
        const size_t idx = (aligned_size - 0x20) / 0x10;
        printf("idx requested: %lu", idx);

        //there is valid bin for this
        if (tcache.bin_counts[idx] > 0) {
            void* ptr = tcache.entries[idx] + 0x10;
            void* next_ptr = tcache.entries[idx]->next;

            ((size_t*)ptr)[0] = 0; //Zero out next !!! WRONG!!!! WE PUT THE KEY/FD IN THE MIDDLE!!!!
            ((size_t*)ptr)[1] = 0; //Zero out key !!! WRONG!!!! WE PUT THE KEY/FD IN THE MIDDLE!!!!

            tcache.entries[idx] = next_ptr;
            tcache.bin_counts[idx]--;

            //Set previnuse of next chunk!
            if (next_ptr != NULL) {
                ((int*)next_ptr)[1] &= CHUNK_PREVINUSE; //todo lol
                //TODO: Tcache bro. if it's empty- carve out the chunks from SBRK!!! that's the easiest way. 
            }

            //TODO: Set previnuse of next chunk if present.
        }

        //continue and fall onto unsorted/fastbin/large/small/gay
    }

    return NULL;
}

void secure_free(void *ptr) {
    if (ptr == NULL) return;

    size_t size = ((size_t*)ptr - 1)[0];
    printf("received size: %lx\n", size);

    if (IS_MMAPED(size)) {
        size &= ~FLAG_MASK;

        if ((secret ^ size) != ((size_t*)ptr - 2)[0]) {
            printf("\nINCORRECT COOKIE! Refusing free\n");
            return;
        }

        const int result = munmap(ptr - 0x10, size);
        printf("(%d) Unmapped %p \n", result, ptr);
    }
}



//first allocation:
//  mmap a huge ass page. Next allocations: carve from there.
//  FIRST IMPLEMENT Tcache, fastbin, unsorted, smallbin, largebin. ONLY THEN
//  actual mitigations & checks and stuff.
