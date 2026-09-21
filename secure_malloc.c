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
#define MIN_CHUNK_SIZE 0x20
#define TCACHE_CHUNK_MAX_SIZE ((TCACHE_BINS-1) * 0x10 + MIN_CHUNK_SIZE)

#define CHUNK_TO_PTR(x) ((x) + 0x10)
#define PTR_TO_CHUNK(x) ((x) - 0x10)

typedef struct mmap_header {
    size_t cookie;
    size_t size;
} mmap_header;

typedef struct tcache_entry tcache_entry;

//TCACHE FORAMTTING:
//-------- PREV SIZE, SIZE  ....... NEXT FD  KEY .....
struct tcache_entry {
    tcache_entry* next; //stores PTR TO HEADER!!
};

typedef struct { //bins store ACTUAL SIZE. meaning HEADER + bin.
    uint16_t bin_counts[TCACHE_BINS];
    tcache_entry* entries[TCACHE_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct tcache;
static __thread size_t secret = 0;

#define ALIGN16(x) (((x) + 0xF) & ~((size_t)0xF))

void *secure_malloc(const size_t size) {
    if (secret == 0)
        secret = random();

    const size_t aligned_size = max(ALIGN16(size), MIN_CHUNK_SIZE); //Round to next 0x10. min of 0x20.

    if (aligned_size > MMAP_THRESHOLD) {
        const size_t page_aligned_size = (aligned_size + sizeof(mmap_header) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        mmap_header *hdr = mmap(NULL, page_aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        hdr->size = page_aligned_size | CHUNK_MMAPED;
        hdr->cookie = secret ^ page_aligned_size;
        return (char*)hdr + sizeof(mmap_header);
    }

    //Let's do tcache (!)
    if (aligned_size <= TCACHE_CHUNK_MAX_SIZE) {
        const size_t idx = (aligned_size - MIN_CHUNK_SIZE) / 0x10;
        printf("idx requested: %lu\n", idx);

        //there is valid bin for this
        if (tcache.bin_counts[idx] > 0) {
            void* ptr = CHUNK_TO_PTR(tcache.entries[idx]);
            void* next_ptr = tcache.entries[idx]->next;

            ((size_t*)ptr)[idx/2] = 0; //Zero out next
            ((size_t*)ptr)[idx/2+1] = 0; //Zero out key

            tcache.entries[idx] = next_ptr;
            tcache.bin_counts[idx]--;

            //Set previnuse of next chunk!
            if (next_ptr != NULL) {
                ((uint64_t*)next_ptr)[1] |= CHUNK_PREVINUSE;
            }

            return ptr;
        }

        //there is no valid tcache chunk. Carve from sbrk.
        void* chunk = sbrk(aligned_size + 0x10);

        ((uint64_t*)chunk)[0] = 0;
        ((uint64_t*)chunk)[1] = aligned_size | CHUNK_PREVINUSE;

        return CHUNK_TO_PTR(chunk);
    }

    //continue and fall onto unsorted/fastbin/large/small/gay
    return NULL;
}

void secure_free(void *ptr) {
    if (ptr == NULL) return;

    size_t raw_size = ((size_t*)ptr - 1)[0];
    printf("received size: %lx\n", raw_size);

    if (IS_MMAPED(raw_size)) {
        size_t size = raw_size & ~FLAG_MASK;
        size_t cookie = ((size_t*)ptr - 2)[0];

        if ((secret ^ size) != cookie) {
            printf("\nINCORRECT COOKIE! Refusing free\n");
            return;
        }

        const int result = munmap(ptr - sizeof(mmap_header), size);
        printf("(%d) Unmapped %p \n", result, ptr);
        return;
    }

    size_t size = raw_size & ~FLAG_MASK;
    size_t idx = (size - MIN_CHUNK_SIZE) / 0x10;

    if (tcache.bin_counts[idx] < MAX_CHUNKS_PER_BIN) {
        void* next = tcache.entries[idx];
        tcache.entries[idx] = PTR_TO_CHUNK(ptr);
        tcache.entries[idx]->next = next;
        tcache.bin_counts[idx]++;
        return;
    }
}

//TODO: Every reference of next is to be repalced with middle of chunk access.
// no point of a chunk.

//first allocation:
//  mmap a huge ass page. Next allocations: carve from there.
//  FIRST IMPLEMENT Tcache, fastbin, unsorted, smallbin, largebin. ONLY THEN
//  actual mitigations & checks and stuff.
