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

#define IDX_TO_CHUNK_SIZE(idx) (((idx) * 0x10) + MIN_CHUNK_SIZE)
#define CHUNK_SIZE_TO_IDX(sz) (((sz) - MIN_CHUNK_SIZE) / 0x10)

#define CHUNK_MIDDLE(idx) (((IDX_TO_CHUNK_SIZE(idx) / 2) & ~0xf))
#define CHUNK_TO_PTR(x) ((x) + 0x10)
#define PTR_TO_CHUNK(x) ((x) - 0x10)

typedef struct mmap_header {
    size_t cookie;
    size_t size;
} mmap_header;

typedef struct tcache_entry tcache_entry;

//TCACHE FORAMTTING:
//-------- PREV SIZE, SIZE  ....... NEXT FD  KEY .....
typedef struct {
    //bins store ACTUAL SIZE. meaning HEADER + bin.
    uint16_t bin_counts[TCACHE_BINS];
    void *entries[TCACHE_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct tcache;
static __thread size_t secret = 0;

#define ALIGN16(x) (((x) + 0xF) & ~((size_t)0xF))

//Different IDXs map to different chunk locations for better security.
void *get_next_tcache(size_t idx);

void set_next_tcache(size_t idx, size_t value);

void *secure_malloc(const size_t size) {
    if (secret == 0)
        secret = random();

    const size_t total_size = max(ALIGN16(size) + 0x10, MIN_CHUNK_SIZE);
    const size_t page_aligned_size = (total_size + sizeof(mmap_header) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    if (page_aligned_size > MMAP_THRESHOLD) {
        mmap_header *chunk = mmap(NULL, page_aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        chunk->size = page_aligned_size | CHUNK_MMAPED;
        chunk->cookie = secret ^ page_aligned_size;
        return (char *) chunk + sizeof(mmap_header);
    }

    //Let's do tcache (!)
    if (total_size <= TCACHE_CHUNK_MAX_SIZE) {
        const size_t idx = CHUNK_SIZE_TO_IDX(total_size);

        //there is valid bin for this
        if (tcache.bin_counts[idx] > 0) {
            void *ptr = CHUNK_TO_PTR(tcache.entries[idx]);
            void *next_ptr = get_next_tcache(idx);

            set_next_tcache(idx, (size_t) NULL); //Zero out next

            tcache.entries[idx] = next_ptr;
            tcache.bin_counts[idx]--;

            //Set previnuse of next physical chunk!
            ((uint64_t *) ((char*)PTR_TO_CHUNK(ptr) + IDX_TO_CHUNK_SIZE(idx)))[1] |= CHUNK_PREVINUSE;

            return ptr;
        }

        //there is no valid tcache chunk. Carve from sbrk.
        void *chunk = sbrk((long)total_size);

        ((uint64_t *) chunk)[0] = 0;
        ((uint64_t *) chunk)[1] = total_size | CHUNK_PREVINUSE; // SIZE IS ALWAYS CHUNK SIZE! NOT PTR SIZE!

        return CHUNK_TO_PTR(chunk);
    }

    //continue and fall onto unsorted/fastbin/large/small/gay
    return NULL;
}

void secure_free(void *ptr) {
    if (ptr == NULL) return;

    size_t raw_size = ((size_t *) ptr - 1)[0];
    printf("received size: %lx\n", raw_size);

    if (IS_MMAPED(raw_size)) {
        const size_t size = raw_size & ~FLAG_MASK;
        const size_t cookie = ((size_t *) ptr - 2)[0];

        if ((secret ^ size) != cookie) {
            printf("\nINCORRECT COOKIE! Refusing free\n");
            return;
        }

        const int result = munmap(ptr - sizeof(mmap_header), size);
        printf("(%d) Unmapped %p \n", result, ptr);
        return;
    }

    const size_t total_size = raw_size & ~FLAG_MASK;
    const size_t idx = CHUNK_SIZE_TO_IDX(total_size);

    if (idx < TCACHE_BINS && tcache.bin_counts[idx] < MAX_CHUNKS_PER_BIN) {
        size_t *next_tcache_entry = tcache.entries[idx];
        tcache.entries[idx] = PTR_TO_CHUNK(ptr);
        tcache.bin_counts[idx]++;
        set_next_tcache(idx, (size_t) next_tcache_entry);

        size_t *next_physical_chunk = (size_t *) ((char *) PTR_TO_CHUNK(ptr) + total_size);
        next_physical_chunk[0] = total_size; //set prev size of next chunk.
        next_physical_chunk[1] &= ~CHUNK_PREVINUSE; //prev chunk is NOT in use.
        return;
    }
}



//TODO: In order:
// tcache
// fastbin
// unsroted
// large & small mechanism
// safe linking add.
// zeroing memory on free...
// benchmarking if have time!!!! finish it all tmrw gl


//first allocation:
//  mmap a huge ass page. Next allocations: carve from there.
//  FIRST IMPLEMENT Tcache, fastbin, unsorted, smallbin, largebin. ONLY THEN
//  actual mitigations & checks and stuff.


void *get_next_tcache(const size_t idx) {
    void *chunk_header = tcache.entries[idx];
    const size_t *ptr_to_middle = (size_t *) ((char *) chunk_header + CHUNK_MIDDLE(idx));
    //that's PTR to chunk mdidle. Now get value.

    return (size_t *) *ptr_to_middle; //ret value at ptr as ptr.
}

void set_next_tcache(const size_t idx, size_t value) {
    void *chunk_header = tcache.entries[idx];
    size_t *ptr_to_middle = (size_t *) ((char *) chunk_header + CHUNK_MIDDLE(idx));
    *ptr_to_middle = value;
}
