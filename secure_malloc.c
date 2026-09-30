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

//largebin stuff
#define LARGEBIN_BINS 64

//TCACHE STUFF
#define TCACHE_BINS 64
#define MAX_CHUNKS_PER_BIN 10
#define MIN_CHUNK_SIZE 0x20
#define TCACHE_CHUNK_MAX_SIZE ((TCACHE_BINS-1) * 0x10 + MIN_CHUNK_SIZE)

#define IDX_TO_CHUNK_SIZE(idx) (((idx) * 0x10) + MIN_CHUNK_SIZE)
#define CHUNK_SIZE_TO_IDX(sz) (((sz) - MIN_CHUNK_SIZE) / 0x10)

#define CHUNK_MIDDLE(idx) (((IDX_TO_CHUNK_SIZE(idx) / 2) & ~0xf))
#define CHUNK_TO_PTR(x) (((void*)(x)) + 0x10)
#define PTR_TO_CHUNK(x) (((void*)(x)) - 0x10)
#define CHUNK_SIZE(x) ((x)->size & ~FLAG_MASK)

typedef struct mmap_header {
    size_t cookie;
    size_t size;
} mmap_header;

//TCACHE FORAMTTING:
//-------- PREV SIZE, SIZE  ....... NEXT FD .....
typedef struct {
    uint16_t bin_counts[TCACHE_BINS];
    void *entries[TCACHE_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct tcache;
static __thread size_t secret = 0;

#define ALIGN16(x) (((x) + 0xF) & ~((size_t)0xF))

//Different IDXs map to different chunk locations for better security.
void *get_next_tcache(size_t idx);
void set_next_tcache(size_t idx, size_t value);

typedef struct {
    size_t prev_size;
    size_t size;
    //prev is at size/2
    //next is at size/2+1
} sorted_entry;

static sorted_entry* sorted_head; //holds a linked list.

static sorted_entry* get_prev_sorted(sorted_entry* entry);
static sorted_entry* get_next_sorted(sorted_entry* entry);
static void set_prev_sorted(sorted_entry* entry, size_t value);
static void set_next_sorted(sorted_entry* entry, size_t value);

static size_t* sorted_allocate(size_t size);
static void sorted_insert(sorted_entry* new_chunk);

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
        //there is no valid tcache chunk. Continue search.
    }

    //Sorted check!
    if (sorted_head != NULL) {
        void* ptr = sorted_allocate(total_size);

        if (ptr != NULL)
            return ptr;
    }

    //continue and fall onto fastbin/large/small/gay

    //no largebins at all... just sbrk.
    void *chunk = sbrk((long)total_size);

    ((uint64_t *) chunk)[0] = 0;
    ((uint64_t *) chunk)[1] = total_size | CHUNK_PREVINUSE; // SIZE IS ALWAYS CHUNK SIZE! NOT PTR SIZE!
    return CHUNK_TO_PTR(chunk);}

void secure_free(void *ptr) {
    if (ptr == NULL) return;

    const size_t raw_size = ((size_t *) ptr - 1)[0];

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

    //Free to sorted
    sorted_insert(PTR_TO_CHUNK(ptr));
}

//TODO: In order:
// tcache V
// COALESCING!!!!
// fastbin
// unsroted
// large & small mechanism
// safe linking add.
// zeroing memory on free...
// benchmarking if have time!!!! finish it all tmrw gl

//first allocation:
//  mmap a huge ass page. Next allocations: carve from there.
//  FIRST IMPLEMENT Tcache (V), fastbin, sorted, smallbin, largebin. ONLY THEN
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

static sorted_entry * get_prev_sorted(sorted_entry *entry) {
    return (sorted_entry*) *(size_t*)((char*)entry + (entry->size/2 & ~0xF));
}

static sorted_entry * get_next_sorted(sorted_entry *entry) {
    return (sorted_entry*)*((size_t*)((char*)entry + (entry->size/2 & ~0xF)) + 1);
}

static void set_prev_sorted(sorted_entry *entry, size_t value) {
    *(size_t*)((char*)entry + (entry->size/2 & ~0xF)) = value;
}
static void set_next_sorted(sorted_entry *entry, size_t value) {
    *((size_t*)((char*)entry + (entry->size/2 & ~0xF)) + 1) = value;
}

//returns null if none
// get the best fit.
static size_t* sorted_allocate(const size_t size) {
    //TODO: Split off the chunk instead of just returning..
    //TODO: If all chunks are too small, run coalescing, then run this AGAIN!

    sorted_entry* best_chunk = NULL;

    //Get a chunk that isn't null. The for loop STOPS when iterator < size... so best_chunk was set to the last one where it DOES matter.
    for (sorted_entry *iterator = sorted_head; iterator != NULL && CHUNK_SIZE(iterator) >= size; iterator = get_next_sorted(iterator)) {
        best_chunk = iterator;
    }

    if (best_chunk == NULL)
        return NULL;

    sorted_entry *prev_chunk = get_prev_sorted(best_chunk);
    sorted_entry *next_chunk = get_next_sorted(best_chunk);

    if (prev_chunk != NULL)
        set_next_sorted(prev_chunk, (size_t) next_chunk);
    else
        sorted_head = next_chunk;

    if (next_chunk != NULL)
        set_prev_sorted(next_chunk, (size_t) prev_chunk);

    //reset ptrs... so no leaks!
    set_prev_sorted(best_chunk, 0);
    set_next_sorted(best_chunk, 0);

    //set next chunk in use to true
    ((size_t *) ((char *) best_chunk + CHUNK_SIZE(best_chunk)))[1] |= CHUNK_PREVINUSE;

    return CHUNK_TO_PTR(best_chunk);
}

void sorted_insert(sorted_entry *new_chunk) {
    //find best location....
    //3 cases.            A > target > B
    //                    A > target > null
    //                    target > A > B

    const size_t new_size = CHUNK_SIZE(new_chunk);
    set_prev_sorted(new_chunk, 0);
    set_next_sorted(new_chunk, 0);

    if (sorted_head == NULL || CHUNK_SIZE(sorted_head) < new_size) { // No list, or biggest. This becomes head.
        if (sorted_head != NULL)
            set_prev_sorted(sorted_head, (size_t) new_chunk);

        set_next_sorted(new_chunk, (size_t) sorted_head);
        sorted_head = new_chunk;
        return;
    }

    //Walk the list. Place such that A > taget > B
    sorted_entry* prev_ptr = sorted_head;
    sorted_entry* curr_ptr = get_next_sorted(prev_ptr);

    while (curr_ptr != NULL && CHUNK_SIZE(curr_ptr) >= new_size) {
        prev_ptr = curr_ptr;
        curr_ptr = get_next_sorted(curr_ptr);
    }

    //link prev to new
    set_next_sorted(prev_ptr, (size_t)new_chunk);
    set_prev_sorted(new_chunk, (size_t)prev_ptr);

    //link new to curr
    if (curr_ptr != NULL) {
        set_next_sorted(new_chunk, (size_t)curr_ptr);
        set_prev_sorted(curr_ptr, (size_t)new_chunk);
    }
}
