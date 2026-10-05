//
// Created by Wihy on 9/20/26.
//
#include "secure_malloc.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../utils/utils.h"
#include "mmap_helper.h"
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE       (4096)

#define IS_PREVINUSE(sz) ((sz) & CHUNK_PREVINUSE)

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

// So we don't accidentally WRITE on unallocated memory();
static void* max_heap_address;
static size_t last_physical_chunk_size;
static int last_chunk_free;

//Tcache chunk formatting:   PREV SIZE, SIZE  ....... NEXT FD .....
typedef struct {
    uint16_t bin_counts[TCACHE_BINS];
    void *entries[TCACHE_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct tcache;
static size_t secret = 0;

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

static void* sorted_allocate(size_t total_size);
static void sorted_unlink(sorted_entry* chunk);
static void sorted_insert(sorted_entry* new_chunk);

static void write_flag_preserve(size_t* ptr, const size_t total_size) {
    *ptr = *ptr & FLAG_MASK | total_size;
}

void *secure_malloc(const size_t size) {
    if (secret == 0)
        secret = random();

    const size_t total_size = max(ALIGN16(size) + 0x10, MIN_CHUNK_SIZE);
    const size_t page_aligned_size = (total_size + sizeof(mmap_header) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    if (page_aligned_size > MMAP_THRESHOLD)
        return mmap_allocate(page_aligned_size, secret);

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

    ((uint64_t *) chunk)[0] = last_physical_chunk_size;                                  // prev chunk size
    ((uint64_t *) chunk)[1] = total_size | (last_chunk_free == 1 ? 0 : CHUNK_PREVINUSE); // SIZE IS ALWAYS CHUNK SIZE! NOT PTR SIZE!

    last_physical_chunk_size = total_size;
    max_heap_address         = chunk + total_size;

    return CHUNK_TO_PTR(chunk);
}


void secure_free(void *ptr) {
    if (ptr == NULL) return;

    const size_t raw_size = ((size_t *) ptr - 1)[0];
    const size_t total_size = raw_size & ~FLAG_MASK;

    if (total_size < MIN_CHUNK_SIZE || ALIGN16(total_size) != total_size) {
        puts("Corrupt chunk detected");
        return;
    }

    if (IS_MMAPED(raw_size)) {
        mmap_free(ptr, total_size, secret);
        return;
    }

    const size_t idx = CHUNK_SIZE_TO_IDX(total_size);

    //free to tcache
    if (idx < TCACHE_BINS && tcache.bin_counts[idx] < MAX_CHUNKS_PER_BIN) {
        size_t *next_tcache_entry = tcache.entries[idx];

        //link new chunk to tcache.
        tcache.entries[idx] = PTR_TO_CHUNK(ptr);
        tcache.bin_counts[idx]++;

        set_next_tcache(idx, (size_t) next_tcache_entry);

        //Prevent coalescing: Even free tcache chunks should be USED.
        return;
    }

    //Free to sorted
    sorted_insert(PTR_TO_CHUNK(ptr));
}


void *get_next_tcache(const size_t idx) {
    void *chunk_header = tcache.entries[idx];
    const size_t *ptr_to_middle = (size_t *) ((char *) chunk_header + CHUNK_MIDDLE(idx)); //that's PTR to chunk mdidle. Now get value.
    return (size_t *) *ptr_to_middle; //ret value at ptr as ptr.
}

void set_next_tcache(const size_t idx, const size_t value) {
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

// returns null if none
// get the best fit.
static void* sorted_allocate(const size_t total_size) {
    //TODO: Split off the chunk instead of just returning..
    //TODO: If all chunks are too small, run coalescing, then run this AGAIN!

    sorted_entry* best_chunk = NULL;

    //Get a chunk that isn't null. The for loop STOPS when iterator < size... so best_chunk was set to the last one where it DOES matter.
    for (sorted_entry *iterator = sorted_head; iterator != NULL && CHUNK_SIZE(iterator) >= total_size; iterator = get_next_sorted(iterator)) {
        best_chunk = iterator;
    }

    if (best_chunk == NULL)
        return NULL;

    const size_t best_chunk_og_size = CHUNK_SIZE(best_chunk);
    sorted_unlink(best_chunk); //Remove our chunk from the sorted list

    //Split if the chunk is too big:
    if (best_chunk_og_size >= total_size + MIN_CHUNK_SIZE) {
        // So split, unlink, insert.

        //best_prev -> best_next
        //Split:
        // Write new size to best_chunk
        // Write new chunk somewhere.

        //set size of best_chunk to less!
        write_flag_preserve(&best_chunk->size, total_size);

        //write a new fake chunk... NO NEED to LINK it... just set size. prev_size = best_chunk_size | CHUNK_PREVINUSE!
        sorted_entry* new_split_chunk = (sorted_entry*)((char *) best_chunk + CHUNK_SIZE(best_chunk));

        new_split_chunk->prev_size = CHUNK_SIZE(best_chunk); //Its just best chunk, which is TAKEN cuz we JUST allocated it.
        new_split_chunk->size      = (best_chunk_og_size - total_size) | CHUNK_PREVINUSE;

        sorted_insert(new_split_chunk);

        //In case we SPLIT the LAST CHUNK, update last_chunk_size!
        if ((char*)max_heap_address == (char*)new_split_chunk + CHUNK_SIZE(new_split_chunk)) {
            last_physical_chunk_size = CHUNK_SIZE(new_split_chunk);
            last_chunk_free = 1;
        }
    } else {
        //We didn't split. So the prev of next is NOT INUSE.
        sorted_entry* physical_next_chunk = (sorted_entry*)((char *) best_chunk + CHUNK_SIZE(best_chunk));

        //set next chunk PREVINUSE only if WE DIDNT ALLOCATE THE LAST CHUNK so we dont write on unallocated mem.
        if ((void*)physical_next_chunk < max_heap_address) {
            ((size_t *) ((char *) best_chunk + CHUNK_SIZE(best_chunk)))[1] |= CHUNK_PREVINUSE;
            last_chunk_free = 0;
        }
    }

    return CHUNK_TO_PTR(best_chunk);
}

// remove a chunk from the unsorted list. Execute BEFORE changing size.. cuz it depedns on it.
void sorted_unlink(sorted_entry *chunk) {
    sorted_entry* prev = get_prev_sorted(chunk);
    sorted_entry* next = get_next_sorted(chunk);

    if (prev != NULL) set_next_sorted(prev, (size_t)next);
    else sorted_head = next;

    if (next != NULL)  set_prev_sorted(next, (size_t)prev);

    //now clear the hcunk.
    set_prev_sorted(chunk, 0);
    set_next_sorted(chunk, 0);
}

void sorted_insert(sorted_entry *new_chunk) {
    //find best location....
    //3 cases.            A > target > B
    //                    A > target > null
    //                    target > A > B
    const size_t new_size = CHUNK_SIZE(new_chunk);

    //set next prevsize, previnuse, etc.
    sorted_entry* next_physical = (sorted_entry*)((char*)new_chunk + new_size);

    if ((void*)next_physical < max_heap_address) { //only write on allocated memory
        next_physical->prev_size = new_size;
        next_physical->size &= ~CHUNK_PREVINUSE; //Cuz it isn't in use anymore.
    }

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
