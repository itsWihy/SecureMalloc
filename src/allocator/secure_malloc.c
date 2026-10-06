/*Important invariants:
 * Sorted list is sorted in descending order
 *
 * Sorted chunk layout:
 * prev size
 * size | flags
 * COOKIE <--- GLOBAL SECRET ^ CHUNK ADDRESS
 * ......
 * Middle of chunk: prev ptr
 *                  next ptr
 * .....
 *
 *
 * Tcache:
 * - PREV SIZE
 * - SIZE | PREVINUSE always ON in tcache. Never coalesce tcache!
 * - COOKIE <-- SECRET ^ GLOBAL SECRET ^ CHUNK ADDRESS
 * - ....
 * - NEXT
 * - ....
 */

//TODO: Safe linking... write your cookies on some PTRs.

#include "secure_malloc.h"

#include <pthread.h>
#include <stdint.h>
#include <sys/random.h>

#include "../utils/utils.h"
#include "mmap_helper.h"
#include <unistd.h>

#define PAGE_SIZE       (4096)

//TCACHE STUFF
#define TCACHE_BINS 64
#define MAX_CHUNKS_PER_BIN 10
#define MIN_CHUNK_SIZE 0x30
#define TCACHE_CHUNK_MAX_SIZE ((TCACHE_BINS-1) * 0x10 + MIN_CHUNK_SIZE)

#define IDX_TO_CHUNK_SIZE(idx) (((idx) * 0x10) + MIN_CHUNK_SIZE)
#define CHUNK_SIZE_TO_IDX(sz) (((sz) - MIN_CHUNK_SIZE) / 0x10)

#define ENTRY_CHUNK_MIDDLE(entry) (((CHUNK_SIZE(entry)/2 & ~0xF) + 0x10))
#define TCACHE_CHUNK_MIDDLE(idx) (((IDX_TO_CHUNK_SIZE(idx) / 2) & ~0xf) + 0x10)

#define CHUNK_TO_PTR(x) (((void*)(x)) + CHUNK_HEADER_SIZE)
#define PTR_TO_CHUNK(x) (((void*)(x)) - CHUNK_HEADER_SIZE)
#define CHUNK_SIZE(x) ((x)->size & ~FLAG_MASK)

// So we don't accidentally WRITE on unallocated memory();
static void* heap_start_address;
static void* heap_end_address;
static size_t last_chunk_size;
static int last_chunk_is_free;

//Tcache chunk formatting:   PREV SIZE, SIZE  ....... NEXT FD .....
typedef struct {
    uint16_t bin_counts[TCACHE_BINS];
    void *entries[TCACHE_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct tcache;
static size_t secret = 0;

#define ALIGN16(x) (((x) + 0xF) & ~((size_t)0xF))

//Different IDXs map to different chunk locations for better security.
static void *get_next_tcache(size_t idx);
static void set_next_tcache(size_t idx, size_t value);
static void handle_cookie_tcache(chunk_entry* tcache_chunk);

static chunk_entry* sorted_head; //holds a linked list.

static int is_last_chunk(chunk_entry *chunk);

static chunk_entry* get_prev_sorted(chunk_entry* entry);
static chunk_entry* get_next_sorted(chunk_entry* entry);
static void set_prev_sorted(chunk_entry* entry, size_t value);
static void set_next_sorted(chunk_entry* entry, size_t value);

static void* sorted_allocate(size_t total_size);
static void sorted_unlink(chunk_entry* chunk);
static void sorted_insert(chunk_entry* new_chunk);
static void sorted_coalesce(chunk_entry* chunk);

static void set_chunk_size(chunk_entry *chunk, size_t total_size);

static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_mutex_t heap_lock = PTHREAD_MUTEX_INITIALIZER;

static void initialization() {
    heap_start_address = sbrk(0);
    getrandom(&secret, sizeof(secret), 0);
}

void *locked_malloc(size_t total_size, size_t page_aligned_size);

void *secure_malloc(const size_t size) {
    if (size > SIZE_MAX / 2)
        die("Secure alloc requested size is too big");

    pthread_once(&once, initialization);

    const size_t total_size = max(ALIGN16(size) + CHUNK_HEADER_SIZE, MIN_CHUNK_SIZE);
    const size_t page_aligned_size = (total_size + sizeof(mmap_header) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    //Let's do tcache (!)
    if (total_size <= TCACHE_CHUNK_MAX_SIZE) {
        const size_t idx = CHUNK_SIZE_TO_IDX(total_size);

        // tcache was hit.
        if (tcache.bin_counts[idx] > 0) {
            //Before allocating: let's verify that heap cookie is intact...
            handle_cookie_tcache(tcache.entries[idx]);

            void *ptr = CHUNK_TO_PTR(tcache.entries[idx]);
            void *next_ptr = get_next_tcache(idx);

            set_next_tcache(idx, (size_t) NULL); //Zero out next

            tcache.entries[idx] = next_ptr;
            tcache.bin_counts[idx]--;
            return ptr;
        }
        //there is no valid tcache chunk. Continue search.
    }

    //No two threads can malloc at the same time.
    pthread_mutex_lock(&heap_lock);
    void* ptr = locked_malloc(total_size, page_aligned_size);
    pthread_mutex_unlock(&heap_lock);

    return ptr;
}

void secure_free(void *ptr) {
    if (ptr == NULL) return;
    if ((size_t)ptr & 0xF) die("Pointer not aligned");

    const size_t raw_size = ((size_t *) ptr - 1)[0];
    const size_t total_size = raw_size & ~FLAG_MASK;
    const size_t tcache_bin_index = CHUNK_SIZE_TO_IDX(total_size);

    chunk_entry* chunk = PTR_TO_CHUNK(ptr);
    chunk_entry* next_physical = (chunk_entry*)((char*)chunk+total_size);

    if (total_size < MIN_CHUNK_SIZE || ALIGN16(total_size) != total_size)
        die("Corrupt chunk detected");

    if (IS_MMAPED(raw_size)) {
        pthread_mutex_lock(&heap_lock);
        mmap_free(ptr, total_size, secret);
        pthread_mutex_unlock(&heap_lock);
        return;
    }

    pthread_mutex_lock(&heap_lock); //Avoid race reading of heap_start, etc.
    if ((void*)chunk < heap_start_address || (char*)chunk + total_size > (char*)heap_end_address)
        die("Chunk out of bounds !");

    //Check for double free...
    if (((void*)next_physical < heap_end_address && !IS_PREVINUSE(next_physical->size)) || (is_last_chunk(chunk) && last_chunk_is_free == 1))
        die("Double free detected");
    pthread_mutex_unlock(&heap_lock);

    //free to tcache
    if (tcache_bin_index < TCACHE_BINS && tcache.bin_counts[tcache_bin_index] < MAX_CHUNKS_PER_BIN) {
        // If cookie is already present, THIS CHUNK IS FREE! DOUBLE FREE OCCURED!
        const size_t cookie = secret ^ (size_t)chunk;
        if (chunk->cookie == cookie)
            die("Double free on tcache detected..");

        void *present_tcache_chunk = tcache.entries[tcache_bin_index];

        //link new chunk to tcache.
        tcache.entries[tcache_bin_index] = chunk;
        tcache.bin_counts[tcache_bin_index]++;

        set_next_tcache(tcache_bin_index, (size_t) present_tcache_chunk);
        chunk->cookie = cookie;
        return;
    }

    pthread_mutex_lock(&heap_lock);
    //Free to sorted && Try coalescing
    sorted_insert(chunk);
    sorted_coalesce(chunk);

    pthread_mutex_unlock(&heap_lock);
}

void *get_next_tcache(const size_t idx) {
    void *chunk_header = tcache.entries[idx];
    const size_t *ptr_to_middle = (size_t *) ((char *) chunk_header + TCACHE_CHUNK_MIDDLE(idx)); //that's PTR to chunk mdidle. Now get value.
    return (size_t *) *ptr_to_middle; //ret value at ptr as ptr.
}

void set_next_tcache(const size_t idx, const size_t value) {
    void *chunk_header = tcache.entries[idx];
    size_t *ptr_to_middle = (size_t *) ((char *) chunk_header + TCACHE_CHUNK_MIDDLE(idx));
    *ptr_to_middle = value;
}

void handle_cookie_tcache(chunk_entry *tcache_chunk) {
    if (tcache_chunk->cookie != (secret ^ (size_t)tcache_chunk))
        die("Wrong tcache cookie.. possible overwrite?");
    tcache_chunk->cookie = 0;
}

void sorted_coalesce(chunk_entry *chunk) {
    chunk_entry* next = (chunk_entry*)((char*)chunk + CHUNK_SIZE(chunk));
    chunk_entry* next_next = NULL;

    if ((void*)next < heap_end_address)
        next_next = (chunk_entry*)((char*)next + CHUNK_SIZE(next));

    //PREV IN USE && NEXT IS LAST CHUNK && LAST IS FREE
    //   coalesce chunk & next
    //   if next_next is set:
    //      set prev size of next next
    if (!is_last_chunk(chunk) &&
        ((is_last_chunk(next) && last_chunk_is_free == 1) ||
        (!is_last_chunk(next) && next_next != NULL && !IS_PREVINUSE(next_next->size)))) {

        sorted_unlink(next);
        sorted_unlink(chunk);
        set_chunk_size(chunk, CHUNK_SIZE(chunk) + CHUNK_SIZE(next));

        if (!is_last_chunk(next) && next_next != NULL)
            next_next->prev_size = CHUNK_SIZE(chunk);

        sorted_insert(chunk);
    }

    if (IS_PREVINUSE(chunk->size)) return; //THis also handles CHUNK being FIRST.

    chunk_entry* prev = (chunk_entry*)((char*)chunk - chunk->prev_size);
    if (CHUNK_SIZE(prev) != chunk->prev_size)
        die("Bad prev size");

    sorted_unlink(prev);
    sorted_unlink(chunk);

    set_chunk_size(prev, CHUNK_SIZE(prev) + CHUNK_SIZE(chunk));

    //Handles correcting prevsize for us
    sorted_insert(prev);
}

void set_chunk_size(chunk_entry *chunk, const size_t total_size)  {
    chunk->size = chunk->size & FLAG_MASK | total_size;
}
static chunk_entry * get_prev_sorted(chunk_entry *entry) {
    return (chunk_entry*) *(size_t*)((char*)entry + ENTRY_CHUNK_MIDDLE(entry));
}
static chunk_entry * get_next_sorted(chunk_entry *entry) {
    return (chunk_entry*)*((size_t*)((char*)entry + ENTRY_CHUNK_MIDDLE(entry)) + 1);
}
static void set_prev_sorted(chunk_entry *entry, const size_t value) {
    *(size_t*)((char*)entry + ENTRY_CHUNK_MIDDLE(entry)) = value;
}
static void set_next_sorted(chunk_entry *entry, const size_t value) {
    *((size_t*)((char*)entry + ENTRY_CHUNK_MIDDLE(entry)) + 1) = value;
}

static int is_last_chunk(chunk_entry *chunk) {
    return (char *) heap_end_address == (char *) chunk + CHUNK_SIZE(chunk);
}

// returns null if none
// get the best fit.
static void* sorted_allocate(const size_t total_size) {
    chunk_entry* best_chunk = NULL;

    //Get a chunk that isn't null. The for loop STOPS when iterator < size... so best_chunk was set to the last one where it DOES matter.
    for (chunk_entry *curr = sorted_head; curr != NULL && CHUNK_SIZE(curr) >= total_size; curr = get_next_sorted(curr)) {
        best_chunk = curr;
    }

    if (best_chunk == NULL)
        return NULL;

    //validate best_chunk cookie & delete it.
    if (best_chunk->cookie != (secret ^ (size_t)best_chunk))
        die("Wrong cookie!! Possible overwrite.");
    best_chunk->cookie = 0;

    const size_t best_chunk_og_size = CHUNK_SIZE(best_chunk);
    sorted_unlink(best_chunk); //Remove our chunk from the sorted list

    //Split if the chunk is too big:
    if (best_chunk_og_size >= total_size + MIN_CHUNK_SIZE) {
        //set size of best_chunk to less!
        set_chunk_size(best_chunk, total_size);

        //write a new fake chunk... NO NEED to LINK it... just set size. prev_size = best_chunk_size | CHUNK_PREVINUSE!
        chunk_entry* new_split_chunk = (chunk_entry*)((char *) best_chunk + CHUNK_SIZE(best_chunk));

        new_split_chunk->prev_size = CHUNK_SIZE(best_chunk); //Its just best chunk, which is TAKEN cuz we JUST allocated it.
        new_split_chunk->size      = best_chunk_og_size - total_size;

        SET_PREVINUSE(new_split_chunk);

        sorted_insert(new_split_chunk);

        //In case we SPLIT the LAST CHUNK, update last_chunk_size!
        if (is_last_chunk(new_split_chunk)) {
            last_chunk_size = CHUNK_SIZE(new_split_chunk);
            last_chunk_is_free = 1;
        }
    } else {
        //We didn't split. So the prev of next is NOT INUSE.
        chunk_entry* physical_next_chunk = (chunk_entry*)((char *) best_chunk + CHUNK_SIZE(best_chunk));

        //set next chunk PREVINUSE only if WE DIDNT ALLOCATE THE LAST CHUNK so we dont write on unallocated mem.
        if ((void*)physical_next_chunk < heap_end_address) {
           physical_next_chunk->size |= CHUNK_PREVINUSE;
        } else { //we allocated the LAST chunk.. so it isn't free.
            last_chunk_is_free = 0;
        }
    }

    return CHUNK_TO_PTR(best_chunk);
}

// remove a chunk from the unsorted list. Execute BEFORE changing size.. cuz it depedns on it.
void sorted_unlink(chunk_entry *chunk) {
    chunk_entry* prev = get_prev_sorted(chunk);
    chunk_entry* next = get_next_sorted(chunk);

    //Check that prev's next == chunk && next's prev == chunk. Also verify their cookies at that.
    if ((prev != NULL && get_next_sorted(prev) != chunk) || (next != NULL && get_prev_sorted(next) != chunk))
        die("Corrupt sorted list!");
    if ((prev != NULL && prev->cookie != (secret ^ (size_t)prev)) || (next != NULL && next->cookie != (secret ^ (size_t)next)))
        die("Bad next/prev chunks...");

    if (prev != NULL) set_next_sorted(prev, (size_t)next);
    else sorted_head = next;

    if (next != NULL)  set_prev_sorted(next, (size_t)prev);

    //now clear the chunk
    set_prev_sorted(chunk, 0);
    set_next_sorted(chunk, 0);
    chunk->cookie = 0;
}

void sorted_insert(chunk_entry *new_chunk) {
    //find best location....
    //3 cases.            A > target > B
    //                    A > target > null
    //                    target > A > B
    new_chunk->cookie = secret ^ (size_t)new_chunk;

    const size_t new_size = CHUNK_SIZE(new_chunk);

    //set next prevsize, previnuse, etc.
    chunk_entry* next_physical = (chunk_entry*)((char*)new_chunk + new_size);

    if ((void*)next_physical < heap_end_address) { //only write on allocated memory
        next_physical->prev_size = new_size;
        ZERO_PREVINUSE(next_physical);
    } else { //This is the LAST chunk we just freed
        last_chunk_is_free = 1;
        last_chunk_size = new_size;
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
    chunk_entry* prev_ptr = sorted_head;
    chunk_entry* curr_ptr = get_next_sorted(prev_ptr);

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

void * locked_malloc(const size_t total_size, const size_t page_aligned_size) {
    if (page_aligned_size > MMAP_THRESHOLD)
        return mmap_allocate(page_aligned_size, secret);

    //Sorted check!
    if (sorted_head != NULL) {
        void* ptr = sorted_allocate(total_size);

        if (ptr != NULL)
            return ptr;
    }

    chunk_entry *chunk = sbrk((long)total_size);

    if (chunk == (void*)-1)
        die("Secure alloc requested size couldn't be fulfilled.");

    chunk->prev_size = last_chunk_size;                                  // prev chunk size
    chunk->size      = total_size | (last_chunk_is_free == 1 ? 0 : CHUNK_PREVINUSE); // SIZE IS ALWAYS CHUNK SIZE! NOT PTR SIZE!
    chunk->cookie    = 0;           //Should be 0 anyways... but JIC

    last_chunk_size = total_size;
    last_chunk_is_free = 0;
    heap_end_address = (char*)chunk + total_size;

    return CHUNK_TO_PTR(chunk);
}


// Walk physical heap from start to finish. Check for inconsistencies.
// Ends at EXACTLY heap_end
void validate_heap() {
    pthread_mutex_lock(&heap_lock);

    //validate:
    // TOTAL heap sizes == heap_end_addr
    // prev size = prev's size.. always!
    chunk_entry* chunk = heap_start_address;

    for (; (void*)chunk < heap_end_address; chunk = (chunk_entry*)((char*)chunk + CHUNK_SIZE(chunk))) {
        chunk_entry* next = (chunk_entry*)((char*)chunk + CHUNK_SIZE(chunk));

        if ((void*)next < heap_end_address) { //if has next, check that sizes match
            if (next->prev_size != CHUNK_SIZE(chunk))
                die("Size inconsisntent");

            if (!IS_PREVINUSE(next->size)) {
                //chunk should be in sorted list!
                chunk_entry* sorted_chunk = sorted_head;

                int found = 0;
                while (found == 0) {
                    if (sorted_chunk == chunk)
                        found = 1;
                    sorted_chunk = get_next_sorted(sorted_chunk);
                    if (sorted_chunk == NULL)
                        break;
                }

                if (found == 0)
                    die("Invalid free chunk!");
            }
        }

    }

    if (chunk != heap_end_address)
        die("Bad heap.. sizes don't add up.");

    pthread_mutex_unlock(&heap_lock);
}
