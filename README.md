# SECURE MALLOC
An allocator that attempts to imitate `malloc` while hardening several aspects of the heap to make exploitation harder.
### Program flow
#### Secure malloc allocation workflow

Checks: total size > 128KB: Use mmap<br>
Else:
    check tcache. On hit, validate cookie (secret ^ addr)
    then, check sorted. Descending order of big sizes.
    find best fit, then split off if valid. 
    if no free chunk is present, move the break

### Mitigations
Every free chunk in the `tcache` or `sorted` contains an inline cookie, consisting of `secret ^ heap_addr`.<br>
Prevents classical buffer overflow without a leak first
Prevents freeing an arbitrary chunk

Pointers are stored in the middle of each chunk. <br>
Prevents classical UAF with only one address of overwrite from writing to nextptr

Double free: Tcache checks `cookie`. If matches, the chunk is already free and aborts <br>
For sorted, if the previnuse of next isn't set, the chunk was freed twice. Abort.

Unlink: Check that `next's prev == chunk == prev's next` on unlink.<br>

Each chunk is checked such that it is in the heap bounds. Can't allocate a chunk outside of the heap range.


### Future additions
- Add safe linking, XOR next,prev PTRs with their location to eliminate partial overwrites
- Binning- add smallbin/fastbin etc.


