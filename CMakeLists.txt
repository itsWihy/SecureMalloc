cmake_minimum_required(VERSION 4.2)
project(SecureMalloc C)

set(CMAKE_C_STANDARD 11)

add_executable(SecureMalloc src/main.c
        src/allocator/secure_malloc.c
        src/allocator/secure_malloc.h
        src/utils/utils.c
        src/utils/utils.h
        src/allocator/mmap_helper.c
        src/allocator/mmap_helper.h
)
