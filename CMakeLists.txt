cmake_minimum_required(VERSION 4.2)
project(SecureMalloc C)

set(CMAKE_C_STANDARD 11)

add_executable(SecureMalloc main.c
        secure_malloc.c
        secure_malloc.h
        utils/utils.c
        utils/utils.h
)
