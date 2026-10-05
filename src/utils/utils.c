//
// Created by Wihy on 9/20/26.
//

#include "utils.h"

#include <ctype.h>
#include <stdio.h>

size_t max(const size_t a, const size_t b) {
    return a > b ? a : b;
}

void hexdump(void *ptr, size_t size) {
    const __uint8_t *bytes = ptr;

    for (int i = 0; i < size; i += 16) {
        printf("%p  ", (void *) (ptr + i));

        for (int j = 0; j < 16; ++j) {
            if (i + j < size) printf("%02x ", bytes[i + j]);
            else              printf("    ");

            if (j == 7) printf(" ");
        }
        printf(" |");

        for (size_t j = 0; j < 16 && i + j < size; j++) {
            __uint8_t byte = bytes[i + j];
            printf("%c", isprint(byte) ? byte : '.');
        }

        puts("|");
    }
}
