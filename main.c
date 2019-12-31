#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include "huff.h"

void print_help_and_exit(char **argv) {
    fprintf(stderr,
            "Usage: %s [-d] <input> <output>\n"
            "Compress or uncompress file (by default, compress file)\n\n"
            "-d\tdecompress\n",
            argv[0]);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    bool decompress = false;
    char *input, *output;
    int in_fd, out_fd;

    if(argc < 3 || argc > 4)
        print_help_and_exit(argv);

    if(argc == 4) {
        if(!strcmp(argv[1], "-d"))
            decompress = true;
        else
            print_help_and_exit(argv);
    }

    if(!decompress) {
        input = argv[1];
        output = argv[2];
    } else {
        input = argv[2];
        output = argv[3];
    }

    in_fd = open(input, O_RDONLY);
    if(in_fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    out_fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(out_fd < 0) {
        perror("open");
        close(in_fd);
        exit(EXIT_FAILURE);
    }

    if(!decompress)
        huffman_encode(in_fd, out_fd);
    else
        huffman_decode(in_fd, out_fd);

    close(in_fd);
    close(out_fd);
}
