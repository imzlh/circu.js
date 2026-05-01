#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: align_binary <file> <alignment>\n");
        return 1;
    }

    const char *path = argv[1];
    int align = atoi(argv[2]);
    if (align <= 0 || (align & (align - 1)) != 0) {
        fprintf(stderr, "Alignment must be a power of 2\n");
        return 1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);

    long remainder = size % align;
    if (remainder == 0) {
        fprintf(stderr, "Already aligned: %ld bytes (mod %d)\n", size, align);
        return 0;
    }

    long pad = align - remainder;
    f = fopen(path, "ab");
    if (!f) {
        perror("fopen append");
        return 1;
    }

    unsigned char zeros[64] = {0};
    long written = 0;
    while (written < pad) {
        long chunk = pad - written;
        if (chunk > 64) chunk = 64;
        if (fwrite(zeros, 1, chunk, f) != (size_t)chunk) {
            perror("fwrite");
            fclose(f);
            return 1;
        }
        written += chunk;
    }

    fclose(f);
    fprintf(stderr, "Aligned %s: %ld -> %ld bytes (+%ld zero bytes)\n",
            path, size, size + pad, pad);
    return 0;
}
