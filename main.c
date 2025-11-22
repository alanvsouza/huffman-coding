#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "huffman.h"

static unsigned char* read_file_all(const char* path, size_t* out_size) {
    FILE* f = fopen(path, "rb");

    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }

    long length = ftell(f);
    if (length < 0) {
        fclose(f);
        return NULL;
    }

    rewind(f);

    unsigned char *buf = malloc(length + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t read = fread(buf, 1, length, f);
    fclose(f);
    buf[read] = '\0';

    if (out_size) *out_size = read;

    return buf;
}

static int write_file_all(const char *path, const unsigned char *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    size_t written = fwrite(data, 1, size, f);
    fclose(f);

    return written == size ? 0 : -1;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s encode <input.txt> <output.bin>   # encode text file into binary\n"
        "  %s decode <input.bin> <output.txt>   # decode binary back to text\n",
        prog, prog);
}

int main(int argc, char** argv) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *inpath = argv[2];
    const char *outpath = argv[3];

    if (strcmp(cmd, "encode") == 0) {
        size_t in_size;
        unsigned char* inbuf = read_file_all(inpath, &in_size);
        if (!inbuf) {
            fprintf(stderr, "Failed to read input file: %s\n", inpath);
            return 2;
        }

        unsigned int out_size = 0;
        unsigned char* outbuf = encode((char*)inbuf, &out_size);
        free(inbuf);
        if (!outbuf) {
            fprintf(stderr, "Encoding failed\n");
            return 3;
        }

        if (write_file_all(outpath, outbuf, out_size) != 0) {
            fprintf(stderr, "Failed to write output file: %s\n", outpath);
            free(outbuf);
            return 4;
        }
        free(outbuf);
        if (in_size > 0) {
            double ratio = (double)out_size / (double)in_size;
            double saved = (1.0 - ratio) * 100.0;
            if (saved >= 0.0) {
                printf("Encoded %s -> %s (%u bytes). Saved: %.2f%%\n", inpath, outpath, out_size, saved);
            } else {
                printf("Encoded %s -> %s (%u bytes). Overhead: %.2f%%\n", inpath, outpath, out_size, -saved);
            }
        } else {
            printf("Encoded %s -> %s (%u bytes)\n", inpath, outpath, out_size);
        }
        return 0;

    } else if (strcmp(cmd, "decode") == 0) {
        size_t in_size;
        unsigned char* inbuf = read_file_all(inpath, &in_size);
        if (!inbuf) {
            fprintf(stderr, "Failed to read input file: %s\n", inpath);
            return 2;
        }

        unsigned int out_size = 0;
        char* outbuf = decode(inbuf, (unsigned int)in_size);
        free(inbuf);
        if (!outbuf) {
            fprintf(stderr, "Decoding failed\n");
            return 3;
        }

        if (write_file_all(outpath, (unsigned char*)outbuf, strlen(outbuf)) != 0) {
            fprintf(stderr, "Failed to write output file: %s\n", outpath);
            free(outbuf);
            return 4;
        }
        printf("Decoded %s -> %s (%zu bytes)\n", inpath, outpath, strlen(outbuf));
        free(outbuf);
        return 0;

    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
