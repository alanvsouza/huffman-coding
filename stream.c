#include <stdio.h>
#include <stdlib.h>

#include "stream.h"

#define DATA_SIZE 1024

BitStream* create_stream() {
    BitStream* stream = (BitStream*)malloc(sizeof(BitStream));
    stream->buffer = 0;
    stream->buffer_size = 0;
    stream->total_length = 0;
    
    stream->data = (unsigned char*)malloc(sizeof(unsigned char) * DATA_SIZE);
    stream->alloced_space = DATA_SIZE;

    return stream;
}

void write_bit(BitStream* stream, unsigned int bit) {
    if (bit == 1) {
        stream->buffer |= 1 << (7U-stream->buffer_size);
    }

    if ((++stream->buffer_size) == 8) {
        flush(stream);
    }
}

void write_byte(BitStream* stream, unsigned char byte) {
    for (int i=7; i>=0; i--) {
        unsigned char bit_mask = 1 << i;
        unsigned int curr_bit = (bit_mask & byte) >> i;
        write_bit(stream, curr_bit);
    }
}

// writes the entire byte buffer to the data array
void flush(BitStream* stream) {
    size_t byte_index = stream->total_length / 8U;

    if (byte_index >= stream->alloced_space) {
        size_t new_space = stream->alloced_space * 2;
        unsigned char* new_ptr = (unsigned char*)realloc(stream->data, new_space * sizeof *stream->data);

        if (new_ptr) {
            stream->data = new_ptr;
            stream->alloced_space = new_space;
        } else {
            printf("[ERROR] Max space reached: failed to allocate memory\n");
            return;
        }
    }

    stream->data[byte_index] = stream->buffer;
    stream->buffer = 0;
    stream->total_length += stream->buffer_size;
    stream->buffer_size = 0;
}

// return the data stored in the stream, while freeing the memory allocated (the stream cannot be used after this)
unsigned char* get_stream_data(BitStream* stream, size_t* length_in_bits) {
    flush(stream);

    unsigned char* data = stream->data;
    *length_in_bits = stream->total_length;
    
    free(stream);

    return data;
}