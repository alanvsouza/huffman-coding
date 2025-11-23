typedef struct {
    unsigned char buffer;
    unsigned int buffer_size;

    size_t total_length;
    size_t alloced_space;
    unsigned char* data;
} BitStream;

BitStream* create_stream();
void write_bit(BitStream* stream, unsigned int bit);
void write_byte(BitStream* stream, unsigned char byte);
void flush(BitStream* stream);
unsigned char* get_stream_data(BitStream* stream, size_t* bytes);

