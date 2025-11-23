#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "stream.h"
#include "huffman_tree.h"
#include "huffman.h"

#define ENCODED_DATA_BUFF_SIZE 1024
#define ENCODED_TREE_BUFF_SIZE 1024

typedef struct {
    unsigned char* bits;
    unsigned int bit_count;
} HuffmanCode;

static HuffmanCode** build_lookup_table(HuffmanTreeNode* root);
static unsigned char* encode_huffman_tree(HuffmanTreeNode* root, size_t* tree_size_in_bytes);
static HuffmanTreeNode* decode_huffman_tree(unsigned char* encoded_tree, size_t* curr_bit, size_t tree_size_in_bytes);
static void decode_data(HuffmanTreeNode* root, BitStream* stream, unsigned char* encoded_data, size_t *curr_bit, size_t total_bits);

static void free_huffman_tree(HuffmanTreeNode* root);
static void free_lookup_table(HuffmanCode** lookup_table);

unsigned char* encode(char* charset, size_t* encoded_data_size) {
    BitStream* data_stream = create_stream();
    
    HuffmanTreeNode* root = build_huffman_tree(charset);
    HuffmanCode** lookup_table = build_lookup_table(root);

    size_t charset_len = strlen(charset);
    for (size_t i=0; i<charset_len; i++) {
        HuffmanCode* curr_code = lookup_table[(unsigned char)charset[i]];

        for (int j=0; j<curr_code->bit_count; j++) {
            write_bit(data_stream, curr_code->bits[j]);
        }
    }

    size_t data_size_in_bits = 0;
    unsigned char* encoded_data = get_stream_data(data_stream, &data_size_in_bits);

    size_t tree_size_in_bits;
    unsigned char* encoded_tree = encode_huffman_tree(root, &tree_size_in_bits);

    size_t tree_size_in_bytes = (tree_size_in_bits / 8U) + 1;
    size_t data_size_in_bytes = (data_size_in_bits / 8U) + 1;

    size_t total_byte_size = tree_size_in_bytes + data_size_in_bytes + 2 * sizeof(uint64_t); // needs to allocate space to the sizes of the tree and the data (in bits)

    unsigned char* result_buffer = (unsigned char*)malloc(sizeof(unsigned char) * total_byte_size);

    unsigned char* curr_byte_ptr = result_buffer;

    uint64_t tree_size_u64 = (uint64_t)tree_size_in_bits;
    memcpy(curr_byte_ptr, &tree_size_u64, sizeof(uint64_t));
    curr_byte_ptr += sizeof(uint64_t);
    memcpy(curr_byte_ptr, encoded_tree, tree_size_in_bytes);
    curr_byte_ptr += tree_size_in_bytes;
    
    uint64_t data_size_u64 = (uint64_t)data_size_in_bits;
    memcpy(curr_byte_ptr, &data_size_u64, sizeof(uint64_t));
    curr_byte_ptr += sizeof(uint64_t);
    memcpy(curr_byte_ptr, encoded_data, data_size_in_bytes);

    *encoded_data_size = total_byte_size;

    if (encoded_tree) free(encoded_tree);
    if (encoded_data) free(encoded_data);
    free_lookup_table(lookup_table);
    free_huffman_tree(root);

    return result_buffer;
}

char* decode(unsigned char* encoded, size_t encoded_size) {
    unsigned char* curr_byte_ptr = encoded;

    uint64_t tree_size_in_bits = 0;
    memcpy(&tree_size_in_bits, curr_byte_ptr, sizeof(uint64_t));
    curr_byte_ptr += sizeof(uint64_t);

    size_t tree_size_in_bytes = (tree_size_in_bits / 8U) + 1;
    unsigned char* encoded_tree = (unsigned char*)malloc(sizeof(unsigned char) * tree_size_in_bytes);
    memcpy(encoded_tree, curr_byte_ptr, tree_size_in_bytes);
    curr_byte_ptr += tree_size_in_bytes;

    uint64_t data_size_in_bits = 0;
    memcpy(&data_size_in_bits, curr_byte_ptr, sizeof(uint64_t));
    curr_byte_ptr += sizeof(uint64_t);

    size_t data_size_in_bytes = (data_size_in_bits / 8U) + 1;
    unsigned char* encoded_data = (unsigned char*)malloc(sizeof(unsigned char) * data_size_in_bytes);
    memcpy(encoded_data, curr_byte_ptr, data_size_in_bytes);

    size_t curr_bit = 0;
    HuffmanTreeNode* root = decode_huffman_tree(encoded_tree, &curr_bit, (size_t)tree_size_in_bits);

    if (!root) {
        if (encoded_tree) free(encoded_tree);
        if (encoded_data) free(encoded_data);
        return NULL;
    }

    BitStream* stream = create_stream();
    curr_bit = 0;
    decode_data(root, stream, encoded_data, &curr_bit, (size_t)data_size_in_bits);

    size_t total_size_in_bits = 0;
    unsigned char* decoded_data = get_stream_data(stream, &total_size_in_bits);

    size_t total_size_in_bytes = (total_size_in_bits / 8U) + (total_size_in_bits % 8U != 0 ? 1 : 0);
    
    char* str = (char*)malloc((sizeof(char) * total_size_in_bytes) + 1);
    size_t i;
    for (i=0; i<total_size_in_bytes; i++) {
        str[i] = (char)decoded_data[i];
    }
    str[i] = '\0';

    if (decoded_data) free(decoded_data);
    if (encoded_tree) free(encoded_tree);
    if (encoded_data) free(encoded_data);
    free_huffman_tree(root);

    return str;
}

static HuffmanCode* copy_huffman_code(HuffmanCode* src) {
    HuffmanCode* dest = malloc(sizeof(HuffmanCode));
    if (!dest) return NULL;
    dest->bit_count = src->bit_count;
    if (src->bit_count > 0) {
        dest->bits = malloc(src->bit_count);
        if (!dest->bits) { free(dest); return NULL; }
        memcpy(dest->bits, src->bits, src->bit_count);
    } else {
        dest->bits = NULL;
    }
    return dest;
}

static void huffman_tree_traversal(HuffmanTreeNode* root, HuffmanCode* accumulator, HuffmanCode** lookup_table) {
    if (!root) return;

    if (!root->is_internal_node) {
        HuffmanCode* curr_code = copy_huffman_code(accumulator);
        lookup_table[(unsigned char)root->c] = curr_code;
        return;
    }

    accumulator->bits[accumulator->bit_count++] = 0;
    huffman_tree_traversal(root->left, accumulator, lookup_table);
    accumulator->bit_count--;

    accumulator->bits[accumulator->bit_count++] = 1;
    huffman_tree_traversal(root->right, accumulator, lookup_table);
    accumulator->bit_count--;
}

static void encode_huffman_tree_recursion(
    HuffmanTreeNode* root,
    BitStream* stream
) {
    if (!root) return;

    if (root->is_internal_node) {
        write_bit(stream, 0);

        encode_huffman_tree_recursion(root->left, stream);
        encode_huffman_tree_recursion(root->right, stream);
    } else {
        write_bit(stream, 1);
        write_byte(stream, root->c);
    }
}

static unsigned int read_bit(unsigned char* bytes, size_t bit_index, size_t max_bits) {
    if (bit_index >= max_bits) return 0;
    
    size_t byte_index = bit_index / 8U;
    unsigned char byte = bytes[byte_index];

    unsigned char mask = 1 << (7 - (bit_index - 8U * byte_index));

    return (byte & mask) != 0;
}

static unsigned int read_byte(unsigned char* bytes, size_t bit_index, size_t max_bits) {
    unsigned char out_byte = 0;
    for (int i=0; i<8; i++) {
        unsigned int bit = read_bit(bytes, bit_index + i, max_bits);
        out_byte |= bit << (7 - i);
    }
    return out_byte;
}

static unsigned char* encode_huffman_tree(HuffmanTreeNode* root, size_t* tree_size_in_bytes) {
    BitStream* huffman_tree_stream = create_stream();
    encode_huffman_tree_recursion(root, huffman_tree_stream);

    return get_stream_data(huffman_tree_stream, tree_size_in_bytes);
}

static HuffmanTreeNode* decode_huffman_tree(unsigned char* encoded_tree, size_t* curr_bit, size_t tree_size_in_bits) {
    if (*curr_bit >= tree_size_in_bits) return NULL;
    
    unsigned int bit = read_bit(encoded_tree, *curr_bit, tree_size_in_bits);
    (*curr_bit) += 1;

    if (bit == 0) {
        HuffmanTreeNode* internal_node = new_internal_node(NULL, NULL);
        internal_node->left = decode_huffman_tree(encoded_tree, curr_bit, tree_size_in_bits);
        internal_node->right = decode_huffman_tree(encoded_tree, curr_bit, tree_size_in_bits);

        return internal_node;
    }

    char c = read_byte(encoded_tree, *curr_bit, tree_size_in_bits);
    (*curr_bit) += 8;
    HuffmanTreeNode* leaf = new_tree_leaf(c, 0);
    return leaf;
}

static void decode_data(HuffmanTreeNode* root, BitStream* stream, unsigned char* encoded_data, size_t *curr_bit, size_t total_bits) {
    if (!root) return;
    
    HuffmanTreeNode* traverse = root;

    while (*curr_bit < total_bits) {
        unsigned int bit = read_bit(encoded_data, (*curr_bit)++, total_bits);
        traverse = bit ? traverse->right : traverse->left;

        if (!traverse) {
            // Malformed tree or data
            return;
        }

        if (!traverse->is_internal_node) {
            write_byte(stream, (unsigned char)traverse->c);
            traverse = root;
        }
    }
}

HuffmanCode** build_lookup_table(HuffmanTreeNode* root) {
    HuffmanCode** lookup_table = (HuffmanCode**)malloc(sizeof(HuffmanCode*) * _8_BIT_ASCII_SIZE);
    for (int i=0; i<_8_BIT_ASCII_SIZE; i++) lookup_table[i] = NULL;

    HuffmanCode accumulator;
     // max theoretical Huffman code size is N-1 (for an alphabet with N symbols)
    accumulator.bits = (unsigned char*)malloc(sizeof(unsigned char) * _8_BIT_ASCII_SIZE-1);
    accumulator.bit_count = 0;

    huffman_tree_traversal(root, &accumulator, lookup_table);

    if (accumulator.bits) free(accumulator.bits);

    return lookup_table;
}

static void free_huffman_tree(HuffmanTreeNode* root) {
    if (!root) return;
    free_huffman_tree(root->left);
    free_huffman_tree(root->right);
    free(root);
}

static void free_lookup_table(HuffmanCode** lookup_table) {
    if (!lookup_table) return;
    for (int i = 0; i < _8_BIT_ASCII_SIZE; i++) {
        HuffmanCode* code = lookup_table[i];
        if (!code) continue;
        if (code->bits) free(code->bits);
        free(code);
    }
    free(lookup_table);
}
