#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "huffman_tree.h"

typedef struct HuffmanTreeNode {
    struct HuffmanTreeNode *left, *right;

    unsigned int freq;
    unsigned int is_internal_node;

    char c;
} HuffmanTreeNode;

typedef struct MinHeap {
    unsigned int size;
    unsigned int capacity;

    HuffmanTreeNode** heap;
} MinHeap;

static HuffmanTreeNode** build_frequencies(char* charset, unsigned int* unique_chars);
static HuffmanTreeNode* remove_from_min_heap(MinHeap* min_heap);
static void add_to_min_heap(MinHeap* min_heap, HuffmanTreeNode* node);
static MinHeap* build_min_heap(char* charset);

HuffmanTreeNode* new_tree_leaf(char data, unsigned int freq) {
    HuffmanTreeNode* leaf = (HuffmanTreeNode*)malloc(sizeof(HuffmanTreeNode));
    leaf->c = data;
    leaf->freq = freq;
    leaf->is_internal_node = 0;
    leaf->left = NULL;
    leaf->right = NULL;
    return leaf;
}

HuffmanTreeNode* new_internal_node(HuffmanTreeNode* left, HuffmanTreeNode* right) {
    HuffmanTreeNode* internal_node = (HuffmanTreeNode*)malloc(sizeof(HuffmanTreeNode));
    internal_node->is_internal_node = 1;
        
    unsigned int left_freq = left != NULL ? left->freq : 0;
    unsigned int right_freq = right != NULL ? right->freq : 0;

    internal_node->freq = left_freq + right_freq;
    internal_node->left = left;
    internal_node->right = right;
    return internal_node;
}

HuffmanTreeNode* build_huffman_tree(char* charset) {
    MinHeap* min_heap = build_min_heap(charset);

    while (min_heap->size > 1) {
        HuffmanTreeNode* first = remove_from_min_heap(min_heap);
        HuffmanTreeNode* second = remove_from_min_heap(min_heap);

        HuffmanTreeNode* internal_node = new_internal_node(first, second);

        add_to_min_heap(min_heap, internal_node);
    }

    HuffmanTreeNode* root = remove_from_min_heap(min_heap);
    if (min_heap->heap) free(min_heap->heap);
    free(min_heap);
    return root;
}

static HuffmanTreeNode** build_frequencies(char* charset, unsigned int* unique_chars) {
    unsigned int* frequencies = (unsigned int*)malloc(sizeof(unsigned int) * _8_BIT_ASCII_SIZE);
    for (int i=0; i<_8_BIT_ASCII_SIZE; i++) frequencies[i] = 0;

    size_t charset_len = strlen(charset);
    
    int unique = 0;
    for (size_t i=0; i<charset_len; i++) {
        unsigned char uc = (unsigned char)charset[i];
        if ((++frequencies[uc]) == 1) unique++;
    }

    int curr_idx = 0;
    HuffmanTreeNode** freq_array = (HuffmanTreeNode**)malloc(sizeof(HuffmanTreeNode*) * unique);
    for (int i=0; i<_8_BIT_ASCII_SIZE; i++) {
        if (frequencies[i] == 0) continue;
        freq_array[curr_idx++] = new_tree_leaf((unsigned char)i, frequencies[i]);
    }

    *unique_chars = unique;
    free(frequencies);
    return freq_array;
}

static void swap_elements(MinHeap* min_heap, int a, int b) {
    HuffmanTreeNode* aux = min_heap->heap[a];
    min_heap->heap[a] = min_heap->heap[b];
    min_heap->heap[b] = aux;
}

static void heapify_down(MinHeap* min_heap, unsigned int idx) {
    int curr = idx;
    int left = curr * 2 + 1;
    int right = curr * 2 + 2;

    int smallest = curr;
    if (left < (int)min_heap->size && min_heap->heap[left]->freq < min_heap->heap[smallest]->freq) smallest = left;
    if (right < (int)min_heap->size && min_heap->heap[right]->freq < min_heap->heap[smallest]->freq) smallest = right;

    if (smallest != curr) {
        swap_elements(min_heap, smallest, curr);
        heapify_down(min_heap, smallest);
    }
}

static void heapify_up(MinHeap* min_heap, unsigned int idx) {
    if (idx < 1) return;

    int curr = idx;
    int parent = (idx-1)/2;

    if (min_heap->heap[curr]->freq < min_heap->heap[parent]->freq) {
        swap_elements(min_heap, curr, parent);
        heapify_up(min_heap, parent);
    }
}

static MinHeap* new_min_heap(HuffmanTreeNode** freq_array, unsigned int capacity) {
    MinHeap* min_heap = (MinHeap*)malloc(sizeof(MinHeap));
    
    min_heap->capacity = capacity;
    min_heap->size = capacity;
    min_heap->heap = freq_array;
    
    for (int i = (min_heap->size / 2) - 1; i >= 0; i--) {
        heapify_down(min_heap, i);
    }

    return min_heap;
}

static MinHeap* build_min_heap(char* charset) {
    unsigned int capacity;
    HuffmanTreeNode** freq_array = build_frequencies(charset, &capacity);

    MinHeap* min_heap = new_min_heap(freq_array, capacity);

    return min_heap;
}

static void add_to_min_heap(MinHeap* min_heap, HuffmanTreeNode* node) {
    min_heap->heap[min_heap->size] = node;
    heapify_up(min_heap, min_heap->size++);
}

static HuffmanTreeNode* remove_from_min_heap(MinHeap* min_heap) {
    HuffmanTreeNode* root = min_heap->heap[0];

    if (min_heap->size-- == 1) return root;

    swap_elements(min_heap, 0, min_heap->size);
    heapify_down(min_heap, 0);
    return root;
}
