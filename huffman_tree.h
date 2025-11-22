#define _8_BIT_ASCII_SIZE 256

typedef struct HuffmanTreeNode {
    struct HuffmanTreeNode *left, *right;

    unsigned int freq;
    unsigned int is_internal_node;

    char c;
} HuffmanTreeNode;

HuffmanTreeNode* build_huffman_tree(char* charset);

HuffmanTreeNode* new_tree_leaf(char data, unsigned int freq);
HuffmanTreeNode* new_internal_node(HuffmanTreeNode* left, HuffmanTreeNode* right);
