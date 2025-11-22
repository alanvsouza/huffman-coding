Huffman Coding
==================

A small Huffman coding implementation in C. The project provides:

- A minimal Huffman tree builder (`huffman_tree.c` / `huffman_tree.h`).
- Encoding/decoding logic (`huffman.c`) that walks the tree to produce per-symbol codes and uses a bit stream helper (`stream.c` / `stream.h`) to pack bits into bytes.
- A simple command-line interface (`main.c`) with these usages:
  - `./main encode input.txt output.bin`
  - `./main decode input.bin output.txt`

This README explains how to build and run the code, important design decisions made while writing it, and the exact binary "protocol" the encoder uses to store the Huffman tree alongside encoded data.

Build & quick start
-------------------

1. Build (uses the workspace build task or compile with gcc):

   gcc -g main.c huffman_tree.c huffman.c stream.c -o main

2. Encode a text file:

   ./main encode input.txt output.bin

   The program prints the encoded size and a percentage showing space saved (or overhead) relative to the original file size.

3. Decode:

   ./main decode output.bin decoded.txt

   `decoded.txt` should match the original input (round-trip).

Binary output format (file "protocol")
--------------------------------------

The encoder writes a compact binary file that contains both a serialized representation of the Huffman tree and the encoded bitstream for the input. The format is intentionally simple and self-contained so the decoder can recreate the tree and decode the data exactly with no additional metadata.

Layout (in order):

1. 4 bytes: tree_size_in_bits (unsigned int, number of bits used to represent the serialized tree)
2. tree_size_in_bytes bytes: serialized tree bytes (see below; the exact byte count is computed as (tree_size_in_bits/8) + 1 in the implementation)
3. 4 bytes: data_size_in_bits (unsigned int, number of bits in the encoded payload)
4. data_size_in_bytes bytes: encoded data bytes (computed as (data_size_in_bits/8) + 1 in the implementation)

Notes about sizes and byte counts:
- Sizes are stored in bits so the decoder knows the exact number of meaningful bits in the last byte. The implementation uses an allocation-rule of (bits/8) + 1 to ensure enough bytes to hold all bits; this means the final byte may be only partially filled.
- The implementation stores the two bit-length headers as `unsigned int` in the platform's native endianness (on typical x86/x86_64 Linux systems this is little-endian). If you move encoded files between platforms with different endianness, you'll need to convert these headers accordingly.

Serialized Huffman tree format
-----------------------------

The tree is serialized using a simple pre-order traversal (root, left, right). Each node writes a small bit-level marker:

- Internal node: write bit `0`
- Leaf node: write bit `1`, followed by the 8-bit value of the character stored in the leaf

This yields a compact representation. Example (pseudo-steps):

- For an internal node: write 0, then recursively encode left subtree, then right subtree.
- For a leaf node containing character `c`: write 1, then write the 8-bit ASCII/byte value of `c`.

Because the encoder records the total number of bits used to encode the tree, the decoder reads exactly that many bits and reconstructs the exact tree structure.

High-level algorithm & data structures
-------------------------------------

- Frequency counting & tree construction
  - The encoder counts frequency of each byte value (0..255) in the input.
  - A simple min-heap of `HuffmanTreeNode*` is used to build the Huffman tree. Each leaf represents a symbol with its frequency.
  - Internal nodes store the sum of frequencies of their children.

- Code table generation
  - The code table (lookup) maps each byte value to its Huffman code (a sequence of bits).
  - The implementation builds codes by traversing the tree and recording 0/1 steps in an `unsigned char *bits` array per code. The code representation is currently "one byte per bit" while the code table exists (this is easy to reason about but memory-inefficient for large alphabets or deep trees).

- Bit stream
  - `BitStream` is a small helper that accumulates bits into a byte buffer. When 8 bits are collected they are stored to the `data` buffer. The stream grows dynamically (realloc doubling strategy) as more bytes are written.
  - The `get_stream_data()` API flushes the final partial byte (if any) and returns the underlying byte array plus its total length in bits.

Design decisions and trade-offs
-------------------------------

- Simplicity over micro-optimizations
  - The project favors clear, easy-to-follow code rather than squeezing every last bit of performance or memory efficiency. Examples:
    - Huffman codes are stored in-memory as `unsigned char*` where each bit is represented in its own byte while building the table. This makes push/pop operations simple but is memory-inefficient. The final stored output is packed into bytes.
    - The bitstream writes single bits using `write_bit()` loops for bytes; this is conceptually simple.

- Portability considerations
  - The code uses `unsigned int` for bit-length headers and writes them directly via `memcpy`. This is simple and fast but assumes the reader and writer share endianness and `unsigned int` width. If you need portable on-disk format, change the headers to a fixed endianness/size (for example, store as 32-bit little-endian using integer conversion helpers).

- Memory ownership and leaks
  - The implementation includes routines to free temporary allocations (the Huffman tree and lookup table) once they are no longer needed so a single encode/decode cycle does not leak significant memory. However, there are still places where error handling paths could be improved (e.g., failing `malloc` in the middle of building structures).

- Safety vs performance
  - Dynamic reallocation growth uses doubling. This is a reasonable generic strategy. For extremely large files or streaming operation, you would want a streaming encoder that writes to disk incrementally rather than building everything in memory.

Edge cases & limitations
------------------------

- Small inputs
  - For very short inputs the encoded file can be larger than the input because the file includes the serialized tree and two 4-byte headers. This is expected for small inputs. The program prints this as "Overhead" when the encoded size is larger than the original.

- Character set
  - The implementation treats input as raw bytes (0..255). It is agnostic to text encodings (UTF-8, ASCII, etc.), but you should use `encode`/`decode` with the same byte stream semantics.

- Ownership and API
  - `encode()` returns an `unsigned char *` buffer and sets an `unsigned int` size. The caller is responsible for freeing the returned buffer.
  - `decode()` returns a null-terminated `char*` that must be freed by the caller.

- Endianness & portability
  - The on-disk headers are written using native `unsigned int` layout. For cross-platform portability, change to a fixed layout (e.g., 32-bit little-endian) and document that.

Potential improvements
----------------------

- Pack in-memory codes more compactly while building the table (store bits packed into bytes instead of one byte per bit). This reduces memory usage and may speed up encoding.
- Stream-based tree output / input: write partial results to disk as you build them to avoid holding entire encoded buffer in memory for large files.
- Use safer serializers for headers (explicit 32-bit little-endian) so encoded files are portable.
- Add more robust error handling paths and unit tests: validate round-trip results automatically for a variety of inputs.
- Compression header: add a small magic number and a version byte at the file start so decoders can sanity-check input files before reading.
