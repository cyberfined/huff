#include "huff.h"
#include "bheap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>

#define BUF_SIZE  1024
#define BIT_LIMIT 32

static char in_buf[BUF_SIZE];
static char out_buf[BUF_SIZE];

/*
 * Read file, count frequency of each byte, build min binary heap.
 */
static inline bheap* get_stat(int in_fd) {
    size_t freqs[256];
    bheap *heap = NULL;
    bheap_node node;
    int len;

    memset(freqs, 0, sizeof(freqs));

    while((len = read(in_fd, in_buf, BUF_SIZE)) > 0) {
        for(int i = 0; i < len; i++)
            freqs[(uint8_t)in_buf[i]]++;
    }

    if(len < 0)
        goto error;

    heap = bheap_new(512);
    if(!heap)
        goto error;

    for(int i = 0; i < 256; i++) {
        if(!freqs[i])
            continue;

        node = (bheap_node) {
            .byte = (uint8_t)i,
            .parent = NULL,
            .frequency = freqs[i],
            .left = NULL,
            .right = NULL,
        };

        if(!bheap_insert(heap, &node))
            goto error;
    }

    return heap;
error:
    perror("get_stat");
    if(heap) bheap_free(heap);
    return NULL;
}

/*
 * Build Huffman binary tree.
 */
static inline bheap_node* build_tree(bheap *heap) {
    bheap_node *f = NULL, *s = NULL;
    while(heap->num_nodes > 1) {
        f = bheap_pop(heap);
        if(!f)
            goto error;

        s = bheap_pop(heap);
        if(!s)
            goto error;

        bheap_node node = (bheap_node) {
            .byte = 0,
            .parent = NULL,
            .frequency = f->frequency + s->frequency,
            .left = f,
            .right = s,
        };

        bheap_node *inserted = bheap_insert(heap, &node);
        if(!inserted)
            goto error;
        f->parent = s->parent = inserted;
        s = NULL;
    }

    return heap->nodes[1];
error:
    perror("build_tree");
    if(f) bheap_node_free(f);
    if(s) bheap_node_free(s);
    return NULL;
}

typedef struct {
    uint32_t code;
    uint8_t  size;
} symbol;

/*
 * Traverse Huffman binary tree, associate code and size of code with each byte.
 */
static inline int get_alphabet(bheap_node *tree, symbol *alphabet) {
    uint32_t code = 0;
    uint8_t size = 0;
    bool dir = false;

    while(tree) {
        if(size > BIT_LIMIT) {
            fputs("get_alphabet: bit limit has been violated", stderr);
            return -1;
        }

        if(!tree->left && !tree->right) {
            alphabet[tree->byte] = (symbol) {
                .code = code,
                .size = size,
            };

            if(!tree->parent) {
                break;
            } else if(tree->parent->left == tree) {
                tree = tree->parent->right;
                code |= 1;
                continue;
            } else {
                dir = true;
            }
        } else if(!dir) {
            tree = tree->left;
            code <<= 1;
            size++;
            continue;
        } 

        if(dir) {
            if(!tree->parent) {
                break;
            } else if(tree->parent->right == tree) {
                tree = tree->parent;
                code = (code ^ 1) >> 1;
                size--;
            } else {
                tree = tree->parent->right;
                code |= 1;
                dir = false;
            }
        }
    }

    return 0;
}

/*
 * Write Huffman binary tree to file.
 */
static inline int write_tree(int out_fd, bheap_node *tree) {
    size_t len = 0;
    uint8_t byte = 0, bits = 8;
    bool dir = false;

    while(tree) {
        if(!tree->left && !tree->right) {
            bits--;
            byte |= (1 << bits);

            uint8_t chr = tree->byte;
            for(int i = 8;;) {
                if(bits == 0) {
                    out_buf[len++] = byte;
                    byte = 0;
                    bits = 8;

                    if(len == sizeof(out_buf)) {
                        if(write(out_fd, out_buf, len) != len)
                            goto error;
                        len = 0;
                    }
                }

                if(i == 0)
                    break;

                bits--;
                i--;
                byte |= ((chr >> i) & 1) << bits;
            }

            if(!tree->parent) {
                break;
            } else if(tree->parent->left == tree) {
                tree = tree->parent->right;
            } else {
                dir = true;
                tree = tree->parent;
            }
        } else if(!dir) {
            bits--;
            tree = tree->left;
        } else if(!tree->parent) {
            break;
        } else if(tree->parent->right == tree) {
            tree = tree->parent;
        } else {
            tree = tree->parent->right;
            dir = false;
        }

        if(bits == 0) {
            out_buf[len++] = byte;
            byte = 0;
            bits = 8;

            if(len == sizeof(out_buf)) {
                if(write(out_fd, out_buf, len) != len)
                    goto error;
                len = 0;
            }
        }
    }

    if(bits != 8)
        out_buf[len++] = byte;

    if(len > 0 && write(out_fd, out_buf, len) != len)
        goto error;

    return 0;
error:
    perror("write_tree");
    return -1;
}

/*
 * Read Huffman binary tree from in_buf.
 */
static inline bheap_node* read_tree(size_t buf_size, size_t *len) {
    bheap_node *tree = NULL, *cur;
    uint8_t read_byte = 0, byte, bits = 0;

    tree = malloc(sizeof(bheap_node));
    if(!tree)
        goto error;
    tree->parent = tree->left = tree->right = NULL;
    cur = tree;

    size_t ret_len = 0;
    while(ret_len < buf_size) {
        if(bits == 0) {
            bits = 8;
            byte = in_buf[ret_len++];
        }
        bits--;

        if(read_byte > 0) {
            read_byte--;
            cur->byte |= ((byte >> bits) & 1) << read_byte;

            if(read_byte == 0) {
                bheap_node *p = cur->right;
                cur->right = NULL;
                if(p)
                    cur = p;
                else
                    break;
            }
            continue;
        }

        if(byte & (1 << bits)) {
            cur->byte = 0;
            read_byte = 8;
        } else {
            bheap_node *left = malloc(sizeof(bheap_node));
            if(!left)
                goto error;

            bheap_node *right = malloc(sizeof(bheap_node));
            if(!right) {
                free(left);
                goto error;
            }

            left->left = right->left = right->right = NULL;
            cur->left = left;
            left->right = right;
            left->parent = right->parent = cur;
            if(cur->right)
                right->right = cur->right;
            cur->right = right;
            cur = left;
        }
    }

    *len = ret_len;

    return tree;
error:
    perror("read_tree");
    if(tree) bheap_node_free(tree);
    return NULL;
}

/*
 * Encode content of input file and write it to output.
 */
static inline int encode(int in_fd, int out_fd, symbol *alphabet) {
    uint8_t byte = 0;
    int in_len, out_len=0;
    uint8_t bit_cnt = 8;

    while((in_len = read(in_fd, in_buf, BUF_SIZE)) > 0) {
        for(int i = 0; i < in_len; i++) {
            uint8_t ind = in_buf[i];

            uint8_t sz = alphabet[ind].size;
            uint32_t code = alphabet[ind].code;
            while(sz) {
                if(bit_cnt >= sz) {
                    bit_cnt -= sz;
                    byte |= (code << bit_cnt);
                    sz = 0;
                } else {
                    sz -= bit_cnt;
                    byte |= (code >> sz);
                    bit_cnt = 0;
                }

                if(bit_cnt == 0) {
                    out_buf[out_len++] = byte;
                    byte = 0;
                    bit_cnt = 8;

                    if(out_len == BUF_SIZE) {
                        if(write(out_fd, out_buf, out_len) != out_len)
                            goto error;
                        out_len = 0;
                    }
                }
            }
        }
    }

    if(in_len < 0)
        goto error;

    if(bit_cnt > 0)
        out_buf[out_len++] = byte;

    if(out_len > 0 && write(out_fd, out_buf, out_len) != out_len)
        goto error;

    return 0;
error:
    perror("huffman_encode");
    return -1;
}

/*
 * Compress input file, write its size, Huffman binary tree and compressed content to the output.
 */
int huffman_encode(int in_fd, int out_fd) {
    int ret = -1;
    symbol alphabet[256];
    struct stat inp_info;
    uint32_t inp_size;
    bheap *heap;
    bheap_node *tree = NULL;

    if(fstat(in_fd, &inp_info) < 0) {
        perror("huffman_encode");
        goto exit;
    }
    inp_size = inp_info.st_size;

    heap = get_stat(in_fd);
    if(!heap)
        goto exit;

    tree = build_tree(heap);
    if(!tree) {
        bheap_free(heap);
        goto exit;
    }
    free(heap->nodes);
    free(heap);

    if(get_alphabet(tree, alphabet) < 0)
        goto exit;

    if(lseek(in_fd, 0, SEEK_SET) < 0) {
        perror("huffman_encode");
        goto exit;
    }

    if(write(out_fd, &inp_size, sizeof(inp_size)) != sizeof(inp_size)) {
        perror("huffman_encode");
        goto exit;
    }

    if(write_tree(out_fd, tree) < 0)
        goto exit;

    if(encode(in_fd, out_fd, alphabet) < 0)
        goto exit;

    ret = 0;
exit:
    if(tree) bheap_node_free(tree);
    return ret;
}

/*
 * Decompress input file and write its content to the output.
 */
int huffman_decode(int in_fd, int out_fd) {
    int in_len, out_len=0;
    uint32_t decoded_len;
    bheap_node *tree=NULL, *node;
    int ret = -1;

    int st = read(in_fd, &decoded_len, sizeof(decoded_len));
    if(st < 0) {
        perror("huffman_decode");
        goto exit;
    }
    if(st != sizeof(decoded_len)) {
        fputs("huffman_decode: input file is too short", stderr);
        goto exit;
    }

    in_len = read(in_fd, in_buf, BUF_SIZE);
    if(in_len < 0) {
        perror("huffman_decode");
        goto exit;
    }

    size_t in_buf_off;
    tree = read_tree(in_len, &in_buf_off);
    if(!tree)
        goto exit;
    node = tree;
    if(in_buf_off == 0) {
        fputs("huffman_decode: input file is too short", stderr);
        goto exit;
    }

    while(decoded_len > 0) {
        for(size_t i = in_buf_off; i < in_len; i++) {
            uint8_t byte = in_buf[i];
            for(int j = 7; j >= 0; j--) {
                if(byte & (1 << j))
                    node = node->right;
                else
                    node = node->left;

                if(!node) {
                    fputs("huffman_decode: decode table is corrupted", stderr);
                    goto exit;
                }

                if(!node->left && !node->right) {
                    out_buf[out_len++] = node->byte;
                    decoded_len--;
                    node = tree;

                    if(out_len == BUF_SIZE || decoded_len == 0) {
                        if(write(out_fd, out_buf, out_len) != out_len) {
                            perror("huffman_decode");
                            goto exit;
                        }
                        out_len = 0;
                    }
                }
            }
        }

        in_len = read(in_fd, in_buf, BUF_SIZE);
        if(in_len == 0) {
            break;
        }
        if(in_len < 0) {
            perror("huffman_decode");
            goto exit;
        }
        in_buf_off = 0;
    }

    ret = 0;
exit:
    if(tree) bheap_node_free(tree);
    return ret;
}
