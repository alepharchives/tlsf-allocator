#ifndef ALLOC_H
#define ALLOC_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define FL_RANGE 32U
#define SL_RANGE 16U

#define SL_RANGE_EXP 4U

#define TAG_OFFSET sizeof(size_t)

#define min(x, y) ((x < y) ? x : y)
#define max(x, y) ((x > y) ? x : y)

typedef struct _block_t {
    size_t size;
    struct _block_t *prev_phys; // prvious physical block
    struct _block_t *prev_bin; // previous bin block
    struct _block_t *next_bin; // next bin block  
} block_t;

block_t *split_block(block_t *block, size_t size);
void list_push(block_t *block);
block_t *list_pop(unsigned int fl, unsigned int sl);
void list_remove(block_t *block);

block_t *merge_left(block_t *block);
block_t *merge_right(block_t *block);

inline int is_block_free(size_t size);
inline void mark_block_used(block_t *block);
inline void mark_block_free(block_t *block);

block_t *find_suitable_block(size_t size);
inline size_t round_bin(size_t size);
void mapping_search(size_t size, unsigned int *fl, unsigned int *sl);
block_t *more_mem(size_t size);

unsigned int find_first_set(unsigned int i);
unsigned int find_last_set(unsigned int i);

inline block_t *ptr_to_block(void *ptr);
inline void *block_to_ptr(block_t *block);

size_t fl_bitmap = 0;
size_t sl_bitmaps[FL_RANGE];

block_t small_blocks[SL_RANGE];
block_t *blocks[FL_RANGE][SL_RANGE];
block_t *wilderness_block = NULL;

#endif
