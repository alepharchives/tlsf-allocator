#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "alloc.h"

void print_block(block_t* block, char* msg) {
     printf("%s block:%p size:%u pp:%p pb:%p nb:%p\n", 
        msg, block, block->size, block->prev_phys, block->prev_bin, block->next_bin);
}

void *calloc(size_t nmemb, size_t size)
{
	void *ptr = malloc(nmemb * size);
	
	if (ptr)
		memset(ptr, 0x00, nmemb * size);

	return ptr;
}

static int count = 0;
void *malloc(size_t size) {
    if (count == 0) {
        memset(sl_bitmaps, 0, FL_RANGE * sizeof(size_t));
        memset(blocks, 0, FL_RANGE * SL_RANGE * sizeof(block_t*));
        count++;
    }

    block_t *block = find_suitable_block(size);
    if (block == NULL) 
        return NULL;
  
    /*
    long rem_size = block->size - size;
    if (rem_size >= 4 * (int)TAG_OFFSET) {
        block_t *rem_block = split_block(block, size);
        //print_block(rem_block, "rem");
        list_push(rem_block);
    }*/

    //print_block(block, "malloc");

    mark_block_used(block);
    return block_to_ptr(block);
}

void free(void *ptr) {
	if (!ptr)
		return;
    
    block_t *block = ptr_to_block(ptr); 
    mark_block_free(block);

    //block = merge_left(block);

    //print_block(block, "ml");

    block = merge_right(block);
 
    list_push(block);
}

block_t *more_mem(size_t size) {     
    // Round size up to nearest multiple of 4
    size = (size + 3U) & ~3U;
    size = max(size, 2*TAG_OFFSET);

    unsigned int amt = size + 2*TAG_OFFSET;
    void *ptr = sbrk(amt);
    if (ptr == (void*) -1)
        return NULL;

    // Block bookkeeping
    block_t *retval = (block_t*) ptr; 
    retval->size = size;
    retval->prev_phys = wilderness_block;
    retval->prev_bin = NULL;
    retval->next_bin = NULL;

    // Set wilderness block
    wilderness_block = retval;

    return retval;
}

block_t *split_block(block_t *block, size_t size) {
    list_remove(block);
 
    size_t rem_size = block->size - size - 2U*TAG_OFFSET;
    block->size = size;

    block_t *rem_block = (block_t*)((char*) block + size + 2U*TAG_OFFSET);      
    rem_block->size = rem_size;
    rem_block->prev_phys = block;
    rem_block->prev_bin = NULL;
    rem_block->next_bin = NULL;

    mark_block_free(rem_block);
      
    print_block(block, "block");
    print_block(rem_block, "rem");

    return rem_block;
}

void list_push(block_t *block) {
    unsigned int fl, sl;
    mapping_search(block->size, &fl, &sl);
 
    block->prev_bin = NULL;
    block->next_bin = NULL;
    if (blocks[fl][sl] != NULL) { 
        blocks[fl][sl]->prev_bin = block;
        block->next_bin = blocks[fl][sl];
    }
    blocks[fl][sl] = block;
    fl_bitmap |= (1 << fl);
    sl_bitmaps[fl] |= (1 << sl);
}

block_t *list_pop(unsigned int fl, unsigned int sl) {
    block_t *retval = blocks[fl][sl];
    if (retval != NULL) {
        block_t *new_head = retval->next_bin;
        if (new_head == NULL) { 
            sl_bitmaps[fl] &= ~(1 << sl);
            if (!sl_bitmaps[fl])
                fl_bitmap &= ~(1 << fl);
        } else { 
            new_head->prev_bin = NULL;
        }

        blocks[fl][sl] = new_head;     
        retval->next_bin = NULL;
    }
    return retval;
}

void list_remove(block_t *block) {
    if (block->prev_bin == NULL) {
        unsigned int fl, sl;
        mapping_search(block->size, &fl, &sl);
        list_pop(fl, sl);
    } else {
        if (block->next_bin != NULL)
            block->next_bin->prev_bin = block->prev_bin;
        if (block->prev_bin != NULL) 
            block->prev_bin->next_bin = block->next_bin;
    }
}

// 0 for free, 1 for in use
#define BLOCK_FREE_BIT 1 

// OK to add sizes, free bit is cleared anyways
block_t *merge_left(block_t *block) {
    if (block->prev_phys== NULL || !(is_block_free(block->prev_phys->size)))
        return block;

    block_t *prev_phys_block = block->prev_phys;
    list_remove(prev_phys_block);

    if (block == wilderness_block) {
        wilderness_block = prev_phys_block;
    } else {
        block_t *next_phys_block = (block_t*)((char*) block + block->size + 2*TAG_OFFSET); 
        next_phys_block->prev_phys = prev_phys_block;
    }

    size_t new_size = block->size + 2*TAG_OFFSET + prev_phys_block->size;
    prev_phys_block->size = new_size;

    return prev_phys_block;
}

block_t *merge_right(block_t *block) {
    if (wilderness_block == block ) 
        return block;

    block_t *next_phys_block = (block_t*)((char*) block + 2*TAG_OFFSET + block->size);
    if (is_block_free(next_phys_block->size)) {
        list_remove(next_phys_block);

        size_t new_size = block->size + 2*TAG_OFFSET + next_phys_block->size;
        block->size = new_size;
        if (next_phys_block == wilderness_block) 
            wilderness_block = block;
    }
    return block;
}

inline int is_block_free(size_t size) {
    return (size & BLOCK_FREE_BIT) == 0;
}

inline void mark_block_used(block_t *block) {
    block->size |= 1;
}

inline void mark_block_free(block_t *block) {
    block->size &= ~1;  
}

// very ghetto round up
inline size_t round_bin(size_t size) {
    return size + (1 << (find_last_set(size) - SL_RANGE_EXP)) - 1;
}

block_t *find_suitable_block(size_t size) {
    unsigned int fl, sl, bin;
    bin = round_bin(size);
    mapping_search(bin, &fl, &sl);

    //printf("fl:%u sl:%u size:%u\n", fl, sl, size);

    unsigned int sl_mask = sl_bitmaps[fl] & (~0 << sl);
    if (sl_mask) {
        return list_pop(fl, find_first_set(sl_mask));
    } else {
        unsigned int fl_mask = fl_bitmap & (~0 << (fl + 1));
        fl = find_first_set(fl_mask);
        if (fl > 0) {
            sl = find_first_set(sl_bitmaps[fl]); 
            return list_pop(fl, sl);
        } else {
            return more_mem(size); 
        }
    }
}

void mapping_search(size_t size, unsigned int *fl, unsigned int *sl) {
    *fl = find_last_set(size);
    *sl = (size >> (*fl - SL_RANGE_EXP)) - SL_RANGE;
}

unsigned int find_first_set(unsigned int i) {
    unsigned int bit;
    asm volatile("bsf %1, %0;"
        :"=r"(bit)
        :"r"(i)  
    );  
    return bit;
}

unsigned int find_last_set(unsigned int i) {
    unsigned int bit;
    asm volatile("bsr %1, %0;"
        :"=r"(bit)    
        :"r"(i) 
    ); 
    return bit;
}

inline block_t *ptr_to_block(void *ptr) {
    return (block_t*)(((char*) ptr) - 2*TAG_OFFSET);
}

inline void *block_to_ptr(block_t *block) {
    return (void*)(((char*) block) + 2*TAG_OFFSET);
}

void *realloc(void *ptr, size_t size)
{
	if (!ptr) {
		return malloc(size);
	} else if (!size) {
		free(ptr);
		return NULL;
	} else {
        block_t *block = ptr_to_block(ptr); 
        size_t old_size = block->size & ~BLOCK_FREE_BIT;
        void *new_ptr = malloc(size);
        
        if (new_ptr == NULL) 
            return NULL;
            
        memcpy(new_ptr, ptr, min(old_size, size));        
        free(ptr);
        return new_ptr;
    }
}
