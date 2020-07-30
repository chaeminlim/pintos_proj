#ifndef VM_SWAP_H
#define VM_SWAP_H

#define SECTORS_PER_PAGE (PGSIZE/BLOCK_SECTOR_SIZE)
#include "vm/page.h"

void swap_init(void);
void swap_in(size_t used_index, void* kaddr);
size_t swap_out(struct page* page);
void swap_pages(void);
void swap_clear (size_t used_index);

#endif