#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "vm/page.h"

#define SECTORS_PER_PAGE (PGSIZE/BLOCK_SECTOR_SIZE)
void init_lru_list(void);
void add_page_lru(struct page*);
void delete_page_lru(struct page*);
struct page* get_victim(void);
struct list_elem* get_next_lru_clock(void);
struct page* find_page_from_lru_list(void *kaddr);

#endif