#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "vm/page.h"

void init_lru_list(void);
void add_page_lru(struct page*);
void delete_page_lru(struct page*);
struct page* get_victim(void);
struct list_elem* get_next_lru_clock(void);
struct page* find_page_from_lru_list(void *kaddr);
void swap_init(size_t used_index);
void swap_in(size_t used_index, void* kaddr);
size_t swap_out(void* kaddr);
void swap_pages(void);
void swap_clear (size_t used_index);

#endif