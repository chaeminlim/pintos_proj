#include "vm/swap.h"
#include "vm/page.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "kernel/bitmap.h"
#include "devices/block.h"


struct lock swap_lock;
struct bitmap* swap_bitmap;
extern struct semaphore filesys_sema;
struct block *swap_block;



void swap_init(void)
{
	swap_block = block_get_role (BLOCK_SWAP);
	swap_bitmap = bitmap_create(BLOCK_SECTOR_SIZE*block_size(swap_block)/PGSIZE);
	bitmap_set_all (swap_bitmap, 0);
	lock_init(&swap_lock);
}

size_t swap_out(struct page* page)
{
    int i;
	size_t empty_slot_index;
    lock_acquire(&swap_lock);
	
    empty_slot_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, 0);

	for (i = 0; i<SECTORS_PER_PAGE; i++)
	{
		block_write(swap_block, SECTORS_PER_PAGE*empty_slot_index + i, page->kaddr + i*BLOCK_SECTOR_SIZE);
	}
	page->vma->swap_slot = empty_slot_index;
	lock_release(&swap_lock);
	return empty_slot_index;
}

void swap_in(size_t used_index, void* kaddr)
{

    lock_acquire(&swap_lock);
	int i;

    if (bitmap_test(swap_bitmap, used_index) == 0)
	{
		return;
	}
	bitmap_flip(swap_bitmap, used_index);

	for (i = 0; i<SECTORS_PER_PAGE; i++)
	{
		block_read(swap_block, SECTORS_PER_PAGE*used_index + i, kaddr + i*BLOCK_SECTOR_SIZE);
	}
	lock_release(&swap_lock);
}

void swap_clear (size_t used_index)
{
    if (used_index-- == 0)
        return;
    lock_acquire (&swap_lock);
    bitmap_set_multiple (swap_bitmap, used_index, 1, false);
    lock_release (&swap_lock);
    }
