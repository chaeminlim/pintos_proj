#include "vm/swap.h"
#include "vm/page.h"
#include "vm/frame.h"
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
	if(swap_block == NULL) NOT_REACHED ();
	size_t swap_size = block_size(swap_block) / (PGSIZE / BLOCK_SECTOR_SIZE);
	swap_bitmap = bitmap_create(swap_size);
	bitmap_set_all (swap_bitmap, true);
	lock_init(&swap_lock);
}

size_t swap_out(struct page* page)
{
    int i;
	ASSERT(!lock_held_by_current_thread(&swap_lock));
    lock_acquire(&swap_lock);
	
    size_t swap_index = bitmap_scan(swap_bitmap, 0, 1, true);

	for (i = 0; i<SECTORS_PER_PAGE; i++)
	{
		block_write(swap_block, 
		SECTORS_PER_PAGE*swap_index + i, 
		page->kaddr + (i*BLOCK_SECTOR_SIZE));
	}
	page->vma->swap_slot = swap_index;
	bitmap_set(swap_bitmap, swap_index, false);
	lock_release(&swap_lock);
	return swap_index;
}

void swap_in(size_t swap_index, void* kaddr)
{
	ASSERT(!lock_held_by_current_thread(&swap_lock));
    lock_acquire(&swap_lock);

	if(swap_index == 0xFFFFFFFF)
	{
		lock_release(&swap_lock);
		return;
	}
    if (bitmap_test(swap_bitmap, swap_index) == true)
	{
		NOT_REACHED();
	}
	size_t i;
	for (i = 0; i < SECTORS_PER_PAGE; i++) 
	{
		block_read (swap_block,
		swap_index * SECTORS_PER_PAGE + i,
		kaddr + (BLOCK_SECTOR_SIZE * i)
		);
	}
	bitmap_set(swap_bitmap, swap_index, true);
	
	lock_release(&swap_lock);
}

void swap_clear (size_t swap_index)
{
	ASSERT(!lock_held_by_current_thread(&swap_lock));
    lock_acquire(&swap_lock);
    if(swap_index == 0xFFFFFFFF)
	{
		lock_release(&swap_lock);
		return;
	}
	if (bitmap_test(swap_bitmap, swap_index) == true) 
	{
	}
	else
	{
		bitmap_set(swap_bitmap, swap_index, true);
	}
    lock_release (&swap_lock);
}
