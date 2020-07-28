#include "vm/swap.h"
#include "vm/page.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "kernel/bitmap.h"
#include "devices/block.h"

struct list lru_list;
struct lock lru_lock;
struct list_elem* lru_clock;
struct semaphore swap_sema;
struct bitmap* swap_bitmap;
extern struct semaphore filesys_sema;



void init_lru_list(void)
{
    list_init(&lru_list);
    lock_init(&lru_lock);
    lru_clock = NULL;

}

void add_page_lru(struct page* page)
{
    ASSERT(lock_held_by_current_thread(&lru_lock));
    list_push_back(&lru_list, &page->lru_elem);
}

void delete_page_lru(struct page* page)
{
    ASSERT(lock_held_by_current_thread(&lru_lock));

    if (lru_clock == &page->lru_elem)
    {
      lru_clock = list_remove (lru_clock);
    }
  else
    {
      list_remove (&page->lru_elem);
    }
}

struct page* find_page_from_lru_list(void *kaddr)
{
    ASSERT(lock_held_by_current_thread(&lru_lock));
    ASSERT (pg_ofs(kaddr) == 0);

    struct list_elem *e;
    for (e = list_begin (&lru_list); e != list_end (&lru_list); e = list_next (e))
    {
        struct page *page = list_entry (e, struct page, lru_elem);
        ASSERT (page);
        if (page->kaddr == kaddr) return page;
    }
    return NULL;
}


// swap
void swap_pages()
{
    lock_acquire(&lru_lock);
    
    struct page *victim = get_victim();
    ASSERT (victim != NULL);
    ASSERT (victim->thread != NULL);
    ASSERT (victim->thread->magic == 0xcd6abf4b);
    ASSERT (victim->vma != NULL);
    bool dirty = pagedir_is_dirty (victim->thread->pagedir, victim->vma->vaddr);
    
    switch (victim->vma->type)
    {
        case PG_BINARY:
        {
            if (dirty)
            {
                victim->vma->swap_slot = swap_out(victim->kaddr);
                victim->vma->type = PG_ANON;
            }
            break;
        }
            
        case PG_FILE:
        {
            if (dirty)
            {
                if (file_write_at (victim->vma->file, victim->vma->vaddr, victim->vma->read_bytes, victim->vma->offset)
                != (int) victim->vma->read_bytes) NOT_REACHED();
            }
            break;
        }
            
        case PG_ANON:
        {
            victim->vma->swap_slot = swap_out(victim->kaddr);
            break;
        }
        default:
            NOT_REACHED ();
    }
    victim->vma->loaded = false;
    lock_release(&lru_lock);
    free_kaddr_page(victim->kaddr);
    
}

struct list_elem * get_next_lru_clock (void)
{
    ASSERT(lock_held_by_current_thread(&lru_lock));
    if (lru_clock == NULL || lru_clock == list_end (&lru_list))
    {
        if (list_empty (&lru_list)) return NULL;
        else return (lru_clock = list_begin (&lru_list));
    }
    lru_clock = list_next (lru_clock);
    if (lru_clock == list_end (&lru_list)) return get_next_lru_clock ();
    return lru_clock;
}

struct page* get_victim (void)
{
    ASSERT(lock_held_by_current_thread(&lru_lock));
    struct page *page;
    struct list_elem *e;
    
    e = get_next_lru_clock();
    ASSERT (e != NULL);
    page = list_entry (e, struct page, lru_elem);

    while (pagedir_is_accessed (page->thread->pagedir, page->vma->vaddr))
    {
        pagedir_set_accessed (page->thread->pagedir, page->vma->vaddr, false);
        e = get_next_lru_clock();
        ASSERT (e != NULL);
        page = list_entry (e, struct page, lru_elem);
        ASSERT (page);
    }
    
    return page;
}


// swaps


void swap_init(size_t size)
{
    sema_init(&swap_sema, 1);
    swap_bitmap = bitmap_create (size); 
}

void swap_in(size_t used_index, void* kaddr)
{
    struct block* swap_block;
    swap_block = block_get_role(BLOCK_SWAP);
    if(used_index-- == 0) NOT_REACHED();
    sema_down (&filesys_sema);
    sema_down (&swap_sema);
    used_index <<= 3;
    int i;
    for (i = 0; i < 8; i++)
    {
        block_read(swap_block, used_index + i, kaddr + BLOCK_SECTOR_SIZE * i);
    }
    used_index >>= 3;
    bitmap_set_multiple(swap_bitmap, used_index, 1, false);
    ASSERT (pg_ofs (kaddr) == 0);
    sema_up(&swap_sema);
    sema_up(&filesys_sema);
}

size_t swap_out(void* kaddr)
{
    struct block *swap_block;
    swap_block = block_get_role (BLOCK_SWAP);

    sema_down (&filesys_sema);
    sema_down (&swap_sema);

    ASSERT (pg_ofs (kaddr) == 0);
    size_t swap_index;
    swap_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
    if (BITMAP_ERROR == swap_index)
    {
    NOT_REACHED();
    return BITMAP_ERROR;
    }
    swap_index <<= 3;
    int i;
    for (i = 0; i < 8; i++)
    block_write (swap_block, swap_index + i, kaddr + BLOCK_SECTOR_SIZE * i);
    swap_index >>= 3;

    ASSERT (pg_ofs (kaddr) == 0);

    sema_up(&swap_sema);
    sema_up(&filesys_sema);

    return swap_index + 1;
}

void swap_clear (size_t used_index)
{
    if (used_index-- == 0)
        return;
    sema_down (&swap_sema);
    bitmap_set_multiple (swap_bitmap, used_index, 1, false);
    sema_up(&swap_sema);
}
