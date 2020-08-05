#include "vm/page.h"
#include "vm/swap.h"
#include "vm/frame.h"
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
extern struct lock filesys_lock;

#define MAX_SWAP 1024
bool IN_SWAP_PAGES[MAX_SWAP];

void init_lru_list(void)
{
    int i = 0;
    for(; i < MAX_SWAP; i++) 
    {IN_SWAP_PAGES[i] = false;}    

    list_init(&lru_list);
    lock_init(&lru_lock);
    lru_clock = NULL;

}

void add_page_lru(struct page* page)
{
    lock_acquire(&lru_lock);
    list_push_back(&lru_list, &page->lru_elem);
    lock_release(&lru_lock);
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
    ASSERT(lru_lock.holder != thread_current());
    lock_acquire(&lru_lock);
    ASSERT(thread_current()->tid < MAX_SWAP);
    IN_SWAP_PAGES[thread_current()->tid] = true;
    struct page *victim = get_victim();
    //victim->vma->pinned = true;
    ASSERT (victim != NULL);
    ASSERT (victim->thread != NULL);
    ASSERT (victim->thread->magic == 0xcd6abf4b);
    ASSERT (victim->vma != NULL);
    ASSERT (victim->vma->loaded == PG_LOADED);
    bool dirty = pagedir_is_dirty(victim->thread->pagedir, victim->vma->vaddr);
    switch (victim->vma->type)
    {
        case PG_BINARY:
        {
            if (dirty)
            {
                victim->vma->swap_slot = swap_out(victim);
                victim->vma->loaded = PG_SWAPED;
                victim->vma->type = PG_ANON;
            }
            else
            {
                victim->vma->loaded = PG_NOT_LOADED;
            }
            break;
        }
            
        case PG_FILE:
        {
            if (dirty)
            {
                printf("addr %0x, status %d\n", victim->vma->vaddr, victim->vma->loaded);
                // 여기서 페이지 폴트 발생
                if (file_write_at(victim->vma->file, victim->vma->vaddr, victim->vma->read_bytes, victim->vma->offset)
                != (int) victim->vma->read_bytes) NOT_REACHED();
                //
            }
            victim->vma->loaded = PG_NOT_LOADED;    
            break;
        }
            
        case PG_ANON:
        {
            victim->vma->swap_slot = swap_out(victim);
            victim->vma->loaded = PG_SWAPED;
            
            break;
        }
        default:
            NOT_REACHED ();
    }
    free_page(victim);
    IN_SWAP_PAGES[thread_current()->tid] = false;
    lock_release(&lru_lock);
}

struct list_elem * get_next_lru_clock (void)
{
    ASSERT(lock_held_by_current_thread(&lru_lock));
    if (lru_clock == NULL || lru_clock == list_end (&lru_list))
    {
        if (list_empty (&lru_list)) return NULL;
        else return (lru_clock = list_front(&lru_list));
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

    do
    {
        e = get_next_lru_clock();
        ASSERT (e != NULL);
        page = list_entry (e, struct page, lru_elem);
        ASSERT(page != NULL);
        ASSERT (page->thread);
        ASSERT (page->thread->magic == 0xcd6abf4b);
        ASSERT (page->vma->loaded == PG_LOADED);

        if(!pagedir_is_accessed(page->thread->pagedir, page->vma->vaddr) && page->vma->pinned != true)
            break;
        pagedir_set_accessed(page->thread->pagedir, page->vma->vaddr, false);
    }while(1);
    
    
    return page;
}


// swaps
