#include <inttypes.h>
#include <list.h>
#include <hash.h>
#include "vm/page.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "lib/string.h"
#include "vm/swap.h"
#include <stdio.h>

extern struct lock lru_lock;

unsigned int vm_hash_func(const struct hash_elem* e, void* aux);
bool vm_func_less (const struct hash_elem* e1,const struct hash_elem* e2, void* aux);

struct page* allocate_page(enum palloc_flags flags, struct vm_area_struct* vma)
{
    struct page* page = (struct page*)malloc(sizeof(struct page));
    if(page == NULL) return NULL;
    memset (page, 0, sizeof (struct page));
    page->thread = thread_current();
    page->vma = vma;
    page->kaddr = palloc_get_page(flags);
    while(page->kaddr == NULL)
    {
        swap_pages();
        page->kaddr = palloc_get_page(flags);
    }
    return page;
}



struct mmap_struct* find_mmap_struct(mapid_t mapping)
{
    struct list_elem *e;
    for (e = list_begin (&thread_current ()->mm_struct.mmap_list);
        e != list_end (&thread_current ()->mm_struct.mmap_list);
        e = list_next (e))
        {
        struct mmap_struct *f = list_entry (e, struct mmap_struct, mmap_elem);
        // 같은 것을 찾았으면 바로 반환합니다.
        if (f->mapid == mapping)
            return f;
        }
  // 찾지 못했습니다.
  return NULL; 
}

unsigned vm_hash_func(const struct hash_elem* e, void* aux UNUSED)
{
    struct vm_area_struct* vma =  hash_entry(e, struct vm_area_struct, elem);
    return hash_int((int)vma->vaddr);
}

bool vm_func_less (const struct hash_elem* e1,const struct hash_elem* e2, void* aux UNUSED)
{
    struct vm_area_struct* vma1 =  hash_entry(e1, struct vm_area_struct, elem);
    struct vm_area_struct* vma2 =  hash_entry(e2, struct vm_area_struct, elem);
    return ((uint32_t)vma1->vaddr < (uint32_t)vma2->vaddr);
}

void init_vm(struct hash* hash_table)
{
    hash_init(hash_table, vm_hash_func, vm_func_less, NULL);
}

bool insert_vma(struct mm_struct* mm_struct, struct vm_area_struct* vma)
{
    if (hash_insert(&mm_struct->vm_area_hash, &vma->elem) == NULL) return true;
    else return false;
}

bool delete_vma(struct mm_struct* mm_struct, struct vm_area_struct* vma)
{
    if(!hash_delete(&mm_struct->vm_area_hash, &vma->elem)) return false;
    free_vaddr_page(vma->vaddr);
    swap_clear (vma->swap_slot);
    free(vma);
    return true;
}

// if fail return NULL
struct vm_area_struct* get_vma_with_vaddr(struct mm_struct* mm_struct, void* vaddr)
{
    struct vm_area_struct vma;
    struct hash_elem *elem;

    vma.vaddr = pg_round_down (vaddr);
    ASSERT (pg_ofs (vma.vaddr) == 0);
    elem = hash_find (&mm_struct->vm_area_hash, &vma.elem);
    return elem ? hash_entry (elem, struct vm_area_struct, elem) : NULL;
}

void destroy_vma(struct hash_elem* e, void* aux UNUSED)
{
    ASSERT (e != NULL);
    struct vm_area_struct* vma = hash_entry(e, struct vm_area_struct, elem);
    free_vaddr_page(vma->vaddr);
    swap_clear(vma->swap_slot);
    free(vma);
}

void free_vaddr_page(void* vaddr)
{
    void* kaddr = pagedir_get_page (thread_current ()->pagedir, vaddr);
    free_kaddr_page (kaddr);
}

void free_kaddr_page(void* kaddr)
{
    if(kaddr == NULL) return;
    lock_acquire(&lru_lock);
    struct page *page = find_page_from_lru_list(kaddr);
    if (page)
    {
        ASSERT (page->thread->magic == 0xcd6abf4b);
        ASSERT (page->vma != NULL);
        pagedir_clear_page (page->thread->pagedir, page->vma->vaddr);
        delete_page_lru(page);
        palloc_free_page(page->kaddr);
        //delete_vma(&thread_current()->mm_struct, page->vma);
        free(page);
    }
    lock_release(&lru_lock);
}

void free_vm(struct mm_struct* mm)
{
    hash_destroy(&mm->vm_area_hash, destroy_vma);
}

mapid_t allocate_mapid()
{
    mapid_t ret = thread_current()->mm_struct.next_mapid;
    thread_current()->mm_struct.next_mapid += 1;
    return ret;
}

