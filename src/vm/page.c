#include <inttypes.h>
#include <list.h>
#include <hash.h>
#include "vm/page.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"

unsigned int vm_hash_func(const struct hash_elem* e, void* aux);
bool vm_func_less (const struct hash_elem* e1,const struct hash_elem* e2, void* aux);

unsigned vm_hash_func(const struct hash_elem* e, void* aux)
{
    struct vm_area_struct* vma =  hash_entry(e, struct vm_area_struct, elem);
    return hash_int((int)vma->vaddr);
}

bool vm_func_less (const struct hash_elem* e1,const struct hash_elem* e2, void* aux)
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
    if(hash_delete(&mm_struct->vm_area_hash, &vma->elem) != NULL) return true;
    else return false;
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

void free_vma(struct hash_elem* e, void* aux)
{
    struct vm_area_struct* vma = hash_entry(e, struct vm_area_struct, elem);
    free_vaddr_page(vma->vaddr);
    free(vma);
}

void free_vaddr_page(void* vaddr)
{
    
    void* addr = pagedir_get_page(thread_current()->pagedir, pg_round_down(vaddr));
    //palloc_free_page();
}

void free_vm(struct mm_struct* mm)
{
    hash_destroy(&mm->vm_area_hash, free_vma);
}

mapid_t allocate_mapid()
{
    return thread_current()->mm_struct.next_mapid++;
}