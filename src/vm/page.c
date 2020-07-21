#include <inttypes.h>
#include <list.h>
#include <hash.h>
#include "vm/page.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

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
    //palloc_free_page(); 페이지 할당을 해제 해줘야함 . 페이지 물리 주소 필요 
    free(vma);
}

void free_vm(struct mm_struct* mm)
{
    hash_destroy(&mm->vm_area_hash, free_vma);
}