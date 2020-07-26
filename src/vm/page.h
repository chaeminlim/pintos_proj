#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <inttypes.h>
#include <list.h>
#include <hash.h>
#include "filesys/file.h"

typedef int mapid_t;

enum PG_TYPE
{
    PG_BINARY,
    PG_ANON,
    PG_FILE
};

struct vm_area_struct
{
    bool loaded;
    bool read_only;
    enum PG_TYPE type;
    unsigned long vm_end;
    struct file* file;
    void* vaddr;
    size_t offset;
    size_t read_bytes;
    size_t zero_bytes;
    struct hash_elem elem;
    struct list_elem mmap_elem;
};

struct mm_struct
{
    struct hash vm_area_hash;
    struct list mmap_list;
    mapid_t next_mapid;
    // pgd
};

struct mmap_struct
{
    mapid_t mapid; 
    struct file* file;
    struct list vma_list;
    struct list_elem mmap_elem;
};

void init_vm(struct hash*);
bool delete_vma(struct mm_struct* mm_struct, struct vm_area_struct* vma);
bool insert_vma(struct mm_struct* mm_struct, struct vm_area_struct* vma);
void free_vm(struct mm_struct* mm);
void free_vma(struct hash_elem* e, void* aux);
struct vm_area_struct* get_vma_with_vaddr(struct mm_struct* mm_struct, void* vaddr);
mapid_t allocate_mapid(void);
void free_vaddr_page(void* vaddr);
struct mmap_struct* find_mmap_struct(mapid_t mapping);


#endif
