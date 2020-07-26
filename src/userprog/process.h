#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"

typedef int tid_t;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool allocate_vm_page_mm(struct vm_area_struct* vma);
bool load_file (void *kaddr, struct vm_area_struct *vma);
#endif /* userprog/process.h */
