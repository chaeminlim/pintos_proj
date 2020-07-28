#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "vm/page.h"
#include "vm/swap.h"

extern struct semaphore filesys_sema;
extern struct lock lru_lock;
extern struct semaphore writer_sema;
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  char* save_ptr, *exe_name;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  //fn_copy = palloc_get_page (PAL_ZERO);
  fn_copy = malloc(2*(strlen(file_name) + 1));

  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, strlen(file_name) + 1);
  strlcpy (fn_copy + strlen(file_name) + 1, file_name, strlen(file_name) + 1);
  exe_name = strtok_r(fn_copy + strlen(file_name) + 1, " ", &save_ptr);
  
  /* Create a new thread to execute ;FILE_NAME. */
  tid = thread_create(exe_name, PRI_DEFAULT, start_process, fn_copy);

  if (tid == TID_ERROR)
  {
    palloc_free_page (fn_copy);
  }
  return tid; 
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  struct thread *t = thread_current();
  char *file_name = file_name_;
  struct intr_frame if_;

  // vm initialization
  init_vm(&t->mm_struct.vm_area_hash);

/* Initialize interrupt frame and load executable. */  
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  t->load_status = load (file_name, &if_.eip, &if_.esp);
  /* If load failed, quit. */
  //hex_dump( if_.esp,  if_.esp, PHYS_BASE -  if_.esp, true);
  sema_up (&t->sema_load); // 부모의 exec을 재개 시킨다
  //palloc_free_page (pg_round_down(file_name));
  free(file_name_ );
  if (!t->load_status) 
  {
    //thread_exit ();
    exit(-1);
  }
  
    
  //set_argument_stack(file_name, )
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

  //hex_dump(if_.esp, if_.esp, PHYS_BASE - if_.esp, true);

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *child;
  int exit_status;
  child = get_child_thread(child_tid);
  if(child == NULL) return -1;

  sema_down(&child->sema_wait);
  list_remove (&child->child_list_elem);
  exit_status = child->exit_code;
  sema_up (&child->sema_exit);
  return exit_status;
}
/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
// clear fd
  int i = 0;
  for(; i < 128; i++)
  {
    if(cur->fd_table[i] != NULL) file_close(cur->fd_table[i]);
  }
  //palloc_free_page (cur->fd_table);
  
  int mapid = 0;
  for(; mapid < cur->mm_struct.next_mapid; mapid++)
  {
    
    struct mmap_struct *mmstrt = find_mmap_struct(mapid);
      if (mmstrt)
        remove_mmap (cur ,mmstrt);
  }

  #ifdef USERPROG
  file_close(cur->executing_file);
  #endif
  free(cur->fd_table);
  // clear vm
  free_vm(&cur->mm_struct);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char* file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);


/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;


  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
  {
    goto done;
  }
  process_activate (); 

  sema_down (&filesys_sema);
  /* Open executable file. */
  file = filesys_open (t->name);
  
  if (file == NULL) 
  {
    sema_up(&filesys_sema);
    printf ("load: %s: open failed\n", file_name);
    goto done; 
  }

  t->executing_file = file;
  file_deny_write (t->executing_file);
  sema_up(&filesys_sema);
  
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  // 파일 오프셋을 옮김
  file_seek (file, ofs);
  // readbytes가 0이하거나 zero_bytes가 0 이하면 에러
  // read + zero = > 페이지 크기
  // 현재 load_segment는 전체 페이지를 불러옴
  // demanding으로 수정
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      /* Get a page of memory. */
      /* uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);
      // 한 페이지 할당 완료

      // Add the page to the process's address space.
      // 프로세스의 주소 공간에 install함
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
         */
      // vm codes
      struct vm_area_struct* vma = (struct vm_area_struct*)malloc(sizeof(struct vm_area_struct));
      if (vma == NULL) return false;
      memset (vma, 0, sizeof (struct vm_area_struct));
      vma->read_bytes = page_read_bytes;
      vma->zero_bytes = page_zero_bytes;
      vma->file = file;
      vma->offset = ofs;
      vma->vaddr = upage;
      vma->type = PG_BINARY;
      vma->read_only = !writable;
      vma->loaded = false;
      insert_vma(&thread_current()->mm_struct, vma);
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char* cmd_line) 
{
  struct page* kpage;
  bool success = false;

  kpage = allocate_page(PAL_USER | PAL_ZERO, NULL);
  
  lock_acquire(&lru_lock);
  add_page_lru(kpage);
  lock_release(&lru_lock);

  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage->kaddr, true);
      if (success) // install page가 성공했을 때, 여기서 부터 argument passing 적용
      {
        // vm
        struct vm_area_struct* vma = (struct vm_area_struct*)malloc(sizeof(struct vm_area_struct));
        if (vma == NULL) return false;
        memset(vma, 0, sizeof(struct vm_area_struct));
        vma->loaded = true;
        vma->vaddr = (uint8_t*)PHYS_BASE - PGSIZE;
        vma->type = PG_ANON;
        vma->read_only = false;
        kpage->vma = vma;
        insert_vma(&thread_current()->mm_struct, vma);
        
        
        *esp = PHYS_BASE;
        // setting argument 시작
        uint8_t* temp_head;
        int total_len = 0;
        int argc = 0;

        // 스택 포인터의 주소를 내리면서, 낮은 주소에서 높은 방향으로 문자열을 쌓아야 함.
        
        // argument string 쌓기
        
        int arg_len = strlen(cmd_line);
        
        *esp -= 1;
        *(uint8_t*) (*esp + 1) = '\0';
        *esp -= arg_len;
        memcpy(*esp, cmd_line, arg_len);
        total_len += (arg_len + 1);
        
        // 띄어쓰기 널 처리
        int index = total_len;
        for(; index >= 0; index--)
        {
          temp_head = (*esp + index); // top 부터 시작
          //printf("%c!\n", *(char*)temp_head);
          if(*temp_head == ' ') 
          { 
            *temp_head = '\0';
          }
        }
        // alignment 하기
        if(total_len % 4 != 0)
        {
          *esp -= (4 - total_len % 4);
        }

        // push argv[argc]
        *esp -= 4;
        * (uint32_t *) *esp = (uint32_t) NULL;
        
          // 맨 윗주소는 '\0'
        for(index = 0; index <= total_len - 1; index++)
        {
          temp_head = (PHYS_BASE - index); // top - 1 부터 시작
          if(*temp_head != '\0' && *(temp_head - 1) == '\0')
          {
            *esp -= 4;
            *(uint32_t *) *esp = (uint32_t) temp_head;
            argc++;
          }
        }

        /*push exe name*/
        *esp -= 4;
        * (uint32_t *) *esp = (uint32_t) (PHYS_BASE - total_len);
        argc++;

        // push argv
        * (uint32_t *) (*esp - 4) = *(uint32_t *) esp;
        *esp -= 4;

        /*push argc*/
        *esp -= 4;
        * (int *) *esp = argc;
        
        /*push return address*/
        *esp -= 4;
        * (uint32_t *) *esp = 0x0;
       
      }
      else
        free_kaddr_page(kpage->kaddr);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


bool load_file (void *kaddr, struct vm_area_struct *vma)
{
  ASSERT (kaddr != NULL);
  ASSERT (vma != NULL);
  ASSERT (vma->type == PG_BINARY || vma->type == PG_FILE);

  if (file_read_at (vma->file, kaddr, vma->read_bytes, vma->offset) != (int) vma->read_bytes)
    {
      return false;
    }

  memset (kaddr + vma->read_bytes, 0, vma->zero_bytes);
  return true;
}



bool allocate_vm_page_mm(struct vm_area_struct* vma)
{
  struct page* kpage = allocate_page(PAL_USER, vma);
  ASSERT (kpage != NULL);
  ASSERT (pg_ofs (kpage->kaddr) == 0);
  ASSERT (vma != NULL);
  // vma의 타입에 따라
  switch(vma->type)
  {
    case PG_BINARY:
    case PG_FILE:
    {
      if (!load_file (kpage->kaddr, vma) ||
          !install_page (vma->vaddr, kpage->kaddr, !vma->read_only))
        {
          NOT_REACHED();
        }
      vma->loaded = true;
      
      lock_acquire(&lru_lock);
      add_page_lru(kpage);
      lock_release(&lru_lock);
      
      return true;
    }
    case PG_ANON:
    {
      swap_in (vma->swap_slot, kpage->kaddr);
      ASSERT (pg_ofs (kpage->kaddr) == 0);
      if (!install_page (vma->vaddr, kpage->kaddr, !vma->read_only))
        {
          NOT_REACHED ();
          free_kaddr_page(kpage);
          return false; 
        }
      vma->loaded = true;
      lock_acquire(&lru_lock);
      add_page_lru(kpage);
      lock_release(&lru_lock);
      return true;
    }
    default:
        NOT_REACHED();
  }
}

void remove_mmap(struct thread* curr, struct mmap_struct* mmapstrt)
{
  sema_down(&writer_sema);
  struct list_elem *e;
  for (e = list_begin (&mmapstrt->vma_list); e != list_end (&mmapstrt->vma_list); )
  {
    struct vm_area_struct* vma = list_entry (e, struct vm_area_struct, mmap_elem);
    if (vma->loaded && pagedir_is_dirty(curr->pagedir, vma->vaddr))
    {
      if (file_write_at (vma->file, vma->vaddr, vma->read_bytes, vma->offset) != (int) vma->read_bytes)
      {   NOT_REACHED (); }
      free_vaddr_page(vma->vaddr);
    }
    vma->loaded = false;
    e = list_remove(e);
    delete_vma(&curr->mm_struct, vma); 
  }
  list_remove(&mmapstrt->mmap_elem);
  free(mmapstrt);
  sema_up(&writer_sema);
}