#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "lib/stdio.h"
#include "devices/input.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include <string.h>
#include "vm/frame.h"

static void syscall_handler (struct intr_frame *);
tid_t exec(const char* cmd_line);
int wait(tid_t);
bool create(const char* file, unsigned intial_size);
bool remove(const char* file);
int open(char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void is_string_safe(char* str);
void is_buffer_safe(void* buffer, unsigned int size);  
mapid_t mmap(int fd, void *addr);
void munmap(mapid_t mapping);

struct semaphore filesys_sema;
struct semaphore writer_sema;
struct semaphore mutex;
int reader_count;

void
syscall_init (void)
{
  sema_init(&filesys_sema, 1);
  sema_init(&writer_sema, 1);
  sema_init(&mutex, 1);
  reader_count = 0;
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{ 
  int syscall_number = *(int*)(f->esp);
  //printf ("system call! number: %d\n", syscall_number);
  
  switch(syscall_number)
  {
    case SYS_HALT:
    {
      halt();
      NOT_REACHED();
      break;
    }
    case SYS_EXIT:
    {
      is_safe_addr(f->esp + 4);
      exit(*(int*)(f->esp + 4));
      NOT_REACHED();
      break;
    }
    case SYS_EXEC:
    {
      is_safe_addr(f->esp + 4);
      char* cmd_line = (char*)*((int*)f->esp + 1);
      uint32_t return_code = exec(cmd_line);
      f->eax = return_code;
      break;
    }
    case SYS_WAIT:
    {
      is_safe_addr(f->esp + 4);
      tid_t pid = *(int*)(f->esp + 4);
      int ret = wait(pid);
      f->eax = ret;
      break;
    }
    case SYS_CREATE:
    {
      is_safe_addr(f->esp + 4);
      is_safe_addr(f->esp + 8);
      char* file = (char*)*((int*)f->esp + 1);
      is_string_safe(file);
      unsigned int initial_size = *(unsigned int*)(f->esp + 8);
      f->eax = create(file, initial_size);
      break;
    }
    case SYS_REMOVE:
    {
      is_safe_addr(f->esp + 4);
      char* file = (char*)*((int*)f->esp + 1);
      is_string_safe(file);
      f->eax = remove(file);
      break;
    }
    case SYS_OPEN:
    {
      is_safe_addr(f->esp + 4);
      char* file = (char*)*((int*)f->esp + 1);
      is_string_safe(file);
      f->eax = open(file);
      break;
    }
    case SYS_FILESIZE:
    {
      is_safe_addr(f->esp + 4);
      int fd = *(int*)(f->esp+4);
      f->eax = filesize(fd);
      break;
    }
    case SYS_READ:
    {
      is_safe_addr(f->esp + 12);
      is_safe_addr(f->esp + 8); 
      is_safe_addr(f->esp + 4); 
      unsigned int size = *(unsigned int*)(f->esp+12);
      void* buffer = (void*)*((int*)f->esp + 2);
      is_buffer_safe(buffer, size); 
      int fd = *(int*)(f->esp+4);
      f->eax = read(fd, buffer, size);
      break;
    }
    case SYS_WRITE:
    {
      is_safe_addr(f->esp + 12);
      is_safe_addr(f->esp + 8);
      is_safe_addr(f->esp + 4);
      unsigned int size = *(unsigned int*)(f->esp+12);
      void* str = (char*)*((int*)f->esp + 2);
      is_string_safe(str);
      int fd = *(int*)(f->esp+4);
      f->eax = write(fd, str, size);
      break;
    }
    case SYS_SEEK:
    {
      is_safe_addr(f->esp + 8);
      is_safe_addr(f->esp + 4);
      unsigned int position = *(unsigned*)(f->esp+8);
      int fd = *(int*)(f->esp+4);
      seek(fd, position);
      break;
    }
    case SYS_TELL:
    {
      is_safe_addr(f->esp + 4);
      int fd = *(int*)(f->esp+4);
      f->eax = tell(fd);
      break;
    }
    case SYS_CLOSE:
    {
      is_safe_addr(f->esp + 4);
      int fd = *(int*)(f->esp+4);
      close(fd);
      break;
    }
    case SYS_MMAP:
    {
      is_safe_addr(f->esp + 8);
      is_safe_addr(f->esp + 4);
      int fd = *(int*)(f->esp+4);
      void* addr = (void*)*((int*)f->esp + 2);
      f->eax = mmap(fd, addr);
      break;
    }                   /* Map a file into memory. */
    case SYS_MUNMAP:
    {
      is_safe_addr(f->esp + 4);
      mapid_t mapid = *(mapid_t*)(f->esp+4);
      munmap(mapid);
      break;
    }
    default:
    {
      exit(-1);
    }
  }
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  thread_current ()->exit_code = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

tid_t exec(const char *file) 
{
  tid_t tid;
  struct thread* child;
  if ((tid = process_execute (file)) == -1) return -1;
  child = get_child_thread(tid);
  ASSERT (child);
  sema_down (&child->sema_load);
  if (!child->load_status) return -1;
  return tid;
}

int wait(tid_t tid) 
{
  return process_wait(tid);
}

bool create(const char* file, unsigned initial_size)
{

  return filesys_create(file, initial_size);
}

bool remove(const char* file)
{
  return filesys_remove(file);
}

int filesize(int fd)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd] == NULL) return -1;
  else return file_length(t->fd_table[fd]);
}

void seek(int fd, unsigned position)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd] == NULL) return;
  else file_seek(t->fd_table[fd], position);
}

unsigned tell(int fd)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd] == NULL) return -1;
  else return file_tell(t->fd_table[fd]);
}

void close(int fd)
{
  sema_down (&filesys_sema);
  struct thread* t = thread_current();
  if(t->fd_table[fd] == NULL) {sema_up (&filesys_sema);return;}
  file_close(t->fd_table[fd]);
  t->fd_table[fd] = NULL;
  sema_up (&filesys_sema);
}
// finished
int open(char *file)
{
  struct file* opened_file = NULL;
  int fd_num;

  sema_down (&filesys_sema);
  opened_file = filesys_open(file);
  
  if(opened_file == NULL)
  {
    sema_up (&filesys_sema);
    return -1;
  }
  else
  {
    fd_num = allocate_fd_id(thread_current());
    if(fd_num == -1) {sema_up (&filesys_sema); return -1;}
    thread_current()->fd_table[fd_num] = opened_file;
    sema_up (&filesys_sema);
    return fd_num;
  }
}

int read(int fd, void* buffer, unsigned size)
{
  sema_down(&filesys_sema);
  
  /* sema_down(&mutex);
  reader_count++;
  if(reader_count == 1) sema_down(&writer_sema);
  sema_up(&mutex);
   *///printf("read!\n");
  struct thread* curr = thread_current();
  int ret;
  if(fd == 1) ret = -1;
  else if(fd == 0) 
  {
    unsigned int i = 0;
    for(; i < size; i++)
    {
      ((char*)buffer)[i] = input_getc();
    }
    ret = size;
  }
  else
  {
    if(curr->fd_table[fd] == NULL) ret = -1;
    else
    {
      int rett = file_read(curr->fd_table[fd], buffer, size);
      ret = rett;
      
    }
  }
  
  /* sema_down(&mutex);
  reader_count--;
  if(reader_count == 0) sema_up(&writer_sema);
  sema_up(&mutex); */

  sema_up(&filesys_sema);
  return ret;
}

int write(int fd, const void* buffer, unsigned size)
{
  
  //printf("try lock acquire ! %d\n", curr->tid);
  //sema_down(&writer_sema);
  sema_down(&filesys_sema);
  struct thread* curr = thread_current();
  int ret;
  //printf("lock acquire ! %d\n", curr->tid);
  if(fd == 0) ret = -1;
  else if(fd == 1)
  {
    putbuf((char*)buffer, size);
    ret =  size;
  }
  else
  {
    if(curr->fd_table[fd] == NULL) ret = -1;
    else
    {
      ret = file_write(curr->fd_table[fd], buffer, size);
    }
  }
  sema_up(&filesys_sema);
  //sema_up(&writer_sema);
  
  return ret;
}

void is_safe_addr(void* vaddr)
{
  if ((unsigned)vaddr < USER_STACK_BOTTOM || !is_user_vaddr((const void*)vaddr))
  {
    exit(-1);
  }
}

void is_buffer_safe(void* buffer, unsigned size)
{
  void* temp_buffer = buffer;
  is_safe_addr(buffer); 
  is_safe_addr((void*)((unsigned)buffer + size)); 
  void* vaddr_last = pg_round_down((void*)((unsigned)buffer + size));
  struct vm_area_struct* vma;

  while(1)
  {
    temp_buffer = pg_round_down(temp_buffer);
    vma = get_vma_with_vaddr(thread_current()->mm_struct, temp_buffer);
    if(vma == NULL) {  exit(-1);}
    if(vma->read_only) exit(-1);
    if(!vma->loaded) allocate_vm_page_mm(vma);
    if(temp_buffer == vaddr_last) break;
    else temp_buffer += PGSIZE;
  }
}

void is_string_safe(char* str)
{
  size_t size = strlen((char*)str);
  void* temp_buffer = (void*)str;
  is_safe_addr(temp_buffer);
  is_safe_addr((void*)((size_t)temp_buffer + size));
  void* vaddr;
  void* vaddr_last = pg_round_down((void*)((unsigned int)temp_buffer + size));
  struct vm_area_struct* vma;

  while(1)
  {
    vaddr = pg_round_down(temp_buffer);
    vma = get_vma_with_vaddr(thread_current()->mm_struct, vaddr);
    if(vma == NULL) { PANIC("vma NULL!"); exit(-1);}
    if(!vma->loaded) allocate_vm_page_mm(vma);
    if(vaddr == vaddr_last) break;
    else temp_buffer += PGSIZE;
  }
}
// for memory mapped file
// return -1 if fails
mapid_t mmap(int fd, void *addr)
{
  if (pg_ofs (addr) != 0) return -1;
  if(fd == 0 || fd == 1) return -1;
  if((unsigned)addr < USER_STACK_BOTTOM) return -1;
  if (is_user_vaddr (addr) == false) return -1;
  // lock
  struct thread* curr = thread_current();
  struct file* target_file = curr->fd_table[fd];
  if(target_file == NULL) {   return -1; }
  struct file* file_reopened = file_reopen(target_file);
  if(file_reopened == NULL) {  return -1; }

  else
  {
    // alloc mmap struct
    struct mmap_struct* mmap_strt = (struct mmap_struct*)malloc(sizeof(struct mmap_struct)); // need to free
    // setup
    if(mmap_strt == NULL) { return -1; }
    memset(mmap_strt, 0, sizeof(struct mmap_struct));
    list_init(&mmap_strt->vma_list);
    mmap_strt->file = file_reopened;
    mmap_strt->mapid = allocate_mapid();
    list_push_back(&curr->mm_struct->mmap_list, &mmap_strt->mmap_elem);
    off_t file_len = file_length(mmap_strt->file);
    size_t offset = 0;
    struct vm_area_struct* vma;
    for(; file_len > 0;)
    {
      // 기존에 존재하는 vma라면
      vma = get_vma_with_vaddr(curr->mm_struct, addr);
      if(vma)
      {
        return -1;
      }
      else
      {
        vma = (struct vm_area_struct*)malloc(sizeof (struct vm_area_struct));
        memset (vma, 0, sizeof(struct vm_area_struct));
        vma->type = PG_FILE;
        vma->read_only = false;
        vma->vaddr = addr;
        vma->offset = offset;
        vma->read_bytes = file_len < PGSIZE ? file_len : PGSIZE;
        vma->zero_bytes = PGSIZE - vma->read_bytes;
        vma->file = mmap_strt->file;
        vma->loaded = false;
        vma->swap_slot = 0xFFFFFFFF;
        list_push_back(&mmap_strt->vma_list, &vma->mmap_elem);
        insert_vma(curr->mm_struct, vma);
        
      }
      //printf("addr %0x\n", (uint32_t)addr);
      addr += PGSIZE;
      offset += PGSIZE;
      file_len -= PGSIZE;
    }
    return mmap_strt->mapid;
  }
}
// free mmap_sturct
void munmap(mapid_t mapping)
{
  // find mmap _ struct
  struct mmap_struct* mmapstrt = find_mmap_struct(mapping);
  if (!mmapstrt) {  return; }
  // m unmap !
  // 찾은 mmap struct의 vma list를 순회하면서, vma가 로드 되어있고  dirty bit이 1 이라면, 파일을 덮어쓰고,  vma->vaddr을 free 하고,
  // vma -> loaded를 false로 만들고, vma->list에서 제거 후, 해쉬 테이블에서도 제거한다/
  remove_mmap(thread_current(), mmapstrt);
}

