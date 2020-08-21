#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
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

extern struct lock lru_lock;
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
void unpin_page_string(char* str);
void unpin_page_buffer(void* buffer, unsigned int size);
// filesys
bool readdir(int fd, char* name);
bool mkdir(const char* dir);
bool chdir(const char* dir);
bool isdir(int fd);
int inumber(int fd);

mapid_t mmap(int fd, void *addr);
void munmap(mapid_t mapping);

struct lock filesys_lock;
struct semaphore writer_sema;
struct semaphore mutex;
int reader_count;

void
syscall_init (void)
{
  lock_init(&filesys_lock);
  sema_init(&writer_sema, 1);
  sema_init(&mutex, 1);
  reader_count = 0;
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{ 
  int syscall_number = *(int*)(f->esp);
 /*  if(syscall_number != 9)
    printf ("system call! number: %d\n", syscall_number); */
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
      is_string_safe(cmd_line);
      f->eax = exec(cmd_line);
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
      unpin_page_string(file);
      break;
    }
    case SYS_REMOVE:
    {
      is_safe_addr(f->esp + 4);
      char* file = (char*)*((int*)f->esp + 1);
      is_string_safe(file);
      f->eax = remove(file);
      unpin_page_string(file);
      break;
    }
    case SYS_OPEN:
    {
      is_safe_addr(f->esp + 4);
      char* file = (char*)*((int*)f->esp + 1);
      is_string_safe(file);
      f->eax = open(file);
      unpin_page_string(file);
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
      unpin_page_buffer(buffer, size);
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
      unpin_page_string(str);
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
    //#ifdef FILESYS
    case SYS_CHDIR:
    {
      is_safe_addr(f->esp + 4);
      void* str = (char*)*((int*)f->esp + 1);
      is_string_safe(str);
      f->eax = chdir(str);
      unpin_page_string(str);
      break;
    }
    case SYS_MKDIR:
    {
      is_safe_addr(f->esp + 4);
      void* str = (char*)*((int*)f->esp + 1);
      is_string_safe(str);
      f->eax = mkdir(str);
      unpin_page_string(str);
      break;
    }
    case SYS_READDIR:
    {
      is_safe_addr(f->esp + 8);
      is_safe_addr(f->esp + 4);
      void* str = (char*)*((int*)f->esp + 2);
      int fd = *(int*)(f->esp+4);
      is_string_safe(str);
      f->eax = readdir(fd, str);
      //printf("RESULT %d\n", f->eax);
      //printf("RESULT %s\n\n", str);
      
      break;
    }
    case SYS_ISDIR:
    {
      is_safe_addr(f->esp + 4);
      int fd = *(int*)(f->esp+4);
      f->eax = isdir(fd);
      break;
    }
    case SYS_INUMBER:
    {
      is_safe_addr(f->esp + 4);
      int fd = *(int*)(f->esp+4);
      f->eax = inumber(fd);
      //printf("INUMBER %d fd %d\n", f->eax, fd);
      break;
    }
    //#endif
    default:
    {
      PANIC("NOT ALLOWED SYSCALL NUMBER %d", syscall_number);
    }
  }
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  thread_current()->exit_code = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

tid_t exec(const char *file) 
{
  tid_t tid;
  struct thread* child;
  if ((tid = process_execute (file)) == -1) 
    goto EXEC_ERR;
  child = get_child_thread(tid);
  ASSERT (child);
  sema_down (&child->sema_load);
  if (!child->load_status) tid = -1;
  
EXEC_ERR:
  return tid;
}

int wait(tid_t tid) 
{
  return process_wait(tid);
}

bool create(const char* file, unsigned initial_size)
{
  lock_acquire(&filesys_lock);
  bool result = filesys_create(file, initial_size, false);
  lock_release(&filesys_lock);
  return result;
}

bool remove(const char* file)
{
  lock_acquire(&filesys_lock);
  bool result = filesys_remove(file);
  lock_release(&filesys_lock);
  return result;
}

int filesize(int fd)
{
  struct thread* t = thread_current();
  if(!t->fd_table[fd].in_use) return -1;
  if(t->fd_table[fd].is_file != 1) return -1;
  if(t->fd_table[fd].file == NULL) return -1;
  else return file_length(t->fd_table[fd].file);
}

void seek(int fd, unsigned position)
{
  struct thread* t = thread_current();
  if(!t->fd_table[fd].in_use) return;
  if(t->fd_table[fd].is_file != 1) return;
  if(t->fd_table[fd].file == NULL) return;
  else file_seek(t->fd_table[fd].file, position);
}

unsigned tell(int fd)
{
  struct thread* t = thread_current();
  if(!t->fd_table[fd].in_use) return -1;
  if(t->fd_table[fd].is_file != 1) return -1;
  if(t->fd_table[fd].file == NULL) return -1;
  else return file_tell(t->fd_table[fd].file);
}


void close(int fd)
{
  ASSERT(!lock_held_by_current_thread(&filesys_lock));
  lock_acquire(&filesys_lock);
  struct thread* t = thread_current();
  if(!t->fd_table[fd].in_use) goto CLOSE_ERR;
  if(t->fd_table[fd].is_file == 2) goto CLOSE_ERR;
  if(t->fd_table[fd].is_file == 1)
  {
    if(t->fd_table[fd].file == NULL) PANIC("NULL ERROR");
    file_close(t->fd_table[fd].file);
    t->fd_table[fd].in_use = false;
    t->fd_table[fd].is_file = 2;
    t->fd_table[fd].file = NULL;
  }
  else if(t->fd_table[fd].is_file == 0)
  {
    if(t->fd_table[fd].dir == NULL) PANIC("NULL ERROR");
    dir_close(t->fd_table[fd].dir);
    t->fd_table[fd].in_use = false;
    t->fd_table[fd].is_file = 2;
    t->fd_table[fd].dir = NULL;
  }

CLOSE_ERR:
  lock_release(&filesys_lock);
}
// finished
int open(char *file)
{
  lock_acquire(&filesys_lock);
  char directory_str[strlen(file)+1];
  char file_name_str[strlen(file)+1];
  divide_path_str(file, directory_str, file_name_str);
  
  /* printf("DIR %s, size %d\n", directory_str, strlen(directory_str));
  printf("FIL %s, size %d\n", file_name_str, strlen(file_name_str)); */
  
  struct dir *dir = get_dir_from_path(directory_str);
  struct inode *inode = NULL;
  if(dir == NULL) 
  {
    lock_release(&filesys_lock);
    return -1;
  }
  if (strlen(file_name_str) > 0) 
  {
    dir_lookup(dir, file_name_str, &inode);
    dir_close(dir);
  }
  else // no file name
  {
    if(strlen(directory_str) == 0)
    {
      dir_close(dir);
      lock_release(&filesys_lock);
      return -1;
    }
    int fd_num = allocate_fd_id(thread_current());
    thread_current()->fd_table[fd_num].dir = dir;
    thread_current()->fd_table[fd_num].file = NULL;
    thread_current()->fd_table[fd_num].in_use = true;
    thread_current()->fd_table[fd_num].is_file = 0;
    lock_release(&filesys_lock);
    //printf("OPEN DIR %s, fd %d\n", file, fd_num);
    return fd_num;
  }

  if (inode == NULL)
  {
    lock_release(&filesys_lock);
    return -1; 
  }
  if(inode_removed(inode))
  {
    inode_close(inode); 
    lock_release(&filesys_lock);
    return -1;
  }

  int fd_num = allocate_fd_id(thread_current());

  if(inode_is_dir(inode))
  {
    thread_current()->fd_table[fd_num].dir = dir_open(inode);
    thread_current()->fd_table[fd_num].file = NULL;
    thread_current()->fd_table[fd_num].in_use = true;
    thread_current()->fd_table[fd_num].is_file = 0;
    //printf("OPEN DIR %s, fd %d\n", file, fd_num);
  }
  else
  {
    thread_current()->fd_table[fd_num].file = file_open(inode);
    thread_current()->fd_table[fd_num].dir = NULL;
    thread_current()->fd_table[fd_num].in_use = true;
    thread_current()->fd_table[fd_num].is_file = 1;
    //printf("OPEN FILE %s, fd %d\n", file, fd_num);
  }
  lock_release(&filesys_lock);
  return fd_num;
}

int read(int fd, void* buffer, unsigned size)
{
  ASSERT(!lock_held_by_current_thread(&filesys_lock));
  lock_acquire(&filesys_lock);

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
    if(!curr->fd_table[fd].in_use) ret = -1;
    else
    {
      if(curr->fd_table[fd].is_file != 1)
      {
        lock_release(&filesys_lock);
        return -1;
      }
      if(curr->fd_table[fd].file == NULL)
      {ret = -1;}
      else
      {
        int rett = file_read(curr->fd_table[fd].file, buffer, size);
        ret = rett;
      }
    }
  }

  lock_release(&filesys_lock);
  return ret;
}

int write(int fd, const void* buffer, unsigned size)
{
  ASSERT(!lock_held_by_current_thread(&filesys_lock));
  lock_acquire(&filesys_lock);
  struct thread* curr = thread_current();
  int ret;
  if(fd == 0) ret = -1;
  else if(fd == 1)
  {
    putbuf((char*)buffer, size);
    ret =  size;
  }
  else
  {
    if(!curr->fd_table[fd].in_use) ret = -1;
    else
    {
      if(curr->fd_table[fd].is_file != 1)
      {
        lock_release(&filesys_lock);
        return -1;
      }
      if(curr->fd_table[fd].file == NULL)
      {ret = -1;}
      else
      {
        ret = file_write(curr->fd_table[fd].file, buffer, size);
      }
    }
  }
  lock_release(&filesys_lock);
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
  is_safe_addr((void*)((unsigned)buffer + size)); 
  void* vaddr_last = pg_round_down((void*)((unsigned)buffer + size));
  struct vm_area_struct* vma;

  while(1)
  {
    temp_buffer = pg_round_down(temp_buffer);
    vma = get_vma_with_vaddr(thread_current()->mm_struct, temp_buffer);
    if(vma == NULL) {  exit(-1); }
    if(vma->read_only) exit(-1) ;
    if(vma->loaded != PG_LOADED) allocate_vm_page_mm(vma);
    vma->pinned = true;
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
    if(vma == NULL) { exit(-1);}
    if(vma->loaded != PG_LOADED) allocate_vm_page_mm(vma);
    vma->pinned = true;
    if(vaddr == vaddr_last) break;
    else temp_buffer += PGSIZE;
  }
}

void unpin_page_string(char* str)
{
  size_t size = strlen((char*)str);
  void* temp_buffer = (void*)str;
  void* vaddr;
  void* vaddr_last = pg_round_down((void*)((unsigned int)temp_buffer + size));
  struct vm_area_struct* vma;

  while(1)
  {
    vaddr = pg_round_down(temp_buffer);
    vma = get_vma_with_vaddr(thread_current()->mm_struct, vaddr);
    if(vma == NULL) { exit(-1); }
    if(vma->loaded != PG_LOADED)  { NOT_REACHED(); exit(-1); }
    vma->pinned = false;
    if(vaddr == vaddr_last) break;
    else temp_buffer += PGSIZE;
  }
}

void unpin_page_buffer(void* buffer, unsigned int size)
{
  void* temp_buffer = buffer;
  void* vaddr_last = pg_round_down((void*)((unsigned)buffer + size));
  struct vm_area_struct* vma;

  while(1)
  {
    temp_buffer = pg_round_down(temp_buffer);
    vma = get_vma_with_vaddr(thread_current()->mm_struct, temp_buffer);
    if(vma == NULL) {  exit(-1);}
    if(vma->read_only) exit(-1);
    if(vma->loaded != PG_LOADED)  { NOT_REACHED(); exit(-1); }
    vma->pinned = false;
    if(temp_buffer == vaddr_last) break;
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
  if(!curr->fd_table[fd].in_use) return -1;
  if(curr->fd_table[fd].file == NULL) return -1;
  if(curr->fd_table[fd].is_file != 1) return -1;
  struct file* target_file = curr->fd_table[fd].file;
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
        vma->loaded = PG_NOT_LOADED;
        vma->swap_slot = 0xFFFFFFFF;
        vma->pinned = false;
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

bool readdir(int fd, char* name)
{
  //printf("INIT %s, fd_num %d\n", name, fd);
  ASSERT(!lock_held_by_current_thread(&filesys_lock));
  lock_acquire(&filesys_lock);
  if(!thread_current()->fd_table[fd].in_use) goto READDIR_ERR;
  if(thread_current()->fd_table[fd].dir == NULL) goto READDIR_ERR;
  if(thread_current()->fd_table[fd].is_file != 0) goto READDIR_ERR;
  struct dir* dir = thread_current()->fd_table[fd].dir;

  if(dir == NULL) goto READDIR_ERR;
  
  bool result;
  do
  {
    result = dir_readdir(dir, name);
    if(!result) break;
    //printf("DIR! %s INODE %d\n", name, inode_get_inumber(dir_get_inode(dir)));
  }
  while(strcmp(name, ".") == 0 || strcmp(name, "..") == 0);

  lock_release(&filesys_lock);
  return result;

READDIR_ERR:
  lock_release(&filesys_lock);
  return false;
}

bool mkdir(const char* dir)
{
  ASSERT(!lock_held_by_current_thread(&filesys_lock));
  lock_acquire(&filesys_lock);
  bool result = filesys_create(dir, 2, true);
  lock_release(&filesys_lock);
  return result;
}

bool chdir(const char* dir)
{
  ASSERT(!lock_held_by_current_thread(&filesys_lock));
  lock_acquire(&filesys_lock);
  struct dir* dirr = get_dir_from_path(dir);
  dir_close(thread_current()->current_dir);
  thread_current()->current_dir =  dirr;
  lock_release(&filesys_lock);
  if(dirr == NULL)
  {
    return false;
  }
  return true;
}

bool isdir(int fd)
{
  ASSERT(!lock_held_by_current_thread(&filesys_lock));
  lock_acquire(&filesys_lock);
  bool result;
  if(!thread_current()->fd_table[fd].in_use) result = false;
  if(thread_current()->fd_table[fd].dir == NULL) result = false;
  if(thread_current()->fd_table[fd].is_file == 0) result = true;
  else result = false;
  lock_release(&filesys_lock);
  return result;
}

int inumber(int fd)
{
  ASSERT(!lock_held_by_current_thread(&filesys_lock));
  lock_acquire (&filesys_lock);
  int result;
  if(!thread_current()->fd_table[fd].in_use) result = -1;
  if(thread_current()->fd_table[fd].is_file == 0)
  {
    if(thread_current()->fd_table[fd].dir == NULL) PANIC("NULL");
    result = inode_get_inumber(dir_get_inode(thread_current()->fd_table[fd].dir));
  }
  else if(thread_current()->fd_table[fd].is_file == 1)
  {
    if(thread_current()->fd_table[fd].file == NULL) PANIC("NULL");
    result = inode_get_inumber(file_get_inode(thread_current()->fd_table[fd].file));
  }
  else
  {
    PANIC("NOT INIT");
  }
  
  lock_release(&filesys_lock);
  return result;
}