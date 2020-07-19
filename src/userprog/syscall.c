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
#include "lib/stdio.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);
//
void is_safe_addr(const void *vaddr);

struct lock file_lock;

void
syscall_init (void)
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  //printf ("system call! number: %d\n", f->esp);
  int syscall_number = *(int*)(f->esp);
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
      char* cmd_line = *(char**)(f->esp + 4);
      int return_code = exec(cmd_line);
      f->eax = (uint32_t) return_code;
      break;
    }
    case SYS_WAIT:
    {
      is_safe_addr(f->esp + 4);
      tid_t pid = *(int*)(f->esp + 4);
      int ret = wait(pid);
      f->eax = (uint32_t) ret;
      break;
    }
    case SYS_CREATE:
    {
      is_safe_addr(f->esp + 4);
      is_safe_addr(f->esp + 8);
      char* file = *(char**)(f->esp + 4);
      unsigned int initial_size = *(unsigned int*)(f->esp + 8);
      f->eax = create(file, initial_size);
      break;
    }
    case SYS_REMOVE:
    {
      is_safe_addr(f->esp + 4);
      char* file = *(char**)(f->esp + 4);
      f->eax = remove(file);
      break;
    }
    case SYS_OPEN:
    {
      is_safe_addr(f->esp + 4);
      char* file =*(char**)(f->esp + 4);
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
      void** buffer = (f->esp+8);
      int fd = *(int*)(f->esp+4);
      f->eax = read(fd, *buffer, size);
      break;
    }
    case SYS_WRITE:
    {
      is_safe_addr(f->esp + 12);
      is_safe_addr(f->esp + 8);
      is_safe_addr(f->esp + 4);
      unsigned int size = *(unsigned int*)(f->esp+12);
      void** buffer = (f->esp+8);
      int fd = *(int*)(f->esp+4);
      f->eax = write(fd, *buffer, size);
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
  is_safe_addr((const uint8_t*)file);
  return filesys_create(file, initial_size);
}

bool remove(const char* file)
{
  is_safe_addr((const uint8_t*)file);
  return filesys_remove(file);
}

int filesize(int fd)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd].valid == false) return -1;
  else return file_length(t->fd_table[fd].file);
}

void seek(int fd, unsigned position)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd].valid == false) return;
  else file_seek(t->fd_table[fd].file, position);
}

unsigned tell(int fd)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd].valid == false) return -1;
  else return file_tell(t->fd_table[fd].file);
}

void close(int fd)
{
  
  struct thread* t = thread_current();
  if(t->fd_table[fd].valid == false) return;
  file_close(t->fd_table[fd].file);
  t->fd_table[fd].valid = false;
  t->fd_table[fd].file = NULL;
}
// finished
int open(char *file)
{
  is_safe_addr((const uint8_t*)file);
  struct file* opened_file = NULL;
  int fd_num;
  lock_acquire (&file_lock);
  opened_file = filesys_open(file);
  lock_release (&file_lock);
  if(opened_file == NULL)
  {
    return -1;
  }
  else
  {
    fd_num = allocate_fd_id(thread_current());
    if(fd_num == -1) return -1;
    thread_current()->fd_table[fd_num].valid = true;
    thread_current()->fd_table[fd_num].file = opened_file;
    return fd_num;
  }
}

int read(int fd, void* buffer, unsigned size)
{
  is_safe_addr((const uint8_t*)buffer);
  struct thread* curr = thread_current();

  //if(fd == 1) exit(-1);
  
  if(fd == 0) 
  {
    lock_acquire(&file_lock);
    unsigned int i = 0;
    for(; i < size; i++)
    {
      ((char*)buffer)[i] = input_getc();
    }
    lock_release(&file_lock);
    return size;
  }
  else
  {
    
    if(curr->fd_table[fd].valid == false) return -1;
    lock_acquire(&file_lock);
    int ret = file_read(curr->fd_table[fd].file, buffer, size);
    lock_release(&file_lock);
    return ret;
  }
}

int write(int fd, const void* buffer, unsigned size)
{
  is_safe_addr((const uint8_t*)buffer);
  struct thread* curr = thread_current();
  if(fd == 0) exit(-1);
  
  if(fd == 1)
  {
    lock_acquire(&file_lock);
    putbuf((char*)buffer, size);
    lock_release(&file_lock);
    return size;
  }
  else
  {
    if(curr->fd_table[fd].valid == false) return -1;
    lock_acquire(&file_lock);
    int ret = file_write(curr->fd_table[fd].file, buffer, size);
    lock_release(&file_lock);
    return ret;
  }
}

void is_safe_addr(const void *vaddr)
{
  if (vaddr < (void *)USER_STACK_BOTTOM || !is_user_vaddr(vaddr))
    {
      exit(-1);
    }
}

