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
#include "lib/kernel/stdio.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

struct lock syscall_file_lock;


void
syscall_init (void)
{
  lock_init(&syscall_file_lock);

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  void* temp_esp = f->esp;
  is_safe_addr(temp_esp);
  int syscall_number = *(int*)temp_esp;
  //hex_dump(f->esp, f->esp, PHYS_BASE - f->esp, true);
  switch(syscall_number)
  {
    case SYS_HALT:
    {
      syscall_halt();
      break;
    }
    case SYS_EXIT:
    {
      is_safe_addr(temp_esp+4);
      int status = *(int*)(temp_esp+4);
      syscall_exit(status);
      break;
    }
    case SYS_EXEC:
    {
      is_safe_addr(temp_esp+4);
      char* cmd_line = (char*)(temp_esp+4);
      f->eax = syscall_exec(cmd_line);
      break;
    }
    case SYS_WAIT:
    {
      is_safe_addr(temp_esp + 4);
      int pid = *(int*)(temp_esp+4);
      f->eax = syscall_wait(pid);
      break;
    }
    case SYS_CREATE:
    {
      is_safe_addr(temp_esp + 4);
      is_safe_addr(temp_esp + 8);
      char* file = (char*)(temp_esp + 4);
      unsigned int initial_size = *(unsigned int*)(temp_esp + 8);
      f->eax = syscall_create(file, initial_size);
      break;
    }
    case SYS_REMOVE:
    {
      is_safe_addr(temp_esp + 4);
      char* file = (char*)(temp_esp + 4);
      f->eax = syscall_remove(file);
      break;
    }
    case SYS_OPEN:
    {
      is_safe_addr(temp_esp + 4);
      char* file = (char*)(temp_esp + 4);
      f->eax = syscall_open(file);
      break;
    }
    case SYS_FILESIZE:
    {
      is_safe_addr(temp_esp + 4);
      int fd = *(int*)(temp_esp+4);
      f->eax = syscall_filesize(fd);
      break;
    }
    case SYS_READ:
    {
      is_safe_addr(temp_esp + 12);
      is_safe_addr(temp_esp + 8);
      is_safe_addr(temp_esp + 4);
      unsigned int size = *(unsigned int*)(temp_esp+12);
      void** buffer = (temp_esp+8);
      int fd = *(int*)(temp_esp+4);
      f->eax = syscall_read(fd, *buffer, size);
      break;
    }
    case SYS_WRITE:
    {
      is_safe_addr(temp_esp + 12);
      is_safe_addr(temp_esp + 8);
      is_safe_addr(temp_esp + 4);
      unsigned int size = *(unsigned int*)(temp_esp+12);
      void** buffer = (temp_esp+8);
      int fd = *(int*)(temp_esp+4);
      //printf("fd %d, buffer %s, size %u\n", fd, (char*)buffer, size);
      f->eax = syscall_write(fd, *buffer, size);
      break;
    }
    case SYS_SEEK:
    {
      is_safe_addr(temp_esp + 8);
      is_safe_addr(temp_esp + 4);
      unsigned int position = *(unsigned*)(temp_esp+8);
      int fd = *(int*)(temp_esp+4);
      syscall_seek(fd, position);
      break;
    }
    case SYS_TELL:
    {
      is_safe_addr(temp_esp + 4);
      int fd = *(int*)(temp_esp+4);
      f->eax = syscall_tell(fd);
      break;
    }
    case SYS_CLOSE:
    {
      is_safe_addr(temp_esp + 4);
      int fd = *(int*)(temp_esp+4);
      syscall_close(fd);
      break;
    }
    default:
    {
      syscall_exit(-1);
    }
  }
}

// finished
void syscall_halt(void)
{
  shutdown_power_off();
}
// not finished
void syscall_exit(int status)
{
  struct thread* t = thread_current();
  t->exit_code = status;
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

tid_t syscall_exec(const char* cmd_line)
{
  struct thread* curr = thread_current();
  tid_t child_id = process_execute(cmd_line);
  // wait to be loaded
  sema_down(&(curr->sema_load));
  // after load
  // if load success return tid
  // else return -1
  struct thread* child_thread = get_child_thread(curr, child_id);
  //printf("exec ! %s call %s\n", curr->name, child_thread->name);
  if(child_thread == NULL) return -1;
  else return child_id;
}
// finished
int syscall_wait(tid_t pid)
{
  return process_wait(pid);
}

bool syscall_create(const char* file, unsigned initial_size)
{
  if(filesys_create(file, initial_size))
  {
    return true;
  }
  else return false;
}
// finished
bool syscall_remove(const char* file)
{
  if(filesys_remove(file))
  {
    return true;
  }
  else return false;
}
// finished
int syscall_filesize(int fd)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd].valid == false) return -1;
  else return file_length(t->fd_table[fd].file);
}
// finished
void syscall_seek(int fd, unsigned position)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd].valid == false) return;
  else file_seek(t->fd_table[fd].file, position);
}
// finished
unsigned syscall_tell(int fd)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd].valid == false) return -1;
  else return file_tell(t->fd_table[fd].file);
}
// finished
void syscall_close(int fd)
{
  struct thread* t = thread_current();
  if(t->fd_table[fd].valid == false) return;
  file_close(t->fd_table[fd].file);
  t->fd_table[fd].valid = false;
  t->fd_table[fd].file = NULL;
}
// finished
int syscall_open(char *file)
{
  struct file* opened_file = NULL;
  int fd_num;
  struct thread* curr = thread_current();
  lock_acquire(&syscall_file_lock);

  opened_file = filesys_open(file);
  if(opened_file == NULL)
  {
    lock_release(&syscall_file_lock);
    return -1;
  }
  else
  {
    fd_num = allocate_fd_id(curr);
    if(fd_num == -1) return -1;
    
    curr->fd_table[fd_num].file = opened_file;
    curr->fd_table[fd_num].valid = true;
    
    lock_release(&syscall_file_lock);
    return fd_num;
  }
}

int syscall_read(int fd, void* buffer, unsigned size)
{
  struct thread* curr = thread_current();
  lock_acquire(&syscall_file_lock);
  if(fd == 0)
  {
    unsigned int i = 0;
    for(; i < size; i++)
    {
      ((char*)buffer)[i] = input_getc();
    }
    lock_release(&syscall_file_lock);
    return size;
  }
  else
  {
    if(curr->fd_table[fd].valid == false) return -1;
    
    int ret = file_read(curr->fd_table[fd].file, buffer, size);
    lock_release(&syscall_file_lock);
    return ret;
  }
}

int syscall_write(int fd, const void* buffer, unsigned size)
{
  struct thread* curr = thread_current();
  lock_acquire(&syscall_file_lock);

  if(fd == 1)
  {
    putbuf((char*)buffer, size);
    lock_release(&syscall_file_lock);
    return size;
  }
  else
  {
    if(curr->fd_table[fd].valid == false) return -1;
    
    int ret = file_write(curr->fd_table[fd].file, buffer, size);
    lock_release(&syscall_file_lock);
    return ret;
  }
}

void is_safe_addr(void* ptr_to_check)
{
  if(0x08048000 > (unsigned)ptr_to_check && (unsigned)ptr_to_check > 0xc0000000) thread_exit();
}
