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
  thread_current()->curr_esp = f->esp;
  //printf ("system call! number: %d\n", f->esp);
  //hex_dump( f->esp,  f->esp, PHYS_BASE -  f->esp, true);
  int syscall_number = *(int*)(f->esp);
  switch(syscall_number)
  {
    case SYS_HALT:
    {
      syscall_halt();
      NOT_REACHED();
      break;
    }
    case SYS_EXIT:
    {
      is_safe_addr(f->esp + 4);
      syscall_exit(*(int*)(f->esp + 4));
      NOT_REACHED();
      break;
    }
    case SYS_EXEC:
    {
      is_safe_addr(f->esp + 4);
      void* cmd_line = f->esp + 4;
      int return_code = syscall_exec((const char*)cmd_line);
      f->eax = (uint32_t) return_code;
      break;
    }
    case SYS_WAIT:
    {
      is_safe_addr(f->esp + 4);
      pid_t pid = *(int*)(f->esp + 4);
      int ret = syscall_wait(pid);
      f->eax = (uint32_t) ret;
      break;
    }
    case SYS_CREATE:
    {
      is_safe_addr(f->esp + 4);
      is_safe_addr(f->esp + 8);
      char** file = (char*)(f->esp + 4);
      unsigned int initial_size = *(unsigned int*)(f->esp + 8);
      f->eax = syscall_create(*file, initial_size);
      break;
    }
    case SYS_REMOVE:
    {
      is_safe_addr(f->esp + 4);
      char** file = (char*)(f->esp + 4);
      f->eax = syscall_remove(*file);
      break;
    }
    case SYS_OPEN:
    {
      is_safe_addr(f->esp + 4);
      char* file = (char*)(f->esp + 4);
      f->eax = syscall_open(file);
      break;
    }
    case SYS_FILESIZE:
    {
      is_safe_addr(f->esp + 4);
      int fd = *(int*)(f->esp+4);
      f->eax = syscall_filesize(fd);
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
      f->eax = syscall_read(fd, *buffer, size);
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
      //printf("fd %d, buffer %s, size %u\n", fd, (char*)buffer, size);
      f->eax = syscall_write(fd, *buffer, size);
      break;
    }
    case SYS_SEEK:
    {
      is_safe_addr(f->esp + 8);
      is_safe_addr(f->esp + 4);
      unsigned int position = *(unsigned*)(f->esp+8);
      int fd = *(int*)(f->esp+4);
      syscall_seek(fd, position);
      break;
    }
    case SYS_TELL:
    {
      is_safe_addr(f->esp + 4);
      int fd = *(int*)(f->esp+4);
      f->eax = syscall_tell(fd);
      break;
    }
    case SYS_CLOSE:
    {
      is_safe_addr(f->esp + 4);
      int fd = *(int*)(f->esp+4);
      syscall_close(fd);
      break;
    }
    default:
    {
      syscall_exit(-1);
    }
  }
}


void syscall_halt(void)
{
  shutdown_power_off();
}

void syscall_exit(int status)
{
  struct thread* curr = thread_current();
  //t->exit_status = status;
  printf("%s: exit(%d)\n", curr->name, status);
  // 프로세스가 exit하면 부모가 자고 있다면 부모를 깨운다. 리턴 코드를 전달한다.
  struct process_control_block* pcb = &curr->pcb;
  if(pcb != NULL) pcb->exitcode = status;
  thread_exit();
}

pid_t syscall_exec(const char *cmd_line) 
{
  //_DEBUG_PRINTF ("[DEBUG] Exec : %s\n", cmdline);
  is_safe_addr((const uint8_t*)cmd_line);
  lock_acquire (&file_lock); // load() uses filesystem
  pid_t pid = process_execute(cmd_line);
  lock_release (&file_lock);
  return pid;
}

int syscall_wait(pid_t pid) 
{
  return process_wait(pid);
}

bool syscall_create(const char* file, unsigned initial_size)
{
  is_safe_addr((const uint8_t*)file);
  if(filesys_create(file, initial_size))
  {
    return true;
  }
  else return false;
}
// finished
bool syscall_remove(const char* file)
{
  is_safe_addr((const uint8_t*)file);
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
  is_safe_addr((const uint8_t*)file);
  struct file* opened_file = NULL;
  int fd_num;
  struct thread* curr = thread_current();
  lock_acquire(&file_lock);

  opened_file = filesys_open(file);
  if(opened_file == NULL)
  {
    lock_release(&file_lock);
    return -1;
  }
  else
  {
    fd_num = allocate_fd_id(curr);
    if(fd_num == -1) return -1;
    
    curr->fd_table[fd_num].file = opened_file;
    curr->fd_table[fd_num].valid = true;
    
    lock_release(&file_lock);
    return fd_num;
  }
}

int syscall_read(int fd, void* buffer, unsigned size)
{
  is_safe_addr((const uint8_t*)buffer);
  struct thread* curr = thread_current();
  lock_acquire(&file_lock);
  if(fd == 0)
  {
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
    
    int ret = file_read(curr->fd_table[fd].file, buffer, size);
    lock_release(&file_lock);
    return ret;
  }
}

int syscall_write(int fd, const void* buffer, unsigned size)
{
  is_safe_addr((const uint8_t*)buffer);
  struct thread* curr = thread_current();
  lock_acquire(&file_lock);

  if(fd == 1)
  {
    putbuf((char*)buffer, size);
    lock_release(&file_lock);
    return size;
  }
  else
  {
    if(curr->fd_table[fd].valid == false) return -1;
    
    int ret = file_write(curr->fd_table[fd].file, buffer, size);
    lock_release(&file_lock);
    return ret;
  }
}


void is_safe_addr(const void *vaddr)
{
  if (vaddr < USER_STACK_BOTTOM || !is_user_vaddr(vaddr))
    {
      syscall_exit(-1);
    }
}