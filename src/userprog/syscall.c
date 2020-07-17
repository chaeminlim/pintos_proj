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

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
<<<<<<< HEAD
  printf ("system call!\n");
  //printf ("system call! number: %d\n", f->esp);
  //hex_dump( f->esp,  f->esp, PHYS_BASE -  f->esp, true);
  thread_exit (); 
=======
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
>>>>>>> parent of 8792133... fix bugs
}


void syscall_halt(void)
{
  shutdown_power_off();
}

void syscall_exit(int status)
{
  struct thread* t = thread_current();
  //t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}
