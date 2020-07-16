#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

void syscall_init (void);

void syscall_halt(void);
void syscall_exit(int status);
/* tid_t syscall_exec(const char* cmd_line);
int syscall_wait(tid_t pid);
bool syscall_create(const char* file, unsigned intial_size);
bool syscall_remove(const char* file);
int syscall_open(const char* file);
int syscall_filesize(int fd);
int syscall_read(int fd, void* buffer, unsigned size);
int syscall_write(int fd, const void* buffer, unsigned size);
void syscall_seek(int fd, unsigned position);
unsigned syscall_tell(int fd);
void syscall_close(int fd);
void is_safe_addr(const void* ptr_to_check);
struct file_descriptor* find_fd(struct thread* t, int fd); */

#endif /* userprog/syscall.h */
