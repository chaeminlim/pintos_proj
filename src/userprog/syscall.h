#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define USER_STACK_BOTTOM ((void *) 0x08048000)
#include "threads/thread.h"
#define USER_STACK_BOTTOM 0x08048000UL
void syscall_init (void);

void is_safe_addr(const void*);

void halt(void);
void exit(int status);
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

#endif /* userprog/syscall.h */