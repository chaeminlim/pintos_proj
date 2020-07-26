#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define USER_STACK_BOTTOM 0x08048000UL

#include "threads/thread.h"

void syscall_init (void);
void is_safe_addr(void*);
void halt(void);
void exit(int status);


#endif /* userprog/syscall.h */