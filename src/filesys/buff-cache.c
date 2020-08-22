#include "filesys/buff-cache.h"
#include "filesys/inode.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "lib/debug.h"
#include "threads/malloc.h"
#include "threads/thread.h"

struct lock buffer_cache_lock;
struct buffer_cache_entry Buffer_Cache[BUFFER_CACHE_SIZE];
bool is_full = false;

void write_back(int index);
int find_in_cache(block_sector_t t);
int clock_buffer(void);

void init_buffer_cache(void)
{
    lock_init(&buffer_cache_lock);

    int i = 0;
    for(; i < BUFFER_CACHE_SIZE; i++)
    {
        Buffer_Cache[i].valid = false;
        Buffer_Cache[i].accessed = false;
        Buffer_Cache[i].dirty = false;
    }
}

void block_buffer_read(struct block *block, block_sector_t sector, void *buffer)
{
    if(sector == NABLOCK) PANIC("READ ON NABLOCK");
    
    lock_acquire(&buffer_cache_lock);
    
    int buffer_index = find_in_cache(sector);
    if(buffer_index == -1) // not found
    {
        buffer_index = clock_buffer();
        Buffer_Cache[buffer_index].valid = true; 
        Buffer_Cache[buffer_index].dirty = false; 
        Buffer_Cache[buffer_index].disk_sector_num = sector;
        Buffer_Cache[buffer_index].block_device = block;
        block_read(block, sector, Buffer_Cache[buffer_index].block);
    }    
    else // cache hit
    {
        if(buffer_index >= BUFFER_CACHE_SIZE) NOT_REACHED();
        if(!Buffer_Cache[buffer_index].valid) NOT_REACHED();
    }

    Buffer_Cache[buffer_index].accessed = true;
    memcpy(buffer, Buffer_Cache[buffer_index].block, BLOCK_SECTOR_SIZE); 
    
    lock_release(&buffer_cache_lock);
}

void block_buffer_write(struct block *block, block_sector_t sector, const void *buffer)
{
    if(sector == NABLOCK) PANIC("WRITE ON NABLOCK");
    lock_acquire(&buffer_cache_lock);

    int buffer_index = find_in_cache(sector);
    if(buffer_index == -1) //not found
    {
        buffer_index = clock_buffer();
        Buffer_Cache[buffer_index].valid = true;
        Buffer_Cache[buffer_index].disk_sector_num = sector;
        Buffer_Cache[buffer_index].block_device = block;
        Buffer_Cache[buffer_index].dirty = false;
        block_read(block, sector, Buffer_Cache[buffer_index].block);
        
    }    
    else // found
    {
        if(buffer_index >= BUFFER_CACHE_SIZE) NOT_REACHED();
        if(!Buffer_Cache[buffer_index].valid) NOT_REACHED();
    }
    
    Buffer_Cache[buffer_index].accessed = true;
    Buffer_Cache[buffer_index].dirty = true;
    memcpy(Buffer_Cache[buffer_index].block, buffer, BLOCK_SECTOR_SIZE); 

    lock_release(&buffer_cache_lock);
}

void remove_buffer_cache(void)
{
    lock_acquire(&buffer_cache_lock);
    int i = 0;
    for(; i < BUFFER_CACHE_SIZE; i++)
    {
        if(Buffer_Cache[i].valid)
        {
            write_back(i);
        }
    }
   lock_release(&buffer_cache_lock);
}

void write_back(int index)
{
    ASSERT(lock_held_by_current_thread(&buffer_cache_lock));
    ASSERT(Buffer_Cache[index].valid);

    if(Buffer_Cache[index].dirty)
    {
        block_write(Buffer_Cache[index].block_device, Buffer_Cache[index].disk_sector_num, Buffer_Cache[index].block);
        Buffer_Cache[index].dirty = false;
    }
}

int find_in_cache(block_sector_t sector)
{
    int i = 0;
    for (i = 0; i < BUFFER_CACHE_SIZE; ++ i)
    {
    if (Buffer_Cache[i].valid == false) continue;
    if (Buffer_Cache[i].disk_sector_num == sector) return i;
    }
    return -1;
}

int clock_buffer(void)
{
    ASSERT(lock_held_by_current_thread(&buffer_cache_lock));
    int clock = 0;
    
    while(1) // find not occupied.
    {
        if(Buffer_Cache[clock].valid == false) return clock;
        if(Buffer_Cache[clock].accessed) Buffer_Cache[clock].accessed = false;
        else break;
        clock++;
        clock %= BUFFER_CACHE_SIZE;
    }

    if(Buffer_Cache[clock].dirty)
    {
        write_back(clock);
    }

    Buffer_Cache[clock].valid = false;
    return clock;
}
