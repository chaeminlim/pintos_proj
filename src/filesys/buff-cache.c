#include "filesys/buff-cache.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "lib/debug.h"
#include "threads/malloc.h"

struct semaphore buffer_cache_writer_sema;
struct semaphore buffer_cache_reader_sema;
struct buffer_cache_entry Buffer_Cache[BUFFER_CACHE_SIZE];
int bce_clock = -1;
bool is_full = false;
int reader_count = 0;

int find_in_cache(struct block* block, block_sector_t t);
int clock_buffer(void);

void init_buffer_cache(void)
{
    /* sema_init(&buffer_cache_writer_sema, 1);
    sema_init(&buffer_cache_reader_sema, 1);
     */
    int i = 0;
    for(; i < BUFFER_CACHE_SIZE; i++)
    {
        Buffer_Cache[i].accessed = false;
        Buffer_Cache[i].dirty = false;
        Buffer_Cache[i].valid = false;
        Buffer_Cache[i].disk_sector_num = -1;
        Buffer_Cache[i].block_device = NULL;
    }
}

void block_buffer_read(struct block *block, block_sector_t sector, void *buffer)
{
    /* sema_down(&buffer_cache_reader_sema);
    reader_count++; if(reader_count == 1) sema_down(&buffer_cache_writer_sema);
    sema_up(&buffer_cache_reader_sema); */

    int buffer_index = find_in_cache(block, sector);
    if(buffer_index == -1) //not found
    {
        buffer_index = clock_buffer();
        block_read(block, sector, Buffer_Cache[buffer_index].block);
        Buffer_Cache[buffer_index].valid = true;
        Buffer_Cache[buffer_index].disk_sector_num = sector;
        Buffer_Cache[buffer_index].block_device = block;
    }    
    else // found
    {
        if(buffer_index >= BUFFER_CACHE_SIZE) NOT_REACHED();
        if(!Buffer_Cache[buffer_index].valid) NOT_REACHED();
    }

    memcpy(buffer, Buffer_Cache[buffer_index].block, BLOCK_SECTOR_SIZE); 
    Buffer_Cache[buffer_index].accessed = true;
    
    /* sema_down(&buffer_cache_reader_sema);
    reader_count--; if(reader_count == 0) sema_up(&buffer_cache_writer_sema);
    sema_up(&buffer_cache_reader_sema);
     */
}

void block_buffer_write(struct block *block, block_sector_t sector, const void *buffer)
{
    /* sema_down(&buffer_cache_writer_sema); */
    int buffer_index = find_in_cache(block, sector);
    if(buffer_index == -1) //not found
    {
        buffer_index = clock_buffer();
        block_read(block, sector, Buffer_Cache[buffer_index].block);
        Buffer_Cache[buffer_index].valid = true;
        Buffer_Cache[buffer_index].disk_sector_num = sector;
        Buffer_Cache[buffer_index].block_device = block;
    }    
    else // found
    {
        if(buffer_index >= BUFFER_CACHE_SIZE) NOT_REACHED();
        if(!Buffer_Cache[buffer_index].valid) NOT_REACHED();
    }
    
    memcpy(Buffer_Cache[buffer_index].block, buffer, BLOCK_SECTOR_SIZE); 
    Buffer_Cache[buffer_index].accessed = true;
    Buffer_Cache[buffer_index].dirty = true;
    /* sema_up(&buffer_cache_writer_sema); */
}

void remove_buffer_cache(void)
{
    /* sema_down(&buffer_cache_writer_sema); */
    int i = 0;
    for(; i < BUFFER_CACHE_SIZE; i++)
    {
        if(Buffer_Cache[i].valid)
            if(Buffer_Cache[i].dirty)
                write_back(&Buffer_Cache[i]);
    }
    /* sema_up(&buffer_cache_writer_sema); */
}

void write_back(struct buffer_cache_entry* bce)
{
    block_write(bce->block_device, bce->disk_sector_num, bce->block);
    bce->dirty = false;
}

int find_in_cache(struct block* block, block_sector_t sector)
{
    int i = 0;
    for(; i < BUFFER_CACHE_SIZE; i++)
    {
        if(Buffer_Cache[i].disk_sector_num == sector && Buffer_Cache[i].block_device == block) return i;
    }
    return -1;
}

int clock_buffer(void)
{
    while(1)
    {
        if(bce_clock == -1 || bce_clock >= BUFFER_CACHE_SIZE)
        {
            bce_clock = 0; continue;
        }
        else
        {
            if(Buffer_Cache[bce_clock].accessed == true)
            {
                Buffer_Cache[bce_clock].accessed = false;
                bce_clock++;
                continue;
            }
            else
                break;   
        }
    }
    if(Buffer_Cache[bce_clock].dirty == true)
    {
        if(Buffer_Cache[bce_clock].valid == true) write_back(&Buffer_Cache[bce_clock]);
    }
    
    Buffer_Cache[bce_clock].accessed = false;
    Buffer_Cache[bce_clock].dirty = false;
    Buffer_Cache[bce_clock].valid = false;
    
    return bce_clock;
}
