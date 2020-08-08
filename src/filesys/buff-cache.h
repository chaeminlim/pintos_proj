#ifndef _FILESYS_BUFF_CACHE_H
#define _FILESYS_BUFF_CACHE_H

#include "devices/block.h"
#include <stdbool.h>

#define BUFFER_CACHE_SIZE 64

struct buffer_cache_entry
{
    uint8_t block[BLOCK_SECTOR_SIZE];
    block_sector_t disk_sector_num;
    struct block* block_device;
    bool dirty;
    bool valid;
    bool accessed;
};

void init_buffer_cache(void);
void block_buffer_read(struct block *block, block_sector_t sector, void *buffer);
void block_buffer_write(struct block *block, block_sector_t sector, const void *buffer);
void write_back(struct buffer_cache_entry* bce);
void remove_buffer_cache(void);

#endif