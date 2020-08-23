#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/buff-cache.h"
#include <stdio.h>

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_BLOCK_NUM 123
#define INDIRECT_BLOCK_NUM 128
#define DOUBLE_INDIRECT_BLOCK_NUM 16384

static uint8_t ZERO_BLOCK[BLOCK_SECTOR_SIZE] = {0};

struct indirect_block
{
  block_sector_t blocks[INDIRECT_BLOCK_NUM];
};

struct double_indirect_block
{
  block_sector_t indirect_blocks[INDIRECT_BLOCK_NUM];
};
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t direct_blocks[DIRECT_BLOCK_NUM]; // index 0 ~ 122
    block_sector_t indirect_blocks; // index 123 ~ 250
    block_sector_t double_indirect_blocks; // index 251 ~ 16,635
    bool is_dir;
    off_t length;                       /* File size in bytes.*/
    unsigned magic;                     /* Magic number. */
  };

bool allocate_inode_disk(struct inode_disk* disk_inode, off_t length, bool extend);
bool free_inode_disk(struct inode_disk* disk_inode);
bool inode_extend(struct inode_disk* disk_inode,  off_t length);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
{
  struct list_elem elem;              /* Element in inode list. */
  block_sector_t sector;              /* Sector number of disk location. */
  int open_cnt;                       /* Number of openers. */
  bool removed;                       /* True if deleted, false otherwise. */
  int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
  struct inode_disk data;             /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (0 <= pos && pos < inode->data.length)
  {
    size_t sector_num = pos / BLOCK_SECTOR_SIZE;
    if(sector_num < DIRECT_BLOCK_NUM)
    {
      return inode->data.direct_blocks[sector_num];
    }
    else if(sector_num >= DIRECT_BLOCK_NUM && sector_num < (INDIRECT_BLOCK_NUM + DIRECT_BLOCK_NUM))
    {
      struct indirect_block* indi_block = calloc(1, sizeof(struct indirect_block));
      sector_num -= DIRECT_BLOCK_NUM; // 0 ~
      ASSERT(inode->data.indirect_blocks != NABLOCK);
      block_buffer_read(fs_device, inode->data.indirect_blocks, indi_block);
      block_sector_t ret = indi_block->blocks[sector_num];
      free(indi_block);
      return ret;
    }
    else if(sector_num >= 251 && sector_num < (INDIRECT_BLOCK_NUM + DIRECT_BLOCK_NUM + DOUBLE_INDIRECT_BLOCK_NUM))
    {
      struct double_indirect_block* double_indi_block = calloc(1, sizeof(struct double_indirect_block));;
      struct indirect_block* indi_block = calloc(1, sizeof(struct indirect_block));;
      sector_num -= (INDIRECT_BLOCK_NUM + DIRECT_BLOCK_NUM);
      size_t indirect_block_num = sector_num / INDIRECT_BLOCK_NUM;
      size_t indirect_block_index = sector_num % INDIRECT_BLOCK_NUM;
      ASSERT(inode->data.double_indirect_blocks != NABLOCK);
      block_buffer_read(fs_device, inode->data.double_indirect_blocks, double_indi_block);
      ASSERT(double_indi_block->indirect_blocks[indirect_block_num] != NABLOCK);
      block_buffer_read(fs_device, double_indi_block->indirect_blocks[indirect_block_num], indi_block);
      block_sector_t ret = indi_block->blocks[indirect_block_index];
      free(double_indi_block);
      free(indi_block);
      return ret;
    }
    NOT_REACHED();
  }
  else
  {
    //printf("pos %d, length %d\n\n", pos, inode->data.length);
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  memset(ZERO_BLOCK, 0, BLOCK_SECTOR_SIZE);
  ASSERT(sizeof(struct inode_disk) == BLOCK_SECTOR_SIZE);
  ASSERT(sizeof(struct indirect_block) == BLOCK_SECTOR_SIZE);
  ASSERT(sizeof(struct double_indirect_block) == BLOCK_SECTOR_SIZE);
}

bool allocate_new_direct_disk(struct inode_disk* disk_inode, size_t needed_blocks, bool extend);
bool allocate_new_indirect_disk(block_sector_t* sector, size_t needed_blocks, bool extend);
bool allocate_new_double_indirect_disk(struct inode_disk* disk_inode, size_t needed_blocks, bool extend);

/* bool allocate_extend_direct_disk(struct inode_disk* disk_inode, size_t needed_blocks);
bool allocate_extend_indirect_disk(block_sector_t* sector, size_t needed_blocks);
bool allocate_extend_double_indirect_disk(struct inode_disk* disk_inode, size_t needed_blocks); */

bool allocate_new_direct_disk(struct inode_disk* disk_inode, size_t needed_blocks, bool extend)
{
  size_t i;
  
  for(i = 0; i < needed_blocks; i++)
  {
    if(disk_inode->direct_blocks[i] == NABLOCK)
    {
      if(!free_map_allocate(1, &(disk_inode->direct_blocks[i]))) return false;
      block_buffer_write(fs_device, disk_inode->direct_blocks[i], ZERO_BLOCK);
    }
    else
    {
      if(!extend) PANIC("DIRECT direct block not clear!");
    }  
  }
  return true;
}

bool allocate_new_indirect_disk(block_sector_t* sector, size_t needed_blocks, bool extend)
{
  size_t i;
  struct indirect_block indi_block;
  
  if(*sector == NABLOCK)
  {
    if(!free_map_allocate(1, sector)) return false;
    memset(&indi_block, NABLOCK, sizeof(indi_block));
  }  
  else 
  { 
    block_buffer_read(fs_device, *sector, &indi_block);
  }

  for(i = 0; i < needed_blocks; i++)
  {
    if(indi_block.blocks[i] == NABLOCK)
    {
      if(!free_map_allocate(1, &indi_block.blocks[i])) return false;
      block_buffer_write(fs_device, indi_block.blocks[i], ZERO_BLOCK);
    }
    else
    {
      if(!extend) PANIC("INDIRECT direct block not clear!");
    }
  }
  block_buffer_write(fs_device, *sector, &indi_block);
  return true;
}

bool allocate_new_double_indirect_disk(struct inode_disk* disk_inode, size_t needed_blocks, bool extend)
{
  size_t i;
  size_t indirect_block_last_index = (needed_blocks / INDIRECT_BLOCK_NUM); // 할당해야 하는 indirect 블럭 수 - 1
  size_t block_left =  needed_blocks % INDIRECT_BLOCK_NUM; // 마지막 indirect에서 할당해야하는 블럭 수

  struct double_indirect_block double_indi_block;
  if(disk_inode->double_indirect_blocks == NABLOCK)
  {
    if(!free_map_allocate(1, &disk_inode->double_indirect_blocks)) return false;
    memset(&double_indi_block, NABLOCK, sizeof(double_indi_block));
  }
  else block_buffer_read(fs_device, disk_inode->double_indirect_blocks, &double_indi_block);

  for(i = 0; i < indirect_block_last_index; i++)
  {
    allocate_new_indirect_disk(&double_indi_block.indirect_blocks[i], INDIRECT_BLOCK_NUM, extend);
  }
  allocate_new_indirect_disk(&double_indi_block.indirect_blocks[indirect_block_last_index], block_left, extend);
  
  block_buffer_write(fs_device, disk_inode->double_indirect_blocks, &double_indi_block);
  return true;
}


bool allocate_inode_disk(struct inode_disk* disk_inode, off_t length, bool extend)
{
  if(length < 0) return false;
  
  size_t sector_num = bytes_to_sectors(length); // 필요한 섹터의 개수
  size_t temp_sector = (sector_num < DIRECT_BLOCK_NUM ? sector_num : DIRECT_BLOCK_NUM);
  // direct disk에 할당
  if(!allocate_new_direct_disk(disk_inode, temp_sector, extend)) return false;
  // 할당 끝나면 변수 업데이트
  if(sector_num < temp_sector) NOT_REACHED();
  sector_num -= temp_sector;
  if(sector_num == 0) return true;
  // indirect level allocation
  temp_sector = (sector_num < INDIRECT_BLOCK_NUM ? sector_num : INDIRECT_BLOCK_NUM);
  // indirect 할당
  if(!allocate_new_indirect_disk(&(disk_inode->indirect_blocks), temp_sector, extend)) PANIC("allocate indirect block fail!");
  
  if(sector_num < temp_sector) NOT_REACHED();
  sector_num -= temp_sector;
  if(sector_num == 0) return true;
  if(sector_num > DOUBLE_INDIRECT_BLOCK_NUM) PANIC("Over size error!");
  // allocate double indirect
  temp_sector = (sector_num < DOUBLE_INDIRECT_BLOCK_NUM ? sector_num : DOUBLE_INDIRECT_BLOCK_NUM); // 할당해야 하는 전체 블럭 수
  // double indirect 할당
  if(!allocate_new_double_indirect_disk(disk_inode, temp_sector, extend)) PANIC("allocate double indirect block fail!");
  return true;
}

bool free_inode_disk(struct inode_disk* disk_inode)
{
  off_t length =  disk_inode->length;
  size_t i, j;
  if(length < 0) return false;
  
  size_t sector_num = bytes_to_sectors(length); // 필요한 섹터의 개수
  // direct block allocation
  size_t temp_sector = (sector_num < DIRECT_BLOCK_NUM ? sector_num : DIRECT_BLOCK_NUM);
  for(i = 0; i < temp_sector; i++)
  {
    if(disk_inode->direct_blocks[i] == NABLOCK) 
      PANIC("FREE NOT ALLOCATED BLOCK");
    free_map_release(disk_inode->direct_blocks[i], 1);
  }
  sector_num -= temp_sector;
  if(sector_num == 0) return true;

  // indirect level allocation
  temp_sector = (sector_num < INDIRECT_BLOCK_NUM ? sector_num : INDIRECT_BLOCK_NUM);

  struct indirect_block* indi_block = calloc(1, sizeof(struct indirect_block));
  block_buffer_read(fs_device, disk_inode->indirect_blocks, indi_block);
  ASSERT (sizeof(struct indirect_block) == BLOCK_SECTOR_SIZE);

  for(i = 0; i < temp_sector; i++)
  {
    if(indi_block->blocks[i] == NABLOCK) 
      PANIC("FREE NOT ALLOCATED BLOCK");
    free_map_release(indi_block->blocks[i], 1);
  }
  free_map_release(disk_inode->indirect_blocks, 1);
  free(indi_block);
  sector_num -= temp_sector;
  if(sector_num == 0) return true;

  if(sector_num > DOUBLE_INDIRECT_BLOCK_NUM) NOT_REACHED();
  // allocate double indirect
  temp_sector = (sector_num < DOUBLE_INDIRECT_BLOCK_NUM ? sector_num : DOUBLE_INDIRECT_BLOCK_NUM); // 할당해야 하는 전체 블럭 수
  size_t indirect_block_needed = (temp_sector / INDIRECT_BLOCK_NUM); // 할당해야 하는 indirect 수 - 1
  size_t block_left =  temp_sector % INDIRECT_BLOCK_NUM; // 마지막 indirect에서 할당해야하는 블럭 수

  struct double_indirect_block* double_indi_block = calloc(1, sizeof(struct double_indirect_block));
  block_buffer_read(fs_device, disk_inode->double_indirect_blocks, double_indi_block);
  struct indirect_block* temp_indi_block = calloc(1, sizeof(struct indirect_block));

  for(i = 0; i < indirect_block_needed; i++)
  {
    block_buffer_read(fs_device, double_indi_block->indirect_blocks[i], temp_indi_block);
    for(j = 0; j < INDIRECT_BLOCK_NUM; j++)
    {
      free_map_release(temp_indi_block->blocks[j], 1);
    }
    free_map_release(double_indi_block->indirect_blocks[i], 1);
  }

  block_buffer_read(fs_device, double_indi_block->indirect_blocks[indirect_block_needed], temp_indi_block);
  for(j = 0; j < block_left; j++)
  {
    free_map_release(temp_indi_block->blocks[j], 1);
  }
  free_map_release(double_indi_block->indirect_blocks[indirect_block_needed], 1);
  free_map_release(disk_inode->double_indirect_blocks, 1);
  free(double_indi_block);
  free(temp_indi_block);
  return true;
}

bool inode_extend(struct inode_disk* disk_inode,  off_t length)
{
  return allocate_inode_disk(disk_inode, length, true);
}
/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  //printf("sector %u, length %d\n\n", sector, length);
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
  {
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    disk_inode->is_dir = is_dir;
    memset(disk_inode->direct_blocks, NABLOCK, DIRECT_BLOCK_NUM * sizeof(NABLOCK));
    disk_inode->indirect_blocks = NABLOCK;
    disk_inode->double_indirect_blocks = NABLOCK;
    if(allocate_inode_disk(disk_inode, length, false))
    {
      block_buffer_write(fs_device, sector, disk_inode);
      success = true;
    }
    else
      PANIC("ALLOCATION FAIL!\n");

    free (disk_inode);
  }
  else
    return false;

  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  //block_read (fs_device, inode->sector, &inode->data);
  block_buffer_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          if(!free_inode_disk(&inode->data)) NOT_REACHED();
        }

      free (inode); 
    }
}

bool inode_removed(struct inode* inode)
{
  ASSERT (inode != NULL);
  return(inode->removed); 
}
/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
  {
    /* Disk sector to read, starting byte offset within sector. */
    //printf("read offset %d size %d, file_length %d\n\n", offset, size, inode->data.length);
    block_sector_t sector_idx = byte_to_sector (inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length (inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    //printf("read offset %d size %d, file_length %d chunk size %d\n\n", offset, size, inode->data.length, chunk_size);
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
    {
      /* Read full sector directly into caller's buffer. */
      block_buffer_read (fs_device, sector_idx, buffer + bytes_read);
    }
    else 
    {
      /* Read sector into bounce buffer, then partially copy
          into caller's buffer. */
      if (bounce == NULL) 
      {
        bounce = malloc (BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      //block_read (fs_device, sector_idx, bounce);
      block_buffer_read (fs_device, sector_idx, bounce);
      memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }
    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  if (inode->deny_write_cnt)
    return 0;

  if(byte_to_sector(inode, offset + size - 1) == -1u ) 
  {
    if(!inode_extend(&inode->data, offset + size)) return -1;

    // write back the (extended) file size
    inode->data.length = offset + size;
    block_buffer_write(fs_device, inode->sector, &inode->data);
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      //printf("write offset %d\n\n", offset);
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_buffer_write(fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
          {
            //block_read (fs_device, sector_idx, bounce);
            block_buffer_read (fs_device, sector_idx, bounce);
          }
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          //block_write (fs_device, sector_idx, bounce);
          block_buffer_write(fs_device, sector_idx, bounce);
        }
        
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  if(bounce != NULL)
    free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

bool inode_is_dir(struct inode* inode)
{
  return inode->data.is_dir;
}

int inode_open_count(struct inode* inode)
{
  return inode->open_cnt;
}