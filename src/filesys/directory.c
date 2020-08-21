#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"


/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  bool status = inode_create(sector, entry_cnt * sizeof (struct dir_entry), true);
  if(!status) return false;

  struct dir* dir = dir_open(inode_open(sector));
  if(dir == NULL) NOT_REACHED();

  struct dir_entry entry;
  
  entry.inode_sector = sector;
  entry.in_use = true;
  memcpy(entry.name, ".", 2);
  
  if(inode_write_at(dir->inode, &entry, sizeof(struct dir_entry), 0) != sizeof(struct dir_entry))
  {
    status = false;
  }

  if(sector == ROOT_DIR_SECTOR) // 루트 디렉터리라면 부모를 가리키는 
  {
    entry.inode_sector = sector;
    entry.in_use = true;
    memcpy(entry.name, "..", 3);
    if(inode_write_at(dir->inode, &entry, sizeof(struct dir_entry), sizeof(struct dir_entry)) != sizeof(struct dir_entry))
    {
      status = false;
    } 
  }
  
  dir_close(dir);
  return status; 
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
   // inode open 이 실패하면 inode도 닫음
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
   // inode reopen은 카운트만 올리고 추가 할당을 하지는 않는다.
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; ; ofs += sizeof e)
  {
    off_t i = inode_read_at(dir->inode, &e, sizeof e, ofs);
    if(i != sizeof e)
    {
      break;
    }
    //printf("name %s ename %s, e.in_use %d\n", name, e.name, e.in_use);
    if (e.in_use && !strcmp (name, e.name)) 
    {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. 
   dir lookup을 하면, inode open을 하기 때문에 inode -close를 꼭 해줘야 한다.
   */
bool
dir_lookup (const struct dir *dir, const char *name, struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
  {
    *inode = inode_open (e.inode_sector);
  }
  else
  {
    *inode = NULL;
  }

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector, bool is_dir)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  // 자식을 만들 떄, 부모로서 설정해준다.
  if(inode_sector != ROOT_DIR_SECTOR)
  {
    if(is_dir) // 디렉토리 일 때,
    {
      struct dir* child_dir = dir_open(inode_open(inode_sector));
      if(child_dir == NULL) NOT_REACHED();
      e.inode_sector = inode_get_inumber(dir_get_inode(dir));
      e.in_use = true;
      memcpy(e.name, "..", 3);
      if(inode_write_at(child_dir->inode, &e, sizeof(e), sizeof(e)) != sizeof(e))
        NOT_REACHED();
      dir_close(child_dir);
    }
  }
  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
  {
    if (!e.in_use)
      break;
  }
    

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

   /* Prevent removing non-empty directory. */
  if (inode_is_dir(inode)) 
  {
    struct dir *target = dir_open(inode);
    bool is_empty = dir_is_empty(target);
    dir_close(target);
    if (!is_empty) goto done;
  }
  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}


void divide_path_str(const char* name, char* directory, char* file_name)
{
  // 슬래쉬로 끝난다면 // 전부다 디렉토리
  // 슬래시로 끝나지 않는다면 디렉토리 또는 파일
  // 슬래시로 끝나지 않을 때, 마지막 인덱스부터 슬래시를 찾음
  // 슬래시를 찾았다면, 슬래시까지 경로
  // 슬래시를 찾지 못했다면 전부 파일
  int length = strlen(name);
  if(length < 0) NOT_REACHED();
  if(length == 0)
  {
    directory[0] = '\0';
    file_name[0] = '\0'; 
    return; 
  }
  if(name[length-1] == '/') // 슬래쉬로 끝날 때
  {
    memcpy(directory, name, length + 1);
    file_name[0] = '\0';
    return;
  }
  else // 슬래시로 끝나지 않을 떄
  {
    int moving_idx = length - 1;
    int flag = false;
    for(;moving_idx >= 0; moving_idx--)
    {
      if(name[moving_idx] == '/')
      {
        flag = true;
        break;
      }
    }
    if(!flag) // 슬래시를 못찾았다면
    {
      directory[0] = '\0';
      memcpy(file_name, name, length + 1);
      return;
    }
    else // 슬래시를 찾았다면
    {
      memcpy(directory, name, moving_idx + 1);
      directory[moving_idx + 1] = '\0';
      memcpy(file_name, name + moving_idx + 1, length - moving_idx);
      file_name[length - moving_idx - 1] = '\0';
    }
  }
}

struct dir* get_dir_from_path(const char* directory)
{
  struct dir* current = NULL;
  int length = strlen(directory);
  char temp_dir[length+1];

  if(length < 0) NOT_REACHED();
  if(length == 0) // 디렉토리가 없을 때, 현재 디렉토리이거나 루트
  {
    if(thread_current()->current_dir == NULL)
      current = dir_open_root();
    else
      current = dir_reopen(thread_current()->current_dir);
    return current;
  }
  
  strlcpy(temp_dir, directory, length + 1);
  bool is_absolute = (temp_dir[0] == '/'); // 절대 경로 플래그
  
  if(is_absolute) // 절대 경로일 때 현재 디렉터리는 루트
    current = dir_open_root();
  else
  {
    if(thread_current()->current_dir == NULL)
      current = dir_open_root();
    else
      current = dir_reopen(thread_current()->current_dir);
  }

  // set current done
  char* token, *save_ptr;
  token = strtok_r(temp_dir, "/", &save_ptr);
  for(; token != NULL; token = strtok_r(NULL, "/", &save_ptr))
  {
    struct inode* inode = NULL;
    if(!dir_lookup(current, token, &inode))
    {
      dir_close(current);
      return NULL;
    }
    else
    {
      struct dir* next = dir_open(inode);
      if(next == NULL)
      {
        return NULL;
      }
      dir_close(current);
      current = next;
    }
  }

  if(inode_removed(dir_get_inode(current)))
  {
    dir_close(current);
    return NULL;
  }
  if(inode_get_inumber(dir_get_inode(current)) < 1)
  {
    NOT_REACHED();
  }

  return current; 
}

bool dir_is_empty (const struct dir *dir)
{
  struct dir_entry e;
  off_t ofs = sizeof(e) * 2;
  for (; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
  {
    if (e.in_use)
      return false;
  }
  return true;
}

void get_dir_name(struct dir* dir, char* name)
{
  ASSERT(dir != NULL);
  struct dir_entry e;
  inode_read_at(dir->inode, &e, sizeof e, 0);
  memcpy(name, e.name, NAME_MAX + 1);
}

void print_all_subdir(struct dir* dir)
{
  struct dir_entry e;
  off_t ofs = 0;
  printf("SUBDIR START\n");
  if(inode_removed(dir->inode))
  {
    printf("inode is removed!\n");
  }
  if(!inode_is_dir(dir->inode))
  {
    printf("Not dir!\n");
  }
  for (; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
  {
    if (e.in_use)
      printf("SUBDIR :%s\n", e.name);
  }
}