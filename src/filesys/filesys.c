#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/buff-cache.h"
#include "userprog/syscall.h"
#include "threads/synch.h"

extern struct lock filesys_lock;
/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  init_buffer_cache();

  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  
  if (format) 
    do_format ();

  free_map_open ();

}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  remove_buffer_cache();
  free_map_close ();
}


/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  block_sector_t inode_sector = 0;
  char directory_str[strlen(name)+1];
  char file_name_str[strlen(name)+1];
  divide_path_str(name, directory_str, file_name_str);
/*   printf("DIR %s, size %d\n", directory_str, strlen(directory_str));
  printf("FIL %s, size %d\n", file_name_str, strlen(file_name_str)); */
  struct dir *dir = get_dir_from_path(directory_str);
  bool success = false;

  if(strlen(file_name_str) <= 0) goto FSCREATE_DONE;
  
  if(!is_dir)
  {
    success = (dir != NULL
                && free_map_allocate (1, &inode_sector)
                && inode_create (inode_sector, initial_size, false)
                && dir_add (dir, file_name_str, inode_sector, is_dir)); 
  }
  else
  {
    success = (dir != NULL
                && free_map_allocate (1, &inode_sector)
                && dir_create (inode_sector, initial_size)
                && dir_add (dir, file_name_str, inode_sector, is_dir));
      
  }
  
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);

FSCREATE_DONE:
  dir_close (dir);
  return success;
}


/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file*
filesys_open (const char *name)
{
  char directory_str[strlen(name)+1];
  char file_name_str[strlen(name)+1];
  divide_path_str(name, directory_str, file_name_str);
  struct dir *dir = get_dir_from_path(directory_str);
  /* 
  printf("DIR %s, size %d\n", directory_str, strlen(directory_str));
  printf("FIL %s, size %d\n", file_name_str, strlen(file_name_str)); 
  */
  struct inode *inode = NULL;
  
  if(dir == NULL) return NULL;

  if (strlen(file_name_str) > 0) 
  {
    dir_lookup(dir, file_name_str, &inode);
    dir_close(dir);
    if(inode == NULL) goto FSOPEN_INODE_F;
    if(inode_removed(inode)) goto FSOPEN_INODE_F;
    if(strlen(file_name_str) <= 0) goto FSOPEN_INODE_F;
    if(inode_is_dir(inode)) NOT_REACHED();

    return file_open (inode);
  }

FSOPEN_INODE_F:
  inode_close(inode); // null이면 그냥 끝남
  return NULL;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  ASSERT(lock_held_by_current_thread(&filesys_lock));
  /* printf("REMOVE !!! %s\n", name); */
  char directory_str[strlen(name)+1];
  char file_name_str[strlen(name)+1];
  divide_path_str(name, directory_str, file_name_str);
  /* printf("DIR %s, size %d\n", directory_str, strlen(directory_str));
  printf("FIL %s, size %d\n", file_name_str, strlen(file_name_str)); */
  if(strcmp(file_name_str, "..") == 0 || strcmp(file_name_str, ".") == 0) return false;
  struct dir *dir = get_dir_from_path(directory_str);
  struct inode* inode = NULL;
  bool success;

  if (strlen(file_name_str) > 0) 
  {
    if(!dir_lookup(dir, file_name_str, &inode))
    {
      // lookup을 fail함
      printf("REMOVE !!! %s\n", name);
      printf("DIR %s, size %d\n", directory_str, strlen(directory_str));
      printf("FIL %s, size %d\n", file_name_str, strlen(file_name_str));
      print_all_subdir(dir);
      
      dir_close(dir);
      return false;
    }

    if(inode_is_dir(inode)) // dir일때
    {
      struct dir* t_dir = dir_open(inode);
      if(inode_open_count(dir_get_inode(t_dir)) > 2)
      {
        //printf("open %d.\n", inode_open_count(dir_get_inode(dir)));
        dir_close(dir);
        dir_close(t_dir);
        return false;
      }
      else
      {
        dir_close(t_dir);
        success = dir_remove(dir, file_name_str);
        dir_close(dir);
        return success;
      }
    }
    else
    {
      success = dir != NULL && dir_remove(dir, file_name_str);
      dir_close(dir);
      return success;
    }
  }
  dir_close(dir);
  return false;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");

  free_map_close ();

  printf ("done.\n");
}

  