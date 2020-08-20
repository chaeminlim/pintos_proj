#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/buff-cache.h"

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
  struct dir *dir = get_dir_from_path(directory_str);
  bool success;

  if(!is_dir)
  {
    success = (dir != NULL
                && free_map_allocate (1, &inode_sector)
                && inode_create (inode_sector, initial_size, false)
                && dir_add (dir, file_name_str, inode_sector, is_dir)); 
  }
  else
  {/* 
    if(dir == NULL) NOT_REACHED();
    if(!(free_map_allocate (1, &inode_sector))) NOT_REACHED();
    if(!(dir_create (inode_sector, initial_size))) NOT_REACHED();
    if(!(dir_add (dir, name, inode_sector, is_dir))) NOT_REACHED(); */
    success = (dir != NULL
                && free_map_allocate (1, &inode_sector)
                && dir_create (inode_sector, initial_size)
                && dir_add (dir, file_name_str, inode_sector, is_dir));
      
  }
  
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);

  dir_close (dir);
  return success;
}


/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  char directory_str[strlen(name)+1];
  char file_name_str[strlen(name)+1];
  divide_path_str(name, directory_str, file_name_str);
  struct dir *dir = get_dir_from_path(directory_str);
  struct inode *inode = NULL;
  if(dir == NULL) return NULL;

  if (strlen(file_name_str) > 0) 
  {
    dir_lookup(dir, file_name_str, &inode);
    dir_close(dir);
  }
  else 
  {
    return NULL;
    //inode = dir_get_inode(dir);
  }

  if (inode == NULL || inode_removed(inode))
  {
    return NULL; 
  }
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char directory_str[strlen(name)+1];
  char file_name_str[strlen(name)+1];
  divide_path_str(name, directory_str, file_name_str);
  struct dir *dir = get_dir_from_path(directory_str);
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir); 

  return success;
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

  