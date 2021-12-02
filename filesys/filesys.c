#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/palloc.h"
#include "filesys/file.h"
#include "filesys/fat.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;
	struct get_dir_struct dir_struct = get_dir_from_name(name, false);
	if(dir_struct.dir == NULL || dir_struct.name == NULL) return false;
	bool success = (dir_struct.dir != NULL
			&& ((inode_sector = fat_create_chain(0)) != 0)
			&& inode_create (inode_sector, initial_size, false, false, NULL)
			&& dir_add (dir_struct.dir, dir_struct.name, inode_sector));
	if (!success && inode_sector != 0)
		fat_remove_chain(inode_sector, 0);
	if(success) {
		// 생성한 파일의 부모 설정
		struct inode *inode;
		inode = inode_open(inode_sector);
		inode_set_parent(inode, inode_get_inumber(dir_get_inode(dir_struct.dir)));
		inode_close(inode);
	}
	dir_close (dir_struct.dir);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	if(strcmp(name, "/") == 0) {
		struct inode *inode = inode_open(ROOT_DIR_CLUSTER);
		return file_open(inode);
	}
	if(strcmp(name, ".") == 0) {
		if(inode_is_removed(dir_get_inode(dir_current))) return NULL;
		struct inode *inode = dir_get_inode(dir_current);
		return file_open(inode);
	}

	struct get_dir_struct dir_struct = get_dir_from_name(name, false);
	if(dir_struct.dir == NULL || dir_struct.name == NULL) return false;
	struct inode *inode = NULL;

	if (dir_struct.dir != NULL)
		dir_lookup (dir_struct.dir, dir_struct.name, &inode);
	dir_close (dir_struct.dir);

	while (inode_is_symlink(inode)){
		char *link = inode_get_symlink(inode);
		dir_struct = get_dir_from_name(link, false);

		if (dir_struct.dir != NULL)
			dir_lookup (dir_struct.dir, dir_struct.name, &inode);
		dir_close (dir_struct.dir);
	}

	return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	if(strcmp(name, "/") == 0) return false;
	struct get_dir_struct dir_struct = get_dir_from_name(name, false);
	if(dir_struct.dir == NULL || dir_struct.name == NULL) return false;
	bool success = dir_struct.dir != NULL && dir_remove (dir_struct.dir, dir_struct.name);
	dir_close (dir_struct.dir);

	return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}

struct get_dir_struct
get_dir_from_name(const char *name, bool until_end) {
	struct get_dir_struct result;
	result.dir = NULL; result.name = NULL;
	struct dir *new_dir = dir_reopen(dir_current);
	struct inode *inode = NULL;

	int level = 0, i;
	char *token;
	char *save_ptr;
	char *buffer = palloc_get_page(PAL_ZERO);

	// 문자열이 비어 있는 경우
	if(*name == '\0') { new_dir = NULL; goto get_dir_return; };

	// /를 공백으로 바꿔서 parsing할 수 있도록 함
	for(i = 0; name[i] != 0; i++) {
		if(name[i] == '/') {
			buffer[i] = ' ';
			if(i != 0) level++;
			else {
				dir_close(new_dir);
				new_dir = dir_open_root();
			}
		}
		else buffer[i] = name[i];
	}

	if(inode_is_removed(dir_get_inode(new_dir))) { new_dir = NULL; goto get_dir_return; }

	for (token = strtok_r (buffer, " ", &save_ptr), i = 0; token != NULL; token = strtok_r (NULL, " ", &save_ptr), i++){
		if(i == level && !until_end) break;
		if(strcmp(token, ".") == 0) {
			dir_close(new_dir);
			new_dir = dir_reopen(dir_current);
			if(new_dir == NULL) goto get_dir_return;
		}
		else if(strcmp(token, "..") == 0) {
			disk_sector_t parent_sector = inode_get_parent(dir_get_inode(new_dir));
			dir_close(new_dir);
			new_dir = dir_open(inode_open(parent_sector));
			if(new_dir == NULL) goto get_dir_return;
		}
		else {
			struct inode *inode;
			dir_lookup(new_dir, token, &inode);
			dir_close(new_dir);
			new_dir = dir_open(inode);
			if(new_dir == NULL) goto get_dir_return;
		}
	}

get_dir_return:
	result.dir = new_dir;
	result.name = name + (token - buffer);
	palloc_free_page(buffer);
	return result;
}
