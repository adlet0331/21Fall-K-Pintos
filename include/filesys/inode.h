#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/disk.h"

struct bitmap;

void inode_init (void);
bool inode_create (disk_sector_t, off_t, bool, bool, char *);
struct inode *inode_open (disk_sector_t);
struct inode *inode_reopen (struct inode *);
disk_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);
bool inode_is_directory(struct inode *);
bool inode_is_symlink(struct inode *);
char *inode_get_symlink(struct inode *);
int inode_get_count(struct inode *);
void inode_change_count(struct inode *, int);
disk_sector_t inode_get_parent(struct inode *);
void inode_set_parent(struct inode *, disk_sector_t);
bool inode_is_removed(struct inode *);

#endif /* filesys/inode.h */
