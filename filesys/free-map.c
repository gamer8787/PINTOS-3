#include "filesys/free-map.h"
#include <bitmap.h>
#include <debug.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/fat.h"
static struct file *free_map_file;   /* Free map file. */
static struct bitmap *free_map;      /* Free map, one bit per disk sector. */

/* Initializes the free map. */
void
free_map_init (void) {
	fat_init();
}

/* Allocates CNT consecutive sectors from the free map and stores
 * the first into *SECTORP.
 * Returns true if successful, false if all sectors were
 * available. */
bool
free_map_allocate (size_t cnt, disk_sector_t *sectorp) {
	cluster_t a = fat_create_chain(cnt);
	if(a== 0){
		return false;
	}
	*sectorp = cluster_to_sector(a);
	return true;
}

/* Makes CNT sectors starting at SECTOR available for use. */
void
free_map_release (disk_sector_t sector, size_t cnt) {
	fat_remove_chain(sector+1,cnt);
}

/* Opens the free map file and reads it from disk. */
void
free_map_open (void) {
	fat_open();
}

/* Writes the free map to disk and closes the free map file. */
void
free_map_close (void) {
	fat_close();

}

/* Creates a new free map file on disk and writes the free map to
 * it. */
void
free_map_create (void) {
	fat_create();
}
