#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

// mmap 했던 주소들을 모아놓음
// 나중에 exit할 때 암시적으로 모두 munmap해야 함
void *mmap_list[100];

struct file_page {
	uint32_t read_bytes;
	uint32_t zero_bytes;
	bool is_last_page;
	struct file *file;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
