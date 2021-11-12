/* file.c: Implementation of memory backed file object (mmaped object). */

#include "lib/round.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
	for(int i=0; i<100; i++) mmap_list[i] = NULL;
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	if(!page->swapped) return true;

	file_seek(page->file.file, page->file.offset);
	file_read(page->file.file, page->va, page->file.read_bytes);
	memset(page->va + page->file.read_bytes, 0, page->file.zero_bytes);

	page->swapped = false;
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	file_seek(page->file.file, page->file.offset);
	if (page->frame != NULL && page->file_written) {
		file_write(page->file.file, page->va, page->file.read_bytes);
	}

	pml4_clear_page(thread_current()->pml4, page->va);
	palloc_free_page(page->frame->kva);
	free(page->frame);

	page->swapped = true;
	page->frame = NULL;
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	pml4_clear_page(thread_current()->pml4, page->va);
	if(page->frame) {
		palloc_free_page(page->frame->kva);
		list_remove(&page->frame->elem);
		free(page->frame);
	}
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t file_offset) {
	size_t read_bytes = file_length(file) < length ? file_length(file) : length;
	size_t zero_bytes = ROUND_UP(length, PGSIZE) - read_bytes;
	off_t va_offset = 0;
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* DONE: Set up aux to pass information to the lazy_load_segment. */
		// 인자 설정
		struct lazy_load_arg *aux = malloc(sizeof(struct lazy_load_arg));
		aux->file = file;
		aux->ofs = file_offset + va_offset;
		aux->upage = addr;
		aux->read_bytes = page_read_bytes;
		aux->zero_bytes = page_zero_bytes;
		aux->writable = writable;
		aux->is_last_page = read_bytes <= page_read_bytes && zero_bytes <= page_zero_bytes;
		aux->type = VM_FILE;

		if(spt_find_page(&thread_current()->spt, addr + va_offset)) return NULL;
		if (!vm_alloc_page_with_initializer (VM_FILE, addr + va_offset,
					writable, lazy_load_segment, aux))
			return NULL;

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		va_offset += PGSIZE;
	}
	for(int i=0; i<100; i++) if(mmap_list[i] == NULL) { mmap_list[i] = addr; break; }
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	for(int i=0; i<100; i++) if(mmap_list[i] == addr) mmap_list[i] = NULL;
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = NULL;
	struct file *file = NULL;
	while(true) {
		page = spt_find_page(spt, addr);
		if(page == NULL) break;

		if(page->operations->type == VM_FILE) {
			file = page->file.file;
			file_seek(file, page->file.offset);
			if (page->frame != NULL && page->file_written)
				file_write(file, addr, page->file.read_bytes);
		}

		bool is_last_page = page->file.is_last_page;
		spt_remove_page(spt, page);
		hash_delete(&spt->page_table, &page->hash_elem);
		
		if(is_last_page) break;;
		addr += PGSIZE;
		page = spt_find_page(spt, addr);
	}
}
