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
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;
	page->writable = page->file_writable;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	pml4_clear_page(thread_current()->pml4, page->va);
	if(page->frame) {
		palloc_free_page(page->frame->kva);
		free(page->frame);
	}
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	size_t read_bytes = file_length(file) < length ? file_length(file) : length;
	size_t zero_bytes = ROUND_UP(length, PGSIZE) - read_bytes;
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
		aux->ofs = offset;
		aux->upage = addr;
		aux->read_bytes = page_read_bytes;
		aux->zero_bytes = page_zero_bytes;
		aux->writable = writable;
		aux->is_last_page = read_bytes <= page_read_bytes && zero_bytes <= page_zero_bytes;
		aux->type = VM_FILE;

		if(spt_find_page(&thread_current()->spt, addr + offset)) return NULL;
		if (!vm_alloc_page_with_initializer (VM_FILE, addr + offset,
					writable, lazy_load_segment, aux))
			return NULL;

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		offset += PGSIZE;
	}
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = spt_find_page(spt, addr);
	struct file *file = page->file.file;
	off_t offset = 0;
	while(page != NULL) {
		if(page == NULL) return;
		file_seek(file, offset);
		if (page->frame != NULL)
			file_write(file, addr, page->file.read_bytes);

		bool is_last_page = page->file.is_last_page;
		spt_remove_page(spt, page);
		hash_delete(&spt->page_table, &page->hash_elem);
		
		if(is_last_page) return;
		addr += PGSIZE;
		offset += PGSIZE;
		page = spt_find_page(spt, addr);
	}
}
