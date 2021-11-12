/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "threads/mmu.h"
#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	page->anon = (struct anon_page) {
		.is_initialized = true,
	};
	
	return true;
}

/* TODO : Swap in the page by read contents from the swap disk. */
// 디스크 -> 메모리
// page가 디스크에 존재하는 상태(swap-out이 된 상태)면 다시 메모리에 복사해 오기
//                존재하지 않는 상태면 true 반환
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	if(!page->swapped) return true;
}

/* TODO : Swap out the page by writing contents to the swap disk. */
// 메모리 -> 디스크
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}

/* TODO : Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	pml4_clear_page(thread_current()->pml4, page->va);
	if(page->frame) {
		palloc_free_page(page->frame->kva);
		free(page->frame);
	}
}
