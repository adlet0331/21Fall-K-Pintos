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
	/* DONE: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	disk_sector_list = malloc(disk_size(swap_disk) / 8);
	for(int i=0; i<disk_size(swap_disk) / 8; i++) disk_sector_list[i] = false;
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

/* DONE : Swap in the page by read contents from the swap disk. */
// 디스크 -> 메모리
// page가 디스크에 존재하는 상태(swap-out이 된 상태)면 다시 메모리에 복사해 오기
//                존재하지 않는 상태면 true 반환
static bool
anon_swap_in (struct page *page, void *kva) {
	if(!page->swapped) return true;

	disk_sector_t sector = page->disk_sector;
	disk_sector_t asdf = disk_size(swap_disk);
	disk_sector_list[sector / 8] = false;
	for(int i=0; i<8; i++) disk_read(swap_disk, sector + i, page->frame->kva + i * DISK_SECTOR_SIZE);
	page->swapped = false;
	return true;
}

/* DONE : Swap out the page by writing contents to the swap disk. */
// 메모리 -> 디스크
static bool
anon_swap_out (struct page *page) {
	disk_sector_t sector;
	for(int i=0; i<disk_size(swap_disk) / 8; i++) if(!disk_sector_list[i]) { sector = i * 8; disk_sector_list[i] = true; break; }

	for(int i=0; i<8; i++) disk_write(swap_disk, sector + i, page->frame->kva + i * DISK_SECTOR_SIZE);
	pml4_clear_page(thread_current()->pml4, page->va);
	palloc_free_page(page->frame->kva);
	free(page->frame);
	page->disk_sector = sector;
	page->swapped = true;
	page->frame = NULL;
	return true;
}

/* DONE : Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	pml4_clear_page(page->pml4, page->va);
	if(page->frame) {
		struct frame *frame = page->frame;

		// 해당 frame을 사용하는 page가 자기뿐이면 frame 제거
		if(list_empty(&frame->forked_page_list)) {
			ASSERT(frame->page == page);
			palloc_free_page(page->frame->kva);
			list_remove(&page->frame->elem);
			free(page->frame);
		}

		// frame->page를 새로운 것으로 설정
		else if(frame->page == page) {
			struct list_elem *e = list_front(&frame->forked_page_list);
			struct page *page = list_entry(e, struct page, list_elem);
			frame->page = page;
		}

		// frame->forked_page_list에서 자신 제거
		else {
			list_remove(&page->list_elem);
		}
	}
}
