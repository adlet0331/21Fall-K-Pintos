/* vm.c: Generic interface for virtual memory objects. */

#include "lib/string.h"
#include "lib/kernel/hash.h"
#include "devices/disk.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "vm/uninit.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	// DONE: Virtual Memory 초기화 - 쓰레드 호출 전
	// frame 리스트 초기화
	list_init(&frame_list);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
// 처음 page lazy하게 만드는 것 (아직 가짜 페이지인 단계)
// uninit_new : Uninit (가짜 페이지) 를 만들어줌. init - lazy_load_segment
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* DONE: Create the page, fetch the initialier according to the VM type,
		 * DONE: and then create "uninit" page struct by calling uninit_new. You
		 * DONE: should modify the field after calling the uninit_new. */
		
		/* DONE: Insert the page into the spt. */
		if (type == VM_ANON){
			struct page *pg = malloc(sizeof(struct page));
			uninit_new(pg, upage, init, VM_ANON, aux, anon_initializer);
			spt_insert_page(spt, pg);
			pg->original_writable = writable;
			pg->type = VM_ANON;
			pg->pml4 = thread_current()->pml4;
			pg->is_loaded = false;
			return true;
		}
		else if (type == VM_FILE){
			struct page *pg = malloc(sizeof(struct page));
			uninit_new(pg, upage, init, VM_FILE, aux, file_backed_initializer);
			spt_insert_page(spt, pg);
			pg->original_writable = writable; // lazy_load할 때는 page에 write 해야 됨
			pg->file_written = false; //처음엔 false로 두지만, 나중에 write 할 때 try_handle_fault에서 true로 바꿔줌. munmap 에서 씀
			pg->type = VM_FILE;
			pg->pml4 = thread_current()->pml4;
			pg->is_loaded = false;
			return true;
		}
		else{
			goto err;
		}		
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
// spt의 page_table에서 VA 로 page 찾기
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *page = NULL;
	/* DONE: Fill this function. */
	struct hash_iterator i;
	hash_first(&i, &spt->page_table);
	while (hash_next(&i)){
		struct page *f = hash_entry(hash_cur(&i), struct page, hash_elem);
		if ((int64_t) f->va == ((int64_t)va & ~PGMASK)){
			return f;
		}
	}
	return NULL;
}

/* Insert PAGE into spt with validation. */
// spt의 page_table에 page 넣기
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	bool succ = false;
	/* DONE: Fill this function. */
	if(hash_find(&spt->page_table, &page->hash_elem)) return true;
	if (hash_insert(&spt->page_table, &page->hash_elem) == NULL){
		succ = true;
	}

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	if (spt_find_page(spt, page->va) == NULL)
		return;
	hash_delete(&spt->page_table, &page->hash_elem);
	vm_dealloc_page (page);
	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* DONE: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* DONE: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
// Get frame. Page X -> Page 요구 | UM Full -> frame 하나 쏙 빼서 그걸로 가져오기
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	// DONE : spt 에서 가능한 page 찾아보기

	void *phys_page = palloc_get_page(PAL_USER);
	if (phys_page == NULL){
		// DONE : user pool 가득 찼을 때 예외처리 (프레임 테이블에서 빼서 가져오기)
		// 프레임 하나 정해서 swap_out 하기
		struct list_elem *e = list_pop_front(&frame_list);
		struct frame *victim = list_entry(e, struct frame, elem);
		swap_out(victim->page);
		phys_page = palloc_get_page(PAL_USER);
	}
	frame = malloc(sizeof(struct frame));
	frame->kva = phys_page;
	frame->page = NULL;
	list_init(&frame->forked_page_list);

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	ASSERT (list_empty(&frame->forked_page_list));
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	void *va = (uint64_t)addr & ~PGMASK;
	vm_alloc_page(VM_ANON, va, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
// Page Fault 났을 때 옴
// 현재 
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;
	/* DONE: Validate the fault */
	/* DONE: Your code goes here */
	page = spt_find_page(spt, addr);
	if(page == NULL){
		// stack growth를 해야 하는 경우
		// 스택의 내부에 있고 + 스택 크기가 1MB를 넘으면 안 됨
		// x86-64 push 연산은 메모리 체크를 먼저 하기 때문에 rsp보다 8byte 앞에 있다
		uintptr_t rsp = user ? f->rsp : thread_current()->syscall_frame->rsp;
		if(addr + 8 >= rsp && addr < USER_STACK && addr + 256 * PGSIZE >= USER_STACK) {
			vm_stack_growth(addr);
			page = spt_find_page(spt, addr);
		}
		else
			return false; // 잘못된 주소
	}

	//forked 당한 frame 이 read only 에 write 요청을 넣어서 들어옴
	bool asdf = list_empty(&page->frame->forked_page_list);
	if (write && page->frame != NULL && !list_empty(&page->frame->forked_page_list) && page->is_loaded){
		// ANON 과 FILE 나눠서 해주기. ANON은 PAGE 하나만 해주면 되지만 FILE은 전체를 MMAP 하는 방법으로 갈 듯
		// parent는 기존의 frame을 유지하고, child들을 새로 만들어주는 것
		struct list_elem *le = list_head(&page->frame->forked_page_list);
		while(le != NULL){
			struct page *other_forked_page = list_entry(le, struct page, list_elem);
			other_forked_page->frame = NULL;
			if (!vm_do_claim_page(other_forked_page))
				return false;
			memcpy(other_forked_page->frame->kva, page->frame->kva, PGSIZE);
			// pml4_set_page(other_forked_page->pml4, other_forked_page->frame, other_forked_page->frame->kva, true);

			other_forked_page = list_next(le);
		}
		//부모 page는 이미 되어 있으니 pml4만 갱신해주자
		struct page *parent_page = page->frame->page;
		// pml4_set_page(parent_page->pml4, parent_page->frame, parent_page->frame->kva, true);
	}

	//DONE

	// read only에 write를 시도한 경우
	if(!page->original_writable && write)
		return false;

	// Frame 할당 후 성공 여부 반환
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* DONE : Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	/* DONE: Fill this function */
	void *va_index = (int64_t)(va) & ~PGMASK;
	struct page *page = spt_find_page(&thread_current()->spt, va_index);

	return vm_do_claim_page (page);
}

/* DONE : Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = page->frame;
	if (page->frame == NULL){ //처음 page fault가 불렸을 때 (read 나 write 로)
		frame = vm_get_frame ();
		
		list_push_back(&frame_list, &frame->elem);

		/* Set links */
		frame->page = page;
		page->frame = frame;

		//pml4 매핑 처음에는 read만 가능하게 하기. write 하려고 하면 또 page_fault 걸려서 아래로 갈 것
		if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, false)) 
			return false;
	}
	else { //read n번 불린 후 write가 불렸을 때
		if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->original_writable))
			return false;
		page->file_written = true;
	}

	// page가 swapped됐다면: swap_in
	//        swapped되지 않았다면: 그냥 끝

	// Uninit의 swap_in (uninit_initialize) 임 - 여기서 page initializer로 초기화 시켜준 후 lazy_load_segment 해줌
	// anon, file의 경우 anon_swap_in, file_swap_in 실행
	page->is_loaded = true;
	return swap_in (page, frame->kva);
}

// Local Func : page의 VA로 hash
unsigned
page_hash_func(struct hash_elem *e, void *aux UNUSED){
	const struct page *p = hash_entry(e, struct page, hash_elem);
	uint64_t va = (uint64_t) p->va & ~PGMASK;
	return hash_bytes((&va), sizeof(va));
}

// Local Func : 두 page의 비교
bool
spt_hash_less_func(struct hash_elem *a, struct hash_elem *b, void *aux){
	return (page_hash_func(a, NULL) < page_hash_func(b, NULL));
}

/* DONE : Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	hash_init(&spt->page_table, page_hash_func, spt_hash_less_func, NULL);
}

/* DONE : Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	// child에서 실행됨
	// 일단은 모든 page를 복사해서 붙임
	struct hash_iterator i;
	hash_first(&i, &src->page_table);
	while(hash_next(&i)) {
		struct page *page = hash_entry(hash_cur(&i), struct page, hash_elem);
		
		if(!vm_alloc_page(page->type, page->va, page->original_writable)) 
			return false;

		struct page *new_page = spt_find_page(dst, page->va);

		if(new_page == NULL) 
			return false;
		if(page->frame) { // 이미 frame이 할당된 page라면 -> frame을 같은 걸로 가리키게 하기. frame->page는 parent page 가리키고 있음.
			new_page->frame = page->frame;
			list_push_back(&page->frame->forked_page_list, &new_page->list_elem);
			pml4_set_page(thread_current()->pml4, page->va, new_page->frame->kva, false); // Write 할 때 page fault가 나도록
		}
		else { // lazy_load 때문에 아직 frame 할당 안 된 상태. Cow 할 때 따로 처리할 필요 X
			new_page->uninit = page->uninit;
		}
	}
	return true;
}

/* DONE : Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* DONE: Destroy all the supplemental_page_table hold by thread and
	 * DONE: writeback all the modified contents to the storage. */
	struct thread *curr = thread_current();
	for(int i=0; i<100; i++) if(curr->mmap_list[i]) do_munmap(curr->mmap_list[i]);

	struct hash_iterator i;
	struct page *pg;
	while (1){
		if(hash_empty(&spt->page_table))
			return;
		hash_first(&i, &spt->page_table);
		hash_next(&i);
		pg = hash_entry(hash_cur(&i), struct page, hash_elem);
		spt_remove_page(spt, pg);
		hash_delete(&spt->page_table, hash_cur(&i));
	}
}
