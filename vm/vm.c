/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
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
	// TODO: Virtual Memory 초기화 - 쓰레드 호출 전
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
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		
		/* TODO: Insert the page into the spt. */
		//TODO : writable 정보, init 랑 aux 처리
		if (type == VM_UNINIT){
			struct page *pg = malloc(sizeof(struct page));
			uninit_new(&pg, &upage, NULL, VM_UNINIT, NULL, NULL);
			spt_insert_page(&spt, &pg);
		}
		else{
			ASSERT(false);
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
	void *page_index = (int64_t)(&va) & VM_INDEX;
	page = hash_entry(hash_find(spt, page_index), struct page, hash_elem);

	return page;
}

/* Insert PAGE into spt with validation. */
// spt의 page_table에 page 넣기
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	int succ = false;
	/* DONE: Fill this function. */
	if (hash_insert(&spt->page_table, &page->hash_elem) == NULL){
		succ = true;
	}

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

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
	// TODO : spt 에서 가능한 page 찾아보기

	void *phys_page = palloc_get_page(PAL_USER);
	if (phys_page == NULL){
		// TODO : user pool 가득 찼을 때 예외처리 (프레임 테이블에서 빼서 가져오기)
	}
	frame = malloc(sizeof(struct frame));
	frame->kva = phys_page;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

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
// 
bool
vm_claim_page (void *va) {
	struct page *page = malloc(sizeof(struct page));
	/* DONE: Fill this function */
	void *va_index = (int64_t)(&va) & VM_INDEX;
	if (spt_find_page(&thread_current()->spt, &va_index) == NULL){
		vm_alloc_page(VM_UNINIT, &va_index, true);
	}

	return vm_do_claim_page (page);
}

/* DONE : Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* DONE: Insert page table entry to map page's VA to frame's PA. */
	struct supplemental_page_table *sup_pt = &thread_current()->spt;
	hash_insert(&sup_pt->page_table, &page->hash_elem);

	return swap_in (page, frame->kva);
}

// Local Func : page의 VA로 hash
unsigned
page_hash_func(struct hash_elem *e, void *aux UNUSED){
	const struct page *p = hash_entry(e, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
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
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* DONE : Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
