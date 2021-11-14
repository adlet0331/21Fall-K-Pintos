#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

// lazy_load_segment, lazy_load_file을 위한 인자
struct lazy_load_arg {
	enum vm_type type;

	struct file *file;
	off_t ofs;
	uint8_t *upage;
	uint32_t read_bytes;
	uint32_t zero_bytes;
	bool writable;

	// lazy_load_file에서만 사용
	bool is_last_page; // 파일의 마지막 페이지인지 구별
	void *mmap_addr; // COW를 위해 추가
};

bool lazy_load_segment (struct page *, struct lazy_load_arg *);

#endif /* userprog/process.h */
