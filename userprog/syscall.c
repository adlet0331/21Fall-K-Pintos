#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

struct lock file_lock;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

bool
invalid_pointer(void *ptr) {
	if(ptr < 0x400000 || ptr > USER_STACK) return true;
	uint64_t *pte = pml4e_walk(thread_current()->pml4, ptr, 0);
	if(pte == NULL) return true;
	return false;
}

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	lock_init(&file_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	uint64_t syscall_type = f->R.rax;
	switch(syscall_type){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			fork(f->R.rdi);
			break;
		case SYS_EXEC:
			if(invalid_pointer(f->R.rdi)) exit(-1);
			else f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			wait(f->R.rdi);
			break;
		case SYS_CREATE:
			if(invalid_pointer(f->R.rdi)) exit(-1);
			else f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			if(invalid_pointer(f->R.rdi)) exit(-1);
			else f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			if(invalid_pointer(f->R.rdi)) exit(-1);
			else f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			if(invalid_pointer(f->R.rsi)) exit(-1);
			else f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			if(invalid_pointer(f->R.rsi)) exit(-1);
			else f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			thread_exit();
	}
}

void
halt(void) {
	power_off();
}

void
exit(int status) {
	thread_current()->tf.R.rax = status;
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

pid_t
fork(const char *thread_name) {
	thread_exit();
}

int
exec(const char *cmd_line) {
	char fn[20] = {};
	for(int i = 0; cmd_line[i] != ' ' && cmd_line[i] != '\0'; i++) fn[i] = cmd_line[i];
	
	return process_exec(fn);
}

int
wait(pid_t pid) {
	thread_exit();
}

bool
create(const char *file, unsigned initial_size) {
	if (strlen(file) == 0)
		return false;
	lock_acquire(&file_lock);
	bool result = filesys_create (file, initial_size);
	lock_release(&file_lock);
	return result;
}

bool
remove(const char *file) {
	lock_acquire(&file_lock);
	bool result = filesys_remove(file);
	lock_release(&file_lock);
	return result;
}

int
open(const char *file) {
	struct thread *curr = thread_current();
	lock_acquire(&file_lock);
	struct file *f = filesys_open(file);
	if(f == NULL) {
		lock_release(&file_lock);
		return -1;
	}
	for(int i = 2; i < 20; i++) {
		if (curr->fd[i] == NULL) {
			curr->fd[i] = f;
			lock_release(&file_lock);
			return i;
		}
	}
	lock_release(&file_lock);
	return -1;
}

int
filesize(int fd) {
	if(fd >= 20 || fd < 0) return 0;
	struct thread *curr = thread_current();
	struct file *f = curr->fd[fd];
	if(f == NULL) return 0;
	lock_acquire(&file_lock);
	int result = file_length(f);
	lock_release(&file_lock);
	return result;
}

int
read(int fd, void *buffer, unsigned size) {
	if(fd == 1 || fd >= 20 || fd < 0) return 0;
	struct thread *curr = thread_current();
	struct file *f = curr->fd[fd];
	if(f == NULL) return -1;
	lock_acquire(&file_lock);
	int result = file_read(f, buffer, size);
	lock_release(&file_lock);
	return result;
}

int
write(int fd, const void *buffer, unsigned size) {
	if(fd >= 20 || fd <= 0) return 0;
	lock_acquire(&file_lock);
	if(fd == 1) {
		putbuf(buffer, size);
		lock_release(&file_lock);
		return size;
	}
	struct thread *curr = thread_current();
	struct file *f = curr->fd[fd];
	if(f == NULL) {
		lock_release(&file_lock);
		return -1;
	}
	int result = file_write(f, buffer, size);
	lock_release(&file_lock);
	return result;
}

void
seek(int fd, unsigned position) {
	if(fd >= 20 || fd < 0) return 0;
	struct thread *curr = thread_current();
	struct file *f = curr->fd[fd];
	if(f == NULL) return;
	lock_acquire(&file_lock);
	file_seek(f, position);
	lock_release(&file_lock);
}

unsigned
tell(int fd) {
	if(fd >= 20 || fd < 0) return 0;
	struct thread *curr = thread_current();
	struct file *f = curr->fd[fd];
	if(f == NULL) return;
	lock_acquire(&file_lock);
	unsigned result = file_tell(f);
	lock_release(&file_lock);
	return result;
}

void
close(int fd) {
	if(fd >= 20 || fd < 0) return;
	struct thread *curr = thread_current();
	struct file *f = curr->fd[fd];
	if(f == NULL) return;
	curr->fd[fd] = NULL;
	lock_acquire(&file_lock);
	file_close(f);
	lock_release(&file_lock);
}
