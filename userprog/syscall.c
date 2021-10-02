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

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	uint64_t syscall_type = f->R.rax;
	// printf("-- system call %llu\n", syscall_type);
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
			exec(f->R.rdi);
			break;
		case SYS_WAIT:
			wait(f->R.rdi);
			break;
		case SYS_CREATE:
			create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			remove(f->R.rdi);
			break;
		case SYS_OPEN:
			open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			filesize(f->R.rdi);
			break;
		case SYS_READ:
			read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			thread_exit();
	}
}

// SYS_HALT,                   /* Halt the operating system. */
// SYS_EXIT,                   /* Terminate this process. */
// SYS_FORK,                   /* Clone current process. */
// SYS_EXEC,                   /* Switch current process. */
// SYS_WAIT,                   /* Wait for a child process to die. */
// SYS_CREATE,                 /* Create a file. */
// SYS_REMOVE,                 /* Delete a file. */
// SYS_OPEN,                   /* Open a file. */
// SYS_FILESIZE,               /* Obtain a file's size. */
// SYS_READ,                   /* Read from a file. */
// SYS_WRITE,                  /* Write to a file. */
// SYS_SEEK,                   /* Change position in a file. */
// SYS_TELL,                   /* Report current position in a file. */
// SYS_CLOSE,                  /* Close a file. */

void
halt(void) {
	power_off();
}

void
exit(int status) {
	thread_current()->tf.R.rax = status;
	printf("%s: exit(%d)\n", thread_current()->name, status);
	process_exit();
}

pid_t
fork(const char *thread_name) {
	thread_exit();
}

int
exec(const char *cmd_line) {
	thread_exit();
}

int
wait(pid_t pid) {
	thread_exit();
}

bool
create(const char *file, unsigned initial_size) {
	thread_exit();
}

bool
remove(const char *file) {
	thread_exit();
}

int
open(const char *file) {
	thread_exit();
}

int
filesize(int fd) {
	thread_exit();
}

int
read(int fd, void *buffer, unsigned size) {
	thread_exit();
}

int
write(int fd, const void *buffer, unsigned size) {
	if(fd == 1) putbuf(buffer, size);
	else thread_exit();
}

void
seek(int fd, unsigned position) {
	thread_exit();
}

unsigned
tell(int fd) {
	thread_exit();
}

void
close(int fd) {
	thread_exit();
}
