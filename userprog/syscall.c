#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include "lib/string.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/flags.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/directory.h"
#include "filesys/inode.h"

struct lock file_lock;
int std_in, std_out;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

// 유저 메모리에 접근하는 포인터인지 판별.
// 커널 메모리에 접근 또는 잘못된 주소면 false 반환
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
	
	//파일 건드릴때 lock 걸어줌
	lock_init(&file_lock);
}

/* The main system call interface */
// 시스템 콜 핸들러. 받고 어셈블리 (%rax, %rdi, %rsi) 처리해주는 곳
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	uint64_t syscall_type = f->R.rax;
	thread_current()->syscall_frame = f;
	switch(syscall_type){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			if(invalid_pointer(f->R.rdi)) exit(-1);
			else f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC:
			if(invalid_pointer(f->R.rdi)) exit(-1);
			else f->R.rax = exec(f->R.rdi);
			exit(-1);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
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
		case SYS_DUP2:
			f->R.rax = dup2(f->R.rdi, f->R.rsi);
			break;
		case SYS_MMAP:
			f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		case SYS_MUNMAP:
			munmap(f->R.rdi);
			break;
		case SYS_CHDIR:
			if(invalid_pointer(f->R.rdi)) exit(-1);
			f->R.rax = chdir(f->R.rdi);
			break;
		case SYS_MKDIR:
			if(invalid_pointer(f->R.rdi)) exit(-1);
			f->R.rax = mkdir(f->R.rdi);
			break;
		case SYS_READDIR:
			if(invalid_pointer(f->R.rsi)) exit(-1);
			f->R.rax = readdir(f->R.rdi, f->R.rsi);
			break;
		case SYS_ISDIR:
			f->R.rax = isdir(f->R.rdi);
			break;
		case SYS_INUMBER:
			f->R.rax = inumber(f->R.rdi);
			break;
		case SYS_SYMLINK:
			if(invalid_pointer(f->R.rdi) || invalid_pointer(f->R.rsi)) exit(-1);
			f->R.rax = symlink(f->R.rdi, f->R.rsi);
			break;
		default:
			thread_exit();
	}
}

// thread/init.h 의 함수 power_off 사용해서 돌아가고 있는 유저 프로그램 바로 종료시키기
void
halt(void) {
	power_off();
}

// 유저 프로그램 종료하기
// kernel로 status 반환 (0 : 성공, 나머지 : 에러)
void
exit(int status) {
	struct thread *curr = thread_current();
	
	// 현재 프로세스의 모든 child를 기다리기
	while(!list_empty(&curr->child_list)) {
		struct list_elem *e = list_front(&curr->child_list);
		struct child_process *child = list_entry(e, struct child_process, elem);
		process_wait(child->tid);
	}

	// 넘겨받은 exit status 출력
	curr->tf.R.rax = status;
	printf("%s: exit(%d)\n", curr->name, status);
	// parent에 정보 저장
	if(curr->parent != NULL)
		curr->child_struct->exit_status = status;
	// file descriptor 다 닫아주고 free 해주기
	if(!lock_held_by_current_thread(&file_lock))
		lock_acquire(&file_lock);
	while(!list_empty(&curr->fd_list)) {
		struct list_elem *e = list_pop_front(&curr->fd_list);
		struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
		if(fd->fd != &std_in && fd->fd != &std_out) file_close(fd->fd);
		free(fd);
	}
	file_close(curr->load_file);
	lock_release(&file_lock);
	thread_exit();
}

// 현재 프로세스(thread_name)와 완전히 똑같은 프로세스 생성 - 실제 실행은 do_fork를 볼 것
// Register(callee-saved는 빼도 됨), File descripter, User Stack
// parent 프로세스는 child가 종료될 때 까지 종료 X
// child process가 종료 실패시 TID_ERROR
pid_t
fork(const char *thread_name) {
	struct thread *curr = thread_current();
	pid_t result = process_fork(thread_name, curr->syscall_frame);
	return result;
}

// 현재 실행중인 프로세스를 cmd_line에 입력한 프로세스로 바꿈
// 성공 : 반환 없음. 
// 실패 : exit state -1 (아무튼 Load or Run 이 안됨)
int
exec(const char *cmd_line) {
	char *fn = palloc_get_page(PAL_USER | PAL_ZERO);
	for(int i = 0; cmd_line[i] != '\0'; i++) fn[i] = cmd_line[i];
	
	return process_exec(fn);
}

// pid에 해당하는 프로세스 wait
// exit status 반환
int
wait(pid_t pid) {
	return process_wait(pid);
}

// file 이름의 initial_size 크기를 가진 파일을 생성
// 성공시 true, 실패시 false
bool
create(const char *file, unsigned initial_size) {
	if (strlen(file) == 0)
		return false;
	lock_acquire(&file_lock);
	bool result = filesys_create (file, initial_size);
	lock_release(&file_lock);
	return result;
}

// file 이름을 가진 파일을 제거
// 성공시 true, 실패시 false
bool
remove(const char *file) {
	lock_acquire(&file_lock);
	bool result = filesys_remove(file);
	lock_release(&file_lock);
	return result;
}

// file 이름을 가진 파일을 오픈
// file descriptor 반환
int
open(const char *file) {
	struct thread *curr = thread_current();
	lock_acquire(&file_lock);
	struct file *f = filesys_open(file);
	lock_release(&file_lock);
	if(f == NULL) return -1;
	struct file_descriptor *file_descriptor = malloc(sizeof(struct file_descriptor));
	struct list_elem *insert_location = list_end(&curr->fd_list);
	// 0과 1은 STDIN, STDOUT를 위해 남겨둠
	int i=2;
	if(!list_empty(&curr->fd_list)) {
		for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
			struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
			if(fd->index > i){
				insert_location = e;
				break;
			}
			i++;
		}
	}
	file_descriptor->fd = f;
	file_descriptor->index = file_descriptor->original_index = i;
	list_insert(insert_location, &file_descriptor->elem);
	return i;
}

// 현재 쓰레드의 fd에 있는 파일의 사이즈 반환
int
filesize(int fd) {
	if(fd < 0) return 0;
	struct thread *curr = thread_current();
	struct file *f = NULL;
	if(list_empty(&curr->fd_list)) return 0;
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		struct file_descriptor *file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == fd) {
			f = file_descriptor->fd;
		}
	}
	if(f == NULL) return 0;
	lock_acquire(&file_lock);
	int result = file_length(f);
	lock_release(&file_lock);
	return result;
}

// fd 파일의 size 만큼을 buffer에 넣는 것으로 읽어오기
// 실패시 -1 반환
int
read(int fd, void *buffer, unsigned size) {
	struct thread *curr = thread_current();
	struct file *f = NULL;
	struct file_descriptor *file_descriptor = NULL;
	if(list_empty(&curr->fd_list)) return 0;
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == fd) {
			f = file_descriptor->fd;
		}
	}
	if(f == NULL) return -1;
	if(f == &std_in) {
		if(curr->stdin_close) return 0;
		lock_acquire(&file_lock);
		for(unsigned i=0; i<size; i++) *(char *)(buffer+i) = input_getc();
		lock_release(&file_lock);
		return size;
	}
	if(f == &std_out) return -1;
	// writable 검사
	struct page *page = spt_find_page(&curr->spt, buffer);
	if(page != NULL && page->original_writable == false) if(!vm_try_handle_fault(curr->syscall_frame, buffer, false, true, true)) exit(-1);
	lock_acquire(&file_lock);
	int result = file_read(f, buffer, size);
	lock_release(&file_lock);
	seek(fd, file_tell(f)); // dup2로 복사한 파일도 처리하기
	return result;
}

// fd 파일에 size 만큼을 buffer에 있는 것 가져와서 적기
// 적기 성공한 byte 만큼을 반환
int
write(int fd, const void *buffer, unsigned size) {
	struct thread *curr = thread_current();
	struct file *f = NULL;
	struct file_descriptor *file_descriptor = NULL;
	if(list_empty(&curr->fd_list)) return 0;
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == fd) {
			f = file_descriptor->fd;
		}
	}
	if(f == NULL) return -1;
	if(f == &std_in) return -1;
	if(f == &std_out) {
		if(curr->stdout_close) return 0;
		lock_acquire(&file_lock);
		putbuf(buffer, size);
		lock_release(&file_lock);
		return size;
	}
	lock_acquire(&file_lock);
	int result = file_write(f, buffer, size);
	lock_release(&file_lock);
	seek(fd, file_tell(f)); // dup2로 복사한 파일도 처리하기
	return result;
}

// fd의 다음 읽기/쓰기를 position으로 바꾸기
// 반환 X
void
seek(int fd, unsigned position) {
	if(fd < 0) return 0;
	struct thread *curr = thread_current();
	struct file *target_file = NULL;
	struct file *f2 = NULL;
	if(list_empty(&curr->fd_list)) return 0;
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		struct file_descriptor *file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == fd) {
			target_file = file_descriptor->fd;
			break;
		}
	}
	if(target_file == NULL) return;
	if(target_file == &std_in || target_file == &std_out) return;
	// dup2로 복사된 fd들도 전부 seek 해줘야 됨
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		struct file_descriptor *file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->fd == &std_in || file_descriptor->fd == &std_out) continue;
		if(file_get_inode(target_file) == file_get_inode(file_descriptor->fd)) {
			lock_acquire(&file_lock);
			file_seek(file_descriptor->fd, position);
			lock_release(&file_lock);
		}
	}
}

// fd의 현재 읽기/쓰기를 하는 position 반환
// 반환 X
unsigned
tell(int fd) {
	if(fd < 0) return 0;
	struct thread *curr = thread_current();
	struct file *f = NULL;
	if(list_empty(&curr->fd_list)) return 0;
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		struct file_descriptor *file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == fd) {
			f = file_descriptor->fd;
		}
	}
	if(f == NULL) return;
	lock_acquire(&file_lock);
	unsigned result = file_tell(f);
	lock_release(&file_lock);
	return result;
}

// fd 닫기
// 반환 X
void
close(int fd) {
	if(fd < 0) return;
	struct thread *curr = thread_current();
	struct file *f = NULL;
	struct file_descriptor *file_descriptor;
	if(list_empty(&curr->fd_list)) return 0;
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == fd) {
			f = file_descriptor->fd;
			break;
		}
	}
	if(f == NULL) return;
	if(f == &std_in) curr->stdin_close = true;
	else if(f == &std_out) curr->stdout_close = true;
	else {
		lock_acquire(&file_lock);
		file_close(f);
		lock_release(&file_lock);
	}
	list_remove(&file_descriptor->elem);
	free(file_descriptor);
}

// file descriptor 복사해 오기
// oldfd에서 newfd로 복사하기
// oldfd가 invalid: 복사 안 하고 -1 반환
// oldfd가 valid: 복사 하고 newfd 반환
int 
dup2(int oldfd, int newfd) {
	struct file_descriptor *file_descriptor;
	struct file_descriptor *old_file_descriptor;
	struct file_descriptor *new_file_descriptor;
	int oldflag = 0, newflag = 0;
	struct thread *curr = thread_current();

	// fd_list가 비어 있으면 실패
	if(list_empty(&curr->fd_list)) 
		return -1;

	// fd_list에 oldfd가 있는지 확인, 있으면 oldflag = 1
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == oldfd) {
			old_file_descriptor = file_descriptor;
			oldflag = 1;
			break;
		}
	}

	// fd_list에 newfd가 있는지 확인, 있으면 newflag = 1
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == newfd) {
			new_file_descriptor = file_descriptor;
			newflag = 1;
			break;
		}
	}

	// oldfd가 invalid 한 경우
	if(!oldflag || old_file_descriptor->fd == NULL)
		return -1;

	// oldfd와 newfd가 같은 경우
	if(oldfd == newfd)
		return newfd;

	// newfd가 존재하지 않는 경우, 새로운 fd 생성
	if(!newflag){
		struct list_elem *insert_location = list_end(&curr->fd_list);
		// fd_list는 오름차순 정렬이므로 insert 위치 정해야 됨
		for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
			file_descriptor = list_entry(e, struct file_descriptor, elem);
			if(file_descriptor->index > newfd) {
				insert_location = e;
				break;
			}
		}
		// new_file_descriptor 만들기
		new_file_descriptor = malloc(sizeof(struct file_descriptor));
		new_file_descriptor->index = newfd;
		new_file_descriptor->original_index = old_file_descriptor->original_index;
		lock_acquire(&file_lock);
		// stdin, stdout인 경우 구별해서 처리
		if(old_file_descriptor->fd != &std_in && old_file_descriptor->fd != &std_out)
			new_file_descriptor->fd = file_duplicate(old_file_descriptor->fd);
		else new_file_descriptor->fd = old_file_descriptor->fd;
		lock_release(&file_lock);
		list_insert(insert_location, &new_file_descriptor->elem);
	}

	// newfd가 존재하는 경우, oldfd에서 복사해서 덮어씀
	else{
		new_file_descriptor->index = newfd;
		new_file_descriptor->original_index = old_file_descriptor->original_index;
		lock_acquire(&file_lock);
		// 기존 newfd 닫기
		if(new_file_descriptor->fd != &std_in && new_file_descriptor->fd != &std_out)
			file_close(new_file_descriptor->fd);
		// stdin, stdout인 경우 구별해서 처리
		if(old_file_descriptor->fd != &std_in && old_file_descriptor->fd != &std_out)
			new_file_descriptor->fd = file_duplicate(old_file_descriptor->fd);
		else new_file_descriptor->fd = old_file_descriptor->fd;
		lock_release(&file_lock);
	}
	
	return newfd;
}

// fd 파일부터 offset 떨어진 곳부터 length만큼의 byte를 addr에 쓰기
// 메모리는 lazy하게 할당됨
// 성공: addr 반환, 실패: NULL 반환
// 실패: fd 파일이 존재하지 않거나, fd 파일이 0byte이거나, length가 0인 경우
// 실패: addr이 NULL이거나 page-align이 아니거나 해당 주소의 메모리가 이미 존재하는 경우
void *
mmap(void *addr, size_t length, int writable, int fd, off_t offset) {
	struct thread *curr = thread_current();
	struct file *file = NULL;
	struct file_descriptor *file_descriptor;
	if(addr == NULL || (uint64_t)addr % PGSIZE != 0 || length <= 0 || offset % PGSIZE != 0) 
		return NULL;
	if (is_kernel_vaddr(addr) || addr == 0 || length > KERN_BASE)
		return NULL;

	// fd 파일 검사
	if(list_empty(&curr->fd_list)) return NULL;
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == fd) {
			file = file_descriptor->fd;
			break;
		}
	}
	if(file == NULL || file_length(file) == 0) 
		return NULL;
	if(file_length(file) < offset) 
		return NULL;

	// addr 주소 영역에 이미 메모리가 존재하는 경우
	for(size_t i = 0; i < length; i += PGSIZE)
		if(spt_find_page(&thread_current()->spt, addr + i)) return NULL;

	return do_mmap(addr, length, writable, file_reopen(file), offset);
}

// addr부터 시작하는 mapping을 unmap하기
// 모든 작성된 byte를 다시 파일에 작성하고 virtual address는 page table에서 제거
// exit 등에 의해 프로세스가 종료될 때 실행됨
void
munmap(void *addr) {
	return do_munmap(addr);
}

// 현재 작업 중인 디렉토리를 dir로 바꿈
// 상대 경로일 수도 있고 절대 경로일 수도 있음
bool
chdir(const char *dir) {
	dir_current = get_dir_from_name(dir, true).dir;
	return dir_current != NULL;
}

// 이름이 dir인 디렉토리 생성
// 이미 존재하는 경우 실패
bool
mkdir(const char *dir) {
	struct get_dir_struct dir_struct = get_dir_from_name(dir, false);
	if(dir_struct.dir == NULL || dir_struct.name == NULL) return false;
	uint32_t clst = fat_create_chain(0);
	if(clst == 0) return false;
	if(!dir_create(clst, 1)) return false;
	if(!dir_add(dir_struct.dir, dir_struct.name, clst)) return false;

	// 생성한 디렉토리의 부모 설정
	struct inode *inode = inode_open(clst);
	inode_set_parent(inode, inode_get_inumber(dir_get_inode(dir_struct.dir)));
	inode_close(inode);

	return true;
}

// fd로부터 디렉토리 엔트리를 읽어서 name에 저장
bool
readdir(int fd, char *name) {
	struct thread *curr = thread_current();
	struct file *file = NULL;
	struct file_descriptor *file_descriptor;
	if(list_empty(&curr->fd_list)) return NULL;
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == fd) {
			file = file_descriptor->fd;
			struct dir *dir = dir_open(file_get_inode(file));
			dir_set_pos(dir, file_tell(file));
			bool result = dir_readdir(dir, name);
			file_seek(file, dir_get_pos(dir));
			return result;
		}
	}
}

// fd가 디렉토리를 가리킨다면 true 반환
// fd가 일반적인 파일을 가리킨다면 false 반환
bool
isdir(int fd) {
	struct thread *curr = thread_current();
	struct file *file = NULL;
	struct file_descriptor *file_descriptor;
	if(list_empty(&curr->fd_list)) return NULL;
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == fd) {
			file = file_descriptor->fd;
			return inode_is_directory(file_get_inode(file));
		}
	}
}

// fd가 가리키는 inode의 번호 반환
// inode의 sector number를 반환하면 됨
int
inumber(int fd) {
	struct thread *curr = thread_current();
	struct file *file = NULL;
	struct file_descriptor *file_descriptor;
	if(list_empty(&curr->fd_list)) return NULL;
	for(struct list_elem *e = list_front(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		file_descriptor = list_entry(e, struct file_descriptor, elem);
		if(file_descriptor->index == fd) {
			file = file_descriptor->fd;
			return inode_get_inumber(file_get_inode(file));
		}
	}
}

// target을 가리키는, 이름이 linkpath인 symbolic link 생성
// 성공하면 0, 실패하면 -1 반환
int
symlink(const char *target, const char *linkpath) {
	disk_sector_t inode_sector = 0;
	struct dir *current_directory = dir_reopen(dir_current);
	char *target_string = malloc(sizeof(target));
	strlcpy(target_string, target, sizeof(target) + 1);
	bool success = (current_directory != NULL
			&& ((inode_sector = fat_create_chain(0)) != 0)
			&& inode_create (inode_sector, 0, false, true, target_string)
			&& dir_add (current_directory, linkpath, inode_sector));
	if (!success && inode_sector != 0)
		fat_remove_chain(inode_sector, 0);
	if(success) {
		// 생성한 파일의 부모 설정
		struct inode *inode;
		inode = inode_open(inode_sector);
		inode_set_parent(inode, inode_get_inumber(dir_get_inode(current_directory)));
		inode_close(inode);
	}
	dir_close (current_directory);

	return success ? 0 : -1;
}
