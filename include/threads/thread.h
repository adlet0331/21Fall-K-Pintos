#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#ifdef VM
#include "vm/vm.h"
#endif
#include "threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

// child process로서의 정보
struct child_process {
	tid_t tid;
	int exit_status;
	struct semaphore wait_sema; // process_wait에서 사용할 sema
	struct list_elem elem;
};

// file descriptor 정보
struct file_descriptor {
	int index;
	int original_index;
	struct file *fd;
	struct list_elem elem;
};

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */

	int64_t time_to_run; // 실행 될 시간
	int original_priority; // 원래 priority
	struct lock *lock; // 내가 기다리는 lock
	struct list locks; // 내가 acquire한 lock
	int nice; // nice 값 (mlfqs)
	int recent_cpu; // recent_cpu 값 (mlfqs)
	struct list_elem all_elem; // 전체 thread의 목록에 들어갈 elem
	struct list child_list; // 자식 프로세스의 list
	struct child_process *child_struct; // child로서의 정보
	struct thread *parent; // 부모 프로세스
	struct list fd_list; // file descriptor의 list
	struct intr_frame *fork_frame; // fork하기 위한 intr_frame
	struct semaphore fork_sema; // fork하기 위한 sema
	struct file *load_file; // 프로세스를 load하기 위한 file
	bool stdin_close; // 프로세스에서 stdin이 close 됐는지 확인
	bool stdout_close; // 프로세스에서 stdout이 close 됐는지 확인
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

// 두 thread의 priority 비교
bool priority_compare (const struct list_elem *, const struct list_elem *, void *);

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);
void thread_refresh_priority (struct thread *); // 내가 가지고 있는 lock을 분석해서 priority의 최댓값을 설정
void thread_donate_priority (struct thread *); // 자신의 priority를 다른 thread에 줌

int thread_get_nice (void);
void thread_set_nice (int);

/* mlfqs 관련 */
int thread_get_load_avg (void);

void thread_update_recent_cpu (struct thread *);
void thread_update_all_recent_cpu (void);
void thread_increment_recent_cpu(void);

void update_all_priority(void);
/* mlfqs 관련 */

int64_t thread_get_time_to_run(void); // 다시 실행할 시간 찾기
void thread_set_time_to_run(int64_t); // 다시 실행할 시간 지정

void do_iret (struct intr_frame *tf);

#endif /* threads/thread.h */
