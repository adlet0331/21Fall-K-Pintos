#include "threads/thread.h"
#include "threads/fixed-point.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/malloc.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

// stdin, stdout file descriptor를 나타냄
extern int std_in, std_out;

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;
static struct list all_list; // block된 thread를 포함하는 list

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

static int global_load_avg; // mlfqs 관련

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&all_list);
	list_init (&destruction_req);
	global_load_avg = 0;

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	// child_process 구조체 생성하기
	struct child_process *child = malloc(sizeof(struct child_process));
	child->tid = tid;
	sema_init(&child->wait_sema, 0);
	list_push_back(&thread_current()->child_list, &child->elem);
	t->child_struct = child;
	t->parent = thread_current();

	// stdin, stdout file descriptor 만들기
	struct file_descriptor *stdin_fd = malloc(sizeof(struct file_descriptor));
	struct file_descriptor *stdout_fd = malloc(sizeof(struct file_descriptor));
	stdin_fd->index = 0;
	stdin_fd->original_index = 0;
	stdin_fd->fd = &std_in;
	stdout_fd->index = 1;
	stdout_fd->original_index = 1;
	stdout_fd->fd = &std_out;
	list_push_back(&t->fd_list, &stdin_fd->elem);
	list_push_back(&t->fd_list, &stdout_fd->elem);

	// mmap_list 초기화
	for(int i=0; i<100; i++) t->mmap_list[i] = NULL;

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);
	t->recent_cpu = thread_current ()->recent_cpu; // mlfqs 관련

	// 자신보다 더 priority가 높은 경우 yield
	if (priority > thread_current ()->priority)
		thread_yield ();

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	list_insert_ordered (&ready_list, &t->elem, priority_compare, NULL); // 알맞은 위치에 삽입 (priority 정렬)
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	// 부모의 wait를 위해 sema_up
	// process_exit 안의 munmap 등에서 시간을 많이 쓰기 때문에
	// synch 문제를 해결하기 위해 sema_up을 여기서 함
	struct thread *curr = thread_current();
	if(curr->parent != NULL)
		sema_up(&curr->child_struct->wait_sema);
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		list_insert_ordered (&ready_list, &curr->elem, priority_compare, NULL); // 알맞은 위치에 삽입
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	if (thread_mlfqs){
		return;
	}
	// original_priority 설정함 (lock 풀리면 다시 돌아가기 위해)
	// ready_list의 front의 priority가 더 높으면 yield
	int prev_priority = thread_current ()->priority;
	thread_current ()->original_priority = new_priority;
	thread_current ()->priority = new_priority;
	thread_refresh_priority (thread_current ());
	if (!list_empty (&ready_list) && list_entry (list_front (&ready_list), struct thread, elem)->priority > new_priority)
		thread_yield ();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

// 내가 가지고 있는 lock을 분석해서 priority의 업데이트 (최대값으로 설정)
void
thread_refresh_priority (struct thread *t) {
	ASSERT (is_thread (t));
	if (list_empty (&t->locks)) return;
	for (struct list_elem *i = list_front (&t->locks); i != list_end (&t->locks); i = list_next (i)) {
		struct lock *lock = list_entry (i, struct lock, elem);
		if (list_empty (&lock->semaphore.waiters)) continue;
		for (struct list_elem *j = list_front (&lock->semaphore.waiters); j != list_end (&lock->semaphore.waiters); j = list_next (j)) {
			struct thread *th = list_entry (j, struct thread, elem);
			thread_refresh_priority (th);
			if (t->priority < th->priority)
				t->priority = th->priority;
		}
	}
	struct thread *i = t;
	while (i->lock != NULL && i->lock->holder != NULL) {
		i->lock->holder->priority = i->priority;
		i = i->lock->holder;
	}
}

// 자신의 priority를 to에게 donate (lock 이슈)
void
thread_donate_priority (struct thread *to) {
	struct thread *curr = thread_current ();
	ASSERT (is_thread (to));
	ASSERT (to->priority < thread_current ()->priority);
	thread_refresh_priority (to);
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
	// mlfqs 관련
	enum intr_level old_level;

	old_level = intr_disable ();
	thread_current()->nice = nice;
	intr_set_level (old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	// mlfqs 관련
	enum intr_level old_level;
	old_level = intr_disable ();

	int curr_nice = thread_current()->nice;
	intr_set_level (old_level);
	return curr_nice;
}

/* Returns 100 times the system load average. */
// mlfqs 관련
int 
thread_get_load_avg(void){
	return fp_round_int (fp_multiply_fp (global_load_avg, int_to_fp (100)));
}

// mlfqs 관련
void
thread_update_load_avg (void) {
	/* TODO: Your implementation goes here */
	//int load_avg = (59/60) * load_avg + (1/60) * ready_threads;
	enum intr_level old_level;
	old_level = intr_disable ();
	
	int asdf = timer_ticks ();

	// int curr_load_avg = fp_divide_fp (int_to_fp (global_load_avg), int_to_fp (100));
	int curr_load_avg = global_load_avg;
	int ready_threads = 0;
	if (!list_empty (&ready_list))
		for (struct list_elem *e = list_front (&ready_list); e != list_end (&ready_list); e = list_next (e)) {
			struct thread *t = list_entry (e, struct thread, elem);
			ASSERT (t != idle_thread);
			int64_t current_time = timer_ticks();
			if (t->time_to_run <= current_time) {
				ready_threads++;
			}
		}
	if(thread_current() != idle_thread){
		ready_threads++;
	}
	int fp_59_60 = fp_divide_fp(int_to_fp(59), int_to_fp(60));
	int fp_1_60 = fp_divide_fp(F, int_to_fp(60));

	int a = fp_multiply_fp(fp_59_60, curr_load_avg);
	int b = fp_multiply_fp(fp_1_60, int_to_fp(ready_threads));
	int result = fp_add_fp(a, b);
	// result = fp_multiply_fp(result, int_to_fp(100));
	// result = fp_round_int(result);
	// if (result < 0){
	// 	result = 0;
	// }
	global_load_avg = result;
	
	intr_set_level (old_level);
	return;
}

/* Returns 100 times the current thread's recent_cpu value. */
// mlfqs 관련
int
thread_get_recent_cpu () {
	/* TODO: Your implementation goes here */
	return fp_round_int(fp_multiply_fp(thread_current ()->recent_cpu, int_to_fp(100)));
}

void
thread_update_all_recent_cpu(){
	for(struct list_elem *thr_elem = list_begin(&all_list); thr_elem != list_end(&all_list); thr_elem = list_next(thr_elem)){
		struct thread *t = list_entry(thr_elem, struct thread, all_elem);
		thread_update_recent_cpu(t);
	}
}

void
thread_update_recent_cpu(struct thread *t){
	//recent_cpu = (2 * load_avg)/(2 * load_avg + 1) * recent_cpu + nice
	if(t == idle_thread){
		return;
	}
	enum intr_level old_level;
	old_level = intr_disable ();
	
	int recent_cpu = t->recent_cpu;
	int nice = t->nice;

	int a = fp_multiply_fp(global_load_avg, int_to_fp(2));
	int b = fp_add_fp(a, F);
	int A = fp_divide_fp(a,b);
	int aa = fp_multiply_fp(A, recent_cpu);

	int result = fp_add_fp(aa, int_to_fp(nice));
	// result = fp_multiply_fp(result, int_to_fp(100));
	// result = fp_round_int(result);

	t->recent_cpu = result;
	intr_set_level (old_level);
}

void
thread_increment_recent_cpu(){
	enum intr_level old_level;
	old_level = intr_disable ();
	struct thread *thr = thread_current();
	if (thr == idle_thread)
		return;

	thr->recent_cpu += F;
	
	intr_set_level(old_level);
	return;
}

void
update_priority(struct thread *curr_thread){
	//priority = PRI_MAX - (recent_cpu / 4) - (nice * 2)
	if(curr_thread == idle_thread){
		return;
	}
	else{
		int priority = PRI_MAX - fp_to_int(curr_thread->recent_cpu) / 4 - curr_thread->nice * 2;
		if(priority < PRI_MIN){
			priority = PRI_MIN;
		}
		if(priority > PRI_MAX){
			priority = PRI_MAX;
		}
		curr_thread->priority = priority;
		return;
	}
}

//모든 priority 업데이트
void
update_all_priority(){
	if (list_empty (&all_list)) return;
	enum intr_level old_level = intr_disable ();
	for(struct list_elem *thr_elem = list_begin(&all_list); thr_elem != list_end(&all_list); thr_elem = list_next(thr_elem)){
		struct thread *t = list_entry(thr_elem, struct thread, all_elem);
		if (t != idle_thread)
			update_priority(t);
	}
	intr_set_level (old_level);
}

// mlfqs 관련 끝

//busy wait 제거
void
thread_set_time_to_run(int64_t time) {
	thread_current ()->time_to_run = time;
}

int64_t
thread_get_time_to_run(void) {
	return thread_current ()->time_to_run;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;

	// 우리가 추가한 멤버의 초기화
	t->time_to_run = 0;
	t->original_priority = priority;
	t->lock = NULL;
	list_init (&t->locks);
	list_init (&t->child_list);
	list_init (&t->fd_list);
	t->stdin_close = false;
	t->stdout_close = false;
	if(thread_mlfqs){
		t->nice = 0;
		t->recent_cpu = 0;
	}
	list_push_back(&all_list, &t->all_elem);
	sema_init(&t->fork_sema, 0);
}

bool
priority_compare (const struct list_elem *a_, const struct list_elem *b_, void *aux UNUSED) {
	struct thread *a = list_entry (a_, struct thread, elem);
	struct thread *b = list_entry (b_, struct thread, elem);
	return a->priority > b->priority;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else {
		// ready list를 정렬하고 순서대로 time_to_run이 지났는지 확인
		list_sort (&ready_list, priority_compare, NULL);
		for (struct list_elem *e = list_front (&ready_list); e != list_end (&ready_list); e = list_next(e)) {
			struct thread *t = list_entry (e, struct thread, elem);
			int64_t current_time = timer_ticks();
			if (t->time_to_run <= current_time) {
				list_remove(e);
				return t;
			}
		}
		return idle_thread;
	}
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
			list_remove (&curr->all_elem); // all_list에서 제거
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}
