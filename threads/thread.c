#include "threads/thread.h"
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

#include <threads/fixed_point.h>
#ifdef USERPROG

#include "userprog/process.h"

#endif

#define NICE_DEFAULT 0
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0 
#define F (1<< 14) //fixed point 1


int load_avg; //

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

/* List of process in THREAD_BLOCKED */
static struct list sleep_list;
static struct list all_list;
/* Minimum of wakeup_tick in sleep_list */
static int64_t next_tick_to_awake = 0;

/* Idle thread. */
static struct thread* idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread* initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func*, void* aux);

static void idle(void* aux UNUSED);
static struct thread* next_thread_to_run(void);
static void init_thread(struct thread*, const char* name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

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
thread_init(void) {
   ASSERT(intr_get_level() == INTR_OFF);

   /* Reload the temporal gdt for the kernel
    * This gdt does not include the user context.
    * The kernel will rebuild the gdt with user context, in gdt_init (). */
   struct desc_ptr gdt_ds = {
      .size = sizeof(gdt) - 1,
      .address = (uint64_t)gdt
   };
   lgdt(&gdt_ds);

   /* Init the globla thread context */
   lock_init(&tid_lock);
   list_init(&ready_list);
   list_init(&sleep_list);
   list_init(&all_list);
   list_init(&destruction_req);

   /* Set up a thread structure for the running thread. */
   initial_thread = running_thread();
   init_thread(initial_thread, "main", PRI_DEFAULT);
   //initial_thread->recent_cpu = RECENT_CPU_DEFAULT;
   //initial_thread->nice = NICE_DEFAULT;
   initial_thread->status = THREAD_RUNNING;
   initial_thread->tid = allocate_tid();
   list_push_back(&all_list, &initial_thread->all_elem);
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start(void) {
   /* Create the idle thread. */
   struct semaphore idle_started;
   sema_init(&idle_started, 0);
   thread_create("idle", PRI_MIN, idle, &idle_started);
   load_avg = LOAD_AVG_DEFAULT;

   /* Start preemptive thread scheduling. */
   intr_enable();   

   /* Wait for the idle thread to initialize idle_thread. */
   sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick(void) {
   struct thread* t = thread_current();

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
      intr_yield_on_return();
}

/* Prints thread statistics. */
void
thread_print_stats(void) {
   printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
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
thread_create(const char* name, int priority,
   thread_func* function, void* aux) {
   struct thread* t;
   tid_t tid;

   ASSERT(function != NULL);

   /* Allocate thread. */
   t = palloc_get_page(PAL_ZERO);
   if (t == NULL)
      return TID_ERROR;

   /* Initialize thread. */
   init_thread(t, name, priority);
   //t->recent_cpu = thread_current()->recent_cpu;
   //t->nice = thread_current()->nice;
   t->parent_thread = thread_current();
   t->create = false;
   t->terminate = false;
   t->terminate_status = -1;
   t->load.value = 0;
   t->exit.value = 0;
   list_push_back(&thread_current()->child_list, &t->child_elem);

   tid = t->tid = allocate_tid();

   /* Call the kernel_thread if it scheduled.
    * Note) rdi is 1st argument, and rsi is 2nd argument. */
   t->tf.rip = (uintptr_t)kernel_thread;
   t->tf.R.rdi = (uint64_t)function;
   t->tf.R.rsi = (uint64_t)aux;
   t->tf.ds = SEL_KDSEG;
   t->tf.es = SEL_KDSEG;
   t->tf.ss = SEL_KDSEG;
   t->tf.cs = SEL_KCSEG;
   t->tf.eflags = FLAG_IF;

   /* Add to run queue. */
   list_push_back(&all_list, &t->all_elem);
   thread_unblock(t);
   test_max_priority();


   return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block(void) {
   ASSERT(!intr_context());
   ASSERT(intr_get_level() == INTR_OFF);
   thread_current()->status = THREAD_BLOCKED;
   schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock(struct thread* t) {
   enum intr_level old_level;

   ASSERT(is_thread(t));

   old_level = intr_disable();
   ASSERT(t->status == THREAD_BLOCKED);
   list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL);
   t->status = THREAD_READY;
   intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char*
thread_name(void) {
   return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread*
   thread_current(void) {
   struct thread* t = running_thread();

   /* Make sure T is really a thread.
      If either of these assertions fire, then your thread may
      have overflowed its stack.  Each thread has less than 4 kB
      of stack, so a few big automatic arrays or moderate
      recursion can cause stack overflow. */
   ASSERT(is_thread(t));
   ASSERT(t->status == THREAD_RUNNING);

   return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid(void) {
   return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit(void) {
   ASSERT(!intr_context());
   list_remove(&thread_current()->all_elem);
#ifdef USERPROG
   thread_current()->terminate = true;
   process_exit();
   sema_up(&thread_current()->exit);
#endif

   /* Just set our status to dying and schedule another process.
      We will be destroyed during the call to schedule_tail(). */
   intr_disable();
   do_schedule(THREAD_DYING);
   NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield(void) {
   struct thread* curr = thread_current();
   enum intr_level old_level;

   ASSERT(!intr_context());

   old_level = intr_disable();
   if (curr != idle_thread)
      list_insert_ordered(&ready_list, &curr->elem, cmp_priority, NULL);
   do_schedule(THREAD_READY);
   intr_set_level(old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority(int new_priority) {
   if (thread_mlfqs) {
      return;
   }
      
   thread_current()->init_priority = new_priority;
   refresh_priority();
   donate_priority();
   test_max_priority();
}

/* Returns the current thread's priority. */
int
thread_get_priority(void) {
   return thread_current()->priority;
}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED)
{

   enum intr_level old_level;
   ASSERT(!intr_context());

   old_level = intr_disable();

   struct thread* curr = thread_current();

   curr->nice = nice;
   mlfqs_priority(curr);
   test_max_priority();

   intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int thread_get_nice(void)
{
   enum intr_level old_level;
   ASSERT(!intr_context());

   old_level = intr_disable();

   int a = thread_current()->nice;
   intr_set_level(old_level);

   return a;
   /* 현재스레드의nice 값을반환한다.
   해당작업중에인터럽트는비활성되어야한다. */
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void) {
   enum intr_level old_level;

   ASSERT(!intr_context());
   old_level = intr_disable();

   int result = fp_to_int_round(mult_mixed(load_avg, 100));
   intr_set_level(old_level);

   return result;
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void)
{
   enum intr_level old_level;

   ASSERT(!intr_context());
   old_level = intr_disable();

   int result = fp_to_int_round(mult_mixed(thread_current()->recent_cpu, 100));
   intr_set_level(old_level);

   return result;
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
idle(void* idle_started_ UNUSED) {
   struct semaphore* idle_started = idle_started_;

   idle_thread = thread_current();
   sema_up(idle_started);

   for (;;) {
      /* Let someone else run. */
      intr_disable();
      thread_block();

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
kernel_thread(thread_func* function, void* aux) {
   ASSERT(function != NULL);

   intr_enable();       /* The scheduler runs with interrupts off. */
   function(aux);       /* Execute the thread function. */
   thread_exit();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread* t, const char* name, int priority) {
   ASSERT(t != NULL);
   ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
   ASSERT(name != NULL);

   memset(t, 0, sizeof * t);
   t->status = THREAD_BLOCKED;
   strlcpy(t->name, name, sizeof t->name);
   t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void*);
   t->priority = priority;
   initial_thread->recent_cpu = RECENT_CPU_DEFAULT;
   initial_thread->nice = NICE_DEFAULT;

   t->magic = THREAD_MAGIC;

   t->init_priority = priority;
   t->wait_on_lock = NULL;
   list_init(&t->donations);
   list_init(&t->child_list);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread*
next_thread_to_run(void) {
   if (list_empty(&ready_list))
      return idle_thread;
   else
      return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret(struct intr_frame* tf) {
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
      : : "g" ((uint64_t)tf) : "memory");
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
thread_launch(struct thread* th) {
   uint64_t tf_cur = (uint64_t)&running_thread()->tf;
   uint64_t tf = (uint64_t)&th->tf;
   ASSERT(intr_get_level() == INTR_OFF);

   /* The main switching logic.
    * We first restore the whole execution context into the intr_frame
    * and then switching to the next thread by calling do_iret.
    * Note that, we SHOULD NOT use any stack from here
    * until switching is done. */
   __asm __volatile(
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
//      palloc_free_page(victim);
   }
   thread_current ()->status = status;
   schedule ();
}

static void
schedule(void) {
   struct thread* curr = running_thread();
   struct thread* next = next_thread_to_run();

   ASSERT(intr_get_level() == INTR_OFF);
   ASSERT(curr->status != THREAD_RUNNING);
   ASSERT(is_thread(next));
   /* Mark us as running. */
   next->status = THREAD_RUNNING;

   /* Start new time slice. */
   thread_ticks = 0;

#ifdef USERPROG
   /* Activate the new address space. */
   process_activate(next);
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
         ASSERT(curr != next);
         list_push_back(&destruction_req, &curr->elem);
      }

      /* Before switching the thread, we first save the information
       * of current running. */
      thread_launch(next);
   }
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void) {
   static tid_t next_tid = 1;
   tid_t tid;

   lock_acquire(&tid_lock);
   tid = next_tid++;
   lock_release(&tid_lock);

   return tid;
}

void thread_sleep(int64_t ticks) {
   struct thread* curr = thread_current();
   enum intr_level old_level;
   ASSERT(!intr_context());

   old_level = intr_disable();
   if (curr != idle_thread)
   {
      //curr->status = THREAD_BLOCKED;                        /* current thread status를 THREAD_BLOCKED로 바꿈 */
      curr->wakeup_tick = ticks;                           /* current thread wakeup_tick을 ticks로 설정 */
      list_push_back(&sleep_list, &curr->elem);               /* sleep queue에 current_element 삽입 */
      if (!next_tick_to_awake || ticks < next_tick_to_awake)      /* next_tick_to_awake가 0이 아니고, ticks가 next_tick_to_awake보다 작을때 update */
      {
         next_tick_to_awake = ticks;
      }
   }
   do_schedule(THREAD_BLOCKED);
   intr_set_level(old_level);
}

void thread_awake(int64_t ticks) {
   struct list_elem* a = list_begin(&sleep_list);
   if (a != list_end(&sleep_list)) {
      struct list_elem* e;
      e = a;
      while (e != list_end(&sleep_list))
         //for (e = a; e != list_end(&sleep_list); e = e->next)
      {
         struct thread* b = list_entry(e, struct thread, elem);
         if (b->wakeup_tick <= ticks) {
            e = list_remove(e);
            thread_unblock(b);
         }
         else {
            e = list_next(e);
            update_next_tick_to_awake(b->wakeup_tick);
         }
      }
   }
}
void update_next_tick_to_awake(int64_t ticks) {
   if (ticks < next_tick_to_awake) {
      next_tick_to_awake = ticks;
   }

   if (next_tick_to_awake <= timer_ticks())
   {
      next_tick_to_awake = ticks;
   }
}

int64_t get_next_tick_to_awake(void) {
   return next_tick_to_awake;
}


void test_max_priority(void) {
   if (!list_empty(&ready_list))
   {
      struct thread* curr = thread_current();                                       /* current thread */
      struct thread* max_prior = list_entry(list_begin(&ready_list), struct thread, elem);   /* priority max tread in ready list */
      enum intr_level old_level ;
      ASSERT (!intr_context());
      if (curr->priority <= max_prior->priority)                                    /* compare priority between current, max */
      {
         old_level = intr_disable();
         list_insert_ordered(&ready_list, &curr->elem, cmp_priority, NULL);
         do_schedule(THREAD_READY);      /* scheduling */
         intr_set_level(old_level);
      }
   }
}

bool cmp_priority(const struct list_elem* a, const struct list_elem* b, void* aux UNUSED) {
   struct thread* thread_a = list_entry(a, struct thread, elem);
   struct thread* thread_b = list_entry(b, struct thread, elem);
   return thread_a->priority > thread_b->priority;
}

void donate_priority(void)
{
   struct thread* cur = thread_current();
   struct thread* holder;
   while (cur->wait_on_lock != NULL) {
      ASSERT(cur->wait_on_lock != NULL);
      holder = cur->wait_on_lock->holder;

      if (holder->priority < cur->priority)
      {
         holder->priority = cur->priority;
      }

      cur = holder;
   }
}


void remove_with_lock(struct lock* lock) {
   struct thread* curr = thread_current();
   struct list* donations = &curr->donations;
   struct list_elem* multi_elem = list_begin(donations);
   
   struct list_elem* multi_end = list_end(&curr->donations);

   if ( !list_empty(donations)){ 
      while (!(multi_elem == multi_end))
      {
         struct thread* t = list_entry(multi_elem, struct thread, donation_elem);
         if (t->wait_on_lock == lock){
            multi_elem = list_remove(multi_elem);
         }else {
            //if(!is_tail(multi_elem))
            ASSERT(multi_elem != list_tail(donations));
            multi_elem = list_next(multi_elem);
         }
      }
   }
}

void refresh_priority(void) {
   struct thread* curr = thread_current();
   struct list_elem* multi_elem = list_begin(&curr->donations);
   struct list_elem* multi_end = list_end(&curr->donations);
   //ASSERT(!list_empty(&curr->donations));
   curr->priority = curr->init_priority ;
   
   if (!list_empty(&curr->donations) && (multi_elem != multi_end) ) {
      while (multi_elem != multi_end)
      {
         struct thread* t = list_entry(multi_elem, struct thread, donation_elem);
         if (curr->priority < t->priority)
         {
            curr->priority = t->priority;
         }
         multi_elem = list_next(multi_elem);
      }
   }
}

int int_to_fp(int n) { return n * F; }                     //integer를fixed point로전환
int fp_to_int_round(int x) {                           //FP를int로전환(반올림) 
   if (x >= 0) return (x + F / 2) / F;                     //FP를int로전환(버림)
   else return (x - F / 2) / F;
}               
int fp_to_int(int x) { return x / F; }                     //FP를int로전환(버림)
int add_fp(int x, int y) { return x + y; }                  //FP의덧셈
int add_mixed(int x, int n) { return x + n * F; }            //FP와int의덧셈
int sub_fp(int x, int y) { return x - y; }                  //FP의뺄셈(x-y)
int sub_mixed(int x, int n) { return x - n * F; }            //FP와int의뺄셈(x - n)
int mult_fp(int x, int y) { return ((int64_t)x) * y / F; }      //FP의곱셈
int mult_mixed(int  x, int n) { return x * n; }               //FP와int의곱셈
int div_fp(int x, int y) { return ((int64_t)x) * F / y; }      //FP의나눗셈(x / y)
int div_mixed(int x, int n) { return x / n; }               //FP와int나눗셈(x / n)

// priority, nice, ready_threads 값은정수, recent_cpu, load_avg값은실수

// priority = PRI_MAX –(recent_cpu/ 4) –(nice * 2)
void mlfqs_priority(struct thread* t) {
   if (t != idle_thread)
   {
      int a = int_to_fp(PRI_MAX);
      int b = div_mixed(t->recent_cpu, 4);
      int c = mult_mixed(int_to_fp(t->nice), 2);
      t->priority = adjust_to_range(fp_to_int_round(a - b - c));
   }
}

int adjust_to_range(int p) {
   if (p < PRI_MIN)
   {
      return PRI_MIN;
   }
   else if (p > PRI_MAX)
   {
      return PRI_MAX;
   }
   else {
      return p;
   }
}


// recent_cpu=(2 * load_avg) / (2 * load_avg+ 1) * recent_cpu+ nice
void mlfqs_recent_cpu(struct thread* t) {
   if (t != idle_thread)
   {
      int a = mult_mixed(load_avg, 2);
      int b = div_fp(a, add_mixed(a, 1));
      int c = mult_fp(b, t->recent_cpu);
      int d = add_mixed(c, (t->nice));
      t->recent_cpu = d;
   }
}
//load_avg= (59/60) * load_avg+ (1/60) * ready_threads
void mlfqs_load_avg(void) {
   int a = div_mixed(int_to_fp(59), 60); //(59/60)
   int b = div_mixed(int_to_fp(1), 60);  //(1/60)
   int ready_threads;
   if (thread_current() != idle_thread)
      ready_threads = ((int)list_size(&ready_list)) + 1;
   else
      ready_threads = (int)list_size(&ready_list);
   load_avg = add_fp(mult_fp(a, load_avg), mult_mixed(b, ready_threads));
}

void mlfqs_increment(void)
{
   if (thread_current() != idle_thread)
      thread_current()->recent_cpu = add_mixed(thread_current()->recent_cpu, 1);
   /* 해당스레드가idle_thread가아닌지검사*/
   /* 현재스레드의recent_cpu값을1증가시킨다. */
}

void mlfqs_recalc(void)
{
   struct list_elem* a = list_begin(&all_list);
   if (a != list_end(&all_list)) {
      struct list_elem* e;
      e = a;
      while (e != list_end(&all_list))
      {
         struct thread* b = list_entry(e, struct thread, all_elem);
         mlfqs_recent_cpu(b);
         mlfqs_priority(b);
         e = list_next(e);
      }   
      ASSERT (e == list_end(&all_list)) ;
   }
   /* 모든thread의recent_cpu와priority값재계산한다. */
}