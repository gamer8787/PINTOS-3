#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "user/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);

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
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	uint64_t syscall_num = f->R.rax;
	struct gp_registers reg = f->R;
	switch(syscall_num) 
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(reg.rdi);
			break;
		case SYS_FORK:
			fork(reg.rdi);
			break;
		case SYS_EXEC:
			exec(reg.rdi);
			break;
		case SYS_WAIT:
			wait(reg.rdi);
			break;
		case SYS_CREATE:
			create(reg.rdi, reg.rsi);
			break;
		case SYS_REMOVE:
			remove(reg.rdi);
			break;
		case SYS_OPEN:
			open(reg.rdi);
			break;
		case SYS_FILESIZE:
			filesize(reg.rdi);
			break;
		case SYS_READ:
			read(reg.rdi, reg.rsi, reg.rdx);
			break;
		case SYS_WRITE:
			write(reg.rdi, reg.rsi, reg.rdx);
			break;
		case SYS_SEEK:
			seek(reg.rdi, reg.rsi);
			break;
		case SYS_TELL:
			tell(reg.rdi);
			break;
		case SYS_CLOSE:
			close(reg.rdi);
			break;
		default:
			break;
	}
}

void check_address(void *addr){
	if (is_kernel_vaddr(addr)) {
		exit(-1);
	}
}

void halt(void) {
	power_off();
}

void exit(int status) {
	struct thread *curr = thread_current();
	curr->terminate_status = status;
	thread_exit();
}

pid_t fork(const char *thread_name) {
	check_address(thread_name);

	return 1;
}

int exec(const char *cmd_line){
	int len = strlen(cmd_line);
	check_address(cmd_line);
	check_address(cmd_line + len);

	int user_pid = process_create_initd(cmd_line);
	if (user_pid == TID_ERROR) {
		return user_pid;
	}
	struct thread *user_thread = get_child_process(user_pid);
	sema_down(&user_thread->load);

	if (user_thread->create){
		return user_pid;
	}
	else {
		return -1;
	}
}

int wait(pid_t pid){
	printf("syscall_wait\n");
	int result = process_wait(pid);
	return result;
}

bool create(const char *file, unsigned initial_size){
	bool result = false;
	int len = strlen(file);
	check_address(file);
	check_address(file + len);

	result = filesys_create(file, initial_size);

	return result;
}

bool remove(const char *file){
	bool result = false;
	int len = strlen(file);
	check_address(file);
	check_address(file + len);

	result = filesys_remove(file);

	return result;
}

int open(const char *file){
	return 0;
}

int filesize(int fd){
	return 0;
}

int read(int fd, void *buffer, unsigned size){
	return 0;
}

int write(int fd, const void *buffer, unsigned size){
	return 0;
}

void seek(int fd, unsigned position){

}

unsigned tell(int fd){
	return 0;
}

void close(int fd){
	
}