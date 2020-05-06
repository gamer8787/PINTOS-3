#include "userprog/syscall.h"
#include <stdio.h>
#include "user/syscall.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <string.h>

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
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int result;
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
        	thread_current()->fork_if=f;
        	f->R.rax = fork(reg.rdi);
        	break;
		case SYS_EXEC:
			exec(reg.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(reg.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(reg.rdi, reg.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(reg.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(reg.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(reg.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(reg.rdi, reg.rsi, reg.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(reg.rdi, reg.rsi, reg.rdx);
			break;
		case SYS_SEEK:
			seek(reg.rdi, reg.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(reg.rdi);
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
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

pid_t fork(const char *thread_name) {
	check_address(thread_name);
	int len = strlen(thread_name);
	check_address(thread_name + len);

	int child_pid = process_fork(thread_name, &thread_current()->tf);
	if (child_pid == TID_ERROR) {
		return TID_ERROR;
	}

	struct thread *child_thread = get_child_process(child_pid);
	if (!child_thread->copied)
	{
		sema_down(&child_thread->fork);
	}
	
	if (child_thread->copied)
	{
		return child_pid;
	}
	else {
		return TID_ERROR;
	}
}

int exec(const char *cmd_line){
	check_address(cmd_line);
	int len = strlen(cmd_line);
	check_address(cmd_line + len);

	int success = process_exec(cmd_line);

	if (success < 0) {
		exit(-1);
	}
}

int wait(pid_t pid){
	int result = process_wait(pid);
	return result;
}

bool create(const char *file, unsigned initial_size){
	bool result = false;
	if (file == NULL)
	{
		exit(-1);
	}
	check_address(file);
	int len = strlen(file);
	check_address(file + len);
	result = filesys_create(file, initial_size);
	return result;
}

bool remove(const char *file){
	bool result = false;
	if (file == NULL)
	{
		exit(-1);
	}
	check_address(file);
	int len = strlen(file);
	check_address(file + len);

	result = filesys_remove(file);

	return result;
}

int open(const char *file){
	if (file == NULL)
	{
		exit(-1);
	}
	check_address(file);
	int len = strlen(file);
	check_address(file + len);
	struct file *f = filesys_open(file);
	if (f == NULL) {
		return -1;
	}
	int fd = process_add_file(f);

	return fd;
}


int filesize(int fd){
	struct file *f = process_get_file(fd);
	off_t length;
	if (f == NULL) 
	{
		return -1;
	}
	else {
		length = file_length(f);
		return length;
	}
}

int read(int fd, void *buffer, unsigned size){
	check_address(buffer);
	check_address(buffer + size);
	lock_acquire(&filesys_lock);
	struct file *f = process_get_file(fd);
	int read_byte = 0;
	char c;
	if (fd == 0) {
		for (int i = 0; i < size; i++) {
			c = input_getc();
			if (c == '\n' || i == size - 1){
				*(char*)(buffer + i) = '\0';
				read_byte++;
				break;
			}
			else {
				*(char*)(buffer + i) = c;
				read_byte++;
			}
		}
		lock_release(&filesys_lock);
		return read_byte;
	}
	else {
		if (f == NULL)
		{
		lock_release(&filesys_lock);
		return -1;
		}
		read_byte = file_read(f, buffer, size);
		lock_release(&filesys_lock);
		return read_byte;
	}
}

int write(int fd, const void *buffer, unsigned size){
	check_address(buffer);
	check_address(buffer + size);
	struct file *f = process_get_file(fd);
	int write_byte = 0;
	if (fd == 1) {
		if (size > 1000) {
			size = 1000;
		}
		putbuf(buffer, size);
		write_byte = strlen((char *)buffer);
		if (size < write_byte){
			write_byte = size;
		}
		return write_byte;
	}
	else {
		if (f == NULL)
		{
		return -1;
		}
		lock_acquire(&filesys_lock);
		write_byte = file_write(f, buffer, size);
		lock_release(&filesys_lock);
		return write_byte;
	}
}

void seek(int fd, unsigned position){
	struct file *f = process_get_file(fd);
	if (f == NULL) {
		return;
	}
	file_seek(f, position);
}

unsigned tell(int fd){
	struct file *f = process_get_file(fd);
	if (f == NULL){
		return 0;
	}
	return file_tell(f);
}

void close(int fd){
	process_close_file(fd);
}