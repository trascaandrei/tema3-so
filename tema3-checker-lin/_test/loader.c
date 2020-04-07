/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#include "exec_parser.h"

static so_exec_t *exec;
static int fd;
static struct sigaction old_action;
struct sigaction action;

static void sig_handler(int signum, siginfo_t *sig, void *context)
{
	int i;
	char *fault = sig->si_addr;
	int pageSize = getpagesize();

	for (i = 0; i < exec->segments_no; i++) {
		if ((char *)exec->segments[i].vaddr
				+ exec->segments[i].mem_size > fault)
			break;
	}

	// address is outside any segment => default handler
	if (i == exec->segments_no || sig->si_code != SEGV_MAPERR)
		old_action.sa_sigaction(signum, sig, context);

	char *vaddr = (char *)exec->segments[i].vaddr;
	char *file_address = vaddr + exec->segments[i].file_size;
	int pageno = (fault - vaddr) / pageSize;

	char *aligned = (char *)ALIGN_DOWN((uintptr_t)fault, pageSize);
	char *addr = mmap(aligned, pageSize, PROT_WRITE,
			MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED, 0, 0);

	if (addr == MAP_FAILED)
		exit(-1);

	int length = pageSize;

	if (aligned + pageSize > file_address) {
		if (aligned < file_address)
			length = file_address - aligned;
		else
			length = 0;
	}

	lseek(fd, exec->segments[i].offset + pageno * pageSize, SEEK_SET);
	read(fd, addr, length);

	//setting permissions on the mapped memory
	if (mprotect(addr, pageSize, exec->segments[i].perm) == -1)
		exit(-1);
}

int so_init_loader(void)
{
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;
	action.sa_sigaction = sig_handler;

	if (sigaction(SIGSEGV, &action, &old_action) == -1)
		exit(-1);
	return 0;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	fd = open(path, O_RDONLY);
	so_start_exec(exec, argv);

	close(fd);
	return 0;
}
