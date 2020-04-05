/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#include "exec_parser.h"

#define DIE(assertion, call_description)				\
	do {								\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",			\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(EXIT_FAILURE);				\
		}							\
	} while (0)

#endif

static so_exec_t *exec;
static struct sigaction old_action;

static void sig_handler(int signum, siginfo_t *sig, void *context)
{
    int pageno;
    int prot = 0;
    int flags = 0;
    int i;
    char *p;
    unsigned int perm;
    unsigned int offset;
    unsigned int size;
    char *start_addr;

    if (sig->si_signo != SIGSEGV) {
        old_action.sa_sigaction(signum, sig, context);
        return;
    }

    for (i = 0; i < exec->segments_no; i++) {
        uintptr_t start = exec->segments[i].vaddr;
        uintptr_t end = exec->segments[i].vaddr + exec->segments[i].mem_size;
        if (start <= (int *)sig->si_addr && end >= (int *)sig->si_addr) {
            pageno = ((char *)sig->si_addr - start) / getpagesize();
            perm = exec->segments[i].perm;
            start_addr = (char *)start;
            offset = exec->segments[i].offset;
            size = exec->segments[i].file_size;
            break;
        }
    }

    flags = MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS;

    if (perm & PERM_R) {
        prot |= PROT_READ;
    }
    if (perm & PERM_W) {
        prot |= PROT_WRITE;
    }
    if (perm & PERM_X) {
        prot |= PROT_EXEC;
    }

    p = mmap(start_addr, pageno * getpagesize(), prot, flags, -1, 0);
    DIE(p == MAP_FAILED, "mmap");

    memcpy(p, (char *)(exec->entry + offset), size);
}

int so_init_loader()
{
	struct sigaction action;
	int rc;

	sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;
	action.sa_sigaction = sig_handler;

	rc = sigaction(SIGSEGV, &action, &old_action);
	DIE(rc == -1, "sigaction");
	return -1;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
