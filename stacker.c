#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <dlfcn.h>

#include "common.h"
#include "unwind.h"

#if 0
#define EXIT_WITH_FAILURE_STR(__str)       do {             \
    char *s = __str ? __str : strerror(errno);              \
    fprintf(stderr, "%s [line: %d]\n", s, __LINE__);        \
    exit(EXIT_FAILURE);                                     \
} while (0)

#define EXIT_WITH_FAILURE       EXIT_WITH_FAILURE_STR(NULL)
#define DEBUG(...)              fprintf(stderr, __VA_ARGS__)
#endif


#define MAX_STACK_DEPTH         128

void *get_start_addr(pid_t pid, const char *fname)
{
    /* Notice that thanks to ASLR, libc can be loaded every time in a different
     * place.  This is probably not the best way to do it, but it should work. */

    char proc_fname[256];
    sprintf(proc_fname, "/proc/%d/maps", pid);

    FILE *fp = fopen(proc_fname, "r");
    long long int load_start;
    long long int load_offset;
    char lib_fname_array[256];
    char *lib_fname = lib_fname_array;
    char perms[16];

    while (!feof(fp) && fscanf(fp, "%llx-%*x %s %llx %*d:%*d %*d", &load_start, perms, &load_offset)) {
        lib_fname[0] = '\0';
        fscanf(fp, "%[^\n]\n", lib_fname);
        while (isspace(*lib_fname)) lib_fname++;

        if (strcmp(lib_fname, fname) != 0) continue;
        if (strcmp(perms, "r-xp") != 0) continue;
        if (load_offset != 0) {
            EXIT_WITH_FAILURE_STR("Code section of libc loaded with offset");
        }

        return (void *)load_start;
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    pid_t pid;

    if (strcmp(argv[1], "self") == 0) {
        pid = getpid();
    } else {
        pid = (pid_t)strtoll(argv[1], NULL, 10);
    }

    void *stack[MAX_STACK_DEPTH];

    int depth = 0;

    char buffer[256];
    sprintf(buffer, "/proc/%d/exe", pid);
    //unwind_prepare(buffer);
    /* Notice that we are looking for the libc start address of the tracked
     * process, not ours (that would be a bit easier) */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        EXIT_WITH_FAILURE;
    }
    wait(NULL);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    void *rip = (void *)regs.rip;
    void *rsp = (void *)regs.rsp;
    stack[depth++] = rip;

    while (rsp && rip) {
        DEBUG("RSP: %p\tRIP: %p\n", rsp, rip);

        void *libc_start_addr = get_start_addr(pid, "/lib/libc-2.11.2.so");
        unwind_prepare("/lib/libc-2.11.2.so");

        if (rip >= libc_start_addr) {
            DEBUG("Looking in libc ELF\n");
            rsp += unwind_find_caller_offset(pid, (void *)(rip - libc_start_addr));
        } else {
            DEBUG("Looking in binary ELF\n");
            void *bin_start_addr = get_start_addr(pid, "/bin/bash");
            unwind_prepare("/bin/bash");
            int32_t offset = unwind_find_caller_offset(pid, (void *)(rip - bin_start_addr));
            DEBUG("Found %d bytes offset\n", offset);
            rsp += offset;
        }
        rip = (void *)ptrace(PTRACE_PEEKDATA, pid, rsp-8, NULL);
        stack[depth++] = rip;
    }
    DEBUG("RSP: %p\tRIP: %p\n", rsp, rip);

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        EXIT_WITH_FAILURE;
    }

    return EXIT_SUCCESS;
}
