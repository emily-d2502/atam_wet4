#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#define FUNCTION_NAME 1
#define PROGRAM_NAME 2

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val);

pid_t run_target(const char* program_name);
void run_breakpoint_debugger(pid_t child_pid);


int main(int argc, char* argv[])
{
    // FIXME: assert(argc >= 2)
    char *function_name = argv[FUNCTION_NAME];
    char *exe_file_name = argv[PROGRAM_NAME];
    char **program = &argv[PROGRAM_NAME];

    /* assert file is an executable */
    int err = 0;
	unsigned long addr = find_symbol(function_name, exe_file_name, &err);

    if (err == -1) {
		printf("PRF:: %s not found! :(\n", function_name);
    } else if (err == -2) {
		printf("PRF:: %s is not a global symbol!\n", function_name);
    } else if (err == -3) {
		printf("PRF:: %s not an executable!\n", exe_file_name);
    } else if (err == -4) {
		printf(" ````````` not accounted for ````````` ");
    }

    pid_t child_pid = run_target(exe_file_name);
    run_breakpoint_debugger(child_pid, addr);















#if defined(HW3)
	if (addr > 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
#endif

#if defined(DEBUG)
    printf("function to find: %s\n", func);
    printf("executable to run: %s", exec[0]);
    for (int i = 1; i < argc - 2; ++i) {
        printf(" %s", exec[i]);
    }
    printf("\n");
#endif

    return 0;
}

void run_breakpoint_debugger(pid_t child_pid, unsigned long addr)
{
    int wait_status;
    struct user_regs_struct regs;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);

    /* Look at the word at the address we're interested in */
    // unsigned long addr = 0x4000cd;
    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
    printf("DBG: Original data at 0x%x: 0x%x\n", addr, data);

    /* Write the trap instruction 'int 3' into the address */
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    wait(&wait_status);
    /* See where the child is now */
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    printf("DBG: Child stopped at RIP = 0x%x\n", regs.rip);

    /* Remove the breakpoint by restoring the previous data and set rdx = 5 */
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data);
    regs.rip -= 1;
	regs.rdx = 5;
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

    /* The child can continue running now */
    ptrace(PTRACE_CONT, child_pid, 0, 0);

    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        printf("DBG: Child exited\n");
    } else {
        printf("DBG: Unexpected signal\n");
    }
}

pid_t run_target(const char* program_name)
{
    pid_t pid = fork();
    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace failed");
            exit(1);
        }
        execl(program_name, program_name, NULL);
    } else {
        perror("fork failed");
        exit(1);
    }
}
