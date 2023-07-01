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

#define PTRACE_TRACEME 1

void run_debugger(pid_t pid);
pid_t run_target(const char* program_name);

int main(int arge, char** argv)
{
    pid_t child_pid = run_target(argv[1]);
    run_debugger(child_pid);
    return 0;
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


void debugger(const char* executable, const char* function_name) {
    pid_t child_pid;
    struct user_regs_struct regs;
    int status;

    child_pid = fork();

    if (child_pid == 0) {
        // Child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(executable, NULL);
    } else {
        // Parent process
        waitpid(child_pid, &status, 0);

        while (WIFSTOPPED(status)) {
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

            if (regs.rip == /* address of the function */) {
                printf("Function '%s' called!\n", function_name);
                // Optionally, perform additional debugging actions here

                // Resume execution
                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
                waitpid(child_pid, &status, 0);
            } else {
                // Resume execution
                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
                waitpid(child_pid, &status, 0);
            }
        }
    }
}