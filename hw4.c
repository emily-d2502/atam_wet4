#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

#include "elf64.h"
#define UND 0

#define LOCAL 0
#define GLOBAL 1

#define	ET_NONE	0	// No file type
#define	ET_REL	1	// Relocatable file
#define	ET_EXEC	2	// Executable file
#define	ET_DYN	3	// Shared object file
#define	ET_CORE	4	// Core file

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
void run_breakpoint_debugger(pid_t child_pid, unsigned long addr);


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
    return 0;
}

unsigned long set_breakpoint(unsigned long addr, pid_t child_pid) 
{
    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)addr, NULL); // read int
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;       // replace with int 3
    ptrace(PTRACE_POKETEXT, child_pid, (void *)addr, (void *)data_trap);         // write inst
    return data;
}

void remove_breakpoint(unsigned long addr, unsigned long original_data, struct user_regs_struct *regs, pid_t child_pid) 
{
    ptrace(PTRACE_POKETEXT, child_pid, (void *)addr, (void *)original_data);
    regs->rip -= 1;
    ptrace(PTRACE_SETREGS, child_pid, 0, regs);
}

void run_breakpoint_debugger(pid_t child_pid, unsigned long func_addr)
{
    int wait_status;
    struct user_regs_struct regs;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        return;
    }

    for (int i = 1;; ++i)
    {
        /* Set breakpoint at function address and read original data */
        unsigned long func_inst = set_breakpoint(func_addr, child_pid);

        /* Let the child run to the breakpoint and wait for it to reach it */
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        if (WIFEXITED(wait_status)) {
            return;
        }

        /* Child stopped at first breakpoint at function address */
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        printf("PRF:: run %d first parameter is %llu\n", i, regs.rdi);
        
        /* Read return address and remove breakpoint */
        unsigned long ret_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)(regs.rsp), NULL);
        remove_breakpoint(func_addr, func_inst, &regs, child_pid);
        unsigned long func_call = set_breakpoint(ret_addr, child_pid);

        /* Let the child run to the breakpoint and wait for it to reach it */
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);

        /* Child stopped at second breakpoint at return address */
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        printf("PRF:: run %d returned with %llu\n", i, regs.rax);
        remove_breakpoint(ret_addr, func_call, &regs, child_pid);
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

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {


    FILE* elf_file = fopen(exe_file_name, "r");

    // read ELF header
    Elf64_Ehdr elf_hdr;
    fread(&elf_hdr, 1, sizeof(elf_hdr), elf_file);
    if (elf_hdr.e_type != ET_EXEC) {
        *error_val = -3;
        return 0;
    }

    // read section name string table
    // first, read its header
    Elf64_Shdr sect_hdr;
    fseek(elf_file, elf_hdr.e_shoff + elf_hdr.e_shstrndx * sizeof(sect_hdr), SEEK_SET);
    fread(&sect_hdr, 1, sizeof(sect_hdr), elf_file);

    // next, read the section, string data
    char *SectNames = (char *) malloc(sect_hdr.sh_size);
    fseek(elf_file, sect_hdr.sh_offset, SEEK_SET);
    fread(SectNames, 1, sect_hdr.sh_size, elf_file);

    Elf64_Shdr sect_hdr_symtab;
    Elf64_Shdr sect_hdr_strtab;
    // find symtab section headers
    for (int idx = 0; idx < elf_hdr.e_shnum; idx++)
    {
        const char* name = "";

        fseek(elf_file, elf_hdr.e_shoff + idx * sizeof(sect_hdr), SEEK_SET);
        fread(&sect_hdr, 1, sizeof(sect_hdr), elf_file);

        name = SectNames + sect_hdr.sh_name;
        if (!strcmp(name, ".symtab")) {
            sect_hdr_symtab = sect_hdr;
        }
        if (!strcmp(name, ".strtab")) {
            sect_hdr_strtab = sect_hdr;
        }
    }

    char *SymbNames = (char *) malloc(sect_hdr_strtab.sh_size);
    fseek(elf_file, sect_hdr_strtab.sh_offset, SEEK_SET);
    fread(SymbNames, 1, sect_hdr_strtab.sh_size, elf_file);

    Elf64_Sym symtab;
    unsigned long ret = 0;
    bool var_found = false;
    bool var_local = false;
    bool var_global = false;
    bool var_defined = false;
    int count = sect_hdr_symtab.sh_size / sect_hdr_symtab.sh_entsize;
    for (int idx = 0; idx < count; idx++)
    {
        const char* name = "";

        fseek(elf_file, sect_hdr_symtab.sh_offset + idx * sizeof(symtab), SEEK_SET);
        fread(&symtab, 1, sizeof(symtab), elf_file);

        name = SymbNames + symtab.st_name;
        if (!strcmp(name, symbol_name)) {
            var_found = true;
            if (ELF64_ST_BIND(symtab.st_info) == LOCAL) {
                var_local = true;
            }
            if (ELF64_ST_BIND(symtab.st_info) == GLOBAL) {
                var_global = true;
                var_defined = symtab.st_shndx != UND;
                if (var_defined) {
                    ret = symtab.st_value;
                }
            }
        }
    }
    if (!var_found) {
        *error_val = -1;
        return ret;
    }
    if (!var_local && !var_global && !var_global) {
        *error_val = -3;
        return 0;
    }
    if (var_local && !var_global) {
        *error_val = -2;
        return ret;
    }
    if (var_global && !var_defined) {
        *error_val = -4;
        return ret;
    }

    free(SymbNames);
    free(SectNames);
    fclose(elf_file);

    *error_val = 1;
    return ret;
}