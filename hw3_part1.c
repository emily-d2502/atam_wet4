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
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define UND 0

#define LOCAL 0
#define GLOBAL 1

#define	ET_NONE	0	//No file type
#define	ET_REL	1	//Relocatable file
#define	ET_EXEC	2	//Executable file
#define	ET_DYN	3	//Shared object file
#define	ET_CORE	4	//Core file


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
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

#if defined(DEBUG)
int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

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
}
#endif
