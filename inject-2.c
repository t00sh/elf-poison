#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#define SYSCALL_ERROR(s) do {                           \
    fprintf(stderr, "%s:%d ", __FILE__, __LINE__);	\
    perror(s);						\
    exit(EXIT_FAILURE);					\
  } while(0)

#define ERROR(s) do {                                           \
    fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, s);	\
    exit(EXIT_FAILURE);						\
  } while(0)

#define INFO(...) do {				\
    fprintf(stdout, "[+] ");			\
    fprintf(stdout, __VA_ARGS__);		\
    fprintf(stdout, "\n");			\
  }while(0)

#define JMP_LENGTH 5
#define JMP_OPCODE 0xe9

typedef struct Elf32_Sect
{
  Elf32_Shdr shdr;
  uint8_t *data;
}Elf32_Sect;


typedef struct Elf32_File
{
  Elf32_Ehdr *ehdr;
  Elf32_Phdr *phdr;
  Elf32_Sect *sections;

}Elf32_File;


/********************************************************************
 * ELF checking functions
 *******************************************************************/
int check_magic(Elf32_File *file)
{
  if(strncmp((char*)file->ehdr->e_ident, ELFMAG, SELFMAG))
    return 0;

  return 1;
}

int check_shname(Elf32_File *file, int sh)
{
  int shname;

  shname = file->ehdr->e_shstrndx;

  if(shname < 0 || shname >= file->ehdr->e_shnum)
    return 0;
  if(file->sections[sh].shdr.sh_name >= file->sections[shname].shdr.sh_size)
    return 0;

  return 1;
}

/********************************************************************
 * misc ELF functions
 *******************************************************************/
const char* section_name(Elf32_File *file, int sh)
{
  int shname;

  shname = file->ehdr->e_shstrndx;
   
  if(!check_shname(file, sh))
    ERROR("Bad sh_name !");

  return (char*)(file->sections[shname].data + file->sections[sh].shdr.sh_name);
}

int get_section_id(Elf32_File *file, const char *shname)
{
  int sh;

  for(sh = 0; sh < file->ehdr->e_shnum; sh++)
    {
      if(!strcmp(shname, section_name(file, sh)))
	return sh;
    }
  return -1;
}


/********************************************************************
 * Load functions
 *******************************************************************/
static void load_ehdr(Elf32_File *file, int fd)
{
  uint32_t size;

  size = sizeof(Elf32_Ehdr);

  if((file->ehdr = malloc(size)) == NULL)
    SYSCALL_ERROR("[-] malloc ");

  if(read(fd, file->ehdr, size) != size)
    ERROR("Bad ELF !");

  if(!check_magic(file))
    ERROR("Not an ELF file !");
}

static void load_phdr(Elf32_File *file, int fd)
{
  uint32_t size;

  size = sizeof(Elf32_Phdr) * file->ehdr->e_phnum;

  if((file->phdr = malloc(size)) == NULL)
    SYSCALL_ERROR("malloc ");

  if(lseek(fd, file->ehdr->e_phoff, SEEK_SET) < 0)
    SYSCALL_ERROR("lseek ");

  if(read(fd, file->phdr, size) != size)
    ERROR("Bad ELF !");
}

static void load_sections(Elf32_File *file, int fd)
{
  int i;
  uint32_t shdr_size, size;
   
  shdr_size = sizeof(Elf32_Shdr);

  if((file->sections = malloc(file->ehdr->e_shnum * sizeof(Elf32_Sect))) == NULL)
    SYSCALL_ERROR("malloc ");

  for(i = 0; i < file->ehdr->e_shnum; i++)
    {
      if(lseek(fd, file->ehdr->e_shoff + i*shdr_size, SEEK_SET) < 0)
	SYSCALL_ERROR("lseek ");

      if(read(fd, &file->sections[i].shdr, shdr_size) != shdr_size)
	ERROR("Bad ELF !");

      if(file->sections[i].shdr.sh_type != SHT_NOBITS)
	{
	  size = file->sections[i].shdr.sh_size;

	  if((file->sections[i].data = malloc(size)) == NULL)
            SYSCALL_ERROR("malloc ");
         
	  if(lseek(fd, file->sections[i].shdr.sh_offset, SEEK_SET) < 0)
            SYSCALL_ERROR("lseek ");

	  if(read(fd, file->sections[i].data, size) != size)
            ERROR("Bad ELF !");
	}
      else
	{
	  file->sections[i].data = NULL;
	}
    }
}

Elf32_File* load_elf32(int fd)
{
  Elf32_File *file;

  if((file = malloc(sizeof(Elf32_File))) == NULL)
    SYSCALL_ERROR("malloc ");

  load_ehdr(file, fd);
  load_phdr(file, fd);
  load_sections(file, fd);

  return file;
}

/********************************************************************
 * Free  functions
 *******************************************************************/
static void free_sections_data(Elf32_File *file)
{
  int i;

  for(i = 0; i < file->ehdr->e_shnum; i++)
    {
      if(file->sections[i].data != NULL)
	free(file->sections[i].data);
    }
}

void free_elf32(Elf32_File *file)
{
  free_sections_data(file);
  free(file->ehdr);
  free(file->phdr);
  free(file->sections);
  free(file);
}

/********************************************************************
 * Print (debug)  functions
 *******************************************************************/

void print_sections(Elf32_File *file)
{
  int i;

  for(i = 0; i < file->ehdr->e_shnum; i++)
    {
      printf("[+] %-20s [%d] %#x -> %#x\n", 
	     section_name(file, i),
	     i,
	     file->sections[i].shdr.sh_offset,
	     file->sections[i].shdr.sh_offset + file->sections[i].shdr.sh_size);
    }
}

void print_ehdr(Elf32_File *file)
{
  printf("[+] [EHDR] %#x -> %#x\n",
	 0,
	 sizeof(Elf32_Ehdr));

  printf("[+] [PHDR] %#x -> %#x\n",
	 file->ehdr->e_phoff,
	 file->ehdr->e_phoff + file->ehdr->e_phnum * sizeof(Elf32_Phdr));

  printf("[+] [SHDR] %#x -> %#x\n", 
	 file->ehdr->e_shoff,
	 file->ehdr->e_shoff + file->ehdr->e_shnum * sizeof(Elf32_Shdr));
  printf("[+] [ENTRY] %#x\n", 
	 file->ehdr->e_entry);
}

/********************************************************************
 * Write functions
 *******************************************************************/
void write_to_file(int fd, void *data, uint32_t size, uint32_t *off)
{
  write(fd, data, size);
  *off += size;
}

void add_padding(int fd, uint32_t *start, uint32_t end)
{
  char c = 0;

  while(*start < end)
    {
      write_to_file(fd, &c, 1, start);
    }
}

void write_sections(Elf32_File *file, uint32_t *offset, int fd)
{
  int i;

  for(i = 0; i < file->ehdr->e_shnum; i++)
    {
      if(file->sections[i].shdr.sh_type != SHT_NOBITS)
	{
	  add_padding(fd, offset, file->sections[i].shdr.sh_offset);
	  write_to_file(fd, file->sections[i].data, file->sections[i].shdr.sh_size, offset);
	}
    }
}

void write_shdr(Elf32_File *file, uint32_t *offset, int fd)
{
  int i;

  for(i = 0; i < file->ehdr->e_shnum; i++)
    {
      write_to_file(fd, &file->sections[i].shdr, sizeof(Elf32_Shdr), offset);
    }
}

void write_file(Elf32_File *file, int fd)
{
  uint32_t offset;

  offset = 0;

  write_to_file(fd, file->ehdr, sizeof(Elf32_Ehdr), &offset);

  add_padding(fd, &offset, file->ehdr->e_phoff);
  write_to_file(fd, file->phdr, sizeof(Elf32_Phdr) * file->ehdr->e_phnum, &offset);

  write_sections(file, &offset, fd);

  add_padding(fd, &offset, file->ehdr->e_shoff);
  write_shdr(file, &offset, fd);
}


/********************************************************************
 * ELF (re)building functions
 *******************************************************************/
int find_last_ptload(Elf32_File *file)
{
  int i;
   
  for(i = 0; i < file->ehdr->e_phnum - 1; i++)
    {
      if(file->phdr[i].p_type == PT_LOAD)
	{
	  if(file->phdr[i+1].p_type == PT_LOAD)
	    {
	      return i+1;
	    }
	}
    }
  return -1;
}

int get_last_section(Elf32_File *file, int ph)
{
  int i;

  for(i = 0; i < file->ehdr->e_shnum; i++)
    {
      if(file->sections[i].shdr.sh_addr + file->sections[i].shdr.sh_size >= file->phdr[ph].p_vaddr + file->phdr[ph].p_memsz)
	return i;
    }
  return -1;
}

int insert_section(Elf32_File *file, int sh, int ph, uint8_t *code,
		   uint32_t length)
{
  Elf32_Sect section;

  file->ehdr->e_shnum++;

  if((file->sections = realloc(file->sections, file->ehdr->e_shnum * sizeof(Elf32_Sect))) == NULL)
    SYSCALL_ERROR("realloc ");

  section.shdr.sh_name = 0;
  section.shdr.sh_type = SHT_PROGBITS;
  section.shdr.sh_flags = SHF_EXECINSTR | SHF_ALLOC;
  section.shdr.sh_offset = file->phdr[ph].p_offset + file->phdr[ph].p_memsz;
  section.shdr.sh_size = length + JMP_LENGTH;
  section.shdr.sh_link = 0;
  section.shdr.sh_info = 0;
  section.shdr.sh_addralign = 16;
  section.shdr.sh_entsize = 0;
  section.shdr.sh_addr = file->phdr[ph].p_vaddr + file->phdr[ph].p_memsz;

  printf("[+] New section %#.8x\n", section.shdr.sh_addr);

  if((section.data = malloc(length + JMP_LENGTH)) == NULL)
    SYSCALL_ERROR("malloc ");

  memcpy(section.data, code, length);
  memmove(file->sections + sh + 2, file->sections + sh + 1, sizeof(Elf32_Sect)*
	  (file->ehdr->e_shnum - sh-2));

  memcpy(file->sections + sh + 1, &section, sizeof(Elf32_Sect));

  return sh + 1;
}

void update_segment_size(Elf32_File *file, int ph, uint32_t codesize)
{
  file->phdr[ph].p_memsz += codesize + JMP_LENGTH;
  file->phdr[ph].p_filesz = file->phdr[ph].p_memsz;
}

void update_e_entry(Elf32_File *file, int sh, uint32_t codesize)
{
  uint32_t last_entry;
  int32_t jmp;
  uint8_t jmp_code[JMP_LENGTH];

  jmp_code[0] = JMP_OPCODE;

  last_entry = file->ehdr->e_entry;
  file->ehdr->e_entry = file->sections[sh].shdr.sh_addr;

  jmp = last_entry - (file->ehdr->e_entry + codesize + JMP_LENGTH);
   
  memcpy(jmp_code+1, &jmp, 4);
  memcpy(file->sections[sh].data + codesize, jmp_code, JMP_LENGTH);
}

void update_sections_offset(Elf32_File *file, int sh)
{
  int i;

  for(i = sh; i < file->ehdr->e_shnum-1; i++)
    {
      file->sections[i+1].shdr.sh_offset = file->sections[i].shdr.sh_offset +
	file->sections[i].shdr.sh_size;
    }

  if(file->ehdr->e_shstrndx > sh)
    file->ehdr->e_shstrndx++;
}

void update_shdr_offset(Elf32_File *file)
{
  int shnum;
   
  shnum = file->ehdr->e_shnum;

  file->ehdr->e_shoff = file->sections[shnum-1].shdr.sh_offset + 
    file->sections[shnum-1].shdr.sh_size;
}

void update_segments_perm(Elf32_File *file)
{
  int i;

  for(i = 0; i < file->ehdr->e_phnum; i++)
    {
      if(file->phdr[i].p_type == PT_LOAD)
	{
	  file->phdr[i].p_flags = PF_X | PF_W | PF_R;
	}
    }
}

void insert_code(Elf32_File *file, uint8_t *code, uint32_t length)
{
  int sh, ph;

  if((ph = find_last_ptload(file)) < 0)
    ERROR("Can't find the segment !");

  if((sh = get_last_section(file, ph)) < 0)
    ERROR("Can't find the section !");

  sh = insert_section(file, sh, ph, code, length);
  update_segment_size(file, ph, length);
  update_segments_perm(file);
  update_e_entry(file, sh, length);
  update_sections_offset(file, sh);
  update_shdr_offset(file);
}


/* Convert 'a' -> 10 */
int hex_to_dec(int c) {
  if(isdigit(c))
    return c - '0';
  if(c >= 'a' && c <= 'f')
    return (c - 'a') + 10;
  if(c >= 'A' && c <= 'F')
    return (c - 'A') + 10;
  
  return -1;
}

/* Test if char is in range [0-9a-fA-F] */
int is_hexa_char(int c) {
  return (isdigit(c) 
	  || (c >= 'a' && c <= 'f') 
	  || (c >= 'A' && c <= 'F'));
}

/* Convert "\x0a\x2c..." to raw data */
uint8_t* opcodes_to_data(char *str, uint32_t *length) {
  int i;
  uint8_t *data;
 
  i = 0;
  if((data = malloc(strlen(str) + 1)) == NULL)
    return NULL;

  while(*str != '\0') {
    if(str[0] == '\\' && str[1] == 'x') {
      if(is_hexa_char(str[2]) && is_hexa_char(str[3])) {
	data[i] = hex_to_dec(str[2]) * 16;
	data[i] += hex_to_dec(str[3]);
	str += 3;
      }
    } else {
      data[i] = *str;
    }
    str++;
    i++;
  }
  *length = i;
  return data;
}

int main(int argc, char **argv)
{
  uint8_t *code;
  uint32_t length;
  Elf32_File *file;
  int fd;

  if(argc != 3)
    {
      printf("Usage : %s <filename> <code>\n", argv[0]);
      exit(EXIT_FAILURE);
    }

  code = opcodes_to_data(argv[2], &length);

  printf("[+] Loading %s in memory...\n", argv[1]);
  if((fd = open(argv[1], O_RDONLY)) < 0)
    SYSCALL_ERROR("open ");

  file = load_elf32(fd);

  close(fd);

  printf("[+] Inserting code...\n");
  insert_code(file, code, length);

  printf("[+] Rewriting binary...\n");
  if((fd = open(argv[1], O_WRONLY)) < 0)
    SYSCALL_ERROR("open ");

  write_file(file, fd);

  close(fd);

  print_sections(file);
  print_ehdr(file);
  printf("[+] DONE.\n");

  free_elf32(file);


  return EXIT_SUCCESS;
}
