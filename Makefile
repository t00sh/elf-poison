.PHONY: clean

CFLAGS = -O2 -g -Wall -Wextra -Wwrite-strings -Wstrict-prototypes 
CFLAGS += -Wunreachable-code -Wuninitialized 

all: inject-1 inject-2

inject-1: inject-1.c Makefile
	@ gcc inject-1.c -I lib lib/libdasm.c -o inject-1
	@ echo '  CC inject-1'

inject-2: inject-2.c Makefile
	@ gcc $(CFLAGS) inject-2.c -o inject-2
	@ echo '  CC inject-2'
clean:
	@ rm inject-1 inject-2
	@ echo '  CLEAN'
