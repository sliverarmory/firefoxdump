# Firefox Dump BOF - Makefile
# Compiles the BOF for x86 and x64 architectures

CC_X64 = x86_64-w64-mingw32-gcc
CC_X86 = i686-w64-mingw32-gcc
CFLAGS = -I src/common -Os -c -DBOF

all: x64 x86

x64:
	$(CC_X64) -o bin/firefoxdump.x64.o $(CFLAGS) src/entry.c

x86:
	$(CC_X86) -o bin/firefoxdump.x86.o $(CFLAGS) src/entry.c

clean:
	rm -f bin/*.o

.PHONY: all x64 x86 clean
