# Firefox Dump BOF - Makefile
# Compiles the BOF for x86 and x64 architectures

CC_X64 = x86_64-w64-mingw32-gcc
CC_X86 = i686-w64-mingw32-gcc
CFLAGS = -Os -c -DBOF -Wall -Wextra -Wpedantic -Werror -Wno-cast-function-type
BIN_DIR = bin

all: x64 x86

x64: | $(BIN_DIR)
	$(CC_X64) -o $(BIN_DIR)/firefoxdump.x64.o $(CFLAGS) src/entry.c

x86: | $(BIN_DIR)
	$(CC_X86) -o $(BIN_DIR)/firefoxdump.x86.o $(CFLAGS) src/entry.c

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -f $(BIN_DIR)/*.o

.PHONY: all x64 x86 clean
