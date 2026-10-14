# Portable POSIX makefile for the OMEN tools.
# Use a POSIX-compatible C compiler (for example, cc, gcc, or clang).

CC = cc
CFLAGS = -O3 -Wall -Wextra -Wpedantic -std=c11

.PHONY: all clean

all: omen-generator omen-level-check

omen-generator: omen_generator.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ omen_generator.c $(LDLIBS)

omen-level-check: omen_level_check.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ omen_level_check.c $(LDLIBS)

clean:
	rm -f omen-generator omen-level-check
