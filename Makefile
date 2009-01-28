CC	= gcc
CFLAGS	= -g -O2 -fomit-frame-pointer -Wall
BINDIR	= /usr/bin

VERSION		:= $(shell cat VERSION)
MINOR_VERSION	:= $(shell cut -d . -f 2 VERSION)
MAJOR_VERSION	:= $(shell cut -d . -f 1 VERSION)

all: bloat

bloat: bloat.c
	$(CC) $(CFLAGS) $< -lx86emu -o $@

install: bloat
	install -m 755 -D bloat $(DESTDIR)$(BINDIR)/bloat

clean:
	rm -f *~ *.o bloat
