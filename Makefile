CC	= gcc
CFLAGS	= -g -O2 -fomit-frame-pointer -Wall
BINDIR	= /usr/bin

GIT2LOG := $(shell if [ -x ./git2log ] ; then echo ./git2log --update ; else echo true ; fi)
GITDEPS := $(shell [ -d .git ] && echo .git/HEAD .git/refs/heads .git/refs/tags)
VERSION := $(shell $(GIT2LOG) --version VERSION ; cat VERSION)
BRANCH  := $(shell [ -d .git ] && git branch | perl -ne 'print $$_ if s/^\*\s*//')
PREFIX  := bloat-$(VERSION)

all: changelog bloat

changelog: $(GITDEPS)
	$(GIT2LOG) --changelog changelog

bloat: bloat.c bios_keys.h uni.h
	$(CC) $(CFLAGS) $< -lx86emu -o $@

install: bloat
	install -m 755 -D bloat $(DESTDIR)$(BINDIR)/bloat

archive: changelog
	@if [ ! -d .git ] ; then echo no git repo ; false ; fi
	mkdir -p package
	git archive --prefix=$(PREFIX)/ $(BRANCH) > package/$(PREFIX).tar
	tar -r -f package/$(PREFIX).tar --mode=0664 --owner=root --group=root --mtime="`git show -s --format=%ci`" --transform='s:^:$(PREFIX)/:' VERSION changelog
	xz -f package/$(PREFIX).tar

clean:
	rm -f *~ *.o bloat
