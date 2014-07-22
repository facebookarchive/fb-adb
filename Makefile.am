# Copyright 2004-present Facebook. All Rights Reserved.
# Link most objects in a library first so that timestamp.c can depend
# on that library and get regenerated only when it changes.
bin_PROGRAMS = fb-adb
noinst_LIBRARIES = libfb-adb.a
libfb_adb_a_SOURCES = \
	adb.c \
	adbenc.c \
	fb-adb.c \
	argv.c \
	chat.c \
	child.c \
	cmd_shex.c \
	cmd_stub.c \
	core.c channel.c \
	dbg.c \
	ringbuf.c \
	termbits.c \
	util.c \
	xmkraw.c

fb_adb_SOURCES = timestamp.c
fb_adb_LDADD = libfb-adb.a

if BUILD_STUB
AM_LDFLAGS = -flto
AM_CFLAGS =
endif

AM_CPPFLAGS = -I.
BUILT_SOURCES = timestamp.c

stubs.o: $(STUB_BINARIES)
$(srcdir)/termbits.c: termnames.h
termnames.h: termnames.h.in termnames.sed
	$(SED) -Ef $(srcdir)/termnames.sed $< >$@

SUBDIRS = $(STUB_SUBDIRS)
DIST_SUBDIRS = $(STUB_SUBDIRS)
CLEANFILES = termnames.h timestamp.c timestamp.c.tmp

if !BUILD_STUB
fb_adb_SOURCES += stubs.s
timestamp.c: timestamp.c.in libfb-adb.a
	$(SED) -e "s/BUILD_TIME/`date +%s`/" $< > $@
else
dummy-update-timestamp:
	$(MAKE) -C .. timestamp.c
timestamp.c: dummy-update-timestamp
	cp -fp ../timestamp.c $@
endif

distclean-local:
	rm -rf toolchain
