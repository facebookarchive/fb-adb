# Copyright (c) 2014, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in
# the LICENSE file in the root directory of this source tree. An
# additional grant of patent rights can be found in the PATENTS file
# in the same directory.
#
# Link most objects in a library first so that timestamp.c can depend
# on that library and get regenerated only when it changes.
#

noinst_LIBRARIES = libfb-adb.a
libfb_adb_a_SOURCES = \
	adb.c \
	adb.h \
	adbenc.c \
	adbenc.h \
	argv.c \
	argv.h \
	channel.h \
	channel.c \
	chat.c \
	chat.h \
	child.c \
	child.h \
	cmd_shex.c \
	cmd_stub.c \
	constants.h \
	core.c \
	core.h \
	dbg.c \
	dbg.h \
	fb-adb.c \
	proto.h \
	ringbuf.c \
	ringbuf.h \
	strutil.h \
	stubs.h \
	termbits.c \
	termbits.h \
	timestamp.h \
	util.c \
	util.h \
	xmkraw.c \
	xmkraw.h

if BUILD_STUB
noinst_PROGRAMS = fb-adb
else
bin_PROGRAMS = fb-adb
endif

fb_adb_SOURCES =
nodist_fb_adb_SOURCES = timestamp.c
fb_adb_LDADD = libfb-adb.a

AM_LDFLAGS=
AM_CFLAGS=

if BUILD_STUB
AM_LDFLAGS += -flto
AM_CFLAGS += -flto
endif

if BUILD_PIC
AM_LDFLAGS += -fPIC -pie
AM_CFLAGS += -fPIC
endif

AM_CPPFLAGS = -I.
BUILT_SOURCES = timestamp.c

if STRIP_STUBS
stub$(EXEEXT): fb-adb$(EXEEXT)
	$(STRIP) -o $@ $<
else
stub$(EXEEXT): fb-adb$(EXEEXT)
	cp -fp $< $@
endif

if BUILD_STUB
all-local: stub$(EXEEXT)
endif

stubs.o: $(STUB_BINARIES)
$(srcdir)/termbits.c: termnames.h
termnames.h: termnames.h.in termnames.sed
	$(SED) -Ef $(srcdir)/termnames.sed $< >$@

SUBDIRS = $(STUB_SUBDIRS)
DIST_SUBDIRS = 
CLEANFILES = termnames.h timestamp.c timestamp.c.tmp
EXTRA_DIST =
EXTRA_DIST += README.md LICENSE PATENTS NEWS stub-config.sh
EXTRA_DIST += timestamp.c.in termnames.h.in termnames.sed

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

dist-hook:
	for x in $(STUB_SUBDIRS); do \
		mkdir -p $(distdir)/$$x; \
		cp -f $(srcdir)/$$x/configure $(distdir)/$$x; \
	done

if BUILD_STUB
distclean-stub:
	rm -rf toolchain
else
distclean-stub:
	for x in $(STUB_SUBDIRS); do \
		if test -d $$x; then $(MAKE) -C $$x distclean; fi; \
	done
	rmdir $(STUB_SUBDIRS)
endif

distclean-local: distclean-stub

clean-local:
	rm -f stub
