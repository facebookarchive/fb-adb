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

CMD_SOURCES = \
	cmd_stub.c \
	cmd_logw.c \
	cmd_readlink.c \
	cmd_finfo.c \
	$(EMPTY)

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
	json.h \
	json.c \
	sha2.h \
	sha2.c \
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
	strutil.c \
	termbits.c \
	termbits.h \
	timestamp.h \
	util.c \
	util.h \
	xmkraw.c \
	xmkraw.h \
	net.c \
	net.h \
	lz4.c \
	lz4.h \
	xenviron.c \
	xenviron.h \
	cmd.h \
	cmd.c \
	$(CMD_SOURCES) \
	$(EMPTY)

nodist_libfb_adb_a_SOURCES = \
	autocmd.h \
	autocmd.c \
	$(EMPTY)

fb_adb_SOURCES =
nodist_fb_adb_SOURCES = timestamp.c
fb_adb_LDADD = libfb-adb.a

AM_CPPFLAGS = -I. -DSHA2_USE_INTTYPES_H=1
AM_CFLAGS = -fvisibility=hidden -std=gnu99
AM_LDFLAGS =

if BUILD_PIC
AM_CFLAGS += -fPIC
AM_LDFLAGS += -fPIC -pie
endif

$(srcdir)/termbits.c: termnames.h
termnames.h: termnames.h.in termnames.sed
	$(SED) -Ef $(srcdir)/termnames.sed $< >$@

# Need to manually specify the sources that depend on autocmd.h so
# that we always build autocmd.h first when bootstrapping.
$(CMD_SOURCES) $(srcdir)/fb-adb.c $(srcdir)/cmd.c: autocmd.h

COMMANDS_XML=$(srcdir)/commands.xml
CMDSPROC_FLAGS=
CMDSPROC=$(PYTHON3) $(srcdir)/cmdsproc.py $(CMDSPROC_FLAGS)

autocmd.h: $(COMMANDS_XML) $(srcdir)/cmdsproc.py
	$(CMDSPROC) h $(COMMANDS_XML) > $@.tmp
	if ! cmp $@ $@.tmp; then mv $@.tmp $@; fi
	rm -f $@.tmp

autocmd.c: $(COMMANDS_XML) $(srcdir)/cmdsproc.py
	$(CMDSPROC) c $(COMMANDS_XML) > $@

CLEANFILES =  termnames.h timestamp.c timestamp.c.tmp
CLEANFILES += autocmd.h autocmd.h.tmp autocmd.c

EXTRA_DIST =

if BUILD_STUB
include Makefile.am.stub
else
include Makefile.am.fb-adb
endif

.DELETE_ON_ERROR:
