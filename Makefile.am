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

fb_adb_SOURCES =
nodist_fb_adb_SOURCES = timestamp.c
fb_adb_LDADD = libfb-adb.a

AM_LDFLAGS=
AM_CFLAGS=

if BUILD_PIC
AM_LDFLAGS += -fPIC -pie
AM_CFLAGS += -fPIC
endif

AM_CPPFLAGS = -I.
BUILT_SOURCES = timestamp.c

$(srcdir)/termbits.c: termnames.h
termnames.h: termnames.h.in termnames.sed
	$(SED) -Ef $(srcdir)/termnames.sed $< >$@

CLEANFILES = termnames.h timestamp.c timestamp.c.tmp

if BUILD_STUB
include Makefile.am.stub
else
include Makefile.am.fb-adb
endif
