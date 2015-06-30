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
	cmd_stub.c \
	cmd_stub.h \
	cmd_logw.c \
	cmd_logw.h \
	cmd_readlink.c \
	cmd_readlink.h \
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
	$(EMPTY)

fb_adb_SOURCES =
nodist_fb_adb_SOURCES = timestamp.c
fb_adb_LDADD = libfb-adb.a

AM_CPPFLAGS = -I.
AM_CFLAGS = -fvisibility=hidden -std=gnu99
AM_LDFLAGS =

if BUILD_PIC
AM_CFLAGS += -fPIC
AM_LDFLAGS += -fPIC -pie
endif

BUILT_SOURCES = timestamp.c

$(srcdir)/termbits.c: termnames.h
termnames.h: termnames.h.in termnames.sed
	$(SED) -Ef $(srcdir)/termnames.sed $< >$@

CLEANFILES = termnames.h timestamp.c timestamp.c.tmp

EXTRA_DIST =

if BUILD_STUB
include Makefile.am.stub
else
include Makefile.am.fb-adb
endif

.DELETE_ON_ERROR:
