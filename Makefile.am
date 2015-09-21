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

CLEANFILES = lock
AM_MAKEFLAGS =
EXTRA_DIST =

# Yes, check_, even though it's our primary bit of code.
# See the comment in Makefile.am.stub.
check_LIBRARIES = libfb-adb.a

# CMD_SOURCES are ones depending on autocmd.h Need to manually specify
# the sources that depend on autocmd.h so that we always build
# autocmd.h first when bootstrapping.
CMD_SOURCES = \
	cmd.c \
	cmd.h \
	cmd_bash_completion.c \
	cmd_fcat.c \
	cmd_finfo.c \
	cmd_getprop.c \
	cmd_help.c \
	cmd_logw.c \
	cmd_ps_json.c \
	cmd_rdex.c \
	cmd_readlink.c \
	cmd_start_daemon.c \
	cmd_stop_daemon.c \
	cmd_tar.c \
	fb-adb.c \
	xfer.c \
	xfer.h \
	$(EMPTY)

libfb_adb_a_SOURCES = \
	adb.c \
	adb.h \
	adbenc.c \
	adbenc.h \
	androidmsg.c \
	androidmsg.h \
	argv.c \
	argv.h \
	channel.c \
	channel.h \
	chat.c \
	chat.h \
	child.c \
	child.h \
	constants.h \
	core.c \
	core.h \
	dbg.c \
	dbg.h \
	elfid.c \
	elfid.h \
	errcodes.h \
	fdrecorder.c \
	fdrecorder.h \
	fs.c \
	fs.h \
	json.c \
	json.h \
	lz4.c \
	lz4.h \
	net.c \
	net.h \
	proto.h \
	ringbuf.c \
	ringbuf.h \
	sha2.c \
	sha2.h \
	strutil.c \
	strutil.h \
	termbits.c \
	termbits.h \
	timestamp.h \
	utf8.c \
	utf8.h \
	util.c \
	util.h \
	valgrind.h \
	xenviron.c \
	xenviron.h \
	xmkraw.c \
	xmkraw.h \
	$(CMD_SOURCES) \
	$(EMPTY)

nodist_libfb_adb_a_SOURCES = \
	autocmd.c \
	autocmd.h \
	$(EMPTY)

fb_adb_SOURCES =
nodist_fb_adb_SOURCES = timestamp.c
fb_adb_LDADD = libfb-adb.a

AM_CPPFLAGS = -I. -DSHA2_USE_INTTYPES_H=1
AM_CFLAGS = -fvisibility=hidden -std=gnu99 $(WARNING_SUPPRESSION)
AM_LDFLAGS =

if BUILD_PIC
AM_CFLAGS += -fPIC
AM_LDFLAGS += -fPIC -pie
endif

CLEANFILES += termnames.h
$(srcdir)/termbits.c: termnames.h
termnames.h: termnames.h.in termnames.sed
	$(SED) -Ef $(srcdir)/termnames.sed $< >$@

COMMANDS_XML=$(srcdir)/commands.xml
CMDSPROC_FLAGS=
CMDSPROC=$(PYTHON3) $(srcdir)/cmdsproc.py $(CMDSPROC_FLAGS) $(CMDSPROC_ENV)

CLEANFILES += autocmd.h
autocmd.h: $(COMMANDS_XML) $(srcdir)/cmdsproc.py
	$(CMDSPROC) h $(COMMANDS_XML) > $@

CLEANFILES += autocmd.c
autocmd.c: $(COMMANDS_XML) $(srcdir)/cmdsproc.py
	$(CMDSPROC) c $(COMMANDS_XML) > $@

EXTRA_DIST += fb-adb.bashsrc.in
CLEANFILES += fb-adb.bashsrc
fb-adb.bashsrc: $(COMMANDS_XML)
fb-adb.bashsrc: $(srcdir)/cmdsproc.py
fb-adb.bashsrc: $(srcdir)/fb-adb.bashsrc.in
fb-adb.bashsrc:
	rm -f $@.tmp
	cat $(srcdir)/fb-adb.bashsrc.in > $@.tmp
	$(CMDSPROC) bashcomplete $(COMMANDS_XML) >> $@.tmp
	chmod ugo-w $@.tmp
	mv -f $@.tmp $@

$(srcdir)/cmd_bash_completion.c: bash_completion.inc
CLEANFILES += bash_completion.inc
bash_completion.inc: fb-adb.bashsrc
	xxd -i < $< > $@

CLEANFILES += libfb-adb.a.stripped
libfb-adb.a.stripped: libfb-adb.a
	cp -f $< $@
	$(STRIP) $@

clean-local:
	rm -f *.tmp *.i *.s *.res

dist-hook:
	for x in $(STUB_SUBDIRS); do \
		mkdir -p $(distdir)/$$x; \
		cp -f $(srcdir)/$$x/configure $(distdir)/$$x; \
	done

if BUILD_STUB
include Makefile.am.stub
else
include Makefile.am.fb-adb
endif

.DELETE_ON_ERROR:

$(CMD_SOURCES:.c=.o): autocmd.h
