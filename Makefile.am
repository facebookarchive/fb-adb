bin_PROGRAMS = adbx
ADBX_NON_TIMESTAMP = adbx.c util.c child.c xmkraw.c ringbuf.c core.c channel.c \
	cmd_stub.c cmd_shex.c dbg.c termbits.c adbenc.c adb.c chat.c

adbx_SOURCES = $(ADBX_NON_TIMESTAMP) timestamp.c

AM_CPPFLAGS = -I.
BUILT_SOURCES = timestamp.c

stubs.o: $(STUB_BINARIES)
$(srcdir)/termbits.c: termnames.h
termnames.h: termnames.h.in termnames.sed
	$(SED) -rf $(srcdir)/termnames.sed $< >$@

timestamp.c: timestamp.c.in $(ADBX_NON_TIMESTAMP:.c=.o)
	$(SED) -e "s/BUILD_TIME/`date +%s`/" $< > $@

SUBDIRS = $(STUB_SUBDIRS)
DIST_SUBDIRS = $(STUB_SUBDIRS)
CLEANFILES = termnames.h timestamp.c timestamp.c.tmp

if !BUILD_STUB
  adbx_SOURCES += stubs.s
endif
