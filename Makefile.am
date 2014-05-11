bin_PROGRAMS = adbx
adbx_SOURCES = adbx.c util.c child.c xmkraw.c ringbuf.c core.c channel.c \
	cmd_stub.c cmd_shex.c dbg.c termbits.c adbenc.c adb.c chat.c

AM_CPPFLAGS = -I.

if BUILD_STUB
if STRIP_STUB
adbx.stripped: adbx
	$(STRIP_STUB) -o $@ $<
else
adbx.stripped: adbx
	cp -f $< $@
endif

all-local: adbx.stripped
endif

stubs.o: $(STUB_BINARIES)
$(srcdir)/termbits.c: termnames.h
termnames.h: termnames.h.in termnames.sed
	$(SED) -rf $(srcdir)/termnames.sed $< >$@

SUBDIRS = $(STUB_SUBDIRS)
DIST_SUBDIRS = $(STUB_SUBDIRS)
CLEANFILES = termnames.h adbx.stripped

if !BUILD_STUB
  adbx_SOURCES += stubs.s
endif

