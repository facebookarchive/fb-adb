# Link most objects in a library first so that timestamp.c can depend
# on that library and get regenerated only when it changes.
bin_PROGRAMS = adbx
noinst_LIBRARIES = libadbx.a
libadbx_a_SOURCES = \
	adb.c \
	adbenc.c \
	adbx.c \
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

adbx_SOURCES = timestamp.c
adbx_LDADD = libadbx.a

# Android demands PIC executables
if BUILD_STUB
AM_CFLAGS = -fPIC -flto
AM_LDFLAGS = -fPIC -pie -flto
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
adbx_SOURCES += stubs.s
timestamp.c: timestamp.c.in libadbx.a
	$(SED) -e "s/BUILD_TIME/`date +%s`/" $< > $@
else
dummy-update-timestamp:
	$(MAKE) -C .. timestamp.c
timestamp.c: dummy-update-timestamp
	cp -fp ../timestamp.c $@
endif

distclean-local:
	rm -rf toolchain
