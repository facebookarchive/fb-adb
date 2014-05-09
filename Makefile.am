bin_PROGRAMS = adbx
adbx_SOURCES = adbx.c util.c child.c xmkraw.c ringbuf.c core.c channel.c \
	cmd_stub.c cmd_shex.c dbg.c termbits.c adbenc.c

termbits.c: termnames.h
termnames.h: termnames.h.in termnames.sed
	$(SED) -rf termnames.sed $< >$@
