#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "util.h"
#include "chat.h"

__attribute__((noreturn))
static void chat_die(void)
{
    die(ECOMM, "lost connection to child");
}


struct chat*
chat_new(int to, int from)
{
    struct chat* cc = xcalloc(sizeof (*cc));
    cc->to = xfdopen(to, "w");
    cc->from = xfdopen(from, "r");
    return cc;
}

char
chat_getc(struct chat* cc)
{
    int c = getc(cc->from);
    if (c == EOF)
        chat_die();

    return c;
}

void
chat_expect(struct chat* cc, char expected)
{
    int c = chat_getc(cc);
    if ((char)c != expected) {
        die(ECOMM,
            "[child] expected 0x%02x %c, found 0x%02x %c",
            expected,
            isprint(expected) ? expected : '.',
            (char) c,
            isprint(c) ? c : '.');
    }
}

void
chat_swallow_prompt(struct chat* cc)
{
    /* 100% reliable prompt detection */
    char c;
    do {
        c = chat_getc(cc);
    } while (c != '#' && c != '$');
    chat_expect(cc, ' ');
}

void
chat_talk_at(struct chat* cc, const char* what)
{
    if (fputs(what, cc->to) == EOF)
        chat_die();

    if (putc('\n', cc->to) == EOF)
        chat_die();

    if (fflush(cc->to) == EOF)
        chat_die();

    /* We expect the child to echo us, so read back the echoed
     * characters.  */
    while (*what)
        chat_expect(cc, *what++);

    /* Yes, this is really what comes back after a \n.  */
    chat_expect(cc, '\r');
    chat_expect(cc, '\r');
    chat_expect(cc, '\n');
}

char*
chat_read_line(struct chat* cc)
{
    char line[512];
    if (fgets(line, sizeof (line), cc->from) == NULL)
        die(ECOMM, "lost connection to child");

    size_t linesz = strlen(line);
    while (linesz > 0 && strchr("\r\n", line[linesz - 1]))
        linesz--;
    line[linesz] = '\0';
    return xstrdup(line);
}
