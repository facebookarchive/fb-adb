#pragma once

struct chat {
    FILE* to;
    FILE* from;
};

struct chat* chat_new(int to, int from);
char chat_getc(struct chat* cc);
void chat_expect(struct chat* cc, char expected);
void chat_swallow_prompt(struct chat* cc);
void chat_talk_at(struct chat* cc, const char* what);
char* chat_read_line(struct chat* cc);
