#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "json.h"
#include "util.h"
#include "utf8.h"

#define UTF8_FULL 0

enum json_state {
    VALUE            =  (1<<0),
    ARRAY_EMPTY      =  (1<<1),
    ARRAY_NONEMPTY   =  (1<<2),
    OBJECT_EMPTY     =  (1<<3),
    OBJECT_NONEMPTY  =  (1<<4),
    STRING           =  (1<<5),
    IOERR            =  (1<<6),
};

struct json_context {
    struct json_context* previous;
    enum json_state state;
};

struct json_writer {
    FILE* out;
    struct json_writer_config config;
    struct json_context* context;
    uint32_t utf8_state;
    uint8_t utf8_buf[5];
    uint8_t utf8_bufsz;
};

static const char*
json_state_name(enum json_state state)
{
#ifndef NDEBUG
    switch (state) {
        case VALUE: return "VALUE";
        case ARRAY_EMPTY: return "ARRAY_EMPTY";
        case ARRAY_NONEMPTY: return "ARRAY_NONEMPTY";
        case OBJECT_EMPTY: return "OBJECT_EMPTY";
        case OBJECT_NONEMPTY: return "OBJECT_NONEMPTY";
        case STRING: return "STRING";
        case IOERR: return "IOERR";
    }
    return "?"; // Keep outside switch to preserve compiler warnings
#else
    return xaprintf("0x%08X", (unsigned) state);
#endif
}

static const char*
json_state_names(unsigned states)
{
#ifndef NDEBUG
    unsigned statebit = 0;
    const char* set = "{";
    int nstate = 0;
    while (states != 0) {
        if (states & 1) {
            enum json_state state = (1<<statebit);
            set = xaprintf("%s%s%s",
                           set,
                           nstate++ > 0 ? "," : "",
                           json_state_name(state));
        }
        states >>= 1;
        statebit++;
    }

    return xaprintf("%s}", set);
#else
    return xaprintf("0x%08X", (unsigned) states);
#endif
}

static void
json_push_context(struct json_writer* writer, enum json_state state)
{
    struct json_context* context = malloc(sizeof (*context));
    if (context == NULL)
        die_oom();
    context->state = state;
    context->previous = writer->context;
    writer->context = context;
}

static void
json_pop_context(struct json_writer* writer)
{
    struct json_context* context = writer->context;
    writer->context = context->previous;
    free(context);
}

static void
json_writer_cleanup(void* data)
{
    struct json_writer* writer = data;
    while (writer->context)
        json_pop_context(writer);
    free(writer);
}

static enum json_state
json_writer_state(struct json_writer* writer)
{
    if (writer->context == NULL)
        die(EINVAL, "json writer terminated");
    return writer->context->state;
}

static void
json_check_state(struct json_writer* writer, unsigned allowed_states)
{
    if ((json_writer_state(writer) & allowed_states) == 0)
        die(EINVAL,
            "json writer in illegal state %s: need one in %s",
            json_state_name(json_writer_state(writer)),
            json_state_names(allowed_states));
}

static void
json_emitc(struct json_writer* writer, char c)
{
    if (putc(c, writer->out) == EOF) {
        writer->context->state = IOERR;
        die_errno("putc");
    }
}

static void
json_emits(struct json_writer* writer, const char* s)
{
    char c;
    while ((c = *s++) != '\0')
        json_emitc(writer, c);
}

static void
json_value_start(struct json_writer* writer)
{
    json_check_state(writer, VALUE | ARRAY_EMPTY | ARRAY_NONEMPTY);
    if (json_writer_state(writer) == ARRAY_NONEMPTY)
        json_emitc(writer, ',');
    else if (json_writer_state(writer) == ARRAY_EMPTY)
        writer->context->state = ARRAY_NONEMPTY;
}

static void
json_value_end(struct json_writer* writer)
{
    if (json_writer_state(writer) == VALUE)
        json_pop_context(writer);
}

struct json_writer*
json_writer_create(FILE* out)
{
    struct cleanup* cl = cleanup_allocate();
    struct json_writer* writer = calloc(1, sizeof (*writer));
    if (writer == NULL)
        die_oom();
    cleanup_commit(cl, json_writer_cleanup, writer);
    writer->out = out;
    writer->config.bad_utf8_mode = JSON_WRITER_BAD_UTF8_REPLACE;
    writer->config.bad_utf8_replacement = "\\uFFFD";
    json_push_context(writer, VALUE);
    return writer;
}

void
json_begin_array(struct json_writer* writer)
{
    json_value_start(writer);
    json_push_context(writer, ARRAY_EMPTY);
    json_emitc(writer, '[');
}

void
json_end_array(struct json_writer* writer)
{
    json_check_state(writer, ARRAY_EMPTY | ARRAY_NONEMPTY);
    json_pop_context(writer);
    json_emitc(writer, ']');
    json_value_end(writer);
}

void
json_begin_object(struct json_writer* writer)
{
    json_value_start(writer);
    json_push_context(writer, OBJECT_EMPTY);
    json_emitc(writer, '{');
}

void
json_end_object(struct json_writer* writer)
{
    json_check_state(writer, OBJECT_EMPTY | OBJECT_NONEMPTY);
    json_pop_context(writer);
    json_emitc(writer, '}');
    json_value_end(writer);
}

static void
json_emit_ascii(struct json_writer* writer, uint8_t c)
{
    if (c == '"' || c == '\\') {
        json_emitc(writer, '\\');
        json_emitc(writer, c);
    } else if (c == '\n') {
        json_emits(writer, "\\n");
    } else if (c == '\r') {
        json_emits(writer, "\\r");
    } else if (c == '\t') {
        json_emits(writer, "\\t");
    } else if (c == '\f') {
        json_emits(writer, "\\f");
    } else if (c <= 0x1F || c == 0x7F) {
        char buf[sizeof ("\\uFFFF")];
        sprintf(buf, "\\u%04x", (unsigned) c);
        json_emits(writer, buf);
    } else {
        json_emitc(writer, c);
    }
}

static void
json_bad_utf8(struct json_writer* writer)
{
    switch (writer->config.bad_utf8_mode) {
        case JSON_WRITER_BAD_UTF8_DELETE:
            break;
        case JSON_WRITER_BAD_UTF8_DIE:
            die(EINVAL, "invalid UTF-8 sequence");
        case JSON_WRITER_BAD_UTF8_REPLACE:
            json_emits(writer, writer->config.bad_utf8_replacement);
            break;
    }
}

void
json_emit_string_part(struct json_writer* writer,
                      const char* s,
                      size_t n)
{
    json_check_state(writer, STRING);
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = s[i];
        assert(writer->utf8_bufsz < sizeof (writer->utf8_buf));
        writer->utf8_buf[writer->utf8_bufsz++] = c;
        switch (utf8_decode(&writer->utf8_state, c)) {
            case UTF8_ACCEPT: {
                if (writer->utf8_bufsz == 1) {
                    json_emit_ascii(writer, c);
                } else {
                    for (uint8_t j = 0; j < writer->utf8_bufsz; ++j) {
                        json_emitc(writer, writer->utf8_buf[j]);
                    }
                }
                writer->utf8_bufsz = 0;
                writer->utf8_state = UTF8_ACCEPT;
                break;
            }
            case UTF8_REJECT: {
                uint8_t utf8_bufsz;
                utf8_bufsz = writer->utf8_bufsz;
                writer->utf8_bufsz = 0;
                writer->utf8_state = UTF8_ACCEPT;
                json_bad_utf8(writer);
                if (utf8_bufsz > 1) {
                    i -= 1; // Reconsider individually
                }
                break;
            }
            default: {
                break;
            }
        }
    }
}

static void
json_begin_string_no_check(struct json_writer* writer)
{
    json_push_context(writer, STRING);
    json_emitc(writer, '"');
    writer->utf8_state = UTF8_ACCEPT;
    writer->utf8_bufsz = 0;
}

void
json_begin_string(struct json_writer* writer)
{
    json_value_start(writer);
    json_begin_string_no_check(writer);
}

void
json_end_string(struct json_writer* writer)
{
    json_check_state(writer, STRING);
    if (writer->utf8_state != UTF8_ACCEPT)
        json_bad_utf8(writer);
    json_pop_context(writer);
    json_emitc(writer, '"');
    json_value_end(writer);
}

void
json_begin_field(struct json_writer* writer, const char* name)
{
    json_check_state(writer, OBJECT_EMPTY | OBJECT_NONEMPTY);
    if (json_writer_state(writer) == OBJECT_NONEMPTY)
        json_emitc(writer, ',');
    else if (json_writer_state(writer) == OBJECT_EMPTY)
        writer->context->state = OBJECT_NONEMPTY;
    json_begin_string_no_check(writer);
    json_emit_string_part(writer, name, strlen(name));
    json_end_string(writer);
    json_emitc(writer, ':');
    json_push_context(writer, VALUE);
}

void
json_emit_string_n(struct json_writer* writer,
                   const char* string,
                   size_t n)
{
    json_begin_string(writer);
    json_emit_string_part(writer, string, n);
    json_end_string(writer);
}

void
json_emit_string(struct json_writer* writer, const char* string)
{
    json_emit_string_n(writer, string, strlen(string));
}

void
json_emit_i64(struct json_writer* writer, int64_t number)
{
    char buf[sizeof ("-18446744073709551616")];
    sprintf(buf, "%lld", (long long) number);
    json_value_start(writer);
    json_emits(writer, buf);
    json_value_end(writer);
}

void
json_emit_u64(struct json_writer* writer, uint64_t number)
{
    char buf[sizeof ("18446744073709551615")];
    sprintf(buf, "%llu", (unsigned long long) number);
    json_value_start(writer);
    json_emits(writer, buf);
    json_value_end(writer);
}

void
json_emit_null(struct json_writer* writer)
{
    json_value_start(writer);
    json_emits(writer, "null");
    json_value_end(writer);
}

void
json_emit_bool(struct json_writer* writer, bool b)
{
    json_value_start(writer);
    json_emits(writer, b ? "true" : "false");
    json_value_end(writer);
}

const struct json_context*
json_save_context(struct json_writer* writer)
{
    return writer->context;
}

void
json_pop_to_saved_context(struct json_writer* writer,
                          const struct json_context* saved_context)
{
    while (writer->context && writer->context != saved_context) {
        switch (writer->context->state) {
            case VALUE:
                json_emit_null(writer);
                break;
            case ARRAY_EMPTY:
            case ARRAY_NONEMPTY:
                json_end_array(writer);
                break;
            case OBJECT_EMPTY:
            case OBJECT_NONEMPTY:
                json_end_object(writer);
                break;
            case STRING:
                json_end_string(writer);
                break;
            case IOERR:
                die(EINVAL, "json object saw IO error");
        }
    }

    if (writer->context == NULL) {
        die(EINVAL, "saved state mismatch");
    }
}
