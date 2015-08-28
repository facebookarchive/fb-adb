#include <stdlib.h>
#include "json.h"
#include "util.h"

enum json_state {
    VALUE            =  (1<<0),
    ARRAY_EMPTY      =  (1<<1),
    ARRAY_NONEMPTY   =  (1<<2),
    OBJECT_EMPTY     =  (1<<3),
    OBJECT_NONEMPTY  =  (1<<4),
    IOERR            =  (1<<5),
};

struct json_context {
    struct json_context* previous;
    enum json_state state;
};

struct json_writer {
    FILE* out;
    struct json_context* context;
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
    struct json_writer* writer = malloc(sizeof (*writer));
    if (writer == NULL)
        die_oom();
    cleanup_commit(cl, json_writer_cleanup, writer);
    writer->out = out;
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
json_emit_string_no_state_check(struct json_writer* writer,
                                const char* string)
{
    char c;
    json_emitc(writer, '"');
    while ((c = *string++) != '\0') {
        if (c == '"') {
            json_emitc(writer, '\\');
            json_emitc(writer, '"');
        } else if (c == '\\') {
            json_emitc(writer, '\\');
            json_emitc(writer, '\\');
        } else if (c <= 0x1F) {
            char buf[sizeof ("\\uXXXX")];
            sprintf(buf, "\\u%04X", (unsigned) c);
            json_emits(writer, buf);
        } else {
            json_emitc(writer, c);
        }
    }
    json_emitc(writer, '"');
}

void
json_begin_field(struct json_writer* writer, const char* name)
{
    json_check_state(writer, OBJECT_EMPTY | OBJECT_NONEMPTY);
    if (json_writer_state(writer) == OBJECT_NONEMPTY)
        json_emitc(writer, ',');
    else if (json_writer_state(writer) == OBJECT_EMPTY)
        writer->context->state = OBJECT_NONEMPTY;
    json_emit_string_no_state_check(writer, name);
    json_emitc(writer, ':');
    json_push_context(writer, VALUE);
}

void
json_emit_string(struct json_writer* writer, const char* string)
{
    json_value_start(writer);
    json_emit_string_no_state_check(writer, string);
    json_value_end(writer);
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
            case IOERR:
                die(EINVAL, "json object saw IO error");
        }
    }

    if (writer->context == NULL) {
        die(EINVAL, "saved state mismatch");
    }
}
