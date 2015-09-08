#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

// Simple, stupid JSON output functions.

struct json_writer;

enum json_writer_bad_utf8_mode {
    // Replace invalid UTF-8 sequences with the empty string
    JSON_WRITER_BAD_UTF8_DELETE,
    // Replace invalid UTF-8 sequences with the configured
    // replacement string
    JSON_WRITER_BAD_UTF8_REPLACE,
    // Die on bad UTF-8 sequences
    JSON_WRITER_BAD_UTF8_DIE,
};

struct json_writer_config {
    // What to do when we see an invalid UTF-8 sequence
    enum json_writer_bad_utf8_mode bad_utf8_mode;
    // Character to insert instead of a bad UTF-8 sequence; must be
    // valid part of JSON string literal --- not escaped!
    const char* bad_utf8_replacement;
};

struct json_writer* json_writer_create(FILE* out);
struct json_writer_config json_writer_get_config(
    struct json_writer* writer);
void json_writer_set_config(
    struct json_writer* writer,
    struct json_writer_config config);
void json_begin_array(struct json_writer* writer);
void json_end_array(struct json_writer* writer);
void json_begin_object(struct json_writer* writer);
void json_end_object(struct json_writer* writer);
void json_begin_field(struct json_writer* writer, const char* name);
void json_emit_string(struct json_writer* writer, const char* string);
void json_emit_string_n(struct json_writer* writer,
                        const char* string,
                        size_t n);
void json_begin_string(struct json_writer* writer);
void json_emit_string_part(
    struct json_writer* writer,
    const char* s,
    size_t n);
void json_end_string(struct json_writer* writer);
void json_emit_u64(struct json_writer* writer, uint64_t number);
void json_emit_i64(struct json_writer* writer, int64_t number);
void json_emit_null(struct json_writer* writer);
void json_emit_bool(struct json_writer* writer, bool b);

struct json_context;

const struct json_context* json_save_context(struct json_writer* writer);
void json_pop_to_saved_context(
    struct json_writer* writer,
    const struct json_context* saved_context);
