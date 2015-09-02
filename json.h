#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

// Simple, stupid JSON output functions

struct json_writer;

struct json_writer* json_writer_create(FILE* out);
void json_begin_array(struct json_writer* writer);
void json_end_array(struct json_writer* writer);
void json_begin_object(struct json_writer* writer);
void json_end_object(struct json_writer* writer);
void json_begin_field(struct json_writer* writer, const char* name);
void json_emit_string(struct json_writer* writer, const char* string);
void json_emit_u64(struct json_writer* writer, uint64_t number);
void json_emit_i64(struct json_writer* writer, int64_t number);
void json_emit_null(struct json_writer* writer);
void json_emit_bool(struct json_writer* writer, bool b);

struct json_context;

const struct json_context* json_save_context(struct json_writer* writer);
void json_pop_to_saved_context(struct json_writer* writer,
                               const struct json_context* saved_context);
