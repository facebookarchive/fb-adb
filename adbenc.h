#pragma once

void adb_encode(unsigned* inout_state,
                char** inout_enc,
                char* encend,
                const char** inout_in,
                const char* inend);

void adb_decode(unsigned* inout_state,
                char** inout_dec,
                char* decend,
                const char** inout_in,
                const char* inend);

size_t read_all_adb_encoded(int fd, void* buf, size_t sz);
void write_all_adb_encoded(int fd, const void* buf, size_t sz);

