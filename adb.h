// Copyright 2004-present Facebook. All Rights Reserved.
#pragma once
void adb_send_file(const char* local,
                   const char* remote,
                   const char* const* adb_args);
