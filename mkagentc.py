#!/usr/bin/env python3
# -*- python-indent-offset: 2 -*-
# Copyright (c) 2014, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in
# the LICENSE file in the root directory of this source tree. An
# additional grant of patent rights can be found in the PATENTS file
# in the same directory.
#
# This file generates agent.c from the agent dex file.  Using Python
# for this purpose is convenient, as it includes both a deterministic
# zip file generator and a hashing utility.
#

import os
import sys
import subprocess
import zipfile
from hashlib import sha256
from io import BytesIO

def die(msg):
  print(msg, file=sys.stderr)
  sys.exit(1)

if len(sys.argv) != 2:
  die("invalid usage")
agent_dex_file_name=sys.argv[1]
xxd=os.environ["XXD"]

with open(agent_dex_file_name, "rb") as agent_dex:
  agent_dex_contents = agent_dex.read()

jar_file = BytesIO()
with zipfile.ZipFile(
    jar_file,
    mode="w",
    allowZip64=False) as zip:
  # Explicitly specificy date for determinism
  fileinfo = zipfile.ZipInfo("classes.dex", (1980, 1, 1, 0, 0, 0))
  zip.writestr(fileinfo, agent_dex_contents)
jar_file.seek(0)
agent_dex_jar_contents=jar_file.read()

xxd_output = subprocess.check_output(
  (xxd, "-i"),
  input = agent_dex_jar_contents)

print("""\
#include <stdint.h>
#include "agent.h"
const char agent_name[] = "%(agent_name)s";
const uint8_t agent_dex_jar[] = {
%(xxd_output)s
};
const size_t agent_dex_jar_size = sizeof(agent_dex_jar);
""" % {
  "agent_name": "agent-" + sha256(agent_dex_jar_contents).hexdigest()[:16],
  "xxd_output": xxd_output.decode("ascii"),
})
