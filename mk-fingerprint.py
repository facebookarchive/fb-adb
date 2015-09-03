#!/usr/bin/env python3
# -*- python-indent-offset: 2 -*-
# Copyright (c) 2014, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in
# the LICENSE file in the root directory of this source tree. An
# additional grant of patent rights can be found in the PATENTS file
# in the same directory.

# This program reads all the ar-archives (.a files, in practice) on
# the command line and prints the SHA256 digest (base64-encoded for
# brevity) of all the contents of all the archives, considered in the
# order they're given in the archive files and on the command
# line, respectively.
#
# We do _not_ include archive metadata, like UIDs, modtimes, and so on
# in the digest, so we can use the hash we compute for deterministic
# build identification.  (We do include the file names
# themselves, however.)
#
# Why not "ar D"? Because we don't always use GNU ar.
#

import sys
import hashlib
import logging
from os.path import basename
from argparse import ArgumentParser
import arpy
from base64 import b64encode

log = logging.getLogger(basename(sys.argv[0]))

def main(argv):
  p = ArgumentParser(
    prog=basename(argv[0]),
    description="Hash the contents of archives")
  p.add_argument("--debug", action="store_true",
                 help="Enable debugging output")
  p.add_argument("archives", metavar="ARCHIVES", nargs="*")
  args = p.parse_args(argv[1:])
  root_logger = logging.getLogger()
  logging.basicConfig()
  if args.debug:
    root_logger.setLevel(logging.DEBUG)
  else:
    root_logger.setLevel(logging.INFO)
  hash = hashlib.sha256()
  for archive_filename in args.archives:
    with open(archive_filename, "rb") as archive_file:
      archive = arpy.Archive(fileobj=archive_file)
      log.debug("opened archive %r", archive_filename)
      for arfile in archive:
        hash.update(arfile.header.name)
        nbytes = 0
        filehash = hashlib.sha256()
        while True:
          buf = arfile.read(32768)
          if not buf:
            break
          hash.update(buf)
          filehash.update(buf)
          nbytes += len(buf)
        log.debug("hashed %s/%s %r %s bytes",
                  archive_filename,
                  arfile.header.name.decode("utf-8"),
                  filehash.hexdigest(),
                  nbytes)
  # 128 bits of entropy is enough for anyone
  digest = hash.digest()[:16]
  log.debug("digest %r", digest)
  print(b64encode(digest, b"@_").decode("ascii").rstrip("="))

if __name__ == "__main__":
  sys.exit(main(sys.argv))
