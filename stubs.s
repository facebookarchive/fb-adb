# Copyright (c) 2014, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in
# the LICENSE file in the root directory of this source tree. An
# additional grant of patent rights can be found in the PATENTS file
# in the same directory.
        .macro bin_data sym, file
        .global \sym
\sym\():
        .incbin "\file"
\sym\()_end:
        .balign 4
        .global \sym\()sz
\sym\()sz:
        .int \sym\()_end - \sym
.endm

bin_data arm_stub, "stub-arm/fb-adb"
bin_data x86_stub, "stub-x86/fb-adb"
bin_data arm_pic_stub, "stub-arm-pic/fb-adb"
bin_data x86_pic_stub, "stub-x86-pic/fb-adb"
