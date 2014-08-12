/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once
/* Some platforms prefix normal symbols with underscores; some don't.
 * Override this default behavior so we can use the same ASM symbol
 * names everywhere.  */

extern char arm_stub[] asm("arm_stub");
extern unsigned arm_stubsz asm("arm_stubsz");
extern char x86_stub[] asm("x86_stub");
extern unsigned x86_stubsz asm("x86_stubsz");
extern char arm_pic_stub[] asm("arm_pic_stub");
extern unsigned arm_pic_stubsz asm("arm_pic_stubsz");
extern char x86_pic_stub[] asm("x86_pic_stub");
extern unsigned x86_pic_stubsz asm("x86_pic_stubsz");
