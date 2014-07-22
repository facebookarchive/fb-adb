// Copyright 2004-present Facebook. All Rights Reserved.
#pragma once
/* Some platforms prefix normal symbols with underscores; some don't.
 * Override this default behavior so we can use the same ASM symbol
 * names everywhere.  */
extern char arm_stub[] asm("arm_stub");
extern unsigned arm_stubsz asm("arm_stubsz");
extern char x86_stub[] asm("x86_stub");
extern unsigned x86_stubsz asm("x86_stubsz");
