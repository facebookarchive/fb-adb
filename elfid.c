/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in
 *  the LICENSE file in the root directory of this source tree. An
 *  additional grant of patent rights can be found in the PATENTS file
 *  in the same directory.
 *
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "elfid.h"
#include "fs.h"

#define EI_NIDENT 16

// For e_type
#define ET_EXEC 2 // Normal executable
#define ET_DYN 3 // PIE executable

// For e_machine
#define EM_386 3
#define EM_ARM 40
#define EM_X86_64 62
#define EM_AARCH64 183

struct elf_header {
    uint8_t e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
};

struct elf_compatible_ctx {
    int fd;
    unsigned api_level;
    unsigned abi_mask;
};

static const struct {
    uint32_t em;
    uint32_t arch_bit;
} arch_map[] = {
    { EM_386,     FB_ADB_ARCH_X86     },
    { EM_ARM,     FB_ADB_ARCH_ARM     },
    { EM_X86_64,  FB_ADB_ARCH_AMD64   },
    { EM_AARCH64, FB_ADB_ARCH_AARCH64 },
};

void
elf_compatible_p_1(void* data)
{
    struct elf_compatible_ctx* ctx = data;
    struct elf_header hdr;
    if (read_all(ctx->fd, &hdr, sizeof (hdr)) != sizeof (hdr))
        die(EIO, "short ELF file");
    const char elfmag[4] = "\177ELF";
    if (memcmp(elfmag, hdr.e_ident, sizeof (elfmag)) != 0)
        die(EIO, "not an ELF file");

    unsigned api_level = ctx->api_level;

    switch (hdr.e_type) {
        case ET_EXEC:
            if (api_level > 19)
                die(EIO, "newer versions of Android support only "
                    "position-independent executables");
            break;
        case ET_DYN:
            if (api_level < 15)
                die(EIO, "older versions of Android cannot "
                    "execute position-independent executables");
            break;
        default:
            die(EIO, "unexpected ELF type %u", (unsigned) hdr.e_type);
    }

    unsigned arch_bit = 0;
    for (size_t i = 0; arch_bit == 0 && i < ARRAYSIZE(arch_map); ++i)
        if (arch_map[i].em == hdr.e_machine)
            arch_bit = arch_map[i].arch_bit;

    if (arch_bit == 0)
        die(EIO, "ELF file not in recognized architecture");

    if ((arch_bit & ctx->abi_mask) == 0)
        die(EIO, "ELF file has no architectures in common "
            "with target machine");
}

bool
elf_compatible_p(int fd,
                 unsigned api_level,
                 unsigned abi_mask)
{
    struct elf_compatible_ctx ctx = {
        .fd = fd,
        .api_level = api_level,
        .abi_mask = abi_mask,
    };
    return !catch_error(elf_compatible_p_1, &ctx, NULL);
}
