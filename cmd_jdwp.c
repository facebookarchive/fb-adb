/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in
 *  the LICENSE file in the root directory of this source tree. An
 *  additional grant of patent rights can be found in the PATENTS file
 *  in the same directory.
 */

#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/queue.h>

#include <assert.h>

#include "util.h"
#include "autocmd.h"
#include "fs.h"
#include "child.h"
#include "constants.h"
#include "adb.h"
#include "net.h"
#include "errcodes.h"
#include "tree.h"

#include "peer.h"

#define JDWP_HANDSHAKE "JDWP-Handshake"
#define JDWP_HANDSHAKE_LENGTH (sizeof (JDWP_HANDSHAKE) - 1)

#define JDWP_COMMANDSET_VIRTUALMACHINE 1
#define JDWP_COMMAND_VM_VERSION 1
#define JDWP_COMMAND_VM_CLASSESBYSIGNATURE 2
#define JDWP_COMMAND_VM_ALLCLASSES 3
#define JDWP_COMMAND_VM_ALLTHREADS 4
#define JDWP_COMMAND_VM_IDSIZES 7
#define JDWP_COMMAND_VM_SUSPEND 8
#define JDWP_COMMAND_VM_RESUME 9
#define JDWP_COMMAND_VM_DISPOSEOBJECTS 14
#define JDWP_COMMAND_VM_ALLCLASSES_GENERIC 20

#define JDWP_COMMANDSET_REFERENCETYPE 2
#define JDWP_COMMAND_RT_SIGNATURE 1
#define JDWP_COMMAND_RT_CLASSLOADER 2
#define JDWP_COMMAND_RT_MODIFIERS 3

#define JDWP_COMMANDSET_CLASSTYPE 3
#define JDWP_COMMANDSET_ARRAYTYPE 4
#define JDWP_COMMANDSET_INTERFACETYPE 5
#define JDWP_COMMANDSET_METHOD 6
#define JDWP_COMMANDSET_FIELD 8

#define JDWP_COMMANDSET_OBJECTREFERENCE 9
#define JDWP_COMMAND_OR_DISABLECOLLECTION 7

#define JDWP_COMMANDSET_STRINGREFERENCE 10
#define JDWP_COMMANDSET_THREADREFERENCE 11
#define JDWP_COMMANDSET_THREADGROUPREFERENCE 12
#define JDWP_COMMANDSET_ARRAYREFERENCE 13

#define JDWP_COMMANDSET_CLASSLOADERREFERENCE 14
#define JDWP_COMMAND_CLR_VISIBLECLASSES 1

#define JDWP_COMMANDSET_EVENTREQUEST 15
#define JDWP_COMMANDSET_STACKFRAME 16
#define JDWP_COMMANDSET_CLASSOBJECTREFERENCE 17
#define JDWP_COMMANDSET_EVENT 64

#define JDWP_COMMANDSET_DDM 199
#define JDWP_COMMAND_DDM_CHUNK 1

#define JDWP_FLAG_REPLY 0x80

#define JDWP_ERROR_NOT_IMPLEMENTED 99

#define MAX_JDWP_TYPE_NESTING 6

#define EVENT_SINGLE_STEP 1
#define EVN_SINGLE_STEP "Ev_SingleStep"

#define EVENT_BREAKPOINT 2
#define EVN_BREAKPOINT "Ev_Breakpoint"

#define EVENT_FRAME_POP 3
#define EVN_FRAME_PO "Ev_FramePop"

#define EVENT_EXCEPTION 4
#define EVN_EXCEPTION "Ev_Exception"

#define EVENT_USER_DEFINED 5
#define EVN_USER_DEFINED "Ev_UserDefined"

#define EVENT_THREAD_START 6
#define EVN_THREAD_START "Ev_ThreadStart"

#define EVENT_THREAD_DEATH 7
#define EVN_THREAD_DEATH "Ev_ThreadDeath"

#define EVENT_CLASS_PREPARE 8
#define EVN_CLASS_PREPARE "Ev_ClassPrepare"

#define EVENT_CLASS_UNLOAD 9
#define EVN_CLASS_UNLOAD "Ev_ClassUnload"

#define EVENT_CLASS_LOAD 10
#define EVN_CLASS_LOAD "Ev_ClassLoad"

#define EVENT_FIELD_ACCESS 20
#define EVN_FIELD_ACCESS "Ev_FieldAccess"

#define EVENT_FIELD_MODIFICATION 21
#define EVN_FIELD_MODIFICATION "Ev_FieldModification"

#define EVENT_EXCEPTION_CATCH 30
#define EVN_EXCEPTION_CATCH "Ev_ExceptionCatch"

#define EVENT_METHOD_ENTRY 40
#define EVN_METHOD_ENTRY "Ev_MethodEntry"

#define EVENT_METHOD_EXIT 41
#define EVN_METHOD_EXIT "Ev_MethodExit"

#define EVENT_METHOD_EXIT_WITH_RETURN_VALUE 42
#define EVN_METHOD_EXIT_WITH_RETURN_VALUE "Ev_MethodExitWithReturnValue"

#define EVENT_MONITOR_CONTENDED_ENTER 43
#define EVN_MONITOR_CONTENDED_ENTER "Ev_MonitorContendedEnter"

#define EVENT_MONITOR_CONTENDED_ENTERED 44
#define EVN_MONITOR_CONTENDED_ENTERED "Ev_MonitorContendedEntered"

#define EVENT_MONITOR_WAIT 45
#define EVN_MONITOR_WAIT "Ev_MonitorWait"

#define EVENT_MONITOR_WAITED 46
#define EVN_MONITOR_WAITED "Ev_MonitorWaited"

#define EVENT_VM_START 90
#define EVN_VM_START "Ev_VmStart"

#define EVENT_VM_DEATH 99
#define EVN_VM_DEATH "Ev_VMDeath"

#define COND_COUNT 1
#define CN_COUNT "Cond_Count"

#define COND_CONDITIONAL 2
#define CN_CONDITIONAL "Cond_Conditional"

#define COND_THREADONLY 3
#define CN_THREADONLY "Cond_ThreadOnly"

#define COND_CLASSONLY 4
#define CN_CLASSONLY "Cond_ClassOnly"

#define COND_CLASSMATCH 5
#define CN_CLASSMATCH "Cond_ClassMatch"

#define COND_CLASSEXCLUDE 6
#define CN_CLASSEXCLUDE "Cond_ClassExclude"

#define COND_LOCATIONONLY 7
#define CN_LOCATIONONLY "Cond_LocationOnly"

#define COND_EXCEPTIONONLY 8
#define CN_EXCEPTIONONLY "Cond_ExceptionOnly"

#define COND_FIELDONLY 9
#define CN_FIELDONLY "Cond_FieldOnly"

#define COND_STEP 10
#define CN_STEP "Cond_Step"

#define COND_INSTANCEONLY 11
#define CN_INSTANCEONLY "Cond_InstanceOnly"

#define COND_SOURCENAMEMATCH 12
#define CN_SOURCENAMEMATCH "Cond_SourceNameMatch"

#define REFKIND_CLASS 1
#define REFKIND_INTERFACE 2
#define REFKIND_ARRAY 3

#define STATUS_VERIFIED 1
#define STATUS_PREPARED 2
#define STATUS_INITIALIZED 4
#define STATUS_ERROR 8

#define ACC_INTERFACE 0x0200

#define ART_HARDCODED_PACKET_MAXIMUM 8192
#define REFERENCE_CACHE_SIZE 5000

#define ENUM_JDWP_ERRORS(x)                       \
    x(JDWP_ERR_NONE, 0),                          \
    x(JDWP_ERR_INVALID_THREAD, 10),               \
    x(JDWP_ERR_INVALID_THREAD_GROUP, 11),         \
    x(JDWP_ERR_INVALID_PRIORITY, 12),             \
    x(JDWP_ERR_THREAD_NOT_SUSPENDED, 13),         \
    x(JDWP_ERR_THREAD_SUSPENDED, 14),             \
    x(JDWP_ERR_THREAD_NOT_ALIVE, 15),             \
    x(JDWP_ERR_INVALID_OBJECT, 20),               \
    x(JDWP_ERR_INVALID_CLASS, 21),                \
    x(JDWP_ERR_CLASS_NOT_PREPARED, 22),           \
    x(JDWP_ERR_INVALID_METHODID, 23),             \
    x(JDWP_ERR_INVALID_LOCATION, 24),             \
    x(JDWP_ERR_INVALID_FIELDID, 25),              \
    x(JDWP_ERR_INVALID_FRAMEID, 30),               \
    x(JDWP_ERR_NO_MORE_FRAMES, 31),                \
    x(JDWP_ERR_OPAQUE_FRAME, 32),                  \
    x(JDWP_ERR_NOT_CURRENT_FRAME, 33),             \
    x(JDWP_ERR_TYPE_MISMATCH, 34),                 \
    x(JDWP_ERR_INVALID_SLOT, 35),                  \
    x(JDWP_ERR_DUPLICATE, 40),                     \
    x(JDWP_ERR_NOT_FOUND, 41),                     \
    x(JDWP_ERR_INVALID_MONITOR, 50),               \
    x(JDWP_ERR_NOT_MONITOR_OWNED, 51),             \
    x(JDWP_ERR_INTERRUPT, 52),                     \
    x(JDWP_ERR_INVALID_CLASS_FORMAT, 60),          \
    x(JDWP_ERR_CIRCULAR_CLASS_DEFINITION, 61),     \
    x(JDWP_ERR_FAILS_VERIFICATION, 62),            \
    x(JDWP_ERR_ADD_METHOD_NOT_IMPLEMENTED, 63),    \
    x(JDWP_ERR_SCHEMA_CHANGE_NOT_IMPLEMENTED, 64), \
    x(JDWP_ERR_INVALID_TYPESTATE, 65),             \
    x(JDWP_ERR_HIERARCHY_CHANGE_NOT_IMPLEMENTED, 66),   \
    x(JDWP_ERR_DELETE_METHOD_NOT_IMPLEMENTED, 66),      \
    x(JDWP_ERR_UNSUPPORTED_VERSION, 68),                \
    x(JDWP_ERR_NAMES_DONT_MATCH, 69),                   \
    x(JDWP_ERR_CLASS_MODIFIERS_CHANGE_NOT_IMPLEMENTED, 70),     \
    x(JDWP_ERR_METHOD_MODIFIERS_CHANGE_NOT_IMPLEMENTED, 71),    \
    x(JDWP_ERR_NOT_IMPLEMENTED, 99),                            \
    x(JDWP_ERR_NULL_POINTER, 100),                              \
    x(JDWP_ERR_ABSENT_INFORMATION, 101),                        \
    x(JDWP_ERR_INVALID_EVENT_TYPE, 102),                        \
    x(JDWP_ERR_ILLEGAL_ARGUMENT, 103),                          \
    x(JDWP_ERR_OUT_OF_MEMORY, 110),                             \
    x(JDWP_ERR_ACCESS_DENIED, 111),                             \
    x(JDWP_ERR_VM_READ, 112),                                   \
    x(JDWP_ERR_INTERNAL, 113),                                  \
    x(JDWP_ERR_UNATTACHED_THREAD, 115),                         \
    x(JDWP_ERR_INVALID_TAG, 500),                               \
    x(JDWP_ERR_ALREADY_INVOKING, 502),                          \
    x(JDWP_ERR_INVALID_INDEX, 503),                             \
    x(JDWP_ERR_INVALID_LENGTH, 504),                            \
    x(JDWP_ERR_INVALID_STRING, 506),                            \
    x(JDWP_ERR_INVALID_CLASS_LOADER, 507),                      \
    x(JDWP_ERR_INVALID_ARRAY, 508),                             \
    x(JDWP_ERR_TRANSPORT_LOAD, 509),                            \
    x(JDWP_ERR_TRANSPORT_INIT, 510),                            \
    x(JDWP_ERR_NATIVE_METHOD, 511),                             \
    x(JDWP_ERR_INVALID_COUNT, 512)

#define JDWP_ERR_MAX JDWP_ERR_INVALID_COUNT

enum jdwp_error {
#define X(name, value) name = value
    ENUM_JDWP_ERRORS(X)
#undef X
};

static const struct jdwp_error_names {
    uint16_t value;
    const char* name;
} jdwp_error_names[] = {
#define X(name, value) { value, #name }
    ENUM_JDWP_ERRORS(X)
#undef X
};



struct jdwp_type_table;
struct jdwp_cursor;
struct jdwp_cursor_frame;
struct jdwp_builder;
struct jdwp_builder_frame;
struct jdwp_header;
struct jdwp_type;
struct jdwp_packet;

static unsigned jdwp_scalar_width(struct jdwp_type* this);
static void jdwp_scalar_advance(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame);

typedef unsigned long long llu;

static void
swap_bytes(void* bytes_in, unsigned nr_bytes)
{
    uint8_t* bytes = bytes_in;
    for (unsigned i = 0; i < nr_bytes / 2; ++i) {
        uint8_t tmp = bytes[i];
        bytes[i] = bytes[nr_bytes - i - 1];
        bytes[nr_bytes - i - 1] = tmp;
    }
}

#ifndef __unused
# define __unused __attribute__((unused))
#endif

static int
cmp_u64(uint64_t a, uint64_t b)
{
    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}

static const char*
jdwp_error_to_string(uint16_t errcode)
{
    for (unsigned i = 0; i < ARRAYSIZE(jdwp_error_names); ++i)
        if (jdwp_error_names[i].value == errcode)
            return jdwp_error_names[i].name;
    return NULL;
}

__attribute__((noreturn))
static void
die_jdwp(uint16_t errcode)
{
    SCOPED_RESLIST(rl);
    const char* name = jdwp_error_to_string(errcode);
    if (name == NULL)
        name = xaprintf("unknown JDWP error %hu", errcode);
    die(JDWP_ERR_TO_FBADB_ERR(errcode),
        "JDWP error code %hu from app: %s",
        errcode, name);
}

static int
jdwp_connect(const struct adb_opts* adb,
             const char* to_what)
{
    SCOPED_RESLIST(rl);
    struct strlist* adb_args_list = strlist_new();
    emit_args_adb_opts(adb_args_list, adb);
    const char* const* adb_args = strlist_to_argv(adb_args_list);

    char* host_socket =
        xaprintf("%s/fb-adb-jdwp-%s.sock",
                 system_tempdir(),
                 gen_hex_random(ENOUGH_ENTROPY));
    const char* local = xaprintf("localfilesystem:%s", host_socket);
    const char* remote = xaprintf("jdwp:%s", to_what);
    struct remove_forward_cleanup* crf =
        remove_forward_cleanup_allocate(local, adb_args);
    adb_add_forward(local, remote, adb_args);
    remove_forward_cleanup_commit(crf);
    dbg("added forward %s -> %s", local, remote);

    int scon = xsocket(AF_UNIX, SOCK_STREAM, 0);
    xconnect(scon, make_addr_unix_filesystem(host_socket));
    WITH_CURRENT_RESLIST(rl->parent);
    return xdup(scon);
}

struct write_all_tolerate_epipe_args {
    int fd;
    const void* buf;
    size_t sz;
};

static void
write_all_tolerate_epipe_1(void* arg)
{
    struct write_all_tolerate_epipe_args* args = arg;
    write_all(args->fd, args->buf, args->sz);
}

static bool
write_all_tolerate_epipe(int fd, const void* buf, size_t sz)
{
    struct write_all_tolerate_epipe_args arg = {
        .fd = fd,
        .buf = buf,
        .sz = sz
    };
    struct errinfo ei = { .want_msg = true };
    if (catch_error(write_all_tolerate_epipe_1, &arg, &ei)) {
        if (ei.err == EPIPE)
            return false;
        die_rethrow(&ei);
    }
    return true;
}

__attribute__((noreturn))
static void
die_early_connection_problem(void)
{
    die(ECOMM,
        "Could not connect to application. "
        "Is app alive? Are you holding the debugger wrong?");
}

static void
do_jdwp_handshake_as_client(int to_app)
{
    if (!write_all_tolerate_epipe(
            to_app,
            JDWP_HANDSHAKE,
            JDWP_HANDSHAKE_LENGTH))
    {
        die_early_connection_problem();
    }

    char reply_buf[JDWP_HANDSHAKE_LENGTH];
    size_t n = read_all(to_app, reply_buf, JDWP_HANDSHAKE_LENGTH);
    if (n < JDWP_HANDSHAKE_LENGTH)
        die_early_connection_problem();
    if (!memcpy(reply_buf, JDWP_HANDSHAKE, JDWP_HANDSHAKE_LENGTH))
        die(ECOMM, "illegal JDWP handshake");
}

static void
do_jdwp_handshake_as_server(int to_debugger)
{
    char buf[JDWP_HANDSHAKE_LENGTH];
    size_t n = read_all(to_debugger, buf, JDWP_HANDSHAKE_LENGTH);
    if (n < JDWP_HANDSHAKE_LENGTH)
        die(ECOMM, "debugger disconnected prematurely");
    if (!memcpy(buf, JDWP_HANDSHAKE, JDWP_HANDSHAKE_LENGTH))
        die(ECOMM, "debugger sent bad handshake");
    write_all(to_debugger, buf, JDWP_HANDSHAKE_LENGTH);
}

struct jdwp_header {
    uint32_t length;
    uint32_t id;
    uint8_t flags;
    union {
        struct {
            uint8_t group;
            uint8_t code;
        } command;
        struct {
            uint16_t error_code;
        } reply;
    };
    uint8_t data[0];
} __attribute__((packed));

_Static_assert(sizeof (struct jdwp_header) == 11, "alignment");

static bool
jdwp_command_p(struct jdwp_header* jh)
{
    return (jh->flags & JDWP_FLAG_REPLY) == 0;
}

static void
jdwp_header_to_host(struct jdwp_header* jh)
{
    jh->length = ntohl(jh->length);
    jh->id = ntohl(jh->id);
    if (!jdwp_command_p(jh))
        jh->reply.error_code = ntohs(jh->reply.error_code);
}

static void
jdwp_header_to_network(struct jdwp_header* jh)
{
    jh->length = htonl(jh->length);
    jh->id = htonl(jh->id);
    if (!jdwp_command_p(jh))
        jh->reply.error_code = htons(jh->reply.error_code);
}

struct jdwp_packet {
    struct reslist* rl; // Owns itself
    LIST_ENTRY(jdwp_packet) link;
    bool on_list;
    bool has_rewritten_id;
    uint32_t original_id;
    struct jdwp_header header;
     // struct hack at end of jdwp_header; do not add data here
};

static void
jdwp_send_packet(int fd, const struct jdwp_header* jh)
{
    assert(sizeof (*jh) <= jh->length);
    struct jdwp_header out_jh = *jh;
    jdwp_header_to_network(&out_jh);
    struct iovec chunks[] = {
        { &out_jh, sizeof (out_jh) },
        { (void*) &jh->data, jh->length - sizeof (*jh) },
    };

    write_all_v(fd, &chunks[0], ARRAYSIZE(chunks));
}

static char*
describe_jdwp_message(struct jdwp_header* jh)
{
    return !jdwp_command_p(jh)
        ? xaprintf("[JDWP reply length:%u id:%u flags:%hhu err:%hu]",
                   jh->length,
                   jh->id,
                   jh->flags,
                   jh->reply.error_code)
        : xaprintf(
            "[JDWP command length:%u id:%u flags:%hhu cmdset:%hhu cmd:%hhu]",
            jh->length,
            jh->id,
            jh->flags,
            jh->command.group,
            jh->command.code);
}

struct jdwp_type;
struct jdwp_command;

struct jdwp_type_table {
    struct reslist* rl;
    struct jdwp_type* types;
    struct jdwp_command* commands;

    struct {
        struct jdwp_type* boolean;
        struct jdwp_type* byte;
        struct jdwp_type* char_;
        struct jdwp_type* double_;
        struct jdwp_type* float_;
        struct jdwp_type* int_;
        struct jdwp_type* long_;
        struct jdwp_type* short_;
        struct jdwp_type* string;
        struct jdwp_type* void_;

        struct jdwp_type* object_id;

        struct jdwp_type* array_id;
        struct jdwp_type* class_loader_id;
        struct jdwp_type* class_object_id;
        struct jdwp_type* string_id;
        struct jdwp_type* thread_group_id;
        struct jdwp_type* thread_id;

        struct jdwp_type* reference_type_id;

        struct jdwp_type* class_id;
        struct jdwp_type* interface_id;
        struct jdwp_type* array_type_id;

        struct jdwp_type* field_id;
        struct jdwp_type* method_id;
        struct jdwp_type* frame_id;

        struct jdwp_type* value;
        struct jdwp_type* arrayregion;
    } type;

};

enum jdwp_type_kind {
    JDWP_TYPE_STRUCT,
    JDWP_TYPE_ARRAY,
    JDWP_TYPE_OTHER,
};

struct jdwp_type {
    struct jdwp_type* next;
    struct jdwp_type_table* tt;
    enum jdwp_type_kind kind;
    char* name;
    struct jdwp_type* supertype;
    unsigned depth;
    void (*init_frame)(
        struct jdwp_type* this,
        struct jdwp_cursor* c,
        struct jdwp_cursor_frame* frame);
    size_t (*read)(
        struct jdwp_type* this,
        struct jdwp_cursor* c,
        struct jdwp_cursor_frame* frame,
        void* value,
        size_t size);
    void (*write)(
        struct jdwp_type* this,
        struct jdwp_cursor* c,
        struct jdwp_cursor_frame* frame,
        const void* value,
        size_t size);
    struct jdwp_type* (*next_type)(
        struct jdwp_type* this,
        struct jdwp_cursor* c,
        struct jdwp_cursor_frame* frame);
    void (*advance)(
        struct jdwp_type* this,
        struct jdwp_cursor* c,
        struct jdwp_cursor_frame* frame);
    union {
        struct {
            unsigned width;
        } scalar;

        struct {
            unsigned nr_fields;
            const char** field_names;
            struct jdwp_type** field_types;
        } struct_;

        struct { // Assume all arrays start with integer count
            struct jdwp_type* element_type;
        } array;
    };
};

static void
noop_init_frame(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{}

static void
jdwp_type_set_supertype(
    struct jdwp_type* type,
    struct jdwp_type* supertype)
{
    if (supertype == NULL) {
        type->supertype = NULL;
    } else {
        for (struct jdwp_type* p = supertype; p != NULL; p = p->supertype)
            assert(p != type);
        type->supertype = supertype;
    }
}

static bool
jdwp_type_isinstance(
    struct jdwp_type* type,
    struct jdwp_type* supertype)
{
    while (type != NULL) {
        if (type == supertype)
            return true;
        type = type->supertype;
    }
    return false;
}

struct jdwp_cursor_frame {
    struct jdwp_type* type;
    union {
        struct {
            uint32_t length;
        } string;
        struct {
            unsigned index;
        } struct_;
        struct {
            uint32_t index;
            uint32_t count;
            struct jdwp_type* element_type;
        } array;
    };
};

struct jdwp_cursor {
    uint8_t* pos;
    uint8_t* end;
    int depth;
    struct jdwp_cursor_frame stack[MAX_JDWP_TYPE_NESTING];
};

static struct jdwp_cursor
jdwp_cursor_create(
    struct jdwp_type* type,
    void* data,
    size_t length)
{
    struct jdwp_cursor c;
    memset(&c, 0, sizeof (c));
    c.pos = data;
    c.end = c.pos + length;
    c.stack[0].type = type;
    type->init_frame(type, &c, &c.stack[0]);
    return c;
}

static bool
jdwp_cursor_has_value(struct jdwp_cursor* c)
{
    return c->depth >= 0 && c->stack[c->depth].type != NULL;
}

static void
jdwp_cursor_memcpy_out(void* out, struct jdwp_cursor* c, size_t length)
{
    if (c->end - c->pos < length)
        die(EINVAL, "truncated packet");
    memcpy(out, c->pos, length);
}

static void
jdwp_cursor_memcpy_out_byteswapped(
    void* out,
    struct jdwp_cursor* c,
    size_t length)
{
    uint8_t* bytes = out;
    jdwp_cursor_memcpy_out(bytes, c, length);
    swap_bytes(bytes, length);
}

static void
jdwp_cursor_slurp(
    void* out,
    struct jdwp_cursor* c,
    size_t length)
{
    jdwp_cursor_memcpy_out_byteswapped(out, c, length);
    c->pos += length;
}

static void
jdwp_cursor_memcpy_in(struct jdwp_cursor* c, const void* in, size_t length)
{
    if (c->end - c->pos < length)
        die(EINVAL, "truncated packet");
    memcpy(c->pos, in, length);
}

static struct jdwp_type*
jdwp_cursor_current_type(struct jdwp_cursor* c)
{
    if (!jdwp_cursor_has_value(c))
        die(EINVAL, "no current value");
    return c->stack[c->depth].type;
}

static void
jdwp_cursor_check_type(
    struct jdwp_cursor* c,
    struct jdwp_type* type)
{
    struct jdwp_type* current_type = jdwp_cursor_current_type(c);
    if (current_type != type) {
        die(EINVAL,
            "expected type `%s', but found `%s'",
            type->name,
            current_type->name);
    }
}

static void
jdwp_cursor_check_struct_field(
    struct jdwp_cursor* c,
    struct jdwp_type* type,
    const char* name)
{
    jdwp_cursor_check_type(c, type); // XXX
}

static void
jdwp_cursor_next(struct jdwp_cursor* c)
{
    if (c->depth < 0)
        return;

    struct jdwp_cursor_frame* current_frame = &c->stack[c->depth];
    struct jdwp_type* current_type = current_frame->type;
    if (current_type == NULL)
        return;

    current_type->advance(current_type, c, current_frame);
    memset(current_frame, 0, sizeof (*current_frame));

    if (c->depth > 0) {
        struct jdwp_cursor_frame* parent_frame = &c->stack[c->depth - 1];
        struct jdwp_type* parent_type = parent_frame->type;
        current_type = parent_type->next_type(parent_type, c, parent_frame);
        current_frame->type = current_type;
        if (current_type != NULL)
            current_type->init_frame(current_type, c, current_frame);
    }
}

static struct jdwp_type* jdwp_array_next_type(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame);

static uint32_t
jdwp_cursor_array_length(struct jdwp_cursor*c)
{
    if (!jdwp_cursor_has_value(c))
        die(EINVAL, "no current value");
    struct jdwp_cursor_frame* frame = &c->stack[c->depth];
    struct jdwp_type* type = frame->type;
    if (type->next_type != jdwp_array_next_type)
        die(EINVAL, "not looking at JDWP array");
    return frame->array.count;
}

static bool
jdwp_cursor_can_enter(struct jdwp_cursor* c)
{
    if (!jdwp_cursor_has_value(c))
        die(EINVAL, "no current value");
    struct jdwp_cursor_frame* frame = &c->stack[c->depth];
    struct jdwp_type* type = frame->type;
    return type->next_type != NULL;
}

static void
jdwp_cursor_enter(struct jdwp_cursor* c)
{
    if (!jdwp_cursor_has_value(c))
        die(EINVAL, "no current value");
    struct jdwp_cursor_frame* parent_frame = &c->stack[c->depth];
    struct jdwp_type* parent_type = parent_frame->type;
    if (parent_type == NULL)
        die(EINVAL, "no current value");
    if (parent_type->next_type == NULL)
        die(EINVAL, "cannot enter type `%s'", parent_type->name);

    struct jdwp_cursor_frame* current_frame = &c->stack[c->depth + 1];
    memset(current_frame, 0, sizeof (*current_frame));
    struct jdwp_type* current_type =
        parent_type->next_type(parent_type, c, parent_frame);
    current_frame->type = current_type;
    if (current_type != NULL)
        current_type->init_frame(current_type, c, current_frame);
    assert(c->depth < MAX_JDWP_TYPE_NESTING);
    c->depth += 1;
}

static bool
jdwp_cursor_has_parent(struct jdwp_cursor* c)
{
    return c->depth > 0;
}

static void
jdwp_cursor_leave(struct jdwp_cursor* c)
{
    if (!jdwp_cursor_has_parent(c))
        die(EINVAL, "return attempted with no parent");
    if (jdwp_cursor_has_value(c))
        die(EINVAL, "premature return attempt");
    c->depth -= 1;
    struct jdwp_cursor_frame* current_frame = &c->stack[c->depth];
    memset(current_frame, 0, sizeof (*current_frame));
    if (c->depth > 0) {
        struct jdwp_cursor_frame* parent_frame = &c->stack[c->depth - 1];
        struct jdwp_type* parent_type = parent_frame->type;
        struct jdwp_type* current_type =
            parent_type->next_type(parent_type, c, parent_frame);
        if (current_type != NULL) {
            current_frame->type = current_type;
            current_type->init_frame(current_type, c, current_frame);
        }
    }
}

static size_t
jdwp_cursor_read(struct jdwp_cursor* c, void* value, size_t size)
{
    struct jdwp_type* current = jdwp_cursor_current_type(c);
    if (current->read == NULL)
        die(EINVAL, "cannot read from type %s", current->name);
    return current->read(current, c, &c->stack[c->depth], value, size);
}

static uint64_t
jdwp_cursor_read_id(struct jdwp_cursor* c, struct jdwp_type* id_type)
{
    uint64_t id = 0;
    jdwp_cursor_read(c, &id, jdwp_scalar_width(id_type));
    return id;
}

static uint8_t
jdwp_cursor_read_u8(struct jdwp_cursor* c)
{
    uint8_t value;
    jdwp_cursor_read(c, &value, sizeof (value));
    return value;
}

static int32_t
jdwp_cursor_read_i32(struct jdwp_cursor* c)
{
    int32_t value;
    jdwp_cursor_read(c, &value, sizeof (value));
    return value;
}

static void jdwp_string_init_frame(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame);

static char*
jdwp_cursor_read_string(struct jdwp_cursor* c)
{
    struct jdwp_type* current = jdwp_cursor_current_type(c);
    if (current->init_frame != jdwp_string_init_frame)
        die(EINVAL, "not a string value; value is `%s'",
            current->name);
    uint32_t nbytes = c->stack[c->depth].string.length;
    char* value = xalloc(nbytes + 1); // overflow check on stack init
    jdwp_cursor_memcpy_out(value, c, nbytes);
    value[nbytes] = '\0';
    return value;
}

static void
jdwp_cursor_write(struct jdwp_cursor* c, void* value, size_t size)
{
    struct jdwp_type* current = jdwp_cursor_current_type(c);
    if (current->write == NULL)
        die(EINVAL, "cannot update value of type %s", current->name);
    current->write(current, c, &c->stack[c->depth], value, size);
}

static uint64_t
jdwp_cursor_write_id(struct jdwp_cursor* c, uint64_t id, struct jdwp_type* id_type)
{
    jdwp_cursor_write(c, &id, jdwp_scalar_width(id_type));
    return id;
}

static struct jdwp_type*
jdwp_try_find_type(
    struct jdwp_type_table* tt,
    const char* name)
{
    for (struct jdwp_type* type = tt->types;
         type != NULL;
         type = type->next)
    {
        if (!strcmp(type->name, name))
            return type;
    }

    return NULL;
}

static struct jdwp_type*
jdwp_find_type(
    struct jdwp_type_table* tt,
    const char* name)
{
    struct jdwp_type* type = jdwp_try_find_type(tt, name);
    if (type == NULL)
        die(EINVAL, "no type called `%s' defined", name);
    return type;
}

static void
generic_advance(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    assert(this->next_type);
    jdwp_cursor_enter(c);
    while (jdwp_cursor_has_value(c))
        jdwp_cursor_next(c);
    jdwp_cursor_leave(c);
}

static void
jdwp_commit_new_type(
    struct jdwp_type_table* tt,
    struct jdwp_type* new_type)
{
    assert(new_type->name != NULL);
    assert(new_type->next == NULL);
    assert(new_type->tt == NULL);

    if (new_type->init_frame == NULL)
        new_type->init_frame = noop_init_frame;
    if (new_type->advance == NULL && new_type->next_type != NULL)
        new_type->advance = generic_advance;
    assert(new_type->init_frame);
    assert(new_type->advance);
    if (new_type->next_type != NULL)
        assert(new_type->depth > 0);
    assert(new_type->depth < MAX_JDWP_TYPE_NESTING);
    new_type->next = tt->types;
    new_type->tt = tt;
    tt->types = new_type;
}

struct jdwp_field_descriptor {
    struct jdwp_type* type;
    const char* name;
};

struct jdwp_type*
jdwp_struct_next_type(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    uint32_t index = frame->struct_.index;
    if (index == this->struct_.nr_fields)
        return NULL;
    return this->struct_.field_types[frame->struct_.index++];
}

static struct jdwp_type*
jdwp_define_struct(
    struct jdwp_type_table* tt,
    const char* name,
    const struct jdwp_field_descriptor* fields)
{
    struct jdwp_type* type = jdwp_try_find_type(tt, name);
    if (type != NULL) {
        die(EINVAL, "type `%s' already defined", name);
    }

    SCOPED_RESLIST(rl);
    type = xcalloc(sizeof (*type));
    type->name = xstrdup(name);

    int max_field_depth = 0;

    unsigned nr_fields = 0;
    for (const struct jdwp_field_descriptor* cur_field = fields;
         cur_field->name != NULL;
         ++cur_field)
    {
        assert(fields[nr_fields].type != NULL);
        ++nr_fields;
    }

    assert(fields[nr_fields].name == NULL);
    assert(fields[nr_fields].type == NULL);

    const char** field_names;
    struct jdwp_type** field_types;

    field_names = xcalloc(nr_fields * sizeof (field_names[0]));
    field_types = xcalloc(nr_fields * sizeof (field_types[0]));

    for (unsigned i = 0; i < nr_fields; ++i) {
        field_names[i] = xstrdup(fields[i].name);
        int field_depth = fields[i].type->depth;
        if (field_depth > max_field_depth)
            max_field_depth = field_depth;
        field_types[i] = fields[i].type;
    }

    type->next_type = jdwp_struct_next_type;
    type->struct_.nr_fields = nr_fields;
    type->struct_.field_names = field_names;
    type->struct_.field_types = field_types;
    type->depth = max_field_depth + 1;
    jdwp_commit_new_type(tt, type);
    reslist_xfer(tt->rl, rl);
    return type;
}

static void
jdwp_array_init_frame(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    jdwp_cursor_slurp(&frame->array.count, c, 4);
    if (frame->array.count > INT32_MAX)
        die(EINVAL, "array too big");
    frame->array.element_type = this->array.element_type;
}

static struct jdwp_type*
jdwp_array_next_type(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    if (frame->array.index == frame->array.count)
        return NULL;
    frame->array.index++;
    return frame->array.element_type;
}

static struct jdwp_type*
jdwp_array_of(
    struct jdwp_type_table* tt,
    struct jdwp_type* element_type)
{
    SCOPED_RESLIST(rl);
    char* name = xaprintf("[%s", element_type->name);
    struct jdwp_type* type = jdwp_try_find_type(tt, name);
    if (type != NULL) {
        return type;
    }

    type = xcalloc(sizeof (*type));
    type->name = name;
    type->init_frame = jdwp_array_init_frame;
    type->next_type = jdwp_array_next_type;
    type->array.element_type = element_type;
    type->depth = element_type->depth + 1;
    jdwp_commit_new_type(tt, type);
    reslist_xfer(tt->rl, rl);
    return type;
}

static struct jdwp_type*
jdwp_define_special_type(
    struct jdwp_type_table* tt,
    struct jdwp_type template)
{
    struct jdwp_type* type = jdwp_try_find_type(tt, template.name);
    if (type != NULL) {
        die(EINVAL, "type `%s' already defined", template.name);
    }

    SCOPED_RESLIST(rl);
    type = xcalloc(sizeof (*type));
    *type = template;
    type->name = xstrdup(template.name);
    jdwp_commit_new_type(tt, type);
    reslist_xfer(tt->rl, rl);
    return type;
}

struct jdwp_command {
    struct jdwp_command* next;
    uint8_t command_group;
    uint8_t command_code;
    struct jdwp_type* type;
    struct jdwp_type* reply_type;
};

static struct jdwp_command*
jdwp_define_command(
    struct jdwp_type_table* tt,
    const char* name,
    uint8_t command_group,
    uint8_t command_code,
    const struct jdwp_field_descriptor* fields,
    const struct jdwp_field_descriptor* reply_fields)
{
    SCOPED_RESLIST(rl);
    struct jdwp_command* command = xcalloc(sizeof (*command));
    command->command_group = command_group;
    command->command_code = command_code;
    command->type = jdwp_define_struct(tt, name, fields);
    if (reply_fields != NULL) {
        // NULL means no reply expected, e.g., notifications
        command->reply_type =
            jdwp_define_struct(tt, xaprintf("%s_Reply", name),
                               reply_fields);
    }
    command->next = tt->commands;
    tt->commands = command;
    reslist_xfer(tt->rl, rl);
    return command;
}

static unsigned
jdwp_scalar_width(struct jdwp_type* this)
{
    if (this->advance != jdwp_scalar_advance)
        die(EINVAL, "type `%s' is not a scalar", this->name);
    int width = this->scalar.width;
    while (width < 0 && this->supertype != NULL) {
        this = this->supertype;
        width = this->scalar.width;
    }
    if (width < 0)
        die(EINVAL, "no width available for type `%s'", this->name);
    assert(width <= 8);
    return (unsigned) width;
}

static size_t
jdwp_scalar_read(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame,
    void* value,
    size_t size)
{
    unsigned width = jdwp_scalar_width(this);
    uint8_t bytes[8];
    jdwp_cursor_memcpy_out(bytes, c, width);
    swap_bytes(bytes, width);
    if (size > width)
        size = width;
    memcpy(value, bytes, size);
    return width;
}

static void
jdwp_scalar_write(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame,
    const void* value,
    size_t size)
{
    unsigned width = jdwp_scalar_width(this);
    if (size > width) {
        die(EINVAL,
            "writing too many bytes: type `%s' width is %u",
            this->name,
            width);
    }
    uint8_t bytes[8];
    memset(bytes, 0, sizeof (bytes));
    memcpy(bytes, value, size);
    swap_bytes(bytes, width);
    jdwp_cursor_memcpy_in(c, bytes, width);
}

static void
jdwp_scalar_advance(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    c->pos += jdwp_scalar_width(this);
}

static void
jdwp_string_init_frame(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    jdwp_cursor_slurp(&frame->string.length, c, 4);
    if (frame->string.length == UINT32_MAX)
        die(EINVAL, "illegal string length");
}

static struct jdwp_type*
jdwp_tag_to_type(
    struct jdwp_type_table* tt,
    uint8_t tag)
{
    switch (tag) {
        case '[':
            return tt->type.array_id;
        case 'B':
            return tt->type.byte;
        case 'C':
            return tt->type.char_;
        case 'L':
            return tt->type.object_id;
        case 'F':
            return tt->type.float_;
        case 'D':
            return tt->type.double_;
        case 'I':
            return tt->type.int_;
        case 'J':
            return tt->type.long_;
        case 'S':
            return tt->type.short_;
        case 'V':
            return tt->type.void_;
        case 'Z':
            return tt->type.boolean;
        case 's':
            return tt->type.string_id;
        case 't':
            return tt->type.thread_id;
        case 'g':
            return tt->type.thread_group_id;
        case 'l':
            return tt->type.class_loader_id;
        case 'c':
            return tt->type.class_object_id;
        default:
            die(EINVAL, "unexpected value tag %d", (int) tag);
    }
}

static void
jdwp_value_init_frame(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    uint8_t tag;
    jdwp_cursor_slurp(&tag, c, 1);
    frame->type = jdwp_tag_to_type(this->tt, tag);
    frame->type->init_frame(frame->type, c, frame);
}

static size_t
jdwp_string_read(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame,
    void* value,
    size_t size)
{
    size_t payload_bytes = frame->string.length;
    char* buf = value;
    jdwp_cursor_memcpy_out(buf, c, XMIN(payload_bytes, size));
    size -= XMIN(payload_bytes, size);
    if (size > 0)
        buf[0] = '\0';
    return payload_bytes + 1;
}

static void
jdwp_string_advance(
        struct jdwp_type* this,
        struct jdwp_cursor* c,
        struct jdwp_cursor_frame* frame)
{
    c->pos += frame->string.length;
}

static void
jdwp_arrayregion_init_frame(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    struct jdwp_type_table* tt = this->tt;
    uint8_t tag;
    jdwp_cursor_slurp(&tag, c, 1);
    switch (tag) {
        case '[':
        case 'L':
        case 's':
        case 't':
        case 'g':
        case 'l':
        case 'c':
            frame->array.element_type = tt->type.value;
        default:
            frame->array.element_type = jdwp_tag_to_type(tt, tag);
    }
    jdwp_cursor_slurp(&frame->array.count, c, 4);
    if (frame->array.count > INT32_MAX)
        die(EINVAL, "bogus arrayregion length");
}

static void
assert_not_advanced(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    abort(); // Should be transmuted to new type before being advanced
}


static struct jdwp_type_table*
jdwp_type_table_new()
{
    struct reslist* tt_rl = reslist_create();
    WITH_CURRENT_RESLIST(tt_rl);
    struct jdwp_type_table* tt = xcalloc(sizeof (*tt));
    tt->rl = tt_rl;

#define SCALAR_DEFAULT                                  \
    .scalar.width = -1,                                 \
        .read = jdwp_scalar_read,                       \
        .write = jdwp_scalar_write,                     \
        .advance = jdwp_scalar_advance

    struct {
        struct jdwp_type** slot;
        struct jdwp_type** supertype_slot;
        struct jdwp_type type;
    } special_types[] = {
        {
            &tt->type.boolean, NULL,
            {
                SCALAR_DEFAULT,
                .name = "boolean",
                .scalar.width = 1,
            }
        },
        {
            &tt->type.byte, NULL,
            {
                SCALAR_DEFAULT,
                .name = "byte",
                .scalar.width = 1,
            }
        },
        {
            &tt->type.char_, NULL,
            {
                SCALAR_DEFAULT,
                .name = "char",
                .scalar.width = 2,
            }
        },
        {
            &tt->type.double_, NULL,
            {
                SCALAR_DEFAULT,
                .name = "double",
                .scalar.width = 4,
            }
        },
        {
            &tt->type.float_, NULL,
            {
                SCALAR_DEFAULT,
                .name = "float",
                .scalar.width = 4,
            }
        },
        {
            &tt->type.int_, NULL,
            {
                SCALAR_DEFAULT,
                .name = "int",
                .scalar.width = 4,
            }
        },
        {
            &tt->type.long_, NULL,
            {
                SCALAR_DEFAULT,
                .name = "long",
                .scalar.width = 8,
            }
        },
        {
            &tt->type.short_, NULL,
            {
                SCALAR_DEFAULT,
                .name = "short",
                .scalar.width = 2,
            }
        },
        {
            &tt->type.string, NULL,
            {
                .name = "string",
                .init_frame = jdwp_string_init_frame,
                .read = jdwp_string_read,
                .advance = jdwp_string_advance,
            }
        },
        {
            &tt->type.void_, NULL,
            {
                SCALAR_DEFAULT,
                .name = "void",
                .scalar.width = 0,
            }
        },
        {
            &tt->type.object_id, NULL,
            {
                SCALAR_DEFAULT,
                .name = "objectID",
            }
        },
        {
            &tt->type.array_id, &tt->type.object_id,
            {
                SCALAR_DEFAULT,
                .name = "arrayID",
            }
        },
        {
            &tt->type.class_loader_id, &tt->type.object_id,
            {
                SCALAR_DEFAULT,
                .name = "classLoaderID",
            }
        },
        {
            &tt->type.class_object_id, &tt->type.object_id,
            {
                SCALAR_DEFAULT,
                .name = "classObjectID",
            }
        },
        {
            &tt->type.string_id, &tt->type.object_id,
            {
                SCALAR_DEFAULT,
                .name = "stringID",
            }
        },
        {
            &tt->type.thread_group_id, &tt->type.object_id,
            {
                SCALAR_DEFAULT,
                .name = "threadGroupID",
            }
        },
        {
            &tt->type.thread_id, &tt->type.object_id,
            {
                SCALAR_DEFAULT,
                .name = "threadID",
            }
        },
        {
            &tt->type.reference_type_id, NULL,
            {
                SCALAR_DEFAULT,
                .name = "referenceTypeID",
            }
        },
        {
            &tt->type.class_id, &tt->type.reference_type_id,
            {
                SCALAR_DEFAULT,
                .name = "classID",
            }
        },
        {
            &tt->type.interface_id, &tt->type.reference_type_id,
            {
                SCALAR_DEFAULT,
                .name = "interfaceID",
            }
        },
        {
            &tt->type.array_type_id, &tt->type.reference_type_id,
            {
                SCALAR_DEFAULT,
                .name = "arrayTypeID",
            }
        },
        {
            &tt->type.field_id, NULL,
            {
                SCALAR_DEFAULT,
                .name = "fieldID",
            }
        },
        {
            &tt->type.method_id, NULL,
            {
                SCALAR_DEFAULT,
                .name = "methodID",
            }
        },
        {
            &tt->type.frame_id, NULL,
            {
                SCALAR_DEFAULT,
                .name = "frameID",
            }
        },
        {
            &tt->type.value, NULL,
            {
                .name = "value",
                .init_frame = jdwp_value_init_frame,
                .advance = assert_not_advanced,
                .depth = 1,
            }
        },
        {
            &tt->type.arrayregion, NULL,
            {
                .name = "arrayregion",
                .init_frame = jdwp_arrayregion_init_frame,
                .next_type = jdwp_array_next_type,
                .depth = 1,
            }
        },
    };

    for (size_t i = 0; i < ARRAYSIZE(special_types); ++i) {
        struct jdwp_type* type = xcalloc(sizeof (*type));
        struct jdwp_type** slot = special_types[i].slot;
        *type = special_types[i].type;
        jdwp_commit_new_type(tt, type);
        if (slot != NULL) {
            assert(*slot == NULL);
            *slot = type;
        }
        struct jdwp_type** supertype_slot = special_types[i].supertype_slot;
        if (supertype_slot != NULL) {
            assert(*supertype_slot);
            jdwp_type_set_supertype(type, *supertype_slot);
        }
    }

    assert(tt->type.boolean);
    assert(tt->type.byte);
    assert(tt->type.char_);
    assert(tt->type.double_);
    assert(tt->type.float_);
    assert(tt->type.int_);
    assert(tt->type.long_);
    assert(tt->type.short_);
    assert(tt->type.string);
    assert(tt->type.void_);
    assert(tt->type.object_id);
    assert(tt->type.array_id);
    assert(tt->type.class_loader_id);
    assert(tt->type.class_object_id);
    assert(tt->type.string_id);
    assert(tt->type.thread_group_id);
    assert(tt->type.thread_id);
    assert(tt->type.reference_type_id);
    assert(tt->type.class_id);
    assert(tt->type.interface_id);
    assert(tt->type.array_type_id);
    assert(tt->type.value);

    return tt;
}

static struct jdwp_command*
jdwp_find_command(struct jdwp_type_table* tt,
                  uint8_t command_group,
                  uint8_t command_code)
{
    for (struct jdwp_command* command = tt->commands;
         command != NULL;
         command = command->next)
    {
        if (command->command_group == command_group &&
            command->command_code == command_code)
        {
            return command;
        }
    }

    return NULL;
}

static struct jdwp_type*
jdwp_find_reply_type(struct jdwp_type_table* tt,
                     struct jdwp_header* header)
{
    assert(jdwp_command_p(header));
    return jdwp_find_command(
        tt,
        header->command.group,
        header->command.code)
        ->reply_type;
}

struct fake_reftype;
struct real_reftype;

struct jdwp_classloader {
    uint64_t id;
    SLIST_ENTRY(jdwp_classloader) link;
    SPLAY_HEAD(fake_reftype_by_signature,
               fake_reftype) fake_reftypes_by_signature;

};

enum jdwp_mode {
    JDWP_MODE_DUMB,
    JDWP_MODE_REWRITE,
};

struct jdwp_proxy {
    struct reslist* rl;
    struct jdwp_type_table* tt;
    LIST_HEAD(, jdwp_packet) pending_packets;
    LIST_HEAD(, jdwp_packet) deferred_from_app;
    SLIST_HEAD(, jdwp_classloader) classloaders;
    SPLAY_HEAD(fake_reftype_by_id, fake_reftype) fake_reftypes_by_id;
    SPLAY_HEAD(real_reftype_by_id, real_reftype) real_reftype_cache;
    uint32_t real_reftype_cache_size;
    uint32_t real_reftype_cache_max;
    int to_app_fd;
    int to_debugger_fd;
    int nr_tx;
    uint32_t seqnum;
    uint64_t next_fake_reftype_id;
    uint32_t app_packet_size_limit;
    uint32_t nr_classloaders;
    uint32_t nr_fake_ids;
    enum jdwp_mode mode;
    bool quiet;
};

__attribute__((format(printf, 2, 3)))
static void
log_warn(struct jdwp_proxy* proxy, const char* fmt, ...)
{
    SCOPED_RESLIST(rl);
    va_list args;
    va_start(args, fmt);
    xprintf(xstderr, "%s: WARNING: %s\n", prgname, xavprintf(fmt, args));
    va_end(args);
}

__attribute__((format(printf, 2, 3)))
static void
log_info(struct jdwp_proxy* proxy, const char* fmt, ...)
{
    if (!proxy->quiet) {
        SCOPED_RESLIST(rl);
        va_list args;
        va_start(args, fmt);
        xprintf(xstderr, "%s: %s\n", prgname, xavprintf(fmt, args));
        va_end(args);
    }
}

static void
send_generic_reply(struct jdwp_proxy* proxy,
                   uint16_t id,
                   int fd,
                   uint16_t error_code)
{
    struct jdwp_header reply = {
        .length = sizeof (reply),
        .id = id,
        .flags = JDWP_FLAG_REPLY,
        .reply.error_code = error_code,
    };
    jdwp_send_packet(fd, &reply);
}

static void
mark_packet_pending(struct jdwp_proxy* proxy,
                    struct jdwp_packet* packet)
{
    assert(!packet->on_list);
    LIST_INSERT_HEAD(&proxy->pending_packets, packet, link);
    packet->on_list = true;
    WITH_CURRENT_RESLIST(proxy->rl);
    reslist_reparent(packet->rl);
}

static struct jdwp_packet*
peek_pending_packet(struct jdwp_proxy* proxy, uint32_t id)
{
    struct jdwp_packet* packet;
    LIST_FOREACH(packet, &proxy->pending_packets, link) {
        if (packet->header.id == id) {
            assert(packet->on_list);
            return packet;
        }
    }
    return NULL;
}

static struct jdwp_packet*
pop_pending_packet(struct jdwp_proxy* proxy, uint32_t id)
{
    struct jdwp_packet* packet = peek_pending_packet(proxy, id);
    if (packet != NULL) {
        assert(packet->on_list);
        LIST_REMOVE(packet, link);
        packet->on_list = false;
        reslist_reparent(packet->rl);
    }

    return packet;
}

struct jdwp_builder {
    struct jdwp_header header;
    struct growable_buffer gb;
    uint32_t length;
    struct jdwp_proxy* proxy;
};

static void
jdwp_builder_start(struct jdwp_builder* b, struct jdwp_proxy* proxy)
{
    memset(b, 0, sizeof (*b));
    b->proxy = proxy;
}

static void
jdwp_builder_raw_bytes(struct jdwp_builder* b, const void* bytes, size_t size)
{
    if (size > UINT32_MAX)
        die(EINVAL, "overlong packet");
    uint32_t new_length = b->length;
    if (SATADD(&new_length, b->length, (uint32_t) size))
        die(EINVAL, "overlong packet");
    while (b->gb.bufsz < new_length)
        grow_buffer_dwim(&b->gb);
    memcpy(b->gb.buf + (new_length - size), bytes, size);
    b->length = new_length;
}

static void
jdwp_builder_u64(struct jdwp_builder* b, uint64_t value)
{
    swap_bytes(&value, sizeof (value));
    jdwp_builder_raw_bytes(b, &value, sizeof (value));
}

static void
jdwp_builder_i64(struct jdwp_builder* b, int64_t value)
{
    swap_bytes(&value, sizeof (value));
    jdwp_builder_raw_bytes(b, &value, sizeof (value));
}

static void
jdwp_builder_i32(struct jdwp_builder* b, int32_t value)
{
    swap_bytes(&value, sizeof (value));
    jdwp_builder_raw_bytes(b, &value, sizeof (value));
}

static void
jdwp_builder_u32(struct jdwp_builder* b, uint32_t value)
{
    swap_bytes(&value, sizeof (value));
    jdwp_builder_raw_bytes(b, &value, sizeof (value));
}

static void
jdwp_builder_i16(struct jdwp_builder* b, int16_t value)
{
    swap_bytes(&value, sizeof (value));
    jdwp_builder_raw_bytes(b, &value, sizeof (value));
}

static void
jdwp_builder_u16(struct jdwp_builder* b, uint16_t value)
{
    swap_bytes(&value, sizeof (value));
    jdwp_builder_raw_bytes(b, &value, sizeof (value));
}

static void
jdwp_builder_i8(struct jdwp_builder* b, int8_t value)
{
    jdwp_builder_raw_bytes(b, &value, sizeof (value));
}

static void
jdwp_builder_u8(struct jdwp_builder* b, uint8_t value)
{
    jdwp_builder_raw_bytes(b, &value, sizeof (value));
}

static void
jdwp_builder_string(struct jdwp_builder* b, const char* s)
{
    size_t slen = strlen(s);
    if (slen > UINT32_MAX)
        die(EINVAL, "overlong string");
    uint32_t slen32 = slen;
    jdwp_builder_u32(b, slen32);
    jdwp_builder_raw_bytes(b, s, slen32);
}

static void
jdwp_builder_id(struct jdwp_builder* b, uint64_t id, struct jdwp_type* type)
{
    if (type->advance != jdwp_scalar_advance)
        die(EINVAL, "type `%s' is not a scalar", type->name);
    switch (jdwp_scalar_width(type)) {
        case 2:
            jdwp_builder_u16(b, id);
            break;
        case 4:
            jdwp_builder_u32(b, id);
            break;
        case 8:
            jdwp_builder_u64(b, id);
            break;
        default:
            die(EINVAL,
                "unsupported scalar width %u",
                jdwp_scalar_width(type));
    }
}

static void
jdwp_builder_reference_type_id(struct jdwp_builder* b, uint64_t id)
{
    jdwp_builder_id(b, id, b->proxy->tt->type.reference_type_id);
}

static void
jdwp_builder_object_id(struct jdwp_builder* b, uint64_t id)
{
    jdwp_builder_id(b, id, b->proxy->tt->type.object_id);
}

static void
jdwp_builder_send(struct jdwp_builder* b, int fd)
{
    assert(b->length <= b->gb.bufsz);
    if (SATADD(&b->header.length, (uint32_t) sizeof (b->header), b->length))
        die(EINVAL, "overlong packet");
    jdwp_header_to_network(&b->header);

    struct iovec chunks[] = {
        { &b->header, sizeof (b->header) },
        { b->gb.buf, b->length },
    };
    write_all_v(fd, &chunks[0], ARRAYSIZE(chunks));
}

static char*
mkspace(int nr)
{
    char* buf = xalloc(nr+1);
    for (int i = 0; i < nr; ++i)
        buf[i] = ' ';
    buf[nr] = '\0';
    return buf;
}

static void
dbg_payload(struct jdwp_type* type,
            void* data,
            size_t data_size)
{
    (void) mkspace;
#ifndef NDEBUG
    SCOPED_RESLIST(rl);
    struct jdwp_cursor c = jdwp_cursor_create(type, data, data_size);
    while (jdwp_cursor_has_value(&c)) {
        type = jdwp_cursor_current_type(&c);
        if (type->advance == jdwp_scalar_advance) {
            uint64_t value = jdwp_cursor_read_id(&c, type);
            dbg("%sfield type %s %llu 0x%llx",
                mkspace(c.depth + 2), type->name,
                (llu) value, (llu) value);
        } else if (type->advance == jdwp_string_advance) {
            dbg("%sfield type %s {%s}",
                mkspace(c.depth + 2), type->name,
                jdwp_cursor_read_string(&c));
        } else if (type->next_type == jdwp_array_next_type) {
            dbg("%sfield type %s (array count:%u)", mkspace(c.depth + 2),
                type->name, c.stack[c.depth].array.count);
        } else if (type->next_type != NULL) {
            dbg("%sfield type %s", mkspace(c.depth + 2), type->name);
        } else {
            dbg("%sfield type %s ?!?!?!?!?!?",
                mkspace(c.depth + 2), type->name);
        }

        if (jdwp_cursor_can_enter(&c)) {
            jdwp_cursor_enter(&c);
            continue;
        }

        jdwp_cursor_next(&c);
        while (!jdwp_cursor_has_value(&c) && jdwp_cursor_has_parent(&c)) {
            jdwp_cursor_leave(&c);
        }
    }
#endif
}

static struct jdwp_packet* peek_pending_packet(
    struct jdwp_proxy* proxy, uint32_t id);

static uint32_t
make_jdwp_id(struct jdwp_proxy* proxy)
{
    uint32_t id;
    do {
        id = proxy->seqnum++;
    } while (peek_pending_packet(proxy, id));
    return id;
}

enum translate_mode {
    TRANSLATE_TO_APP,
    TRANSLATE_TO_DEBUGGER,
};

static uint16_t translate_payload(
    struct jdwp_proxy* proxy,
    enum translate_mode mode,
    struct jdwp_type* top_type,
    void* data,
    size_t data_size);

enum all_classes_reply_mode {
    ALL_CLASSES_REPLY_CLR,
    ALL_CLASSES_REPLY_CLASSES,
    ALL_CLASSES_REPLY_GENERIC,
};

static void
jdwp_send_all_classes_reply(
    struct jdwp_proxy* proxy,
    uint32_t id,
    enum all_classes_reply_mode mode,
    uint64_t class_loader_filter);

static void
on_jdwp_command(struct jdwp_proxy* proxy,
                struct jdwp_packet* packet,
                int recv_fd,
                int onward_fd)
{
    bool from_debugger = recv_fd == proxy->to_debugger_fd;

    struct jdwp_command* command = jdwp_find_command(
        proxy->tt,
        packet->header.command.group,
        packet->header.command.code);

    if (!command) {
        log_warn(proxy, "unsupported command (%hhu %hhu)",
                 packet->header.command.group,
                 packet->header.command.code);
        send_generic_reply(proxy, packet->header.id, recv_fd,
                           JDWP_ERROR_NOT_IMPLEMENTED);
        return;
    }

    if (dbg_enabled_p()) {
        dbg("Command: %s", describe_jdwp_message(&packet->header));
        dbg_payload(command->type,
                    packet->header.data,
                    packet->header.length - sizeof (packet));
        dbg("Command payload end");
    }

    if (packet->header.command.group == JDWP_COMMANDSET_VIRTUALMACHINE &&
        (packet->header.command.code == JDWP_COMMAND_VM_ALLCLASSES_GENERIC ||
         packet->header.command.code == JDWP_COMMAND_VM_ALLCLASSES))
    {
        jdwp_send_all_classes_reply(
            proxy,
            packet->header.id,
            ( packet->header.command.code == JDWP_COMMAND_VM_ALLCLASSES_GENERIC
              ? ALL_CLASSES_REPLY_GENERIC
              : ALL_CLASSES_REPLY_CLASSES ),
            0);
        return;
    }

    if (packet->header.command.group == JDWP_COMMANDSET_CLASSLOADERREFERENCE &&
        packet->header.command.code == JDWP_COMMAND_CLR_VISIBLECLASSES)
    {
        struct jdwp_cursor c = jdwp_cursor_create(
            command->type,
            packet->header.data,
            packet->header.length - sizeof (packet));
        jdwp_cursor_enter(&c);
        uint64_t clr_id = jdwp_cursor_read_id(&c, proxy->tt->type.object_id);
        jdwp_cursor_next(&c);
        jdwp_cursor_leave(&c);
        jdwp_send_all_classes_reply(
            proxy,
            packet->header.id,
            ALL_CLASSES_REPLY_CLR,
            clr_id);

        return;
    }

    dbg("translating payload for command ID %u", packet->header.id);
    uint16_t err = translate_payload(
        proxy,
        from_debugger ? TRANSLATE_TO_APP : TRANSLATE_TO_DEBUGGER,
        command->type,
        packet->header.data,
        packet->header.length - sizeof(packet->header));

    if (err != 0) {
        dbg("translating produced JDWP error %hu (%s)",
            err, jdwp_error_to_string(err) ?: "???");
        send_generic_reply(proxy, packet->header.id, onward_fd, err);
        return;
    }

    dbg("post-translation for command ID %u", packet->header.id);
    dbg_payload(command->type,
                packet->header.data,
                packet->header.length - sizeof (packet));
    dbg("end post-translation");

    if (!from_debugger) {
        jdwp_send_packet(onward_fd, &packet->header);
        return;
    }

    packet->original_id = packet->header.id;
    packet->header.id = make_jdwp_id(proxy);
    packet->has_rewritten_id = true;
    dbg("rewrote command ID from debugger %u to proxy ID %u",
        packet->original_id,
        packet->header.id);
    jdwp_send_packet(onward_fd, &packet->header);
    if (command->reply_type)
        mark_packet_pending(proxy, packet);
}

static void
on_jdwp_reply(struct jdwp_proxy* proxy,
              struct jdwp_packet* packet,
              int recv_fd,
              int onward_fd)
{
    SCOPED_RESLIST(rl);
    bool from_app = recv_fd == proxy->to_app_fd;
    if (!from_app) {
        log_warn(proxy, "received reply packet from debugger: dropping");
        return;
    }

    struct jdwp_packet* command_packet =
        pop_pending_packet(proxy, packet->header.id);

    if (command_packet == NULL) {
        log_warn(proxy,
                 "dropping spurious reply packet %s",
                 describe_jdwp_message(&packet->header));
        return;
    }

    if (command_packet->has_rewritten_id) {
        dbg("rewrote reply command ID from %u to original debugger ID %u",
            packet->header.id, command_packet->original_id);
        packet->header.id = command_packet->original_id;
    }

    struct jdwp_command* command =
        jdwp_find_command(
            proxy->tt,
            command_packet->header.command.group,
            command_packet->header.command.code);

    struct jdwp_type* reply_type = command->reply_type;
    if (reply_type == NULL) {
        log_warn(proxy,
                 "command type `%s' has no reply type, but we have a reply!",
                 command->type->name);
    } else {
        dbg("Reply to %s (%s): %s",
            command->type->name,
            describe_jdwp_message(&command_packet->header),
            describe_jdwp_message(&packet->header));
        if (packet->header.reply.error_code != 0) {
            dbg("  %s", jdwp_error_to_string(packet->header.reply.error_code));
        } else {
            dbg_payload(reply_type,
                        packet->header.data,
                        packet->header.length - sizeof (packet));
        }
        dbg("Reply payload end");

        if (packet->header.reply.error_code == 0) {
            dbg("Translating reply payload");
            uint16_t err = translate_payload(
                proxy,
                TRANSLATE_TO_DEBUGGER,
                reply_type,
                packet->header.data,
                packet->header.length - sizeof(packet->header));

            if (err != 0) {
                dbg("translating reply produced JDWP error %hu (%s)",
                    err, jdwp_error_to_string(err) ?: "???");
                send_generic_reply(proxy, packet->header.id, onward_fd, err);
                return;
            }

            dbg("Done translating reply payload");

            dbg("post-translation reply payload");
            dbg_payload(reply_type,
                        packet->header.data,
                        packet->header.length - sizeof (packet));
            dbg("end post-translation reply payload");
        }
    }

    jdwp_send_packet(onward_fd, &packet->header);
}

static void
jdwp_untagged_value_init_frame(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    abort();
}

static void
jdwp_event_modifier_init_frame(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    uint8_t mod_kind;
    jdwp_cursor_slurp(&mod_kind, c, 1);
    const char* actual_type_name = NULL;
    switch (mod_kind) {
        case COND_COUNT:
            actual_type_name = CN_COUNT;
            break;
        case COND_CONDITIONAL:
            actual_type_name = CN_CONDITIONAL;
            break;
        case COND_THREADONLY:
            actual_type_name = CN_THREADONLY;
            break;
        case COND_CLASSONLY:
            actual_type_name = CN_CLASSONLY;
            break;
        case COND_CLASSMATCH:
            actual_type_name = CN_CLASSMATCH;
            break;
        case COND_CLASSEXCLUDE:
            actual_type_name = CN_CLASSEXCLUDE;
            break;
        case COND_LOCATIONONLY:
            actual_type_name = CN_LOCATIONONLY;
            break;
        case COND_EXCEPTIONONLY:
            actual_type_name = CN_EXCEPTIONONLY;
            break;
        case COND_FIELDONLY:
            actual_type_name = CN_FIELDONLY;
            break;
        case COND_STEP:
            actual_type_name = CN_STEP;
            break;
        case COND_INSTANCEONLY:
            actual_type_name = CN_INSTANCEONLY;
            break;
        case COND_SOURCENAMEMATCH:
            actual_type_name = CN_SOURCENAMEMATCH;
            break;
        default:
            die(EINVAL, "unknown event modifier %u", (unsigned) mod_kind);
    }

    struct jdwp_type_table* tt = this->tt;
    frame->type = jdwp_find_type(tt, actual_type_name);
    frame->type->init_frame(frame->type, c, frame);
}

static void
jdwp_event_init_frame(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    uint8_t event_kind;
    jdwp_cursor_slurp(&event_kind, c, 1);
    const char* actual_type_name = NULL;
    switch (event_kind) {
        case EVENT_VM_START:
            actual_type_name = EVN_VM_START;
            break;
        case EVENT_SINGLE_STEP:
            actual_type_name = EVN_SINGLE_STEP;
            break;
        case EVENT_BREAKPOINT:
            actual_type_name = EVN_BREAKPOINT;
            break;
        case EVENT_METHOD_ENTRY:
            actual_type_name = EVN_METHOD_ENTRY;
            break;
        case EVENT_METHOD_EXIT:
            actual_type_name = EVN_METHOD_EXIT;
            break;
        case EVENT_METHOD_EXIT_WITH_RETURN_VALUE:
            actual_type_name = EVN_METHOD_EXIT_WITH_RETURN_VALUE;
            break;
        case EVENT_MONITOR_CONTENDED_ENTER:
            actual_type_name = EVN_MONITOR_CONTENDED_ENTER;
            break;
        case EVENT_MONITOR_CONTENDED_ENTERED:
            actual_type_name = EVN_MONITOR_CONTENDED_ENTERED;
            break;
        case EVENT_MONITOR_WAIT:
            actual_type_name = EVN_MONITOR_WAIT;
            break;
        case EVENT_MONITOR_WAITED:
            actual_type_name = EVN_MONITOR_WAITED;
            break;
        case EVENT_EXCEPTION:
            actual_type_name = EVN_EXCEPTION;
            break;
        case EVENT_THREAD_START:
            actual_type_name = EVN_THREAD_START;
            break;
        case EVENT_THREAD_DEATH:
            actual_type_name = EVN_THREAD_DEATH;
            break;
        case EVENT_CLASS_PREPARE:
            actual_type_name = EVN_CLASS_PREPARE;
            break;
        case EVENT_CLASS_UNLOAD:
            actual_type_name = EVN_CLASS_UNLOAD;
            break;
        case EVENT_FIELD_ACCESS:
            actual_type_name = EVN_FIELD_ACCESS;
            break;
        case EVENT_FIELD_MODIFICATION:
            actual_type_name = EVN_FIELD_MODIFICATION;
            break;
        case EVENT_VM_DEATH:
            actual_type_name = EVN_VM_DEATH;
            break;
        default:
            die(EINVAL, "unknown event %u", (unsigned) event_kind);
    }

    struct jdwp_type_table* tt = this->tt;
    frame->type = jdwp_find_type(tt, actual_type_name);
    frame->type->init_frame(frame->type, c, frame);
}

static void
gobble_hack_advance(
    struct jdwp_type* this,
    struct jdwp_cursor* c,
    struct jdwp_cursor_frame* frame)
{
    c->pos = c->end;
}

static void
setup_jdwp_types(struct jdwp_type_table* tt)
{
#define NO_REPLY NULL
#define NO_FIELDS ((const struct jdwp_field_descriptor[]){{ NULL, NULL }})
#define FIELDS(...)                                             \
    ((const struct jdwp_field_descriptor[]){                    \
        __VA_ARGS__,                                            \
        { NULL, NULL }})
#define ARRAY(t) jdwp_array_of(tt, (t))
#define STRUCT(name, ...) jdwp_define_struct(tt,(name),FIELDS(__VA_ARGS__))
#define COMMAND(name, group, code, data, reply) \
    jdwp_define_command(tt, (name), (group), (code), (data), (reply))

    struct jdwp_type* object_id = tt->type.object_id;

    struct jdwp_type* array_id = tt->type.array_id;
    struct jdwp_type* boolean = tt->type.boolean;
    struct jdwp_type* byte = tt->type.byte;
    struct jdwp_type* class_loader_id = tt->type.class_loader_id;
    struct jdwp_type* class_object_id = tt->type.class_object_id;
    struct jdwp_type* int_ = tt->type.int_;
    struct jdwp_type* long_ = tt->type.long_;
    struct jdwp_type* string = tt->type.string;
    struct jdwp_type* string_id = tt->type.string_id;
    struct jdwp_type* thread_group_id = tt->type.thread_group_id;
    struct jdwp_type* thread_id = tt->type.thread_id;

    struct jdwp_type* array_type_id = tt->type.array_type_id;
    struct jdwp_type* class_id = tt->type.class_id;
    struct jdwp_type* interface_id = tt->type.interface_id;
    struct jdwp_type* reference_type_id = tt->type.reference_type_id;

    struct jdwp_type* method_id = tt->type.method_id;
    struct jdwp_type* frame_id = tt->type.frame_id;
    struct jdwp_type* field_id = tt->type.field_id;

    struct jdwp_type* value = tt->type.value;
    struct jdwp_type* arrayregion = tt->type.arrayregion;

    struct jdwp_type* tagged_object_id =
        jdwp_define_special_type(
            tt,
            (struct jdwp_type) {
                .name = "taggedObjectID",
                    .init_frame = jdwp_value_init_frame,
                    .advance = assert_not_advanced,
                    .depth = 1,
                    });

    struct jdwp_type* location =
        STRUCT("Location",
               { byte, "tag" },
               { class_id, "clazz" },
               { method_id, "method" },
               { long_, "index" });

    STRUCT(CN_COUNT, { int_, "count" });
    STRUCT(CN_CONDITIONAL, { int_, "exprID" });
    STRUCT(CN_THREADONLY, { thread_id, "thread" });
    STRUCT(CN_CLASSONLY, { reference_type_id, "clazz" });
    STRUCT(CN_CLASSMATCH, { string, "classPattern" });
    STRUCT(CN_CLASSEXCLUDE, { string, "classPattern" });
    STRUCT(CN_LOCATIONONLY, { location, "loc" });
    STRUCT(CN_EXCEPTIONONLY,
           { reference_type_id, "exceptionOrNull" },
           { boolean, "caught" },
           { boolean, "uncaught" });
    STRUCT(CN_FIELDONLY,
           { reference_type_id, "declaring" },
           { field_id, "fieldID" });
    STRUCT(CN_STEP,
           { thread_id, "thread" },
           { int_, "size" },
           { int_, "depth" });
    STRUCT(CN_INSTANCEONLY, { object_id, "instance" });
    STRUCT(CN_SOURCENAMEMATCH, { string, "sourceNamePattern" });

    struct jdwp_type* event_modifier =
        jdwp_define_special_type(
            tt,
            (struct jdwp_type) {
                .name = "eventModifier",
                    .init_frame = jdwp_event_modifier_init_frame,
                    .advance = assert_not_advanced,
                    .depth = 1,
                    });

    STRUCT(EVN_VM_START,
           { int_, "requestID" },
           { thread_id, "thread" });
    STRUCT(EVN_SINGLE_STEP,
           { int_, "requestID" },
           { thread_id, "thread" },
           { location, "location" });
    STRUCT(EVN_BREAKPOINT,
           { int_, "requestID" },
           { thread_id, "thread" },
           { location, "location" });
    STRUCT(EVN_METHOD_ENTRY,
           { int_, "requestID" },
           { thread_id, "threadID" },
           { location, "location" });
    STRUCT(EVN_METHOD_EXIT,
           { int_, "requestID" },
           { thread_id, "threadID" },
           { location, "location" });
    STRUCT(EVN_METHOD_EXIT_WITH_RETURN_VALUE,
           { int_, "requestID" },
           { thread_id, "threadID" },
           { location, "location" },
           { value, "value" });
    STRUCT(EVN_MONITOR_CONTENDED_ENTER,
           { int_, "requestID" },
           { thread_id, "threadID" },
           { tagged_object_id, "object" },
           { location, "location" });
    STRUCT(EVN_MONITOR_CONTENDED_ENTERED,
           { int_, "requestID" },
           { thread_id, "thread" },
           { tagged_object_id, "object" },
           { location, "location" });
    STRUCT(EVN_MONITOR_WAIT,
           { int_, "requestID" },
           { thread_id, "thread" },
           { tagged_object_id, "object" },
           { location, "location" },
           { long_, "timeout" });
    STRUCT(EVN_MONITOR_WAITED,
           { int_, "requestID" },
           { thread_id, "thread" },
           { tagged_object_id, "object" },
           { location, "location" },
           { boolean, "timed_out" });
    STRUCT(EVN_EXCEPTION,
           { int_, "requestID" },
           { thread_id, "thread" },
           { location, "location" },
           { tagged_object_id, "exception" },
           { location, "catchLocation" });
    STRUCT(EVN_THREAD_START,
           { int_, "requestID" },
           { thread_id, "thread" });
    STRUCT(EVN_THREAD_DEATH,
           { int_, "requestID" },
           { thread_id, "threadID" });
    STRUCT(EVN_CLASS_PREPARE,
           { int_, "requestiD" },
           { thread_id, "threadID" },
           { byte, "refTypeTag" },
           { reference_type_id, "typeID" },
           { string, "signature" },
           { int_, "status" });
    STRUCT(EVN_CLASS_UNLOAD,
           { int_, "requestID" },
           { string, "signature" });
    STRUCT(EVN_FIELD_ACCESS,
           { int_, "requestID" },
           { thread_id, "thread" },
           { location, "location" },
           { byte, "refTypeTag" },
           { reference_type_id, "typeID" },
           { field_id, "fieldID" },
           { tagged_object_id, "object" });
    STRUCT(EVN_FIELD_MODIFICATION,
           { int_, "requestID" },
           { thread_id, "thread" },
           { location, "location" },
           { byte, "refTypeTag" },
           { reference_type_id, "typeID" },
           { field_id, "fieldID" },
           { tagged_object_id, "object" },
           { value, "valueToBe" });
    STRUCT(EVN_VM_DEATH,
           { int_, "requestID" });

    struct jdwp_type* event =
        jdwp_define_special_type(
            tt,
            (struct jdwp_type) {
                .name = "event",
                    .init_frame = jdwp_event_init_frame,
                    .advance = assert_not_advanced,
                    .depth = 2,
                    });

    struct jdwp_type* untagged_value =
        jdwp_define_special_type(
            tt,
            (struct jdwp_type) {
                .name = "untaggedValue",
                    .init_frame = jdwp_untagged_value_init_frame,
                    .advance = assert_not_advanced,
                    });

    // Type treats remainer of message as opaque; untagged_value
    // parsing is too complicated right now, but since we don't need
    // to rewrite anything inside, just skip.
    struct jdwp_type* gobble_hack =
        jdwp_define_special_type(
            tt,
            (struct jdwp_type) {
                .name = "gobbleHack",
                    .init_frame = noop_init_frame,
                    .advance = gobble_hack_advance,
                    });

    COMMAND("VM_Version",
            JDWP_COMMANDSET_VIRTUALMACHINE, JDWP_COMMAND_VM_VERSION,
            NO_FIELDS,
            FIELDS(
                { string, "description" },
                { int_, "jdwpMajor" },
                { int_, "jdwpMinor" },
                { string, "vmVersion" },
                { string, "vmName" }));

    struct jdwp_type* cbs_class_record =
        STRUCT("CBS_ClassRecord",
               { byte, "refTypeTag" },
               { reference_type_id, "typeID" },
               { int_, "status" });

    COMMAND("VM_ClassesBySignature",
            JDWP_COMMANDSET_VIRTUALMACHINE,
            JDWP_COMMAND_VM_CLASSESBYSIGNATURE,
            FIELDS({ string, "signature" }),
            FIELDS({ ARRAY(cbs_class_record), "classes" }));

    struct jdwp_type* ac_class_record =
        STRUCT("AC_ClassRecord",
               { byte, "refTypeTag" },
               { reference_type_id, "typeID" },
               { string, "signature" },
               { int_, "status" });

    COMMAND("VM_AllClasses",
            JDWP_COMMANDSET_VIRTUALMACHINE, JDWP_COMMAND_VM_ALLCLASSES,
            NO_FIELDS,
            FIELDS({ ARRAY(ac_class_record), "classes" }));

    COMMAND("VM_AllThreads",
            JDWP_COMMANDSET_VIRTUALMACHINE, JDWP_COMMAND_VM_ALLTHREADS,
            NO_FIELDS,
            FIELDS({ ARRAY(thread_id), "threads" }));

    COMMAND("VM_TopLevelThreadGroups",
            JDWP_COMMANDSET_VIRTUALMACHINE, 5,
            NO_FIELDS,
            FIELDS({ ARRAY(thread_group_id), "groups" }));

    COMMAND("VM_Dispose",
            JDWP_COMMANDSET_VIRTUALMACHINE, 6,
            NO_FIELDS,
            NO_FIELDS);

    COMMAND("VM_IDSizes",
            JDWP_COMMANDSET_VIRTUALMACHINE, JDWP_COMMAND_VM_IDSIZES,
            NO_FIELDS,
            FIELDS(
                { int_, "fieldIDSize" },
                { int_, "methodIDSize" },
                { int_, "objectIDSize" },
                { int_, "referenceTypeIDSize" },
                { int_, "frameIDSize" }));

    COMMAND("VM_Suspend",
            JDWP_COMMANDSET_VIRTUALMACHINE, JDWP_COMMAND_VM_SUSPEND,
            NO_FIELDS,
            NO_FIELDS);

    COMMAND("VM_Resume",
            JDWP_COMMANDSET_VIRTUALMACHINE, JDWP_COMMAND_VM_RESUME,
            NO_FIELDS,
            NO_FIELDS);

    COMMAND("VM_Exit",
            JDWP_COMMANDSET_VIRTUALMACHINE, 10,
            FIELDS({ int_, "exitCode" }),
            NO_FIELDS);

    COMMAND("VM_CreateString",
            JDWP_COMMANDSET_VIRTUALMACHINE, 11,
            FIELDS({ string, "utf" }),
            FIELDS({ string_id, "stringObject" }));

    COMMAND("VM_Capabilities",
            JDWP_COMMANDSET_VIRTUALMACHINE, 12,
            NO_FIELDS,
            FIELDS(
                { boolean, "canWatchFieldModification"},
                { boolean, "canWatchFieldAccess"},
                { boolean, "canGetBytecodes"},
                { boolean, "canGetSyntheticAttribute"},
                { boolean, "canGetOwnedMonitorInfo"},
                { boolean, "canGetCurrentContendedMonitor"},
                { boolean, "canGetMonitorInfo"}));

    COMMAND("VM_ClassPaths",
            JDWP_COMMANDSET_VIRTUALMACHINE, 13,
            NO_FIELDS,
            FIELDS(
                { string, "baseDir"},
                { ARRAY(string), "classpaths" },
                { ARRAY(string), "bootclasspaths" }));

    struct jdwp_type* dispose_request =
        STRUCT("DO_Request",
               { object_id, "object" },
               { int_, "refCnt" });

    COMMAND("VM_DisposeObjects",
            JDWP_COMMANDSET_VIRTUALMACHINE, JDWP_COMMAND_VM_DISPOSEOBJECTS,
            FIELDS({ ARRAY(dispose_request), "requests" }),
            NO_FIELDS);

    COMMAND("VM_HoldEvents",
            JDWP_COMMANDSET_VIRTUALMACHINE, 15,
            NO_FIELDS,
            NO_FIELDS);

    COMMAND("VM_ReleaseEvents",
            JDWP_COMMANDSET_VIRTUALMACHINE, 16,
            NO_FIELDS,
            NO_FIELDS);

    COMMAND("VM_CapabilitiesNew",
            JDWP_COMMANDSET_VIRTUALMACHINE, 17,
            NO_FIELDS,
            FIELDS(
                { boolean, "canWatchFieldModification"},
                { boolean, "canWatchFieldAccess"},
                { boolean, "canGetBytecodes"},
                { boolean, "canGetSyntheticAttribute"},
                { boolean, "canGetOwnedMonitorInfo"},
                { boolean, "canGetCurrentContendedMonitor"},
                { boolean, "canGetMonitorInfo"},
                { boolean, "canRedefineClasses"},
                { boolean, "canAddMethod"},
                { boolean, "canUnstrictedlyRedefineClasses"},
                { boolean, "canPopFrames"},
                { boolean, "canUseInstanceFilters"},
                { boolean, "canGetSourceDebugExtension"},
                { boolean, "canRequestVMDeathEvent"},
                { boolean, "canSetDefaultStratum"},
                { boolean, "canGetInstanceInfo"},
                { boolean, "canRequestMonitorEvents"},
                { boolean, "canGetMonitorFrameInfo"},
                { boolean, "canUseSourceNameFilters"},
                { boolean, "canGetConstantPool"},
                { boolean, "canForceEarlyReturn"},
                { boolean, "reserved22"},
                { boolean, "reserved23"},
                { boolean, "reserved25"},
                { boolean, "reserved26"},
                { boolean, "reserved27"},
                { boolean, "reserved28"},
                { boolean, "reserved29"},
                { boolean, "reserved30"},
                { boolean, "reserved31"},
                { boolean, "reserved32"}));

    struct jdwp_type* redef_class =
        STRUCT("RDC_Class",
               { reference_type_id, "refType" },
               { ARRAY(byte), "classfile" });

    COMMAND("VM_RedefineClasses",
            JDWP_COMMANDSET_VIRTUALMACHINE, 18,
            FIELDS({ ARRAY(redef_class), "classes" }),
            NO_FIELDS);

    COMMAND("VM_SetDefaultStratum",
            JDWP_COMMANDSET_VIRTUALMACHINE, 19,
            FIELDS({ string, "stratumID" }),
            NO_FIELDS);

    struct jdwp_type* acwg =
        STRUCT("ACWG_ClassEntry",
              { byte, "refTypeTag" },
              { reference_type_id, "typeID" },
              { string, "signature" },
              { string, "genericSignature" },
              { int_, "status" });

    COMMAND("VM_AllClassesWithGeneric",
            JDWP_COMMANDSET_VIRTUALMACHINE, JDWP_COMMAND_VM_ALLCLASSES_GENERIC,
            NO_FIELDS,
            FIELDS({ ARRAY(acwg), "classes" }));

    COMMAND("VM_InstanceCounts",
            JDWP_COMMANDSET_VIRTUALMACHINE, 21,
            FIELDS({ ARRAY(reference_type_id), "refType" }),
            FIELDS({ ARRAY(long_), "counts" }));

    COMMAND("RT_Signature",
            JDWP_COMMANDSET_REFERENCETYPE, JDWP_COMMAND_RT_SIGNATURE,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ string, "signature" }));

    COMMAND("RT_ClassLoader",
            JDWP_COMMANDSET_REFERENCETYPE, JDWP_COMMAND_RT_CLASSLOADER,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ class_loader_id, "classLoader" }));

    COMMAND("RT_Modifiers",
            JDWP_COMMANDSET_REFERENCETYPE, JDWP_COMMAND_RT_MODIFIERS,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ int_, "modBits" }));

    struct jdwp_type* field_record =
        STRUCT("FieldRecord",
               { field_id, "fieldID" },
               { string, "name" },
               { string, "signature" },
               { int_, "modBits" });

    COMMAND("RT_Fields",
            JDWP_COMMANDSET_REFERENCETYPE, 4,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ ARRAY(field_record), "fields" }));

    struct jdwp_type* method_record =
        STRUCT("MethodsRecord",
               { method_id, "methodID" },
               { string, "name" },
               { string, "signature" },
               { int_, "modBits" });

    COMMAND("RT_Methods",
            JDWP_COMMANDSET_REFERENCETYPE, 5,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ ARRAY(method_record), "methods" }));

    COMMAND("RT_GetValues",
            JDWP_COMMANDSET_REFERENCETYPE, 6,
            FIELDS(
                { reference_type_id, "refType" },
                { ARRAY(field_id), "fields" }),
            FIELDS({ ARRAY(value), "values" }));

    COMMAND("RT_SourceFile",
            JDWP_COMMANDSET_REFERENCETYPE, 7,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ string, "sourceFile" }));

    struct jdwp_type* nested_type_result =
        STRUCT("RT_NestedTypeResult",
               { byte, "refTypeTag" },
               { reference_type_id, "typeID" });

    COMMAND("RT_NestedTypes",
            JDWP_COMMANDSET_REFERENCETYPE, 8,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ ARRAY(nested_type_result), "classes"}));

    COMMAND("RT_Status",
            JDWP_COMMANDSET_REFERENCETYPE, 9,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ int_, "status" }));

    COMMAND("RT_Interfaces",
            JDWP_COMMANDSET_REFERENCETYPE, 10,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ ARRAY(interface_id), "interfaces" }));

    COMMAND("RT_ClassObject",
            JDWP_COMMANDSET_REFERENCETYPE, 11,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ class_object_id, "classObject" }));

    COMMAND("RT_SourceDebugExtension",
            JDWP_COMMANDSET_REFERENCETYPE, 12,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ string, "extension" }));

    COMMAND("RT_SignatureWithGeneric",
        JDWP_COMMANDSET_REFERENCETYPE, 13,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS(
                { string, "signature" },
                { string, "genericSignature" }));

    struct jdwp_type* generic_field =
        STRUCT("FieldsWithGenericRecord",
               { field_id, "fieldID" },
               { string, "name" },
               { string, "signature" },
               { string, "genericSignature" },
               { int_, "modBits" });

    COMMAND("RT_FieldsWithGeneric",
            JDWP_COMMANDSET_REFERENCETYPE, 14,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ ARRAY(generic_field), "fields"}));

    struct jdwp_type* generic_method =
        STRUCT("MethodsWithGenericResult",
               { method_id, "methodID" },
               { string, "name" },
               { string, "signature" },
               { string, "genericSignature" },
               { int_, "modBits" });

    COMMAND("RT_MethodsWithGeneric",
            JDWP_COMMANDSET_REFERENCETYPE, 15,
            FIELDS({ reference_type_id, "refType" }),
            FIELDS({ ARRAY(generic_method), "methods" }));

   COMMAND("RT_Instances",
           JDWP_COMMANDSET_REFERENCETYPE, 16,
           FIELDS(
               { reference_type_id, "refType" },
               { int_, "maxInstances" }),
           FIELDS({ ARRAY(tagged_object_id), "instances" }));

   COMMAND("RT_ClassFileVersion",
           JDWP_COMMANDSET_REFERENCETYPE, 17,
           FIELDS({ reference_type_id, "refType" }),
           FIELDS(
               { int_, "majorVersion" },
               { int_, "minorVersion" }));

   COMMAND("RT_ConstantPool",
           JDWP_COMMANDSET_REFERENCETYPE, 18,
           FIELDS({ reference_type_id, "refType" }),
           FIELDS(
               { int_, "count" },
               { ARRAY(byte), "bytes" }));

   COMMAND("CT_Superclass",
           JDWP_COMMANDSET_CLASSTYPE, 1,
           FIELDS({ class_id, "clazz" }),
           FIELDS({ class_id, "superclass" }));

   struct jdwp_type* ct_setvalue =
       STRUCT("CT_SetValueRecord",
              { field_id, "fieldID" },
              { untagged_value, "value" });
   (void) ct_setvalue;

   COMMAND("CT_SetValues",
           JDWP_COMMANDSET_CLASSTYPE, 2,
           FIELDS(
               { class_id, "clazz" },
               // { ARRAY(ct_setvalue), "values" }
               { gobble_hack, "values" }),
           NO_FIELDS);

   COMMAND("CT_InvokeMethod",
           JDWP_COMMANDSET_CLASSTYPE, 3,
           FIELDS(
               { class_id, "clazz" },
               { thread_id, "thread" },
               { method_id, "method" },
               { ARRAY(value), "arguments" }),
           FIELDS(
               { value, "returnValue" },
               { tagged_object_id, "exception" }));

   COMMAND("CT_NewInstance",
           JDWP_COMMANDSET_CLASSTYPE, 4,
           FIELDS(
               { class_id, "clazz" },
               { thread_id, "thread" },
               { method_id, "method" },
               { ARRAY(value), "arguments" }),
           FIELDS(
               { tagged_object_id, "newObject" },
               { tagged_object_id, "exception" }));

   COMMAND("AT_NewInstance",
           JDWP_COMMANDSET_ARRAYTYPE, 1,
           FIELDS(
               { array_type_id, "arrType" },
               { int_, "length" }),
           FIELDS({ tagged_object_id, "newArray" }));

   struct jdwp_type* line_table_entry =
       STRUCT("M_LineTableEntry",
              { long_, "lineCodeIndex" },
              { int_, "lineNumber" });

   COMMAND("M_LineTable",
           JDWP_COMMANDSET_METHOD, 1,
           FIELDS(
               { reference_type_id, "refType" },
               { method_id, "methodID" }),
           FIELDS(
               { long_, "start" },
               { long_, "end" },
               { int_, "lines" },
               { ARRAY(line_table_entry), "lines" }));

   struct jdwp_type* slot_record =
       STRUCT("M_SlotRecord",
              { long_, "codeIndex" },
              { string, "name" },
              { string, "signature" },
              { int_, "length" },
              { int_, "slot" });

   COMMAND("M_VariableTable",
           JDWP_COMMANDSET_METHOD, 2,
           FIELDS(
               { reference_type_id, "refType" },
               { method_id, "methodID" }),
           FIELDS(
               { int_, "argCnt" },
               { ARRAY(slot_record), "slots" }));

   COMMAND("M_bytecodes",
           JDWP_COMMANDSET_METHOD, 3,
           FIELDS(
               { reference_type_id, "refType" },
               { method_id, "methodID" }),
           FIELDS({ARRAY(byte), "bytecode"}));

   COMMAND("M_IsObsolete",
           JDWP_COMMANDSET_METHOD, 4,
           FIELDS(
               { reference_type_id, "refType" },
               { method_id, "methodID" }),
           FIELDS({ boolean, "isObsolete" }));

   struct jdwp_type* generic_slot_record =
       STRUCT("M_GenericSlotRecord",
              { long_, "codeIndex" },
              { string, "name" },
              { string, "signature" },
              { string, "genericSignature" },
              { int_, "length" },
              { int_, "slot" });

   COMMAND("M_VariableTableWithGeneric",
           JDWP_COMMANDSET_METHOD, 5,
           FIELDS(
               { reference_type_id, "refType" },
               { method_id, "methodID" }),
           FIELDS(
               { int_, "argCnt" },
               { ARRAY(generic_slot_record), "slots" }));

   COMMAND("OR_ReferenceType",
           JDWP_COMMANDSET_OBJECTREFERENCE, 1,
           FIELDS({ object_id, "object" }),
           FIELDS(
               { byte, "refTypeTag" },
               { reference_type_id, "typeID" }));

   COMMAND("OR_GetValues",
           JDWP_COMMANDSET_OBJECTREFERENCE, 2,
           FIELDS(
               { object_id, "object" },
               { ARRAY(field_id), "fields" }),
           FIELDS({ ARRAY(value), "values" }));

   struct jdwp_type* or_setvalue =
       STRUCT("OR_SetValuesRecord",
              { field_id, "field" },
              { untagged_value, "value" });
   (void) or_setvalue;

   COMMAND("OR_SetValues",
           JDWP_COMMANDSET_OBJECTREFERENCE, 3,
           FIELDS(
               { object_id, "object" },
               // { ARRAY(or_setvalue), "fields" }
               { gobble_hack, "fields" }),
           NO_FIELDS);

   COMMAND("OR_MonitorInfo",
           JDWP_COMMANDSET_OBJECTREFERENCE, 5,
           FIELDS({ object_id, "object" }),
           FIELDS(
               { thread_id, "owner" },
               { int_, "entryCount" },
               { ARRAY(thread_id), "waiters" }));

   COMMAND("OR_InvokeMethod",
           JDWP_COMMANDSET_OBJECTREFERENCE, 6,
           FIELDS(
               { object_id, "object" },
               { thread_id, "thread" },
               { class_id, "clazz" },
               { method_id, "method" },
               { ARRAY(value), "arguments" }),
           FIELDS(
               { value, "returnValue" },
               { tagged_object_id, "exception" }));

   COMMAND("OR_DisableCollection",
           JDWP_COMMANDSET_OBJECTREFERENCE,
           JDWP_COMMAND_OR_DISABLECOLLECTION,
           FIELDS({ object_id, "object" }),
           NO_FIELDS);

   COMMAND("OR_EnableCollection",
           JDWP_COMMANDSET_OBJECTREFERENCE, 8,
           FIELDS({ object_id, "object" }),
           NO_FIELDS);

   COMMAND("OR_IsCollected",
           JDWP_COMMANDSET_OBJECTREFERENCE, 9,
           FIELDS({ object_id, "object" }),
           FIELDS({ boolean, "isCollected" }));

   COMMAND("OR_ReferringObjects",
           JDWP_COMMANDSET_OBJECTREFERENCE, 10,
           FIELDS(
               { object_id, "object" },
               { int_, "maxReferrers" }),
           FIELDS( { ARRAY(tagged_object_id), "referringObjects" }));

   COMMAND("SR_Value",
           JDWP_COMMANDSET_STRINGREFERENCE, 1,
           FIELDS({ object_id, "stringObject" }),
           FIELDS({ string, "stringValue" }));

   COMMAND("T_Name",
           JDWP_COMMANDSET_THREADREFERENCE, 1,
           FIELDS({ thread_id, "thread" }),
           FIELDS({ string, "threadName" }));

   COMMAND("T_Suspend",
           JDWP_COMMANDSET_THREADREFERENCE, 2,
           FIELDS({ thread_id, "thread" }),
           NO_FIELDS);

   COMMAND("T_Resume",
           JDWP_COMMANDSET_THREADREFERENCE, 3,
           FIELDS({ thread_id, "thread" }),
           NO_FIELDS);

   COMMAND("T_Status",
           JDWP_COMMANDSET_THREADREFERENCE, 4,
           FIELDS({ thread_id, "thread" }),
           FIELDS(
               { int_, "threadStatus" },
               { int_, "suspendStatus" }));

   COMMAND("T_ThreadGroup",
           JDWP_COMMANDSET_THREADREFERENCE, 5,
           FIELDS({ thread_id, "thread" }),
           FIELDS({ thread_group_id, "group" }));

   struct jdwp_type* frame_record =
       STRUCT("T_FrameRecord",
              { frame_id, "frameID" },
              { location, "location" });

   COMMAND("T_Frames",
           JDWP_COMMANDSET_THREADREFERENCE, 6,
           FIELDS(
               { thread_id, "thread" },
               { int_, "startFrame" },
               { int_, "length" }),
           FIELDS({ ARRAY(frame_record), "frames" }));

   COMMAND("T_FrameCount",
           JDWP_COMMANDSET_THREADREFERENCE, 7,
           FIELDS({ thread_id, "thread" }),
           FIELDS({ int_, "frameCount" }));

   COMMAND("T_OwnedMonitors",
           JDWP_COMMANDSET_THREADREFERENCE, 8,
           FIELDS({ thread_id, "thread" }),
           FIELDS({ ARRAY(tagged_object_id), "owned" }));

   COMMAND("T_CurrentContendedMonitor",
           JDWP_COMMANDSET_THREADREFERENCE, 9,
           FIELDS({ thread_id, "thread" }),
           FIELDS({ tagged_object_id, "monitor" }));

   COMMAND("T_Stop",
           JDWP_COMMANDSET_THREADREFERENCE, 10,
           FIELDS(
               { thread_id, "thread" },
               { object_id, "throwable" }),
           NO_FIELDS);

   COMMAND("T_Interrupt",
           JDWP_COMMANDSET_THREADREFERENCE, 11,
           FIELDS({ thread_id, "thread" }),
           NO_FIELDS);

   COMMAND("T_SuspendCount",
           JDWP_COMMANDSET_THREADREFERENCE, 12,
           FIELDS({ thread_id, "thread" }),
           FIELDS({ int_, "suspendCount" }));

   struct jdwp_type* owned_monitor_record =
       STRUCT("T_OwnedMonitorRecord",
              { tagged_object_id, "monitor" },
              { int_, "stack_depth" });

   COMMAND("T_OwnedMonitorsStackDepthInfo",
           JDWP_COMMANDSET_THREADREFERENCE, 13,
           FIELDS({ thread_id, "thread" }),
           FIELDS({ ARRAY(owned_monitor_record), "owned" }));

   COMMAND("T_ForceEarlyReturn",
           JDWP_COMMANDSET_THREADREFERENCE, 14,
           FIELDS(
               { thread_id, "thread" },
               { value, "value" }),
           NO_FIELDS);

   COMMAND("TG_Name",
           JDWP_COMMANDSET_THREADGROUPREFERENCE, 1,
           FIELDS({ thread_group_id, "group" }),
           FIELDS({ string, "groupName" }));

   COMMAND("TG_Parent",
           JDWP_COMMANDSET_THREADGROUPREFERENCE, 2,
           FIELDS({ thread_group_id, "group" }),
           FIELDS({ thread_group_id, "parentGroup" }));

   COMMAND("TG_Children",
           JDWP_COMMANDSET_THREADGROUPREFERENCE, 3,
           FIELDS({ thread_group_id, "group" }),
           FIELDS(
               { ARRAY(thread_id), "childThreads" },
               { ARRAY(thread_group_id), "childGroups" }));

   COMMAND("AR_Length",
           JDWP_COMMANDSET_ARRAYREFERENCE, 1,
           FIELDS({ array_id, "arrayObject" }),
           FIELDS({ int_, "arrayLength" }));

   COMMAND("AR_GetValues",
           JDWP_COMMANDSET_ARRAYREFERENCE, 2,
           FIELDS(
               { array_id, "arrayObject" },
               { int_, "firstIndex" },
               { int_, "length" }),
           FIELDS({ arrayregion, "values" }));

   COMMAND("AR_SetValues",
           JDWP_COMMANDSET_ARRAYREFERENCE, 3,
           FIELDS(
               { array_id, "arrayObject" },
               { int_, "firstIndex" },
               { int_, "length" },
               // { ARRAY(untagged_value), "values" }),
               { gobble_hack, "values" }),
           NO_FIELDS);

   struct jdwp_type* visible_class_record =
       STRUCT("CL_VisibleClassRecord",
              { byte, "refTypeTag" },
              { reference_type_id, "typeID" });

   COMMAND("CL_VisibleClasses",
           JDWP_COMMANDSET_CLASSLOADERREFERENCE,
           JDWP_COMMAND_CLR_VISIBLECLASSES,
           FIELDS({ class_loader_id, "classLoaderObject" }),
           FIELDS({ ARRAY(visible_class_record), "classes" }));

   COMMAND("ER_Set",
           JDWP_COMMANDSET_EVENTREQUEST, 1,
           FIELDS(
               { byte, "eventKind" },
               { byte, "suspendPolicy" },
               { ARRAY(event_modifier), "modifiers" }),
           FIELDS({ int_, "requestID" }));

   COMMAND("ER_Clear",
           JDWP_COMMANDSET_EVENTREQUEST, 2,
           FIELDS(
               { byte, "eventKind" },
               { int_, "requestID" }),
           NO_FIELDS);

   struct jdwp_type* sf_value =
       STRUCT("SF_SlotRecord",
              { int_, "slot" },
              { byte, "sigbyte" });

   COMMAND("SF_GetValues",
           JDWP_COMMANDSET_STACKFRAME, 1,
           FIELDS(
               { thread_id, "thread" },
               { frame_id, "frame" },
               { ARRAY(sf_value), "slots" }),
           FIELDS({ ARRAY(value), "slotValue"}));

   struct jdwp_type* sf_set_value =
       STRUCT("SF_SetValueSlotRecord",
              { int_, "slot" },
              { value, "slotValue" });

   COMMAND("SF_SetValues",
           JDWP_COMMANDSET_STACKFRAME, 2,
           FIELDS(
               { thread_id, "thread" },
               { frame_id, "frame" },
               { ARRAY(sf_set_value), "slotValues" }),
           NO_FIELDS);

   COMMAND("SF_ThisObject",
           JDWP_COMMANDSET_STACKFRAME, 3,
           FIELDS(
               { thread_id, "thread" },
               { frame_id, "frame" }),
           FIELDS({ tagged_object_id, "objectThis" }));

   COMMAND("SF_PopFrames",
           JDWP_COMMANDSET_STACKFRAME, 4,
           FIELDS(
               { thread_id, "thread" },
               { frame_id, "frame" }),
           NO_FIELDS);

   COMMAND("COR_ReflectedType",
           JDWP_COMMANDSET_CLASSOBJECTREFERENCE, 1,
           FIELDS({ class_object_id, "classObject" }),
           FIELDS(
               { byte, "refTypeTag" },
               { reference_type_id, "typeID" }));

   COMMAND("EV_Composite",
           JDWP_COMMANDSET_EVENT, 100,
           FIELDS(
               { byte, "suspendPolicy" },
               { ARRAY(event), "events" }),
           NO_REPLY);

   COMMAND("DD_Chunk",
           JDWP_COMMANDSET_DDM, JDWP_COMMAND_DDM_CHUNK,
           FIELDS(
               { byte, "hack" }),
           NO_FIELDS);
}

static struct jdwp_packet*
jdwp_pop_deferred_packet_from_app(struct jdwp_proxy* proxy)
{
    if (LIST_EMPTY(&proxy->deferred_from_app))
        return NULL;

    struct jdwp_packet* packet = LIST_FIRST(&proxy->deferred_from_app);
    assert(packet->on_list);
    LIST_REMOVE(packet, link);
    packet->on_list = false;
    reslist_reparent(packet->rl);
    return packet;
}

static void
jdwp_defer_packet_from_app(
    struct jdwp_proxy* proxy,
    struct jdwp_packet* packet)
{
    assert(!packet->on_list);
    LIST_INSERT_HEAD(&proxy->deferred_from_app, packet, link);
    packet->on_list = true;
    WITH_CURRENT_RESLIST(proxy->rl);
    reslist_reparent(packet->rl);
}

static struct jdwp_packet*
jdwp_read_packet(struct jdwp_proxy* proxy, int fd)
{
    struct jdwp_header header;
    size_t nr_read;

    nr_read = read_all(fd, &header, sizeof (header));
    if (nr_read == 0 && proxy->nr_tx == 0)
        die(ERR_JDWP_EOF, "EOF from peer");
    if (nr_read < sizeof (header))
        die(EINVAL, "short read of packet header");

    jdwp_header_to_host(&header);
    if (header.length < sizeof (header))
        die(EINVAL, "impossibly small JDWP packet");

    size_t allocsz = offsetof(struct jdwp_packet, header);
    if (SATADD(&allocsz, allocsz, header.length) ||
        SATADD(&allocsz, allocsz, 1))
    {
        die(EINVAL, "impossibly huge JDWP packet");
    }

    struct reslist* rl = reslist_create();
    WITH_CURRENT_RESLIST(rl);
    struct jdwp_packet* packet = xcalloc(allocsz);
    packet->rl = rl;
    packet->header = header;
    size_t to_read = header.length - sizeof (header);
    nr_read = read_all(fd, &packet->header.data[0], to_read);
    if (nr_read < to_read) {
        die(ERR_JDWP_EOF, "short read of JDWP packet");
    }
    return packet;
}

static struct jdwp_packet*
jdwp_read_packet_from_app(struct jdwp_proxy* proxy)
{
    struct jdwp_packet* packet =
        jdwp_pop_deferred_packet_from_app(proxy);
    if (packet == NULL)
        packet = jdwp_read_packet(proxy, proxy->to_app_fd);
    return packet;
}

static void
cleanup_decrement_transact_count(void* arg)
{
    struct jdwp_proxy* proxy = arg;
    assert(proxy->nr_tx > 0);
    proxy->nr_tx -= 1;
}

static struct jdwp_packet*
jdwp_transact_with_app(struct jdwp_proxy* proxy,
                       struct jdwp_builder* b)
{
    SCOPED_RESLIST(rl);

    assert(proxy->nr_tx == 0);
    struct cleanup* cl_nr_tx = cleanup_allocate();
    proxy->nr_tx += 1;
    cleanup_commit(cl_nr_tx, cleanup_decrement_transact_count, proxy);

    uint32_t transaction_id = make_jdwp_id(proxy);
    struct jdwp_header* command = &b->header;
    command->id = transaction_id;
    jdwp_builder_send(b, proxy->to_app_fd);

    LIST_HEAD(, jdwp_packet) deferred = LIST_HEAD_INITIALIZER(&deferred);
    struct jdwp_packet* reply = NULL;
    do {
        SCOPED_RESLIST(rl_loop);
        struct jdwp_packet* packet = jdwp_read_packet_from_app(proxy);
        WITH_CURRENT_RESLIST(rl);
        reslist_reparent(packet->rl);
        if (!jdwp_command_p(&packet->header) &&
            packet->header.id == transaction_id)
        {
            reply = packet;
        } else {
            assert(!packet->on_list);
            LIST_INSERT_HEAD(&deferred, packet, link);
            packet->on_list = true;
        }
    } while (!reply);

    while (!LIST_EMPTY(&deferred)) {
        struct jdwp_packet* packet = LIST_FIRST(&deferred);
        assert(packet->on_list);
        LIST_REMOVE(packet, link);
        packet->on_list = false;
        jdwp_defer_packet_from_app(proxy, packet);
    }

    WITH_CURRENT_RESLIST(rl->parent);
    reslist_reparent(reply->rl);

    if (reply->header.reply.error_code != 0)
        die_jdwp(reply->header.reply.error_code);

    return reply;
}

static void
handle_packet_toplevel(
    struct jdwp_proxy* proxy,
    struct jdwp_packet* packet,
    int recv_fd,
    int onward_fd)
{
    dbg("received from %s JDWP packet %s",
        ( recv_fd == proxy->to_debugger_fd
          ? "debugger"
          : "debugee" ),
        describe_jdwp_message(&packet->header));

    if (proxy->mode == JDWP_MODE_REWRITE) {
        if (jdwp_command_p(&packet->header))
            on_jdwp_command(proxy, packet, recv_fd, onward_fd);
        else
            on_jdwp_reply(proxy, packet, recv_fd, onward_fd);
    } else {
        jdwp_send_packet(onward_fd, &packet->header);
    }
}

static void
update_type_sizes(struct jdwp_proxy* proxy)
{
    SCOPED_RESLIST(rl);

    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_VIRTUALMACHINE;
    b.header.command.code = JDWP_COMMAND_VM_IDSIZES;
    struct jdwp_packet* reply =
        jdwp_transact_with_app(proxy, &b);

    struct jdwp_type* int_ = proxy->tt->type.int_;
    struct jdwp_type* reply_type =
        jdwp_find_reply_type(proxy->tt, &b.header);
    struct jdwp_cursor c =
        jdwp_cursor_create(
            reply_type,
            reply->header.data,
            reply->header.length - sizeof (reply->header));

    int32_t fieldIDSize;
    int32_t methodIDSize;
    int32_t objectIDSize;
    int32_t referenceTypeIDSize;
    int32_t frameIDSize;

    jdwp_cursor_check_type(&c, reply_type);
    jdwp_cursor_enter(&c);

    jdwp_cursor_check_struct_field(&c, int_, "fieldIDSize");
    jdwp_cursor_read(&c, &fieldIDSize, sizeof (fieldIDSize));
    jdwp_cursor_next(&c);

    jdwp_cursor_check_struct_field(&c, int_, "methodIDSize");
    jdwp_cursor_read(&c, &methodIDSize, sizeof (methodIDSize));
    jdwp_cursor_next(&c);

    jdwp_cursor_check_struct_field(&c, int_, "objectIDSize");
    jdwp_cursor_read(&c, &objectIDSize, sizeof (objectIDSize));
    jdwp_cursor_next(&c);

    jdwp_cursor_check_struct_field(&c, int_, "referenceTypeIDSize");
    jdwp_cursor_read(&c, &referenceTypeIDSize, sizeof (referenceTypeIDSize));
    jdwp_cursor_next(&c);

    jdwp_cursor_check_struct_field(&c, int_, "frameIDSize");
    jdwp_cursor_read(&c, &frameIDSize, sizeof (frameIDSize));
    jdwp_cursor_next(&c);

    jdwp_cursor_leave(&c);

    assert(c.pos == c.end);

    proxy->tt->type.field_id->scalar.width = fieldIDSize;
    proxy->tt->type.method_id->scalar.width = methodIDSize;
    proxy->tt->type.object_id->scalar.width = objectIDSize;
    proxy->tt->type.reference_type_id->scalar.width = referenceTypeIDSize;
    proxy->tt->type.frame_id->scalar.width = frameIDSize;

    dbg("updated type sizes: fieldIDSize:%d methodIDSize:%d "
        "objectIDSize:%d referenceTypeIDSize:%d frameIDSize:%d",
        (int) fieldIDSize,
        (int) methodIDSize,
        (int) objectIDSize,
        (int) referenceTypeIDSize,
        (int) frameIDSize);
}

struct heap_dump {
    uint8_t* data;
    size_t size;
};

static struct heap_dump
read_heap_dump(
    struct jdwp_proxy* proxy)
{
    SCOPED_RESLIST(rl);

    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_DDM;
    b.header.command.code = JDWP_COMMAND_DDM_CHUNK;
    b.header.id = make_jdwp_id(proxy);

    uint8_t chunk_type[] = { 'H', 'P', 'D', 'S' }; // HeaP Dump Streaming
    uint32_t chunk_length = 0;
    jdwp_builder_raw_bytes(&b, chunk_type, sizeof (chunk_type));
    jdwp_builder_u32(&b, chunk_length);

    log_info(proxy, "requesting heap dump for class list; please wait...");
    double start_time = seconds_since_epoch();
    jdwp_transact_with_app(proxy, &b);

    // Between our requesting a heap dump and getting the JDWP reply,
    // the debugee should have sent us a command packet containing the
    // dump itself.  (Why not put the dump in the reply? That would
    // make sense. Can't have that on mobile.)  Pull the dump packet
    // out of the queue, assume ownership, and give it to our caller.

    struct jdwp_packet* dump = NULL;
    struct jdwp_packet* packet;

    LIST_FOREACH(packet, &proxy->deferred_from_app, link) {
        if (jdwp_command_p(&packet->header) &&
            packet->header.command.group == JDWP_COMMANDSET_DDM &&
            packet->header.command.code == JDWP_COMMAND_DDM_CHUNK &&
            packet->header.length >= 8 &&
            memcmp(packet->header.data, chunk_type, 4) == 0)
        {
            assert(packet->on_list);
            LIST_REMOVE(packet, link);
            packet->on_list = false;
            reslist_reparent(packet->rl);
            dump = packet;
            break;
        }
    }

    if (dump == NULL)
        die(EINVAL, "did not receive JDWP dump reply as expected");

    double elapsed = seconds_since_epoch() - start_time;
    log_info(proxy, "heap dump received (%uKB in %g seconds)",
             (unsigned) ((dump->header.length - sizeof (dump->header))/1024),
             elapsed);

    uint8_t* payload = &dump->header.data[0];
    uint32_t chunk_size;
    memcpy(&chunk_size, payload + 4, 4);
    chunk_size = ntohl(chunk_size);

    WITH_CURRENT_RESLIST(rl->parent);
    reslist_reparent(dump->rl);
    struct heap_dump hd = {
        .data = payload + 8,
        .size = chunk_size,
    };
    return hd;
}

enum hd_item_type {
    HD_ITEM_STRING,
    HD_ITEM_CLASS,
};

struct hd_item {
    uint64_t id;
    enum hd_item_type type;
    RB_ENTRY(hd_item) link;
    union {
        struct {
            char data[0];
        } string;

        struct {
            uint64_t name_string_id;
        } class;
    };
};

struct hd_parse_context {
    uint8_t* start;
    uint8_t* pos;
    uint8_t* end;
    int id_size;
    RB_HEAD(hd_items, hd_item) items;
};

static int
hd_item_cmp(struct hd_item* left, struct hd_item* right)
{
    if (left->id < right->id)
        return -1;
    if (left->id > right->id)
        return 1;
    if (left->type < right->type)
        return -1;
    if (left->type > right->type)
        return 1;
    return 0;
}

RB_PROTOTYPE_STATIC(hd_items, hd_item, link, hd_item_cmp);
RB_GENERATE_STATIC(hd_items, hd_item, link, hd_item_cmp);

static void
hd_checked_memcpy(
    struct hd_parse_context* pc,
    void* out_bytes,
    size_t size)
{
    if (pc->end - pc->pos < size)
        die(EINVAL, "truncated heap dump");
    memcpy(out_bytes, pc->pos, size);
}

#define HPROF_TAG_STRING 0x01
#define HPROF_TAG_LOAD_CLASS 0x02
#define HPROF_TAG_HEAP_DUMP 0x0C
#define HPROF_TAG_HEAP_DUMP_SEGMENT 0x1C

static void
hd_slurp(
    struct hd_parse_context* pc,
    void* out_bytes,
    size_t size)
{
    hd_checked_memcpy(pc, out_bytes, size);
    pc->pos += size;
}

static void
hd_skip(
    struct hd_parse_context* pc,
    size_t size)
{
    if (pc->end - pc->pos < size)
        die(EINVAL, "truncated heap dump");
    pc->pos += size;
}

static uint32_t
hd_slurp_u32(struct hd_parse_context* pc)
{
    uint32_t value;
    hd_slurp(pc, &value, sizeof (value));
    value = ntohl(value);
    return value;
}

static uint16_t
hd_slurp_u16(struct hd_parse_context* pc)
{
    uint16_t value;
    hd_slurp(pc, &value, sizeof (value));
    value = ntohs(value);
    return value;
}

static uint8_t
hd_slurp_u8(struct hd_parse_context* pc)
{
    uint8_t value;
    hd_slurp(pc, &value, sizeof (value));
    return value;
}

static char*
hd_slurp_string(struct hd_parse_context* pc, size_t size)
{
    if (size == SIZE_MAX)
        die(EINVAL, "bogus string size");
    char* data = xalloc(size + 1);
    hd_slurp(pc, data, size);
    data[size] = '\0';
    return data;
}

static void
hd_check_id(struct hd_parse_context* pc)
{
    if (pc->id_size < 0)
        die(EINVAL, "no ID size read for heap dump");
}

static uint64_t
hd_slurp_id(struct hd_parse_context* pc)
{
    hd_check_id(pc);
    assert(pc->id_size <= 8);
    uint8_t bytes[pc->id_size];
    hd_slurp(pc, &bytes[0], pc->id_size);
    swap_bytes(&bytes[0], pc->id_size);
    uint64_t value = 0;
    memcpy(&value, bytes, pc->id_size);
    return value;
}

static struct hd_item*
hd_find_item(struct hd_parse_context* pc,
             uint64_t id,
             enum hd_item_type type)
{
    struct hd_item search = {
        .id = id,
        .type = type,
    };
    return RB_FIND(hd_items, &pc->items, &search);
}

static const char*
hd_find_string(struct hd_parse_context* pc, uint64_t id)
{
    struct hd_item* item = hd_find_item(pc, id, HD_ITEM_STRING);
    return item == NULL ? NULL : item->string.data;
}

static void
hd_insert_item(struct hd_parse_context* pc, struct hd_item* item)
{
#ifndef NDEBUG
    if (hd_find_item(pc, item->id, item->type) != NULL)
        die(EINVAL, "duplicate item id:%llu type:%d",
            (llu) item->id, item->type);
#endif
    RB_INSERT(hd_items, &pc->items, item);
}

static unsigned
hd_slurp_element_size(struct hd_parse_context* pc)
{
    uint8_t eltype = hd_slurp_u8(pc);
    unsigned elsize;
    switch (eltype) {
        case 2: // object
            hd_check_id(pc);
            elsize = pc->id_size;
            break;
        case 4: // boolean
            elsize = 1;
            break;
        case 5: // char
            elsize = 2;
            break;
        case 6: // float
            elsize = 4;
            break;
        case 7: // double
            elsize = 8;
            break;
        case 8: // byte
            elsize = 1;
            break;
        case 9: // short
            elsize = 2;
            break;
        case 10: // int
            elsize = 4;
            break;
        case 11: // long
            elsize = 8;
            break;
        default:
            die(EINVAL, "unexpected primitive array item type %hhu", eltype);
    }
    return elsize;
}

static void
hd_intern_string_chunk(struct hd_parse_context* pc, size_t length)
{
    hd_check_id(pc);
    if (length < pc->id_size)
        die(EINVAL, "short string tag");
    size_t data_size = length - pc->id_size;
    size_t allocsz;
    if (SATADD(&allocsz, sizeof(struct hd_item), data_size) ||
        SATADD(&allocsz, allocsz, 1) /* terminating NUL */)
        die(EINVAL, "overlong tag");
    struct hd_item* item = xcalloc(allocsz);
    item->id = hd_slurp_id(pc);
    item->type = HD_ITEM_STRING;
    hd_slurp(pc, item->string.data, data_size);
    item->string.data[data_size] = '\0';
#ifdef HPROF_VERBOSE_DEBUG
    dbg("interning string chunk id:%llu data:[%s]",
        (llu) item->id, item->string.data);
#endif
    hd_insert_item(pc, item);
}

static void
hd_intern_class_chunk(struct hd_parse_context* pc, size_t length)
{
    struct hd_item* item = xcalloc(sizeof (*item));
    item->type = HD_ITEM_CLASS;
    hd_skip(pc, 4); // Don't care about serial number
    item->id = hd_slurp_id(pc);
    hd_skip(pc, 4); // Don't care about stack trace serial number
    item->class.name_string_id = hd_slurp_id(pc);
#if HPROF_VERBOSE_DEBUG
    dbg("interning class id:%llu name:[%s]",
        (llu) item->id,
        hd_find_string(pc, item->class.name_string_id));
#endif
    hd_insert_item(pc, item);
}

struct hd_class_list {
    size_t nr_classes;
    char** signatures;
};

static char*
java_class_name_to_signature(const char* name)
{
    size_t namelen = strlen(name);
    unsigned array_depth = 0;
    while (namelen >= 2 && name[namelen - 2] == '[' && name[namelen - 1] == ']') {
        array_depth += 1;
        namelen -= 2;
    }

    size_t allocsz = 1/*L*/ + array_depth + namelen + 2 /*;NUL*/;
    char* signature = xalloc(allocsz);
    char* pos = signature;
    while (array_depth > 0) {
        *pos++ = '[';
        --array_depth;
    }

    static const struct {
        char c;
        const char* name;
    } primitives[] = {
        { 'Z', "boolean" },
        { 'B', "byte" },
        { 'C', "char" },
        { 'S', "short" },
        { 'I', "int" },
        { 'J', "long" },
        { 'F', "float" },
        { 'D', "double" }
    };

    bool found_primitive = false;
    for (unsigned i = 0; i < ARRAYSIZE(primitives); ++i) {
        const char* primitive_name = primitives[i].name;
        size_t primitive_namelen = strlen(primitive_name);
        if (namelen >= primitive_namelen &&
            memcmp(name, primitive_name, primitive_namelen) == 0 &&
            ( name[primitive_namelen] == '\0' ||
              name[primitive_namelen] == '[' ))
        {
            found_primitive = true;
            *pos++ = primitives[i].c;
            break;
        }
    }

    if (!found_primitive) {
        *pos++ = 'L';
        for (size_t i = 0; i < namelen; ++i) {
            char c = name[i];
            if (c == '.')
                c = '/';
            *pos++ = c;
        }
        *pos++ = ';';
    }

    *pos++ = '\0';
    return signature;
}

static struct heap_dump
map_heap_dump(const char* filename)
{
    int fd = xopen("/home/dancol/com.facebook.wakizashi.hprof", O_RDONLY, 0);
    struct stat stat = xfstat(fd);

    struct heap_dump hd = {
        .data = (uint8_t*) mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0),
        .size = stat.st_size,
    };

    if (hd.data == (uint8_t*) MAP_FAILED)
        die_errno("mmap");

    return hd;
}

static struct hd_class_list
read_class_list_via_heap_dump(struct jdwp_proxy* proxy)
{
    SCOPED_RESLIST(rl);
    struct heap_dump hd = read_heap_dump(proxy);
    struct hd_parse_context pc_buf = {
        .start = hd.data,
        .pos = hd.data,
        .end = hd.data + hd.size,
        .id_size = -1,
    };
    struct hd_parse_context* pc = &pc_buf;
    RB_INIT(&pc->items);

    char* magic = xstrndup((char*) pc->pos, pc->end - pc->pos);
    dbg("heap dump format: [%s]", magic);
    pc->pos += strlen(magic) + 1;
    if (pc->pos > pc->end)
        die(EINVAL, "truncated heap dump");

    if (strcmp(magic, "JAVA PROFILE 1.0.3") != 0)
        die(EINVAL, "invalid heap dump format [%s]", magic);

    pc->id_size = hd_slurp_u32(pc);
#if HPROF_VERBOSE_DEBUG
    dbg("heap dump ID size is %u", pc->id_size);
#endif
    if (pc->id_size > 8)
        die(EINVAL, "bogus heap dump ID size %u", pc->id_size);

    hd_skip(pc, 8); // We don't care about dump timestamp

    while (pc->pos < pc->end) {
        uint8_t tag = hd_slurp_u8(pc);
        hd_skip(pc, 4); // Don't care about timestamp
        uint32_t length = hd_slurp_u32(pc);
        if (tag == HPROF_TAG_STRING) {
            hd_intern_string_chunk(pc, length);
        } else if (tag == HPROF_TAG_LOAD_CLASS) {
            hd_intern_class_chunk(pc, length);
        } else {
#if HPROF_VERBOSE_DEBUG
            dbg("skipping hprof chunk type:0x%02hhx length:%u", tag, length);
#endif
            hd_skip(pc, length);
        }
    }

    WITH_CURRENT_RESLIST(rl->parent);

    struct hd_item* item;
    struct hd_class_list hcl;
    memset(&hcl, 0, sizeof (hcl));
    RB_FOREACH(item, hd_items, &pc->items)
        if (item->type == HD_ITEM_CLASS)
            hcl.nr_classes++;

    if (hcl.nr_classes > SIZE_MAX / sizeof (hcl.signatures[0]))
        die(EINVAL, "too many classes");

    size_t i = 0;
    hcl.signatures = xalloc(hcl.nr_classes * sizeof (hcl.signatures[0]));
    RB_FOREACH(item, hd_items, &pc->items) {
        if (item->type == HD_ITEM_CLASS) {
            uint64_t name_string_id = item->class.name_string_id;
            const char* name = hd_find_string(pc, name_string_id);
            if (name == NULL) {
                log_warn(proxy,
                         "could not find name of class (id:%llu) in heap dump",
                         (llu) name_string_id);
                hcl.nr_classes -= 1;
                continue;
            }
            hcl.signatures[i++] = java_class_name_to_signature(name);
        }
    }

    assert(i == hcl.nr_classes);
    return hcl;
}

static struct fdh*
listen_on_jdwp_on_port(struct jdwp_proxy* proxy, const char* port)
{
    SCOPED_RESLIST(rl);
    static const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_flags = AI_PASSIVE,
        .ai_socktype = SOCK_STREAM,
    };

    struct addrinfo* ai =
        xgetaddrinfo_interruptible("localhost", port, &hints);

    while (ai && ai->ai_family != AF_INET)
        ai = ai->ai_next;

    if (!ai)
        die(ENOENT, "xgetaddrinfo returned no addresses");

    int sock = xsocket(ai->ai_family,
                       ai->ai_socktype,
                       ai->ai_protocol);

    int v = 1;
    xsetsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof (v));

    // Bind to TCP socket and start accepting connections
    struct addr* listen_addr = addrinfo2addr(ai);
    xbind(sock, listen_addr);
    xlisten(sock, 1);

    log_info(proxy,
             "listening on %s for JDWP connection",
             describe_addr(listen_addr));

    WITH_CURRENT_RESLIST(rl->parent);
    return fdh_dup(sock);
}

static void
suspend_vm(struct jdwp_proxy* proxy)
{
    SCOPED_RESLIST(rl);
    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_VIRTUALMACHINE;
    b.header.command.code = JDWP_COMMAND_VM_SUSPEND;
    jdwp_transact_with_app(proxy, &b);
}

static void
resume_vm(struct jdwp_proxy* proxy)
{
    SCOPED_RESLIST(rl);
    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_VIRTUALMACHINE;
    b.header.command.code = JDWP_COMMAND_VM_RESUME;
    jdwp_transact_with_app(proxy, &b);
}

static void
dispose_object_id(struct jdwp_proxy* proxy, uint64_t id)
{
    SCOPED_RESLIST(rl);
    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_VIRTUALMACHINE;
    b.header.command.code = JDWP_COMMAND_VM_DISPOSEOBJECTS;
    jdwp_builder_i32(&b, 1); // number of dispose records

    // dispose record
    jdwp_builder_reference_type_id(&b, id); // id
    jdwp_builder_i32(&b, 1); // refcount

    jdwp_transact_with_app(proxy, &b);
}

// Keep track of fake reference type IDs we've sent to the debugger.
// We keep these references around forever.

struct jdwp_classloader;
struct fake_reftype {
    SPLAY_ENTRY(fake_reftype) link_by_fake_id;
    uint64_t fake_id;
    SPLAY_ENTRY(fake_reftype) link_by_signature;
    struct jdwp_classloader* cl;
    const char* signature;
    uint8_t ref_type_tag;
    int32_t status;
    bool was_unloaded;
    struct real_reftype* real; // weak; set to NULL when real disappears
};

static int
fake_reftype_cmp_by_id(
    struct fake_reftype* left,
    struct fake_reftype* right)
{
    return cmp_u64(left->fake_id, right->fake_id);
}

SPLAY_PROTOTYPE_STATIC(
    fake_reftype_by_id,
    fake_reftype,
    link_by_fake_id,
    fake_reftype_cmp_by_id);

SPLAY_GENERATE_STATIC(
    fake_reftype_by_id,
    fake_reftype,
    link_by_fake_id,
    fake_reftype_cmp_by_id);

static int
fake_reftype_cmp_by_signature(
    struct fake_reftype* left,
    struct fake_reftype* right)
{
    return strcmp(left->signature, right->signature);
}

SPLAY_PROTOTYPE_STATIC(
    fake_reftype_by_signature,
    fake_reftype,
    link_by_signature,
    fake_reftype_cmp_by_signature);

SPLAY_GENERATE_STATIC(
    fake_reftype_by_signature,
    fake_reftype,
    link_by_signature,
    fake_reftype_cmp_by_signature);

// Keep track of reference types we've received from the debuggee; we
// flush these once we have too many.

struct real_reftype {
    SPLAY_ENTRY(real_reftype) link;
    uint64_t real_id;
    uint64_t refcount;
    struct fake_reftype* fake; // strong
    struct reslist* rl;
};

static int
real_reftype_cmp(
    struct real_reftype* left,
    struct real_reftype* right)
{
    return cmp_u64(left->real_id, right->real_id);
}

SPLAY_PROTOTYPE_STATIC(
    real_reftype_by_id,
    real_reftype,
    link,
    real_reftype_cmp);

SPLAY_GENERATE_STATIC(
    real_reftype_by_id,
    real_reftype,
    link,
    real_reftype_cmp);

static struct real_reftype*
find_real_reftype_by_real_id(
    struct jdwp_proxy* proxy,
    uint64_t real_id)
{
    struct real_reftype probe = {
        .real_id = real_id,
    };
    return SPLAY_FIND(real_reftype_by_id, &proxy->real_reftype_cache, &probe);
}

static struct fake_reftype*
find_fake_reftype_by_signature(
    struct jdwp_classloader* cl,
    const char* signature)
{
    struct fake_reftype probe = {
        .signature = signature,
    };
    return SPLAY_FIND(fake_reftype_by_signature,
                      &cl->fake_reftypes_by_signature,
                      &probe);
}

static char*
fetch_signature_for_reftype(
    struct jdwp_proxy* proxy,
    uint64_t id)
{
    SCOPED_RESLIST(rl);
    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_REFERENCETYPE;
    b.header.command.code = JDWP_COMMAND_RT_SIGNATURE;
    jdwp_builder_id(&b, id, proxy->tt->type.reference_type_id);
    struct jdwp_packet* reply =
        jdwp_transact_with_app(proxy, &b);
    struct jdwp_cursor c = jdwp_cursor_create(
        jdwp_find_reply_type(proxy->tt, &b.header),
        reply->header.data,
        reply->header.length - sizeof (reply->header));
    jdwp_cursor_enter(&c);
    char* signature;
    {
        WITH_CURRENT_RESLIST(rl->parent);
        signature = jdwp_cursor_read_string(&c);
    }
    jdwp_cursor_next(&c);
    jdwp_cursor_leave(&c);
    dbg("reftype_id:%llu signature:{%s}", (llu) id, signature);
    return signature;
}

static uint64_t
fetch_classloader_for_reftype(
    struct jdwp_proxy* proxy,
    uint64_t id)
{
    SCOPED_RESLIST(rl);
    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_REFERENCETYPE;
    b.header.command.code = JDWP_COMMAND_RT_CLASSLOADER;
    jdwp_builder_id(&b, id, proxy->tt->type.reference_type_id);
    struct jdwp_packet* reply =
        jdwp_transact_with_app(proxy, &b);
    struct jdwp_cursor c = jdwp_cursor_create(
        jdwp_find_reply_type(proxy->tt, &b.header),
        reply->header.data,
        reply->header.length - sizeof (reply->header));
    jdwp_cursor_enter(&c);
    uint64_t classloader_id =
        jdwp_cursor_read_id(&c, proxy->tt->type.object_id);
    jdwp_cursor_next(&c);
    jdwp_cursor_leave(&c);
    return classloader_id;
}

static bool
fetch_is_interface_for_reftype(
    struct jdwp_proxy* proxy,
    uint64_t id)
{
    SCOPED_RESLIST(rl);
    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_REFERENCETYPE;
    b.header.command.code = JDWP_COMMAND_RT_MODIFIERS;
    jdwp_builder_id(&b, id, proxy->tt->type.reference_type_id);
    struct jdwp_packet* reply =
        jdwp_transact_with_app(proxy, &b);
    struct jdwp_cursor c = jdwp_cursor_create(
        jdwp_find_reply_type(proxy->tt, &b.header),
        reply->header.data,
        reply->header.length - sizeof (reply->header));
    jdwp_cursor_enter(&c);
    int32_t modifiers = jdwp_cursor_read_i32(&c);
    jdwp_cursor_next(&c);
    jdwp_cursor_leave(&c);
    return modifiers & ACC_INTERFACE;
}

static struct jdwp_classloader*
find_or_create_classloader(
    struct jdwp_proxy* proxy,
    uint64_t id,
    bool* created_anew)
{
    struct jdwp_classloader* cl;
    if (created_anew)
        *created_anew = false;
    SLIST_FOREACH(cl, &proxy->classloaders, link) {
        if (cl->id == id)
            return cl;
    }

    dbg("creating new CL structure for CL %llu", (llu) id);

    WITH_CURRENT_RESLIST(proxy->rl);
    cl = xcalloc(sizeof (*cl));
    cl->id = id;
    SPLAY_INIT(&cl->fake_reftypes_by_signature);
    SLIST_INSERT_HEAD(&proxy->classloaders, cl, link);
    proxy->nr_classloaders += 1;
    if (created_anew)
        *created_anew = true;
    return cl;
}

static void
disable_gc_for_object(struct jdwp_proxy* proxy, uint64_t id)
{
    SCOPED_RESLIST(rl);
    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_OBJECTREFERENCE;
    b.header.command.code = JDWP_COMMAND_OR_DISABLECOLLECTION;
    jdwp_builder_reference_type_id(&b, id);
    jdwp_transact_with_app(proxy, &b);
}

static struct jdwp_classloader*
cl_for_reftype(struct jdwp_proxy* proxy, uint64_t real_reftype_id)
{
    bool cl_created_anew;
    struct jdwp_classloader* cl =
        find_or_create_classloader(
            proxy,
            fetch_classloader_for_reftype(proxy, real_reftype_id),
            &cl_created_anew);
    if (cl->id == 0) {
        // Do nothing: we're looking at the system classloader
    } else if (cl_created_anew) {
        // We hold onto classloaders forever, so the VM should too
        disable_gc_for_object(proxy, cl->id);
    } else {
        // We don't want to overflow the object reference count, so
        // release the refcount back to the VM if we already have a
        // permanent reference in the jdwp_classloader
        dispose_object_id(proxy, cl->id);
    }

    return cl;
}

static void
flush_reftype_cache_1(struct jdwp_proxy* proxy, uint32_t max_to_kill)
{
    SCOPED_RESLIST(rl);
    struct real_reftype* rr;
    struct real_reftype* rr_first;
    struct real_reftype_by_id* cache = &proxy->real_reftype_cache;
    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_VIRTUALMACHINE;
    b.header.command.code = JDWP_COMMAND_VM_DISPOSEOBJECTS;
    uint32_t to_kill = XMIN(max_to_kill, proxy->real_reftype_cache_size);
    jdwp_builder_i32(&b, to_kill);

    rr_first = SPLAY_MIN(real_reftype_by_id, cache);
    rr = rr_first;
    for (uint32_t i = 0;
         i < to_kill;
         ++i, rr = SPLAY_NEXT(real_reftype_by_id, cache, rr))
    {
        jdwp_builder_reference_type_id(&b, rr->real_id);
        jdwp_builder_i32(&b, rr->refcount);
    }

    jdwp_transact_with_app(proxy, &b);

    struct real_reftype* rr_next = rr_first;
    for (uint32_t i = 0; i < to_kill; ++i) {
        rr = rr_next;
        rr_next = SPLAY_NEXT(real_reftype_by_id, cache, rr);
        assert(rr);
        SPLAY_REMOVE(real_reftype_by_id, &proxy->real_reftype_cache, rr);
        assert(rr->fake);
        rr->fake->real = NULL;
        reslist_destroy(rr->rl);
    }

    proxy->real_reftype_cache_size -= to_kill;
}

static void
flush_reftype_cache(struct jdwp_proxy* proxy)
{
    uint32_t overhead = sizeof (struct jdwp_header) + 4;
    uint32_t bytes_per_dispose =
        jdwp_scalar_width(proxy->tt->type.reference_type_id) + 4;

    if (proxy->app_packet_size_limit < overhead + bytes_per_dispose)
        die(EINVAL, "cannot dispose objects: app_packet_size_limit "
            "too small to fit even one object");

    uint32_t max_disposes_per_packet =
        (proxy->app_packet_size_limit - overhead) / bytes_per_dispose;

    dbg("clearing reftype cache cursize:%u max:%u per-pkt:%u",
        proxy->real_reftype_cache_size,
        proxy->real_reftype_cache_max,
        max_disposes_per_packet);


    while (proxy->real_reftype_cache_size)
        flush_reftype_cache_1(proxy, max_disposes_per_packet);
    assert(SPLAY_EMPTY(&proxy->real_reftype_cache));
}

static struct fake_reftype*
translate_and_cache_real_reftype(
    struct jdwp_proxy* proxy,
    uint64_t real_id,
    const char* optional_signature,
    const uint8_t* optional_ref_type_tag)
{
    SCOPED_RESLIST(rl);

    struct real_reftype* rr = find_real_reftype_by_real_id(proxy, real_id);
    bool new_real_reftype = false;
    if (rr == NULL) {
        assert(proxy->real_reftype_cache_max > 0);
        if (proxy->real_reftype_cache_size >= proxy->real_reftype_cache_max)
            flush_reftype_cache(proxy);

        new_real_reftype = true;
        WITH_CURRENT_RESLIST(proxy->rl);
        struct reslist* rr_rl = reslist_create();
        WITH_CURRENT_RESLIST(rr_rl);
        rr = xcalloc(sizeof (*rr));
        rr->real_id = real_id;
        rr->rl = rr_rl;
        SPLAY_INSERT(real_reftype_by_id, &proxy->real_reftype_cache,  rr);
        proxy->real_reftype_cache_size += 1;
    }
    assert(rr->refcount < UINT64_MAX);
    rr->refcount += 1;

    if (new_real_reftype) {
        assert(rr->fake == NULL);
        struct jdwp_classloader* cl = cl_for_reftype(proxy, real_id);
        const char* signature = optional_signature;
        if (signature == NULL)
            signature = fetch_signature_for_reftype(proxy, real_id);
        rr->fake = find_fake_reftype_by_signature(cl, signature);
        if (rr->fake != NULL) {
            assert(rr->fake->real == NULL);
        } else {
            uint8_t ref_type_tag;
            if (optional_ref_type_tag != NULL)
                ref_type_tag = *optional_ref_type_tag;
            else if (signature[0] == '[')
                ref_type_tag = REFKIND_ARRAY;
            else
                ref_type_tag = fetch_is_interface_for_reftype(proxy, real_id)
                    ? REFKIND_INTERFACE
                    : REFKIND_CLASS;
            WITH_CURRENT_RESLIST(proxy->rl);
            struct fake_reftype* fr = xcalloc(sizeof (*fr));
            fr->fake_id = ++proxy->next_fake_reftype_id;
            fr->cl = cl;
            fr->signature = xstrdup(signature);
            fr->ref_type_tag = ref_type_tag;
            SPLAY_INSERT(
                fake_reftype_by_signature,
                &cl->fake_reftypes_by_signature,
                fr);
            SPLAY_INSERT(
                fake_reftype_by_id,
                &proxy->fake_reftypes_by_id,
                fr);
            proxy->nr_fake_ids += 1;
            rr->fake = fr;
        }
        rr->fake->real = rr;
    }

    return rr->fake;
}

static struct fake_reftype*
find_fake_reftype_by_id(
    struct jdwp_proxy* proxy,
    uint64_t id)
{
    struct fake_reftype probe = {
        .fake_id = id,
    };
    return SPLAY_FIND(fake_reftype_by_id, &proxy->fake_reftypes_by_id, &probe);
}

static void
refresh_classes_with_signature(
    struct jdwp_proxy* proxy,
    const char* signature)
{
    SCOPED_RESLIST(rl);
    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_VIRTUALMACHINE;
    b.header.command.code = JDWP_COMMAND_VM_CLASSESBYSIGNATURE;
    jdwp_builder_string(&b, signature);
    struct jdwp_packet* reply = jdwp_transact_with_app(proxy, &b);
    struct jdwp_type* reply_type =
        jdwp_find_reply_type(proxy->tt, &b.header);
    struct jdwp_cursor c =
        jdwp_cursor_create(
            reply_type,
            reply->header.data,
            reply->header.length - sizeof (reply->header));
    jdwp_cursor_enter(&c);
    uint32_t nr_classes = jdwp_cursor_array_length(&c);
    jdwp_cursor_enter(&c);
    struct jdwp_type* reference_type_id = proxy->tt->type.reference_type_id;
    for (uint32_t i = 0; i < nr_classes; ++i) {
        jdwp_cursor_enter(&c);
        uint8_t ref_type_tag = jdwp_cursor_read_u8(&c);
        if (ref_type_tag != REFKIND_CLASS &&
            ref_type_tag != REFKIND_INTERFACE &&
            ref_type_tag != REFKIND_ARRAY)
            die(EINVAL, "invalid ref type id from debugee: %hhu", ref_type_tag);
        jdwp_cursor_next(&c);
        uint64_t real_refid = jdwp_cursor_read_id(&c, reference_type_id);
        jdwp_cursor_next(&c);
        int32_t status = jdwp_cursor_read_i32(&c);
        jdwp_cursor_next(&c);
        jdwp_cursor_leave(&c);
        struct fake_reftype* fr =
            translate_and_cache_real_reftype(
                proxy,
                real_refid,
                signature,
                &ref_type_tag);
        fr->status = status;
        jdwp_cursor_next(&c);
    }
    jdwp_cursor_leave(&c);
    jdwp_cursor_leave(&c);
}

static uint64_t
translate_fake_reftype_to_real_reftype(
    struct jdwp_proxy* proxy,
    uint64_t fake_id)
{
    struct fake_reftype* fr = find_fake_reftype_by_id(proxy, fake_id);
    if (fr == NULL) {
        struct real_reftype* rr = find_real_reftype_by_real_id(proxy, fake_id);
        if (rr != NULL)
            dbg("LEAK OF REAL ID %llu!!!!", (llu) rr->real_id);
        dbg("could not find fake reftype by fake_id:%llu", (llu) fake_id);
        die_jdwp(JDWP_ERR_INVALID_OBJECT);
    }
    if (fr->real == NULL && !fr->was_unloaded)
        refresh_classes_with_signature(proxy, fr->signature);
    if (fr->real == NULL) {
        // We didn't find any classes with this signature,
        // so it must have been unloaded
        if (!fr->was_unloaded)
            fr->was_unloaded = true;
        dbg("no classes found with sig {%s} and cl:%llu",
            fr->signature, (llu) fr->cl->id);
        die_jdwp(JDWP_ERR_INVALID_CLASS);
    }
    return fr->real->real_id;
}

static void
jdwp_send_all_classes_reply(
    struct jdwp_proxy* proxy,
    uint32_t id,
    enum all_classes_reply_mode mode,
    uint64_t class_loader_filter)
{
    struct fake_reftype* fr;
    uint32_t nr_live_classes = 0;
    SPLAY_FOREACH(fr, fake_reftype_by_id, &proxy->fake_reftypes_by_id) {
        if (mode == ALL_CLASSES_REPLY_CLR &&
            fr->cl->id != class_loader_filter)
        {
            continue;
        }
        if (!fr->was_unloaded)
            nr_live_classes++;
    }

    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.id = id;
    b.header.flags = JDWP_FLAG_REPLY;
    jdwp_builder_u32(&b, nr_live_classes);
    SPLAY_FOREACH(fr, fake_reftype_by_id, &proxy->fake_reftypes_by_id) {
        if (mode == ALL_CLASSES_REPLY_CLR &&
            fr->cl->id != class_loader_filter)
        {
            continue;
        }
        if (fr->was_unloaded)
            continue;
        jdwp_builder_u8(&b, fr->ref_type_tag);
        jdwp_builder_reference_type_id(&b, fr->fake_id);
        if (mode > ALL_CLASSES_REPLY_CLR) {
            jdwp_builder_string(&b, fr->signature);
            if (mode >= ALL_CLASSES_REPLY_GENERIC)
                jdwp_builder_string(&b, ""); // ART 6.x does the same
            jdwp_builder_u32(&b, fr->status);
        }
    }
    jdwp_builder_send(&b, proxy->to_debugger_fd);
}

static void
translate_payload_2(
    struct jdwp_proxy* proxy,
    enum translate_mode mode,
    struct jdwp_type* top_type,
    void* data,
    size_t data_size)
{
    SCOPED_RESLIST(rl);
    struct jdwp_type* reference_type_id = proxy->tt->type.reference_type_id;
    struct jdwp_cursor c = jdwp_cursor_create(top_type, data, data_size);
    while (jdwp_cursor_has_value(&c)) {
        struct jdwp_type* type = jdwp_cursor_current_type(&c);
        if (jdwp_cursor_can_enter(&c)) {
            jdwp_cursor_enter(&c);
            continue;
        }

        if (jdwp_type_isinstance(type, reference_type_id)) {
            uint64_t id = jdwp_cursor_read_id(&c, reference_type_id);
            if (id != 0) {
                const char* direction;
                uint64_t orig_id = id;
                if (mode == TRANSLATE_TO_DEBUGGER) {
                    direction = "debugger";
                    id = translate_and_cache_real_reftype(
                        proxy, id, NULL, NULL)->fake_id;
                } else if (mode == TRANSLATE_TO_APP) {
                    direction = "app";
                    id = translate_fake_reftype_to_real_reftype(proxy, id);
                } else {
                    assert(!"invalid mode");
                }

                (void) orig_id;
                (void) direction;
                dbg("rewrote reference_type_id %llu to %llu for "
                    "consumption by %s",
                    (llu) orig_id,
                    (llu) id,
                    direction);
            }
            jdwp_cursor_write_id(&c, id, reference_type_id);
        }

        jdwp_cursor_next(&c);
        while (!jdwp_cursor_has_value(&c) && jdwp_cursor_has_parent(&c)) {
            jdwp_cursor_leave(&c);
        }
    }
}

struct translate_args {
    struct jdwp_proxy* proxy;
    enum translate_mode mode;
    struct jdwp_type* top_type;
    void* data;
    size_t data_size;
};

static void
translate_payload_1(void* arg)
{
    struct translate_args* info = arg;
    translate_payload_2(
        info->proxy,
        info->mode,
        info->top_type,
        info->data,
        info->data_size);
}

static uint16_t
translate_payload(
    struct jdwp_proxy* proxy,
    enum translate_mode mode,
    struct jdwp_type* top_type,
    void* data,
    size_t data_size)
{
    uint16_t ret = 0;
    struct errinfo ei = { .want_msg = true };
    struct translate_args info = {
        .proxy = proxy,
        .mode = mode,
        .top_type = top_type,
        .data = data,
        .data_size = data_size,
    };
    if (catch_error(translate_payload_1, &info, &ei)) {
        if (JDWP_ERR_TO_FBADB_ERR(0) <= ei.err &&
            ei.err <= JDWP_ERR_TO_FBADB_ERR(JDWP_ERR_MAX))
        {
            ret = ei.err - ERR_JDWP_BASE;
        } else {
            die_rethrow(&ei);
        }
    }
    return ret;
}

struct vm_info {
    const char* description;
    int32_t major;
    int32_t minor;
    const char* version;
    const char* name;
};

static struct vm_info
update_vm_version(struct jdwp_proxy* proxy)
{
    SCOPED_RESLIST(rl);
    struct vm_info vi;
    struct jdwp_builder b;
    jdwp_builder_start(&b, proxy);
    b.header.command.group = JDWP_COMMANDSET_VIRTUALMACHINE;
    b.header.command.code = JDWP_COMMAND_VM_VERSION;
    struct jdwp_packet* reply = jdwp_transact_with_app(proxy, &b);
    struct jdwp_type* reply_type =
        jdwp_find_reply_type(proxy->tt, &b.header);
    struct jdwp_cursor c =
        jdwp_cursor_create(
            reply_type,
            reply->header.data,
            reply->header.length - sizeof (reply->header));

    memset(&vi, 0, sizeof (vi));
    WITH_CURRENT_RESLIST(rl->parent);
    jdwp_cursor_enter(&c);
    vi.description = jdwp_cursor_read_string(&c);
    jdwp_cursor_next(&c);
    vi.major = jdwp_cursor_read_i32(&c);
    jdwp_cursor_next(&c);
    vi.minor = jdwp_cursor_read_i32(&c);
    jdwp_cursor_next(&c);
    vi.version = jdwp_cursor_read_string(&c);
    jdwp_cursor_next(&c);
    vi.name = jdwp_cursor_read_string(&c);
    jdwp_cursor_next(&c);
    jdwp_cursor_leave(&c);
    return vi;
}

static bool
may_be_pid(const char* s)
{
    for (; *s; ++s)
        if (!('0' <= *s && *s <= '9'))
            return false;
    return true;
}

static char*
pidof(const struct cmd_jdwp_info* info, const char* what)
{
    SCOPED_RESLIST(rl);

    struct start_peer_info spi = {
        .adb = info->adb,
        .transport = info->transport,
        .specified_io = true,
        .io[STDIN_FILENO] = CHILD_IO_DEV_NULL,
        .io[STDOUT_FILENO] = CHILD_IO_PIPE,
    };

    struct child* peer = start_peer(
        &spi, strlist_from_argv(ARGV("pidof", what)));
    char* resp = slurp_fd(peer->fd[STDOUT_FILENO]->fd, NULL);
    child_wait_die_on_error(peer);
    WITH_CURRENT_RESLIST(rl->parent);
    return xstrdup(resp);
}

static void
jdwp_main_1(void* arg)
{
    const struct cmd_jdwp_info* info = arg;
    SCOPED_RESLIST(rl);
    struct jdwp_proxy proxy_object = {
        .rl = rl,
        .tt = jdwp_type_table_new(),
        .to_app_fd = -1,
        .to_debugger_fd = -1,
        .real_reftype_cache_max = REFERENCE_CACHE_SIZE,
        .app_packet_size_limit = INT32_MAX,
        .next_fake_reftype_id = 1000000000LLU /* make more prominent */,
        .quiet = info->jdwp.quiet,
    };

    struct jdwp_proxy* proxy = &proxy_object;
    setup_jdwp_types(proxy->tt);
    LIST_INIT(&proxy->pending_packets);
    LIST_INIT(&proxy->deferred_from_app);
    SLIST_INIT(&proxy->classloaders);
    SPLAY_INIT(&proxy->fake_reftypes_by_id);
    SPLAY_INIT(&proxy->real_reftype_cache);

    const char* to_what = info->to_what;
    if (!may_be_pid(to_what))
        to_what = pidof(info, to_what);

    proxy->to_app_fd = jdwp_connect(&info->adb, to_what);
    dbg("connected to device jdwp for [%s]: to_app_fd=%d",
        info->to_what, proxy->to_app_fd);

    do_jdwp_handshake_as_client(proxy->to_app_fd);
    update_type_sizes(proxy);
    struct vm_info vi = update_vm_version(proxy);
    dbg("VM: description:[%s] major:%d minor:%d version:[%s] name:[%s]",
        vi.description, vi.major, vi.minor, vi.version, vi.name);

    // Yes, Dalvik still sets the fields to 1.6
    bool is_art = string_starts_with_p(vi.description, "Android Runtime 2.");
    if (is_art) {
        log_info(proxy, "ART detected");
        // ART's JDWP implementation is boneheaded and has a hardcoded
        // 8K receive buffer.  It'll *send* us bigger packets, but
        // won't accept them.
        proxy->app_packet_size_limit = ART_HARDCODED_PACKET_MAXIMUM;
    }

    const char* mode = info->jdwp.mode ?: "auto";
    if (strcmp(mode, "auto") == 0)
        mode = is_art ? "rewrite" : "dumb";

    if (strcmp(mode, "rewrite") == 0) {
        proxy->mode = JDWP_MODE_REWRITE;
        log_info(proxy, "Activing large-application protocol rewriting");
    } else {
        log_info(proxy, "Proxying JDWP protocol literally");
        assert(strcmp(mode, "dumb") == 0);
    }

    if (info->jdwp.suspend) {
        log_info(proxy, "suspending VM as requested");
        suspend_vm(proxy);
    }

    const char* accept_port = info->jdwp.jdwp_listen_port ?: "12345";
    struct fdh* server_socket = listen_on_jdwp_on_port(proxy, accept_port);

    if (proxy->mode == JDWP_MODE_REWRITE) {
        suspend_vm(proxy);
        struct hd_class_list hcl = read_class_list_via_heap_dump(proxy);
        log_info(proxy, "learing about the %u classes from the heap dump",
                 (unsigned) hcl.nr_classes);
        double start_time = seconds_since_epoch();
        for (size_t i = 0; i < hcl.nr_classes; ++i) {
            if (i > 0 && i % 5000 == 0)
                log_info(proxy, "learned about %u classes", (unsigned) i);
            refresh_classes_with_signature(proxy, hcl.signatures[i]);
        }
        double elapsed = seconds_since_epoch() - start_time;
        log_info(proxy, "learned about %u classes in %g seconds",
                 (unsigned) hcl.nr_classes, elapsed);
        dbg("done refreshing classes: generated %u fake reftype "
            "IDs for %u classloaders",
            proxy->nr_fake_ids, proxy->nr_classloaders);
        resume_vm(proxy);
    }

    log_info(proxy, "accepting connection");
    proxy->to_debugger_fd = xaccept(server_socket->fd);
    fdh_destroy(server_socket);
    dbg("accepted JDWP connection on port %s: to_debugger_fd=%d",
        accept_port, proxy->to_debugger_fd);

    do_jdwp_handshake_as_server(proxy->to_debugger_fd);

    struct pollfd fds[] = {
        { proxy->to_app_fd, POLLIN },
        { proxy->to_debugger_fd, POLLIN },
    };

    struct jdwp_packet* packet;

    for (;;) {
        SCOPED_RESLIST(rl_loop);
        packet = jdwp_pop_deferred_packet_from_app(proxy);
        if (packet != NULL) {
            handle_packet_toplevel(
                proxy,
                packet,
                proxy->to_app_fd,
                proxy->to_debugger_fd);
            continue;
        }

        for (unsigned i = 0; i < ARRAYSIZE(fds); ++i)
            fds[i].revents = 0;
        xpoll(fds, ARRAYSIZE(fds), -1);
        for (unsigned i = 0; i < ARRAYSIZE(fds); ++i) {
            if (!fds[i].revents) continue;
            int recv_fd = fds[i].fd;
            int onward_fd = fds[(i+1)%2].fd;
            packet = jdwp_read_packet(proxy, recv_fd);
            handle_packet_toplevel(proxy, packet, recv_fd, onward_fd);
        }
    }
}

int
jdwp_main(const struct cmd_jdwp_info* info)
{
    (void) jdwp_builder_i64;
    (void) jdwp_builder_i16;
    (void) jdwp_builder_i8;
    (void) jdwp_builder_object_id;
    (void) hd_slurp_u16;
    (void) hd_slurp_string;
    (void) hd_slurp_element_size;
    (void) map_heap_dump;

    struct errinfo ei = { .want_msg = true };
    if (catch_error(jdwp_main_1, (void*) info, &ei)) {
        if (ei.err != ERR_JDWP_EOF)
            die_rethrow(&ei);
    }
    return 0;
}
