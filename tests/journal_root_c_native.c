// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_journal_root.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <wchar.h>
_Static_assert(sizeof(wchar_t) == sizeof(uint16_t), "Windows native argument width");
#endif

/* This executable links the actual shared C ABI, without test-support objects
 * or native C++ adapters. Its only path is an explicit fixture supplied by the
 * runner. Provisioning, security and all durability I/O belong to the worker. */
#ifdef _WIN32
int wmain(int argc, wchar_t **argv) {
#else
int main(int argc, char **argv) {
#endif
    ckfe_engine *engine = NULL;
    ckfe_directory *parent = NULL;
    ckfjr_root *root = NULL, *alias = NULL;
    ckfe_error error;
    ckfjr_options_v1 options;
    ckfjr_snapshot_v1 snapshot;
    int result = 0;
    uint32_t drained = 0;
    time_t deadline;
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "journal_root_c_native: line %d: %s\n", __LINE__, #condition); \
    result = 1; goto done; } } while (0)
    ckfe_error_init(&error);
    ckfjr_options_init_v1(&options);
    ckfjr_snapshot_init_v1(&snapshot);
    CHECK(argc == 2);
    CHECK(ckfe_abi_version_major() == 0 && ckfe_abi_version_minor() >= 4);
    CHECK(ckfe_engine_create(&engine) == CKFE_API_OK && engine != NULL);
#ifdef _WIN32
    CHECK(ckfe_directory_open_utf16(engine, (const uint16_t *)argv[1], wcslen(argv[1]),
        0, &parent, &error) == CKFE_API_OK);
#else
    CHECK(ckfe_directory_open_utf8(engine, argv[1], 0, &parent, &error) == CKFE_API_OK);
#endif
    options.parent = parent;
    options.disposition = CKFJR_PROVISION_CHILD;
#ifdef _WIN32
    {
        static const uint16_t name[] = {'p','u','r','e','-','c','-','r','o','o','t'};
        options.child.encoding = CKFJR_UTF16;
        options.child.data = name;
        options.child.byte_count = sizeof(name);
    }
#else
    options.child.encoding = CKFJR_POSIX_BYTES;
    options.child.data = "pure-c-root";
    options.child.byte_count = sizeof("pure-c-root") - 1;
#endif
    CHECK(ckfjr_start_v1(&options, &root) == CKFE_API_OK && root != NULL);
    /* Start must already own the parent and copied component. */
    ckfe_directory_destroy(parent); parent = NULL;
    ckfe_engine_destroy(engine); engine = NULL;
    memset(&options, 0, sizeof(options));
    deadline = time(NULL) + 60;
    for (;;) {
        CHECK(ckfjr_poll_v1(root, &snapshot) == CKFE_API_OK);
        if (snapshot.state == CKFJR_READY) break;
        CHECK(snapshot.state == CKFJR_PREPARING);
        CHECK(time(NULL) < deadline);
        CHECK(ckfjr_wait_v1(root, 20) == CKFE_API_OK);
    }
    CHECK(snapshot.identity_scheme != 0);
    CHECK(snapshot.directory_creates == 1);
    CHECK(snapshot.acquired_directories >= 2 && snapshot.flushed_directories != 0);
    CHECK(snapshot.failure_domain == CKFE_ERROR_NONE && !snapshot.recovery_required);
    CHECK(ckfjr_retain_v1(root, &alias) == CKFE_API_OK && alias != NULL);
    ckfjr_release(root); root = alias; alias = NULL;
    CHECK(ckfjr_poll_v1(root, &snapshot) == CKFE_API_OK && snapshot.state == CKFJR_READY);
done:
    ckfe_directory_destroy(parent);
    ckfe_engine_destroy(engine);
    ckfjr_release(alias);
    if (root != NULL) {
        if (ckfjr_finish_v1(root) != CKFE_API_OK) result = 1;
        deadline = time(NULL) + 60;
        for (;;) {
            if (ckfjr_worker_drained_v1(root, &drained) != CKFE_API_OK) { result = 1; break; }
            if (drained) break;
            if (time(NULL) >= deadline) { result = 1; break; }
            if (ckfjr_wait_v1(root, 20) != CKFE_API_OK) { result = 1; break; }
        }
        if (ckfjr_poll_v1(root, &snapshot) != CKFE_API_OK || !drained ||
            snapshot.state != CKFJR_COMPLETE || !snapshot.worker_drained ||
            snapshot.failure_domain != CKFE_ERROR_NONE || snapshot.recovery_required) {
            fprintf(stderr, "journal_root_c_native: final state=%u drained=%u error=%u/%lld %s\n",
                snapshot.state, drained, snapshot.failure_domain,
                (long long)snapshot.failure_code, snapshot.failure_operation);
            result = 1;
        }
        ckfjr_release(root);
    }
    ckfe_error_free(&error);
    if (!result) puts("shared C journal root: provision, parent lifetime, retain and final drain passed");
    return result;
#undef CHECK
}
