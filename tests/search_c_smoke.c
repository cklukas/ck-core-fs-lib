// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif

#include "ck_fs_search.h"

#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif

static void tiny_sleep(void) {
#ifndef _WIN32
    struct timespec ts = {0, 5000000L};
    nanosleep(&ts, NULL);
#endif
}

#ifndef _WIN32
static void wait_search_done(const ckfes_job *job, ckfes_snapshot_v1 *snap) {
    for (int i = 0; i < 2000; ++i) {
        assert(ckfes_poll_v1(job, snap) == CKFE_API_OK);
        if (snap->state != CKFES_RUNNING) break;
        tiny_sleep();
    }
    assert(snap->state != CKFES_RUNNING);
}

static void release_and_drain(ckfes_job *job) {
    ckfes_request_cancel(job);
    uint32_t drained = 0;
    for (int i = 0; i < 2000; ++i) {
        assert(ckfes_worker_drained_v1(job, &drained) == CKFE_API_OK);
        if (drained) break;
        tiny_sleep();
    }
    assert(drained == 1);
    ckfes_release(job);
}

static void rm_rf(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
        chmod(path, 0700);
        char cmd[4096];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
        (void)system(cmd);
    } else {
        unlink(path);
    }
}
#endif

int main(void) {
    ckfe_error err;
    ckfe_error_init(&err);

    ckfes_options_v1 opts;
    ckfes_options_init_v1(&opts);
    assert(opts.version == CKFES_VERSION);
    assert(opts.struct_size == sizeof(opts));

    ckfes_job *bad_job = (ckfes_job *)(uintptr_t)1;
    assert(ckfes_start_v1(NULL, &bad_job, &err) == CKFE_API_INVALID_ARGUMENT);
    assert(bad_job == NULL);

    /* Relative root path must be rejected */
    opts.root_path.data = "relative/path";
    opts.root_path.units = 13;
    opts.root_path.encoding = CKFES_POSIX_BYTES;
    bad_job = (ckfes_job *)(uintptr_t)1;
    assert(ckfes_start_v1(&opts, &bad_job, &err) == CKFE_API_INVALID_ARGUMENT);
    assert(bad_job == NULL);

    /* Invalid UTF-16 relative address must be rejected; valid UNC lexical validation */
    const uint16_t rel_u16[] = {'f', 'o', 'o'};
    ckfes_options_init_v1(&opts);
    opts.root_path.data = rel_u16;
    opts.root_path.units = 3;
    opts.root_path.encoding = CKFES_UTF16;
    assert(ckfes_start_v1(&opts, &bad_job, &err) == CKFE_API_INVALID_ARGUMENT);

    /* Reversed size bounds must be rejected */
    ckfes_options_init_v1(&opts);
    opts.root_path.data = "/";
    opts.root_path.units = 1;
    opts.has_minimum_size = 1;
    opts.has_maximum_size = 1;
    opts.minimum_size = 100;
    opts.maximum_size = 50;
    assert(ckfes_start_v1(&opts, &bad_job, &err) == CKFE_API_INVALID_ARGUMENT);

#ifndef _WIN32
    const char *tmp_base = getenv("TMPDIR");
    if (!tmp_base || !*tmp_base) tmp_base = "/var/tmp";
    char tmpl[1024];
    snprintf(tmpl, sizeof(tmpl), "%s/ckfes-test-XXXXXX", tmp_base);
    char *root = mkdtemp(tmpl);
    assert(root != NULL);

    char outside[1024];
    snprintf(outside, sizeof(outside), "%s/ckfes-outside-XXXXXX", tmp_base);
    char *ext_dir = mkdtemp(outside);
    assert(ext_dir != NULL);

    char ext_secret[1200];
    snprintf(ext_secret, sizeof(ext_secret), "%s/report-999.txt", ext_dir);
    FILE *fp = fopen(ext_secret, "wb");
    assert(fp != NULL);
    fputs("NEEDLE_CROSS_BOUNDARY\n", fp);
    fclose(fp);

    /* Build deep path > 320 bytes (> legacy 260 MAX_PATH) + UTF-8 exact name */
    char cur[2048];
    snprintf(cur, sizeof(cur), "%s", root);
    for (int d = 0; d < 6; ++d) {
        char seg[96];
        snprintf(seg, sizeof(seg), "/segment_%02d_abcdefghijklmnopqrstuvwxyz_0123456789_longdir", d);
        strcat(cur, seg);
        assert(mkdir(cur, 0700) == 0);
    }
    assert(strlen(cur) > 320);

    char deep_file[2200];
    snprintf(deep_file, sizeof(deep_file), "%s/report-42-Ümlaut.txt", cur);
    fp = fopen(deep_file, "wb");
    assert(fp != NULL);
    /* Place needle straddling the 65536-byte read chunk boundary */
    for (size_t i = 0; i < 65530; ++i) fputc('A', fp);
    fputs("NEEDLE_CROSS_BOUNDARY", fp);
    for (size_t i = 0; i < 200; ++i) fputc('B', fp);
    fclose(fp);
    struct timespec recent_ts[2] = {{1760000000L, 0}, {1760000000L, 0}};
    assert(utimensat(AT_FDCWD, deep_file, recent_ts, 0) == 0);

    /* Old small file that should be excluded by size/date filters */
    char old_file[1200];
    snprintf(old_file, sizeof(old_file), "%s/report-01-old.txt", root);
    fp = fopen(old_file, "wb");
    assert(fp != NULL);
    fputs("NEEDLE_CROSS_BOUNDARY small\n", fp);
    fclose(fp);
    struct timespec old_ts[2] = {{1600000000L, 0}, {1600000000L, 0}};
    assert(utimensat(AT_FDCWD, old_file, old_ts, 0) == 0);

    /* Binary file containing NUL + needle (must be skipped when skip_binary_content=1) */
    char bin_file[1200];
    snprintf(bin_file, sizeof(bin_file), "%s/report-02-bin.txt", root);
    fp = fopen(bin_file, "wb");
    assert(fp != NULL);
    const char bin_payload[] = "BIN\0NEEDLE_CROSS_BOUNDARY";
    fwrite(bin_payload, 1, sizeof(bin_payload), fp);
    fclose(fp);

    /* Hidden file */
    char hid_file[1200];
    snprintf(hid_file, sizeof(hid_file), "%s/.hidden_report.txt", root);
    fp = fopen(hid_file, "wb");
    assert(fp != NULL);
    fputs("NEEDLE_CROSS_BOUNDARY\n", fp);
    fclose(fp);

    /* Symlink pointing to outside directory — must NEVER be traversed */
    char sym_path[1200];
    snprintf(sym_path, sizeof(sym_path), "%s/escape_link", root);
    assert(symlink(ext_dir, sym_path) == 0);

    /* Unreadable directory when non-root — must be skipped gracefully */
    char denied_dir[1200];
    snprintf(denied_dir, sizeof(denied_dir), "%s/denied_sub", root);
    assert(mkdir(denied_dir, 0700) == 0);
    if (geteuid() != 0) {
        assert(chmod(denied_dir, 0000) == 0);
    }

    /* 1) Combined glob + cross-boundary content + min_size + modified_not_before */
    ckfes_options_init_v1(&opts);
    opts.root_path.data = root;
    opts.root_path.units = strlen(root);
    const char *glob_pat = "report-[0-9]*.txt";
    opts.name_mode = CKFES_NAME_GLOB;
    opts.name_query.data = glob_pat;
    opts.name_query.units = strlen(glob_pat);
    const char *needle = "needle_cross_boundary";
    opts.content_query.data = needle;
    opts.content_query.units = strlen(needle);
    opts.case_sensitive = 0;
    opts.include_hidden = 0;
    opts.skip_binary_content = 1;
    opts.has_minimum_size = 1;
    opts.minimum_size = 60000;
    opts.has_modified_not_before = 1;
    opts.modified_not_before.seconds = 1700000000L;

    ckfes_job *job = NULL;
    assert(ckfes_start_v1(&opts, &job, &err) == CKFE_API_OK);
    assert(job != NULL);

    ckfes_snapshot_v1 snap;
    wait_search_done(job, &snap);
    assert(snap.state == CKFES_COMPLETE);
    assert(snap.matched_entries == 1);

    ckfes_hit_v1 hit;
    uint32_t got = 0;
    assert(ckfes_page_v1_get(job, 0, &hit, 1, &got) == CKFE_API_OK);
    assert(got == 1);
    assert(hit.kind == CKFE_OBJECT_REGULAR_FILE);
    assert(hit.logical_size > 65536);

    uint64_t req_units = 0;
    uint32_t enc = 99;
    assert(ckfes_path_copy_v1(job, 0, NULL, 0, &req_units, &enc) == CKFE_API_BUFFER_TOO_SMALL);
    assert(req_units == hit.relative_units && req_units > 300 && enc == CKFES_POSIX_BYTES);
    char *rel_buf = (char *)malloc((size_t)req_units + 1);
    assert(rel_buf != NULL);
    assert(ckfes_path_copy_v1(job, 0, rel_buf, req_units, &req_units, &enc) == CKFE_API_OK);
    rel_buf[req_units] = '\0';
    assert(strstr(rel_buf, "report-42-Ümlaut.txt") != NULL);
    free(rel_buf);
    release_and_drain(job);

    /* 2) Cancellation + drain test */
    for (int i = 0; i < 120; ++i) {
        char fpath[1200];
        snprintf(fpath, sizeof(fpath), "%s/bulk-%03d.dat", root, i);
        fp = fopen(fpath, "wb");
        assert(fp != NULL);
        fputs("bulk content line\n", fp);
        fclose(fp);
    }
    ckfes_options_init_v1(&opts);
    opts.root_path.data = root;
    opts.root_path.units = strlen(root);
    opts.include_hidden = 1;
    assert(ckfes_start_v1(&opts, &job, &err) == CKFE_API_OK);
    ckfes_request_cancel(job);
    release_and_drain(job);

    chmod(denied_dir, 0700);
    rm_rf(root);
    rm_rf(ext_dir);
#endif
    ckfe_error_free(&err);
    puts("search_c_smoke: PASS");
    return 0;
}
