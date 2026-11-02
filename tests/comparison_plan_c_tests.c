// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_plan.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef NDEBUG
#error "comparison_plan_c_tests requires enabled assertions"
#endif

static ckfsp_identity identity(unsigned char id) {
    ckfsp_identity result;
    memset(&result, 0, sizeof(result));
    result.namespace_id = 1; result.scheme = CKFSP_ID_POSIX;
    result.volume[0] = 1; result.object[0] = id;
    result.has_generation = 1; result.generation = 1;
    return result;
}
static ckfsp_entry file(const void *key, uint64_t length, unsigned char id) {
    ckfsp_entry e;
    ckfsp_entry_init(&e);
    e.relative_key.data = key; e.relative_key.length = length;
    e.object.state = CKFSP_OBJECT_STABLE;
    e.object.known_fields = CKFSP_FIELD_IDENTITY | CKFSP_FIELD_KIND | CKFSP_FIELD_SIZE | CKFSP_FIELD_MODIFIED | CKFSP_FIELD_CHANGE_COOKIE;
    e.object.identity = identity(id); e.object.kind = CKFSP_REGULAR_FILE;
    e.object.size = 10; e.object.modified.seconds = 100;
    e.object.timestamp_quantum_ns = 1; e.object.change_cookie = 1;
    return e;
}
static void digest(ckfsp_entry *e, unsigned char value) {
    e->has_digest = 1;
    memset(&e->digest, 0, sizeof(e->digest));
    e->digest.state = CKFSP_DIGEST_COMPLETE_STABLE; e->digest.algorithm = CKFSP_SHA256;
    e->digest.bytes[0] = value; e->digest.bytes_read = e->object.size;
    e->digest.before = e->object; e->digest.after = e->object;
}
static ckfsp_input input(ckfsp_entry *s, uint64_t sn, ckfsp_entry *d, uint64_t dn) {
    ckfsp_input in;
    ckfsp_input_init(&in);
    in.options.topology = CKFSP_DISJOINT;
    in.source.state = in.destination.state = CKFSP_INVENTORY_COMPLETE_STABLE;
    in.source.has_root = in.destination.has_root = 1;
    in.source.root = identity(100); in.destination.root = identity(200);
    in.source.entries = s; in.source.entry_count = sn;
    in.destination.entries = d; in.destination.entry_count = dn;
    return in;
}
static ckfsp_plan *plan(const ckfsp_input *in) {
    ckfsp_plan *p = NULL;
    assert(ckfsp_plan_create(in, &p) == CKFSP_OK && p != NULL);
    return p;
}
static ckfsp_row row(const ckfsp_plan *p) {
    ckfsp_row result; ckfsp_page page;
    assert(ckfsp_plan_page(p, 0, &result, 1, &page) == CKFSP_OK);
    assert(page.row_count == 1 && result.token.plan_id == page.plan_id);
    return result;
}
static ckfsp_row preview(ckfsp_input *in) {
    ckfsp_plan *p = plan(in);
    ckfsp_row r = row(p); ckfsp_plan_destroy(p); return r;
}
static void profiles(void) {
    uint32_t profile;
    ckfsp_entry s = file("a", 1, 1), d = file("a", 1, 2);
    ckfsp_input in = input(&s, 1, NULL, 0);
    for (profile = CKFSP_COPY; profile <= CKFSP_COMPARE; ++profile) {
        ckfsp_row r;
        in.options.profile = profile; in.destination.entry_count = 0; in.destination.entries = NULL;
        r = preview(&in);
        assert(r.relation == CKFSP_REL_SOURCE_ONLY);
        assert(r.action == (profile == CKFSP_COMPARE ? CKFSP_ACTION_REPORT : profile == CKFSP_MOVE ? CKFSP_ACTION_MOVE_AFTER_COMMIT : CKFSP_ACTION_COPY));
        in.destination.entries = &d; in.destination.entry_count = 1;
        d.object.size = 20; d.object.modified.seconds = 99;
        r = preview(&in);
        assert(r.action == (profile == CKFSP_COMPARE ? CKFSP_ACTION_REPORT :
            profile == CKFSP_COPY || profile == CKFSP_MOVE ? CKFSP_ACTION_REVIEW :
            profile == CKFSP_MISSING_ONLY ? CKFSP_ACTION_SKIP : CKFSP_ACTION_REPLACE));
    }
}
static void digest_and_unknown(void) {
    ckfsp_entry s = file("a", 1, 1), d = file("a", 1, 2);
    ckfsp_input in = input(&s, 1, &d, 1);
    ckfsp_row r;
    in.options.profile = CKFSP_SYNC;
    r = preview(&in); assert(r.relation == CKFSP_REL_SAME_SIZE_MTIME && r.relation != CKFSP_REL_IDENTICAL);
    in.options.comparison_mode = CKFSP_SIZE;
    r = preview(&in); assert(r.relation == CKFSP_REL_SAME_SIZE);
    in.options.comparison_mode = CKFSP_COMPLETE_DIGEST;
    r = preview(&in); assert(r.relation == CKFSP_REL_UNKNOWN && r.action == CKFSP_ACTION_REVIEW);
    digest(&s, 1); digest(&d, 1);
    r = preview(&in); assert(r.relation == CKFSP_REL_IDENTICAL);
    d.digest.state = CKFSP_DIGEST_INCOMPLETE;
    r = preview(&in); assert(r.relation == CKFSP_REL_UNKNOWN && r.destination_protected);
    digest(&d, 1); d.digest.after.identity.object[15] = 42;
    r = preview(&in); assert(r.reason == CKFSP_REASON_DIGEST_BINDING_MISMATCH);
    digest(&d, 2); r = preview(&in); assert(r.relation == CKFSP_REL_CONTENT_DIFFERENT);
    in.source.entries = NULL; in.source.entry_count = 0; in.options.profile = CKFSP_MIRROR;
    d.digest.state = CKFSP_DIGEST_UNKNOWN;
    r = preview(&in); assert(r.relation == CKFSP_REL_UNKNOWN && r.action != CKFSP_ACTION_REMOVE_FILE);
    in.options.comparison_mode = CKFSP_SIZE;
    in.source.state = CKFSP_INVENTORY_INCOMPLETE;
    r = preview(&in); assert(r.reason == CKFSP_REASON_INCOMPLETE_INVENTORY);
    in.source.state = CKFSP_INVENTORY_COMPLETE_STABLE; d.object.state = CKFSP_OBJECT_DENIED;
    r = preview(&in); assert(r.relation == CKFSP_REL_UNKNOWN);
}
static void keys_pages_and_tokens(void) {
    const unsigned char raw_key[] = {0xff, 'z'};
    ckfsp_entry entries[3] = {file("c", 1, 3), file(raw_key, sizeof(raw_key), 2), file("a", 1, 1)};
    ckfsp_input in = input(entries, 3, NULL, 0);
    ckfsp_plan *p, *other;
    ckfsp_row rows[2], repeat[2]; ckfsp_page page;
    ckfsp_summary summary; uint64_t n; uint32_t validation;
    unsigned char buffer[4] = {7, 7, 7, 7};
    in.options.limits.max_page_rows = 2;
    p = plan(&in); other = plan(&in);
    assert(ckfsp_plan_get_summary(p, &summary) == CKFSP_OK && summary.rows == 3 && summary.source_bytes == 30);
    assert(ckfsp_plan_page(p, 0, rows, 2, &page) == CKFSP_OK);
    assert(page.row_count == 2 && page.next_offset == 2 && page.has_next && rows[0].source_index == 0);
    assert(ckfsp_plan_page(p, 0, repeat, 2, &page) == CKFSP_OK);
    assert(memcmp(rows, repeat, sizeof(rows)) == 0);
    assert(ckfsp_plan_page(p, 2, repeat, 2, &page) == CKFSP_OK && page.row_count == 1 && !page.has_next);
    assert(ckfsp_plan_path_length(p, 3, &n) == CKFSP_OK && n == sizeof(raw_key));
    assert(ckfsp_plan_copy_path(p, 3, buffer, 1, &n) == CKFSP_BUFFER_TOO_SMALL && n == 0 && buffer[0] == 0);
    assert(ckfsp_plan_copy_path(p, 3, buffer, sizeof(buffer), &n) == CKFSP_OK && n == sizeof(raw_key));
    assert(memcmp(buffer, raw_key, sizeof(raw_key)) == 0 && buffer[2] == 7); // no implicit NUL
    assert(ckfsp_plan_page(p, 3, repeat, 2, &page) == CKFSP_OK && page.row_count == 0);
    memset(repeat, 7, sizeof(repeat)); memset(&page, 7, sizeof(page));
    assert(ckfsp_plan_page(p, 4, repeat, 2, &page) == CKFSP_INVALID_ARGUMENT && page.row_count == 0 && repeat[0].token.row_id == 0);
    assert(ckfsp_plan_page(p, 0, repeat, 0, &page) == CKFSP_INVALID_ARGUMENT);
    assert(ckfsp_plan_revalidate(p, &rows[0].token, &in, &validation) == CKFSP_OK && validation == CKFSP_REVALIDATION_MATCHES);
    assert(ckfsp_plan_revalidate(other, &rows[0].token, &in, &validation) == CKFSP_OK && validation == CKFSP_REVALIDATION_FOREIGN_TOKEN);
    entries[0].object.size = 11;
    assert(ckfsp_plan_revalidate(p, &rows[0].token, &in, &validation) == CKFSP_OK && validation == CKFSP_REVALIDATION_EVIDENCE_CHANGED);
    assert(ckfsp_plan_get_summary(p, &summary) == CKFSP_OK && summary.source_bytes == 30); // owned immutable copies
    entries[0].object.size = 10; entries[0].object.identity.volume[15] = 1;
    assert(ckfsp_plan_revalidate(p, &rows[0].token, &in, &validation) == CKFSP_OK && validation == CKFSP_REVALIDATION_EVIDENCE_CHANGED);
    entries[0].object.identity.volume[15] = 0; entries[0].object.identity.object[15] = 1;
    assert(ckfsp_plan_revalidate(p, &rows[0].token, &in, &validation) == CKFSP_OK && validation == CKFSP_REVALIDATION_EVIDENCE_CHANGED);
    entries[0].object.identity.object[15] = 0; entries[0].object.identity.namespace_id = 2;
    assert(ckfsp_plan_revalidate(p, &rows[0].token, &in, &validation) == CKFSP_OK && validation == CKFSP_REVALIDATION_EVIDENCE_CHANGED);
    in.version = 99;
    assert(ckfsp_plan_revalidate(p, &rows[0].token, &in, &validation) == CKFSP_INVALID_ARGUMENT && validation == CKFSP_REVALIDATION_NOT_CHECKED);
    n = 7; assert(ckfsp_plan_path_length(p, 0, &n) == CKFSP_INVALID_ARGUMENT && n == 0);
    n = 7; assert(ckfsp_plan_copy_path(NULL, 1, buffer, sizeof(buffer), &n) == CKFSP_INVALID_ARGUMENT && n == 0 && buffer[0] == 0);
    ckfsp_plan_destroy(p); ckfsp_plan_destroy(other); ckfsp_plan_destroy(NULL);
}
static void filters_and_protection(void) {
    ckfsp_entry d[2] = {file("dir", 3, 1), file("dir/a", 5, 2)};
    ckfsp_input in = input(NULL, 0, d, 2);
    ckfsp_bytes exclusion = {"dir/a", 5};
    ckfsp_plan *p; ckfsp_row r[2]; ckfsp_page page;
    d[0].object.kind = CKFSP_DIRECTORY; d[0].object.known_fields &= ~CKFSP_FIELD_SIZE;
    in.options.profile = CKFSP_MIRROR;
    in.excluded_paths = &exclusion; in.exclusion_count = 1;
    p = plan(&in);
    assert(ckfsp_plan_page(p, 0, r, 2, &page) == CKFSP_OK);
    assert(r[0].reason == CKFSP_REASON_PROTECTED_DESCENDANT && r[1].reason == CKFSP_REASON_EXCLUDED);
    ckfsp_plan_destroy(p);
    in.exclusion_count = 0; in.excluded_paths = NULL;
    in.options.filters.has_minimum_size = 1; in.options.filters.minimum_size = 11;
    p = plan(&in); assert(ckfsp_plan_page(p, 0, r, 2, &page) == CKFSP_OK);
    assert(r[1].reason == CKFSP_REASON_FILTERED && r[0].destination_protected); ckfsp_plan_destroy(p);
    in.options.filters.has_minimum_size = 0; in.options.filters.has_modified_before = 1;
    in.options.filters.modified_before.seconds = 100;
    p = plan(&in); assert(ckfsp_plan_page(p, 0, r, 2, &page) == CKFSP_OK && r[1].reason == CKFSP_REASON_FILTERED); ckfsp_plan_destroy(p);
}
static void invalid_inputs(void) {
    ckfsp_entry e = file("a", 1, 1);
    ckfsp_input in = input(&e, 1, NULL, 0);
    ckfsp_plan *p = (ckfsp_plan *)(uintptr_t)1;
    ckfsp_summary summary; ckfsp_page page; ckfsp_row r; uint32_t v = 77;
    assert(ckfsp_plan_create(NULL, &p) == CKFSP_INVALID_ARGUMENT && p == NULL);
    assert(ckfsp_plan_create(&in, NULL) == CKFSP_INVALID_ARGUMENT);
    in.version = 2; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT && p == NULL);
    in.version = CKFSP_VERSION; in.struct_size--; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    in.struct_size = sizeof(in); in.options.version = 2; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    in.options.version = CKFSP_VERSION; in.options.struct_size++; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    in.options.struct_size = sizeof(in.options); in.options.reserved = 1; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    in.options.reserved = 0; e.version++; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    e.version = CKFSP_VERSION; e.struct_size--; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    e.struct_size = sizeof(e); e.flags = 4; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    e.flags = 0; e.object.known_fields |= 32; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    e.object.known_fields &= ~32U; e.object.modified.nanoseconds = 1000000000U;
    assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    e.object.modified.nanoseconds = 0; e.object.identity.has_generation = 2;
    assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    e.object.identity.has_generation = 1; e.has_digest = 2; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    e.has_digest = 0; in.source.entry_count = UINT64_MAX; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    in.source.entry_count = 1; in.source.entries = NULL; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    in.source.entries = &e; in.options.limits.max_page_rows = 4097; assert(ckfsp_plan_create(&in, &p) == CKFSP_INVALID_ARGUMENT);
    in.options.limits.max_page_rows = 1; in.options.topology = CKFSP_OVERLAP;
    assert(ckfsp_plan_create(&in, &p) == CKFSP_PLAN_UNAVAILABLE && p == NULL);
    memset(&summary, 7, sizeof(summary)); assert(ckfsp_plan_get_summary(NULL, &summary) == CKFSP_INVALID_ARGUMENT && summary.rows == 0);
    memset(&page, 7, sizeof(page)); memset(&r, 7, sizeof(r));
    assert(ckfsp_plan_page(NULL, 0, &r, 1, &page) == CKFSP_INVALID_ARGUMENT && page.plan_id == 0 && r.token.plan_id == 0);
    assert(ckfsp_plan_revalidate(NULL, NULL, NULL, &v) == CKFSP_INVALID_ARGUMENT && v == CKFSP_REVALIDATION_NOT_CHECKED);
    ckfsp_input_init(NULL); ckfsp_entry_init(NULL);
}
int main(void) {
    profiles(); digest_and_unknown(); keys_pages_and_tokens(); filters_and_protection(); invalid_inputs();
    puts("comparison_plan_c_tests: all assertions passed");
    return 0;
}
