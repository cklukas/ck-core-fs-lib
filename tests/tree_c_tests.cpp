// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "mac_capability_fixture.hpp"
#include "ck_fs_tree.h"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <string>
#include <thread>

namespace {
ckfet_snapshot_v1 wait(ckfet_job* job, bool command = false) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    ckfet_snapshot_v1 s{};
    do {
        assert(ckfet_poll_v1(job, &s) == CKFE_API_OK);
        if (command ? s.command_state >= CKFET_COMMAND_ACCEPTED :
            (s.state == CKFET_AWAITING_REVIEW || s.state >= CKFET_COMPLETE)) return s;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while (std::chrono::steady_clock::now() < until);
    std::fprintf(stderr, "tree timeout state=%u command=%u code=%lld\n", s.state, s.command_state, (long long)s.failure_code);
    std::abort();
}
void show(const ckfet_snapshot_v1& s) {
    std::fprintf(stderr, "state=%u failure=%u/%u/%lld completed=%llu failed=%llu\n", s.state,
        s.failure_state, s.failure_domain, (long long)s.failure_code,
        (unsigned long long)s.completed_items, (unsigned long long)s.failed_items);
}
void drained(ckfet_job* job) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    std::uint32_t done = 99;
    assert(ckfet_worker_drained_v1(nullptr, &done) == CKFE_API_INVALID_ARGUMENT && done == 0);
    assert(ckfet_worker_drained_v1(job, nullptr) == CKFE_API_INVALID_ARGUMENT);
    do {
        assert(ckfet_worker_drained_v1(job, &done) == CKFE_API_OK && done <= 1);
        if (done) {
            ckfet_snapshot_v1 s{};
            assert(ckfet_poll_v1(job, &s) == CKFE_API_OK && s.state >= CKFET_COMPLETE);
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while (std::chrono::steady_clock::now() < until);
    std::abort();
}
void pause_ack(ckfet_job* job, std::uint32_t desired) {
    ckfet_request_pause(job,desired);
    const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    do {
        ckfet_snapshot_v1 s{}; assert(ckfet_poll_v1(job,&s)==CKFE_API_OK);
        if (s.pause_requested==desired && s.paused==desired) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while(std::chrono::steady_clock::now()<until);
    std::abort();
}
ckfjr_snapshot_v1 root_wait(ckfjr_root* root,bool final) {
    const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(30);
    do {
        ckfjr_snapshot_v1 out;ckfjr_snapshot_init_v1(&out);
        assert(ckfjr_poll_v1(root,&out)==CKFE_API_OK);
        if(final?out.worker_drained:(out.state==CKFJR_READY||out.worker_drained))return out;
        const auto status=ckfjr_wait_v1(root,50);
        assert(status==CKFE_API_OK||status==CKFE_API_NOT_READY);
    } while(std::chrono::steady_clock::now()<until);
    std::abort();
}
}
int main(int argc, char** argv) {
    assert(argc == 4);
    const std::string root = argv[1], journal = argv[2], mode = argv[3];
    ckfe_engine* engine = nullptr; ckfe_directory* parent = nullptr;
    ckfe_entry *source = nullptr, *target = nullptr;
    ckfe_error e{}; ckfe_error_init(&e);
    assert(ckfe_engine_create(&engine) == CKFE_API_OK);
    assert(ckfe_directory_open_utf8(engine, root.c_str(), 0, &parent, &e) == CKFE_API_OK);
    assert(ckfe_entry_open_utf8(parent, "source", &source, &e) == CKFE_API_OK);
    assert(ckfe_entry_open_utf8(parent, "target", &target, &e) == CKFE_API_OK);
    const bool prepared=mode=="prepared_stale";
    const bool compare=mode=="compare";
    bool provision=prepared;
#ifdef _WIN32
    // Legacy pathname tests adopt a directory already privately provisioned
    // by the real worker. The tree operation never secures a scanned folder.
    provision=!compare;
#endif
    ckfjr_root* journal_owner=nullptr;
    if(provision) {
        ckfjr_options_v1 setup;ckfjr_options_init_v1(&setup);
        setup.parent=parent;setup.disposition=CKFJR_PROVISION_CHILD;
#ifdef _WIN32
        const char16_t component[]=u"journals";
        setup.child.encoding=CKFJR_UTF16;setup.child.data=component;setup.child.byte_count=sizeof(component)-sizeof(char16_t);
#else
        setup.child.data="journals";setup.child.byte_count=8;
#endif
        assert(ckfjr_start_v1(&setup,&journal_owner)==CKFE_API_OK&&journal_owner);
        const auto ready=root_wait(journal_owner,false);
        if(ready.state!=CKFJR_READY)std::fprintf(stderr,"root prepare failed %u/%u/%lld %s\n",ready.failure_state,ready.failure_domain,(long long)ready.failure_code,ready.failure_operation);
        assert(ready.state==CKFJR_READY&&!ready.worker_drained);
        assert(ready.directory_creates==1&&ready.flushed_directories>0);
        if(prepared) {
            ckfjr_root* alias=nullptr;assert(ckfjr_retain_v1(journal_owner,&alias)==CKFE_API_OK&&alias);
            ckfjr_release(journal_owner);journal_owner=alias;
        } else {
            // Release every provision-worker handle before the legacy tree
            // worker adopts the same existing private directory independently.
            assert(ckfjr_finish_v1(journal_owner)==CKFE_API_OK);
            const auto final=root_wait(journal_owner,true);
            if(final.state!=CKFJR_COMPLETE)std::fprintf(stderr,"fixture root finish failed %u/%u/%lld %s\n",final.failure_state,final.failure_domain,(long long)final.failure_code,final.failure_operation);
            assert(final.state==CKFJR_COMPLETE&&final.worker_drained&&!final.recovery_required);
            ckfjr_release(journal_owner);journal_owner=nullptr;
            std::fprintf(stderr,"fixture private journal provisioned and worker drained\n");
        }
    }
    ckfet_options_v1 o{}; ckfet_options_init_v1(&o);
    assert(o.version == CKFET_VERSION && o.struct_size == sizeof(o));
    o.profile = CKFSP_COPY; o.allow_metadata_loss = 0; o.operation_id[0] = 37;
    o.metadata_scope = CKFE_METADATA_ORDINARY_CALLER_VISIBLE_V1;
    o.metadata_ownership = CKFE_OWNERSHIP_ORIGINAL;
    if(compare) {o.profile=CKFSP_COMPARE;o.allow_metadata_loss=0;o.metadata_scope=CKFE_METADATA_COMPLETE_V1;}
#ifdef _WIN32
    // Fixture arguments are UTF-8 from Python. Convert at the test boundary,
    // then exercise the exact UTF-16 native journal address API.
    // All characters in this generated task root are ASCII by construction.
    std::u16string native;
    for (unsigned char c : journal) { assert(c < 128); native.push_back(static_cast<char16_t>(c)); }
    o.journal_root = {native.data(), native.size(), CKFET_UTF16, 0};
#else
    o.journal_root = {journal.data(), journal.size(), CKFET_POSIX_BYTES, 0};
#endif
    if(compare) {
        o.journal_root={};std::fill(std::begin(o.operation_id),std::end(o.operation_id),0);
        for(auto profile:{CKFSP_COPY,CKFSP_SYNC}) {
            auto mutating=o;mutating.profile=profile;
            ckfet_job* refused=reinterpret_cast<ckfet_job*>(1);
            assert(ckfet_start_v1(source,target,&mutating,&refused,&e)==CKFE_API_INVALID_ARGUMENT&&!refused);
            mutating.operation_id[0]=1;
            assert(ckfet_start_v1(source,target,&mutating,&refused,&e)==CKFE_API_INVALID_ARGUMENT&&!refused);
        }
    }
    // This validly encoded but nonexistent hint must never be opened. Native
    // authority is the prepared root acquired independently through its owner.
#ifdef _WIN32
    const auto unused_hint=root+"\\not-the-journal-root";
    const std::u16string unused_hint_wide(unused_hint.begin(),unused_hint.end());
#else
    const auto unused_hint=root+"/not-the-journal-root";
#endif
    if(prepared) {
#ifdef _WIN32
        o.journal_root={unused_hint_wide.data(),unused_hint_wide.size(),CKFET_UTF16,0};
#else
        o.journal_root={unused_hint.data(),unused_hint.size(),CKFET_POSIX_BYTES,0};
#endif
    }
    ckfet_job* job = reinterpret_cast<ckfet_job*>(1);
    auto invalid = o; invalid.reserved = 1;
    assert(ckfet_start_v1(source, target, &invalid, &job, &e) == CKFE_API_INVALID_ARGUMENT && job == nullptr);
#if defined(__APPLE__)
    const auto target_before=mac_capability_fixture::observe(std::filesystem::path(root)/"target");
    const auto journal_before=mac_capability_fixture::observe(journal);
#endif
    assert((prepared?ckfet_start_with_journal_root_v1(source,target,&o,journal_owner,&job,&e):
        ckfet_start_v1(source,target,&o,&job,&e))==CKFE_API_OK&&job);
    // A running job owns both roots after these public owners are destroyed.
    ckfe_entry_destroy(source); ckfe_entry_destroy(target);
    ckfe_directory_destroy(parent); ckfe_engine_destroy(engine);
    if (mode == "cancel") {
        ckfet_request_pause(job, 1); ckfet_request_cancel(job);
        drained(job);
        ckfet_snapshot_v1 s{};assert(ckfet_poll_v1(job,&s)==CKFE_API_OK);
        show(s); assert(s.state == CKFET_CANCELLED);
        ckfet_release(job); ckfe_error_free(&e); return 0;
    }
    auto s = wait(job); show(s); assert(s.state == CKFET_AWAITING_REVIEW && s.plan_generation);
    // Idle review waits must acknowledge pause without a command. Admission
    // may queue a review while paused, but the worker cannot consume it until
    // the resume acknowledgement. This exercises the actual C worker loop.
    pause_ack(job,1);
    std::uint64_t paused_command=0;
    assert(ckfet_review_v1(job,s.plan_generation,nullptr,0,nullptr,0,&paused_command)==CKFE_API_OK && paused_command);
    assert(ckfet_poll_v1(job,&s)==CKFE_API_OK && s.paused && s.command_state==CKFET_COMMAND_PENDING);
    if(mode=="cancelreview") {
        ckfet_request_cancel(job);
        drained(job);
        assert(ckfet_poll_v1(job,&s)==CKFE_API_OK && s.state==CKFET_CANCELLED);
        assert(s.command_id==paused_command && s.command_state==CKFET_COMMAND_REJECTED);
        assert(!s.receipt_id);
        ckfet_release(job);ckfe_error_free(&e);return 0;
    }
    pause_ack(job,0);
    s=wait(job,true);
    assert(s.command_id==paused_command && s.command_state>=CKFET_COMMAND_ACCEPTED);
    assert(ckfet_acknowledge_command_v1(job,paused_command)==CKFE_API_OK);
    ckfet_row_v1 rows[32]{}; ckfet_page_v1 p{};
    assert(ckfet_page_v1_get(job, s.plan_generation, 0, rows, 32, &p) == CKFE_API_OK);
    assert(p.row_count && p.total_rows >= p.row_count);
    std::uint64_t bytes = 0;
    assert(ckfet_key_copy_v1(job, s.plan_generation, rows[0].row_id, nullptr, 0, &bytes) == CKFE_API_BUFFER_TOO_SMALL && bytes);
    std::string key(bytes, '\0');
    assert(ckfet_key_copy_v1(job, s.plan_generation, rows[0].row_id, key.data(), bytes, &bytes) == CKFE_API_OK);
    ckfet_rule_v1 rule{};
    ckfet_name_choice_v1 choice{};
    std::uint64_t selected = 0;
    const std::string incoming_name = "alpha-incoming";
    const std::u16string incoming_wide = u"alpha-incoming";
    const bool keep_both = mode == "keepboth";
    if (keep_both) {
        for (std::uint64_t i = 0; i < p.row_count; ++i)
            if (rows[i].source.presence == CKFET_PRESENCE_PRESENT && rows[i].source.kind == CKFSP_REGULAR_FILE &&
                rows[i].destination.presence == CKFET_PRESENCE_PRESENT) selected = rows[i].row_id;
        assert(selected);
        rule.version = CKFET_VERSION; rule.struct_size = sizeof(rule); rule.kind = CKFET_CONFLICT_EXISTING_REGULAR;
        rule.choice = CKFET_KEEP_BOTH_INCOMING; rule.scope = CKFET_SCOPE_ITEM; rule.protect_nonempty = 1;
        rule.plan_generation = s.plan_generation; rule.selected_rows = &selected; rule.selected_count = 1;
        choice.row_id = selected; choice.side = CKFET_NAME_INCOMING;
#ifdef _WIN32
        choice.component = {incoming_wide.data(),incoming_wide.size(),CKFET_UTF16,0};
#else
        choice.component = {incoming_name.data(),incoming_name.size(),CKFET_POSIX_BYTES,0};
#endif
    }
    if(compare) {
        rule.version=CKFET_VERSION;rule.struct_size=sizeof(rule);rule.kind=CKFET_CONFLICT_EXISTING_REGULAR;
        rule.choice=CKFET_ASK;rule.scope=CKFET_SCOPE_JOB;rule.protect_nonempty=1;rule.retain_replaced=1;
        rule.plan_generation=s.plan_generation;
    }
    std::uint64_t command = 999;
    assert(ckfet_review_v1(job, s.plan_generation + 1, nullptr, 0, nullptr, 0, &command) == CKFE_API_STALE_PLAN && command == 0);
    auto submit = [&] { return ckfet_review_names_v1(job,s.plan_generation,(keep_both||compare) ? &rule : nullptr,(keep_both||compare) ? 1 : 0,
        keep_both ? &choice : nullptr,keep_both ? 1 : 0,nullptr,0,&command); };
    if (keep_both) {
        assert(ckfet_review_v1(job,s.plan_generation,&rule,1,nullptr,0,&command) == CKFE_API_OK);
        s = wait(job,true); assert(s.command_state == CKFET_COMMAND_REJECTED && !s.receipt_id);
        ckfet_rule_counts_v1 counts{};
        assert(ckfet_rule_counts_get_v1(job,0,&counts) == CKFE_API_OK && counts.matched_rows == 1 && counts.unresolved_rows == 1);
        assert(ckfet_page_v1_get(job,s.plan_generation,selected - 1,rows,1,&p) == CKFE_API_OK);
        assert(rows[0].has_decision && rows[0].decision_state == CKFET_DECISION_REVIEW);
        assert(ckfet_acknowledge_command_v1(job,s.command_id) == CKFE_API_OK);
    }
    assert(submit() == CKFE_API_OK && command);
    s = wait(job, true); show(s); assert(s.command_state == CKFET_COMMAND_ACCEPTED && s.receipt_id);
    if (keep_both) {
        ckfet_rule_counts_v1 counts{};
        assert(ckfet_rule_counts_get_v1(job,0,&counts) == CKFE_API_OK && counts.matched_rows == 1 && counts.applied_rows == 1 && !counts.unresolved_rows);
    }
    const auto old_receipt = s.receipt_id;
    assert(ckfet_review_v1(job, s.plan_generation, nullptr, 0, nullptr, 0, &command) == CKFE_API_BUSY && command == 0);
    assert(ckfet_acknowledge_command_v1(job,s.command_id) == CKFE_API_OK);
    assert(submit() == CKFE_API_OK);
    s = wait(job, true); assert(s.command_state == CKFET_COMMAND_ACCEPTED && s.receipt_id != old_receipt);
    assert(ckfet_acknowledge_command_v1(job,s.command_id) == CKFE_API_OK);
    assert(ckfet_execute_v1(job, s.plan_generation, old_receipt, &command) == CKFE_API_STALE_PLAN && !command);
    if (mode == "stale"||prepared) { std::puts("REVIEWED"); std::fflush(stdout); assert(std::getchar() == 'x'); }
#if defined(__APPLE__)
    const auto source_before=mac_capability_fixture::observe(std::filesystem::path(root)/"source");
#endif
    assert(ckfet_execute_v1(job, s.plan_generation, s.receipt_id, &command) == CKFE_API_OK);
    s = wait(job, true); show(s);
#if defined(__APPLE__)
    if(!compare){
        assert(s.command_state==CKFET_COMMAND_REJECTED&&s.failure_state==CKFE_OBSERVATION_UNSUPPORTED&&
          s.failure_domain==CKFE_ERROR_ADAPTER&&s.failure_code==14);
        assert(!s.completed_items&&!s.copied_bytes&&!s.partial&&!s.recovery_required);
        assert(mac_capability_fixture::observe(std::filesystem::path(root)/"source")==source_before&&
          mac_capability_fixture::observe(std::filesystem::path(root)/"target")==target_before&&
          mac_capability_fixture::observe(journal)==journal_before);
        assert(ckfet_acknowledge_command_v1(job,s.command_id)==CKFE_API_OK);
        // Fresh review still cannot bypass a missing native capability.
        assert(submit()==CKFE_API_OK&&command);s=wait(job,true);
        assert(s.command_state==CKFET_COMMAND_ACCEPTED&&s.receipt_id);
        assert(ckfet_acknowledge_command_v1(job,s.command_id)==CKFE_API_OK);
        assert(ckfet_execute_v1(job,s.plan_generation,s.receipt_id,&command)==CKFE_API_OK&&command);
        s=wait(job,true);assert(s.command_state==CKFET_COMMAND_REJECTED&&s.failure_state==CKFE_OBSERVATION_UNSUPPORTED&&
          s.failure_domain==CKFE_ERROR_ADAPTER&&s.failure_code==14);
        ckfet_request_cancel(job);drained(job);assert(ckfet_poll_v1(job,&s)==CKFE_API_OK&&s.state==CKFET_CANCELLED);
        assert(!s.completed_items&&!s.copied_bytes&&!s.partial&&!s.recovery_required);
        assert(mac_capability_fixture::observe(std::filesystem::path(root)/"source")==source_before&&
          mac_capability_fixture::observe(std::filesystem::path(root)/"target")==target_before&&
          mac_capability_fixture::observe(journal)==journal_before);
        if(journal_owner){assert(ckfjr_finish_v1(journal_owner)==CKFE_API_OK);const auto final=root_wait(journal_owner,true);
          assert(final.state==CKFJR_COMPLETE&&final.worker_drained);ckfjr_release(journal_owner);}
        ckfet_release(job);ckfe_error_free(&e);
        std::puts("Mac C Tree issued receipt cannot bypass unsupported execution admission; no data/journal effects");
        return 0;
    }
#endif
    assert(s.command_state == CKFET_COMMAND_ACCEPTED);
    if (s.command_state == CKFET_COMMAND_ACCEPTED) {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (s.state < CKFET_COMPLETE && std::chrono::steady_clock::now() < until) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            assert(ckfet_poll_v1(job, &s) == CKFE_API_OK);
        }
    }
    show(s);
    if (mode == "stale"||prepared) assert(s.state != CKFET_COMPLETE && s.state >= CKFET_COMPLETE);
    else assert(s.state == CKFET_COMPLETE && !s.recovery_required && !s.failed_items);
    if (keep_both) {
        std::uint32_t encoding = 0;
        assert(ckfet_native_copy_v1(job,s.plan_generation,selected,CKFET_NATIVE_RESULTING_NAME,0,nullptr,0,&bytes,&encoding) == CKFE_API_BUFFER_TOO_SMALL);
        assert(bytes == incoming_name.size());
    }
    ckfet_snapshot_v1 events[64]{}; std::uint64_t count = 0, coalesced = 0;
    assert(ckfet_drain_v1(job, events, 64, &count, &coalesced) == CKFE_API_OK && count);
    for (std::uint64_t i = 1; i < count; ++i) assert(events[i].sequence > events[i-1].sequence);
    assert(ckfet_poll_v1(job, &s) == CKFE_API_OK && s.state >= CKFET_COMPLETE);
    drained(job);
    if(journal_owner) {
        assert(ckfjr_finish_v1(journal_owner)==CKFE_API_OK);
        const auto final=root_wait(journal_owner,true);assert(final.state==CKFJR_COMPLETE&&final.worker_drained);
        // Keep the terminal tree handle while the root closes. Cached result
        // paging must neither retain native authority nor perform native I/O.
        assert(ckfet_page_v1_get(job,s.plan_generation,0,rows,32,&p)==CKFE_API_OK&&p.row_count);
        ckfjr_release(journal_owner);
    }
    ckfet_release(job); ckfe_error_free(&e);
}
