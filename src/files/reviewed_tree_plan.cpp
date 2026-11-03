// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "reviewed_tree_plan.hpp"
#include "sha256.hpp"
#include "native_delete_recovery_evidence.hpp"
#include "retained_target.hpp"
#include "directory_name_rules.hpp"
#include "prepared_journal_root.hpp"
#include "private_journal_scope.hpp"
#include "metadata_semantic_digest.hpp"
#include "metadata_ownership_digest.hpp"
#include "native_sync_observation.hpp"
#include "native_main_content_job.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <algorithm>
#include <map>
#include <set>

namespace ck::files {
namespace {
UnavailableObservation error(AdapterError code, const char* op,
    ObservationState state = ObservationState::Failed) {
    return {state, {ErrorDomain::Adapter, static_cast<std::int64_t>(code), op}};
}
bool interrupted_for_stop(const UnavailableObservation& e,std::stop_token stop)noexcept {
    return stop.stop_requested()&&e.error.domain==ErrorDomain::Adapter&&
        e.error.code==static_cast<std::int64_t>(AdapterError::InterruptedRead);
}
template<class T> Observation<T> unavailable(const UnavailableObservation& e) {
    return Observation<T>::unavailable(e.state, e.error);
}
template<class T> Observation<T> invalid(const char* op) {
    return unavailable<T>(error(AdapterError::PlanInvalid, op));
}
template<class Cursor> Observation<bool> qualify_namespace(const Cursor& cursor) {
    // Older pinned adapters have no qualification boundary; absence is never
    // inferred support. Current adapters supply the native provider check.
    if constexpr (requires { cursor.qualify_identity_bound_rename(); })
        return cursor.qualify_identity_bound_rename();
    else return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.native_namespace_qualification", ObservationState::Unsupported));
}
template<class Policy> Observation<RegularMetadataPreservation::Pointer> preservation_for(
    const HeldChild::Pointer& source, const Policy& policy, std::stop_token stop) {
    if constexpr (requires { policy.metadata_policy; }) {
        if (policy.metadata_policy) return RegularMetadataPreservation::create_with_policy(
            source, policy.allow_unhandled_metadata_loss, *policy.metadata_policy, stop);
    }
    return RegularMetadataPreservation::create(source, policy.allow_unhandled_metadata_loss, policy.metadata_scope, stop);
}
bool same(const ObjectIdentity& a, const ObjectIdentity& b) {
    return compare_identity(a, b) == IdentityComparison::Same;
}
template<class T> bool equal(const Observation<T>& a, const Observation<T>& b) {
    if (a.value() && b.value()) return *a.value() == *b.value();
    return !a.value() && !b.value() && a.state() == b.state() &&
        a.unavailable_detail()->error == b.unavailable_detail()->error;
}
bool qualified(const BasicMetadata& m) {
    return m.identity.value() && same(*m.identity.value(), *m.identity.value()) &&
        m.kind.value() && m.mount_id.value() && m.modified.value() && m.changed.value() &&
        (*m.kind.value() == ObjectKind::Directory ||
         (*m.kind.value() == ObjectKind::RegularFile && m.logical_size.value()));
}
bool unchanged(const BasicMetadata& a, const BasicMetadata& b) {
    return qualified(a) && qualified(b) && same(*a.identity.value(), *b.identity.value()) &&
        equal(a.kind, b.kind) && equal(a.mount_id, b.mount_id) &&
        equal(a.modified, b.modified) && equal(a.changed, b.changed) &&
        (*a.kind.value() == ObjectKind::Directory || equal(a.logical_size, b.logical_size)) &&
        equal(a.posix_permissions, b.posix_permissions) && equal(a.posix_uid, b.posix_uid) &&
        equal(a.posix_gid, b.posix_gid) && equal(a.link_count, b.link_count) &&
        equal(a.bsd_flags, b.bsd_flags) && equal(a.windows_attributes, b.windows_attributes);
}
std::string key_component(const NativeName& name, bool fold = false) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string key = name.posix_bytes() ? "p" : "w";
    auto unit = [&](unsigned value, unsigned digits) {
        if (fold && value >= 'A' && value <= 'Z') value += 'a' - 'A';
        for (unsigned n = digits; n; --n) key += hex[(value >> (4 * (n - 1))) & 15];
    };
    if (name.posix_bytes()) for (unsigned char c : *name.posix_bytes()) unit(c, 2);
    else for (char16_t c : *name.windows_units()) unit(c, 4);
    return key;
}
std::string key_path(const std::vector<NativeName>& names, bool fold = false) {
    std::string out;
    for (const auto& n : names) { if (!out.empty()) out += '/'; out += key_component(n, fold); }
    return out;
}
bool ascii_units(const NativeName& n) {
    if (n.posix_bytes()) return std::all_of(n.posix_bytes()->begin(), n.posix_bytes()->end(), [](unsigned char c) { return c < 128; });
    return std::all_of(n.windows_units()->begin(), n.windows_units()->end(), [](char16_t c) { return c < 128; });
}
ComparisonObject comparison_object(const BasicMetadata& m) {
    ComparisonObject out;
    out.state = ComparisonObjectState::Stable;
    out.identity = *m.identity.value(); out.kind = *m.kind.value();
    if (m.logical_size.value() && *m.kind.value() == ObjectKind::RegularFile) out.size = *m.logical_size.value();
    out.modified = *m.modified.value(); out.timestamp_quantum_ns = 1;
    return out;
}
MetadataReplayPolicy capture_policy(const ReviewedTreePlanRequest& r) {
    if(r.copy_policy.metadata_policy)return *r.copy_policy.metadata_policy;
    MetadataReplayPolicy p;p.scope=r.copy_policy.metadata_scope;
    p.ownership=p.scope==RegularMetadataScope::CompleteMetadataV1?MetadataOwnership::Original:MetadataOwnership::CurrentCaller;
    return p;
}
std::array<std::byte,32> metadata_schema() {
    Sha256 hash;constexpr char domain[]="ck-core-fs-lib/native-preserved-metadata";
    hash.update(std::as_bytes(std::span(domain,sizeof(domain)-1)));std::array<std::byte,8> version{};
    for(unsigned i=0;i<version.size();++i)version[i]=std::byte((metadata_semantic_digest_version>>(8*i))&255);
    hash.update(version);return hash.digest();
}
std::array<std::byte,32> metadata_binding(const MetadataReplayPolicy& policy) {
    Sha256 application;constexpr char domain[]="ck-core-fs-lib/reviewed-tree-preservation";
    application.update(std::as_bytes(std::span(domain,sizeof(domain)-1)));
    return native_sync_policy_binding(application.digest(),policy);
}
bool equal_object(const ComparisonObject&a,const ComparisonObject&b){
    return a.state==b.state&&a.identity.has_value()==b.identity.has_value()&&(!a.identity||same(*a.identity,*b.identity))&&
        a.kind==b.kind&&a.size==b.size&&a.modified==b.modified&&a.timestamp_quantum_ns==b.timestamp_quantum_ns&&a.change_cookie==b.change_cookie;
}
bool equal_metadata(const std::optional<ComparisonMetadataDigest>& a,const std::optional<ComparisonMetadataDigest>& b) {
    if(!a||!b)return bool(a)==bool(b);
    return a->state==b->state&&a->algorithm==b->algorithm&&a->schema==b->schema&&a->policy_binding==b->policy_binding&&
        a->bytes==b->bytes&&a->ownership==b->ownership&&a->canonical_owner_digest==b->canonical_owner_digest&&
        equal_object(a->before,b->before)&&equal_object(a->after,b->after);
}
class TreeCaptureLatch final:public MetadataCaptureFailureLatch {
public:
    explicit TreeCaptureLatch(std::shared_ptr<PreparedJournalRoot> r):root_(std::move(r)){}
    void record_first(MetadataCaptureCleanupError e)const noexcept override {
        if(first)return;first=e;
        if(root_)detail::record_prepared_journal_consumer_failure(*root_,e.state,e.domain,e.code,e.operation);
    }
    void release_root()noexcept{root_.reset();}
    mutable std::optional<MetadataCaptureCleanupError> first;
private:
    std::shared_ptr<PreparedJournalRoot> root_;
};
struct Node {
    std::vector<NativeName> names;
    HeldChild::Pointer held;
    std::shared_ptr<const DirectoryCursor> directory;
    BasicMetadata metadata;
    ComparisonEntry entry;
    std::optional<UnavailableObservation> metadata_failure={};
    std::optional<std::uint64_t> all_stream_bytes={};
};
struct Tree {
    BasicMetadata root_metadata;
    std::shared_ptr<const DirectoryCursor> root;
    std::map<std::string, Node> nodes;
    std::optional<ComparisonMetadataDigest> root_metadata_digest;
};
// This scanner consumes one native enumeration record or at most one bounded
// content read per step. Directory version brackets qualify absence; files are
// read completely with exact identity/version brackets. A second independent
// full scan is required before the immutable comparison plan is published.
class Scanner {
public:
    Scanner(HeldChild::Pointer root, const ReviewedTreePlanRequest& request,JournalScopeGuard::Pointer scope)
        : root_(std::move(root)), request_(request),scope_guard_(std::move(scope)),policy_(capture_policy(request)),
          budget_(std::make_shared<MetadataCaptureBudget>(request.metadata_limits)),
          latch_(std::make_shared<TreeCaptureLatch>(request.prepared_journal_root)) {}
    ~Scanner(){close_capture();}
    std::optional<MetadataCaptureCleanupError> finish_io()noexcept {close_capture();return latch_->first;}
    bool complete = false;
    std::optional<UnavailableObservation> failure;
    Tree tree;
    void step(std::stop_token stop) {
        try {
            if(!scope(stop))return;
            step_impl(stop);
            if(!scope(stop))return;
            if(failure)close_capture();
        }catch(...){close_capture();throw;}
    }
    void step_impl(std::stop_token stop) {
        if (complete || failure || stop.stop_requested()) return;
        if (!tree.root) { start(stop); return; }
        if (reading_) { read_step(stop); return; }
        if (frames_.empty()) { complete = true; return; }
        auto& frame = frames_.back();
        auto read = frame.cursor->read(1, stop);
        if (read.state == DirectoryReadState::Error) {
            failure = read.error.value_or(error(AdapterError::InvalidNativeResult, "reviewed_tree.enumerate")); return;
        }
        if (read.state == DirectoryReadState::Cancelled) return;
        if (!read.names.empty()) {
            auto name = std::move(read.names.front());
            if (!name.is_valid()) { fail(AdapterError::InvalidIdentifier, "reviewed_tree.native_name"); return; }
            auto names = frame.names; names.push_back(name);
            auto key = key_path(names), folded = key_path(names, true);
            if (names.size() > request_.comparison.filters.maximum_depth || names.size() > 1024 ||
                key.size() > request_.limits.max_path_bytes || tree.nodes.size() >= request_.limits.max_entries ||
                key.size() > request_.limits.max_total_path_bytes - path_bytes_) {
                fail(AdapterError::InventoryLimit, "reviewed_tree.inventory_limit"); return;
            }
            path_bytes_ += key.size();
            if (!folded_.insert(folded).second) { fail(AdapterError::PlanTopologyUnsafe, "reviewed_tree.case_collision"); return; }
            auto held = HeldChild::observe(frame.cursor, name, stop);
            if (!held.value()) { failure = *held.unavailable_detail(); return; }
            if(scope_guard_) {
                auto allowed=scope_guard_->check_entry(**held.value(),stop);
                if(!allowed.value()){failure=*allowed.unavailable_detail();return;}
                if(!*allowed.value()){fail(AdapterError::PlanTopologyUnsafe,"reviewed_tree.private_entry_false",ObservationState::Unsupported);return;}
            }
            const auto m = (*held.value())->metadata();
            if (!qualified(m)) { fail(AdapterError::UnsupportedQuery, "reviewed_tree.kind_or_version", ObservationState::Unsupported); return; }
            if (*m.mount_id.value() != *tree.root_metadata.mount_id.value()) { fail(AdapterError::PlanTopologyUnsafe, "reviewed_tree.mount_crossing"); return; }
            if (*m.kind.value() == ObjectKind::RegularFile) {
                auto readable = HeldChild::observe_with_access(frame.cursor, name, EntryAccess::ContentRead, stop);
                if (!readable.value()) { failure = *readable.unavailable_detail(); return; }
                if(scope_guard_) {
                    auto allowed=scope_guard_->check_entry(**readable.value(),stop);
                    if(!allowed.value()){failure=*allowed.unavailable_detail();return;}
                    if(!*allowed.value()){fail(AdapterError::PlanTopologyUnsafe,"reviewed_tree.private_read_entry_false",ObservationState::Unsupported);return;}
                }
                if (!unchanged(m, (*readable.value())->metadata())) { fail(AdapterError::MetadataChanged, "reviewed_tree.read_open_changed", ObservationState::Changed); return; }
                held = std::move(readable);
            }
            Node node{names, *held.value(), {}, m, {}};
            node.entry.relative_path = key; node.entry.object = comparison_object(m);
            if (*m.kind.value() == ObjectKind::Directory) {
                auto opened = frame.cursor->open_directory_child(name);
                if (!opened.value()) { failure = *opened.unavailable_detail(); return; }
                node.directory = std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
                auto live = node.directory->inspect_basic();
                if (!live.value() || !unchanged(m, *live.value())) { fail(AdapterError::MetadataChanged, "reviewed_tree.directory_changed", ObservationState::Changed); return; }
                for (const auto& f : frames_) if (same(*f.before.identity.value(), *m.identity.value())) {
                    fail(AdapterError::PlanTopologyUnsafe, "reviewed_tree.directory_cycle"); return;
                }
                auto cursor = std::const_pointer_cast<DirectoryCursor>(node.directory);
                tree.nodes.emplace(key, std::move(node));
                frames_.push_back({std::move(cursor), std::move(names), m});
                begin_read(key);
            } else {
                if (*m.logical_size.value() > request_.copy_policy.copy_limits.max_bytes) {
                    fail(AdapterError::InventoryLimit, "reviewed_tree.file_bytes"); return;
                }
                tree.nodes.emplace(key, std::move(node));
                begin_read(key);
            }
            return;
        }
        if (read.state == DirectoryReadState::End) {
            if(scope_guard_) {
                auto valid=scope_guard_->check_root(stop);
                if(!valid.value()){failure=*valid.unavailable_detail();return;}
                if(!*valid.value()){fail(AdapterError::PlanTopologyUnsafe,"reviewed_tree.private_root_false",ObservationState::Unsupported);return;}
            }
            auto now = frame.cursor->inspect_basic();
            if (!now.value() || !unchanged(frame.before, *now.value())) {
                fail(AdapterError::MetadataChanged, "reviewed_tree.directory_version", ObservationState::Changed); return;
            }
            frames_.pop_back();
        }
    }
private:
    struct Frame { std::shared_ptr<DirectoryCursor> cursor; std::vector<NativeName> names; BasicMetadata before; };
    void fail(AdapterError c, const char* op, ObservationState s = ObservationState::Failed) { failure = error(c, op, s); }
    void start(std::stop_token stop) {
        auto now = root_->refresh();
        if (!now.value()) { failure = *now.unavailable_detail(); return; }
        if(scope_guard_) {
            auto checked=scope_guard_->check_entry(**now.value(),stop);
            if(!checked.value()){failure=*checked.unavailable_detail();return;}
            if(!*checked.value()){fail(AdapterError::PlanTopologyUnsafe,"reviewed_tree.private_scan_entry_false",ObservationState::Unsupported);return;}
        }
        if (!qualified((*now.value())->metadata()) || !root_->metadata().identity.value() ||
            !same(*root_->metadata().identity.value(), *(*now.value())->metadata().identity.value()) ||
            *(*now.value())->metadata().kind.value() != ObjectKind::Directory) {
            fail(AdapterError::PlanDecisionStale, "reviewed_tree.root_membership", ObservationState::Changed); return;
        }
        auto opened = root_->parent()->open_directory_child(root_->name());
        if (!opened.value()) { failure = *opened.unavailable_detail(); return; }
        auto cursor = std::shared_ptr<DirectoryCursor>(std::move(opened).take_value());
        auto metadata = cursor->inspect_basic();
        if (!metadata.value() || !unchanged((*now.value())->metadata(), *metadata.value())) {
            fail(AdapterError::PlanDecisionStale, "reviewed_tree.root_open", ObservationState::Changed); return;
        }
        tree.root_metadata = *metadata.value(); tree.root = cursor;
        frames_.push_back({std::move(cursor), {}, tree.root_metadata});
        root_node_.held=*now.value();root_node_.metadata=tree.root_metadata;root_node_.directory=tree.root;
        root_node_.entry.object=comparison_object(tree.root_metadata);begin_read({});
    }
    Node& node(){return reading_->empty()?root_node_:tree.nodes.at(*reading_);}
    void begin_read(std::string key){reading_=std::move(key);capture_attempted_=false;content_attempted_=false;}
    bool scope(std::stop_token stop) {
        if(!scope_guard_)return true;
        auto valid=scope_guard_->check_root(stop);
        if(!valid.value()){failure=*valid.unavailable_detail();close_capture();return false;}
        if(!*valid.value()){fail(AdapterError::PlanTopologyUnsafe,"reviewed_tree.capture_scope_false",ObservationState::Unsupported);close_capture();return false;}
        if(reading_&&node().held){auto allowed=scope_guard_->check_entry(*node().held,stop);
            if(!allowed.value()){failure=*allowed.unavailable_detail();close_capture();return false;}
            if(!*allowed.value()){fail(AdapterError::PlanTopologyUnsafe,"reviewed_tree.capture_entry_false",ObservationState::Unsupported);close_capture();return false;}}
        return true;
    }
    void close_capture()noexcept {
        if(content_){try{auto done=content_->finish_read();
            if(!done.value()||!*done.value()){
                if(!latch_->first)latch_->record_first({done.state(),done.unavailable_detail()?done.unavailable_detail()->error.domain:ErrorDomain::Adapter,
                    done.unavailable_detail()?done.unavailable_detail()->error.code:static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"reviewed_tree.content_finish"});
            }
        }catch(...){latch_->record_first({ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"reviewed_tree.content_finish_exception"});}
        content_.reset();}
        if(capture_){try{auto done=capture_->finish_io();
            if(!done.value()||!*done.value()){
                if(!latch_->first)latch_->record_first({done.state(),done.unavailable_detail()?done.unavailable_detail()->error.domain:ErrorDomain::Adapter,
                    done.unavailable_detail()?done.unavailable_detail()->error.code:static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"reviewed_tree.capture_finish"});
            }
        }catch(...){latch_->record_first({ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"reviewed_tree.capture_finish_exception"});}
        capture_.reset();}
    }
    bool close_checked(){close_capture();if(latch_->first){const auto&e=*latch_->first;failure=UnavailableObservation{e.state,{e.domain,e.code,e.operation}};return false;}return true;}
    ComparisonMetadataDigest empty_fact(const Node& n)const {
        ComparisonMetadataDigest out;out.algorithm=ComparisonDigestAlgorithm::Sha256;out.schema=metadata_schema();out.policy_binding=metadata_binding(policy_);
        out.ownership=policy_.ownership==MetadataOwnership::Original?ComparisonMetadataOwnership::Original:ComparisonMetadataOwnership::CurrentCaller;
        out.before=out.after=n.entry.object;return out;
    }
    void finish_read(){if(reading_->empty())tree.root_metadata_digest=root_node_.entry.metadata_digest;reading_.reset();}
    bool membership(std::stop_token stop) {
        auto& n=node();auto now=n.held->inspect_basic();auto member=n.held->refresh(stop);
        if(!now.value()){failure=*now.unavailable_detail();return false;}
        if(!member.value()){failure=*member.unavailable_detail();return false;}
        if(!(*member.value())->continues(*n.held)||!unchanged(n.metadata,*now.value())||!unchanged(n.metadata,(*member.value())->metadata())){
            fail(AdapterError::MetadataChanged,"reviewed_tree.capture_membership",ObservationState::Changed);return false;}
        return scope(stop);
    }
    void capture_unavailable(const UnavailableObservation& e,std::stop_token stop) {
        if(!close_checked())return;
        if(e.state==ObservationState::Changed||e.state==ObservationState::Failed||e.error.code==static_cast<std::int64_t>(AdapterError::InventoryLimit)||stop.stop_requested()){
            failure=e;return;}
        auto& n=node();auto fact=empty_fact(n);fact.state=e.state==ObservationState::Denied?ComparisonDigestState::Denied:ComparisonDigestState::Unknown;
        n.entry.metadata_digest=fact;n.metadata_failure=e;
        if(request_.copy_policy.allow_unhandled_metadata_loss&&n.metadata.kind.value()&&
           *n.metadata.kind.value()==ObjectKind::RegularFile){
            // Explicit loss authorizes MAIN CONTENT observation only. Never
            // substitute Ordinary policy or manufacture preserved metadata.
            n.entry.metadata_digest->state=ComparisonDigestState::Unknown;
            content_attempted_=true;
            if(!membership(stop))return;
            if(!n.metadata.logical_size.value()){failure=error(AdapterError::UnsupportedQuery,"reviewed_tree.content_size",ObservationState::Unknown);return;}
            const auto size=*n.metadata.logical_size.value();
            const auto full_admitted=budget_->admitted_logical_bytes();
            const auto this_admitted=full_admitted-node_admission_start_;
            // Metadata admission may have already charged this source's main
            // bytes before a later query refused. Charge only its uncovered
            // main bytes; hidden channels remain unproved and their total
            // stays Unknown. Prior complete stream admissions remain charged.
            const auto added=size>this_admitted?size-this_admitted:0;
            if(loss_main_bytes_>request_.metadata_limits.max_logical_bytes-full_admitted||
               added>request_.metadata_limits.max_logical_bytes-full_admitted-loss_main_bytes_){
                failure=error(AdapterError::InventoryLimit,"reviewed_tree.content_aggregate_budget",ObservationState::Unknown);return;}
            loss_main_bytes_+=added;
            NativeMainContentLimits limits{{request_.digest_chunk_bytes},request_.copy_policy.copy_limits.max_bytes};
            auto begin=NativeMainContentJob::begin_held(n.held,limits,scope_guard_,latch_,stop);
            if(!begin.value()){failure=*begin.unavailable_detail();return;}
            content_=std::move(begin).take_value();return;
        }
        if(membership(stop))finish_read();
    }
    void read_step(std::stop_token stop) {
        auto& n=node();
        if(content_attempted_){read_content_step(stop);return;}
        if(!capture_attempted_){capture_attempted_=true;
            node_admission_start_=budget_->admitted_logical_bytes();
            auto limits=request_.metadata_limits;limits.read={request_.digest_chunk_bytes};
            const auto remaining=request_.metadata_limits.max_logical_bytes-budget_->admitted_logical_bytes()-loss_main_bytes_;
            limits.max_logical_bytes=std::min(request_.copy_policy.copy_limits.max_bytes,remaining);
            auto begin=MetadataCaptureJob::begin_held(n.held,policy_,limits,budget_,latch_);
            if(!begin.value()){capture_unavailable(*begin.unavailable_detail(),stop);return;}
            capture_=std::move(begin).take_value();return;
        }
        auto advanced=capture_->advance(stop);
        if(!advanced.value()){capture_unavailable(*advanced.unavailable_detail(),stop);return;}
        if(capture_->progress().phase!=MetadataCapturePhase::Complete)return;
        auto result=capture_->result();if(!result.value()){capture_unavailable(*result.unavailable_detail(),stop);return;}
        const auto& proof=**result.value();auto digest=native_metadata_proof_digest(proof,stop);
        if(!digest.value()){capture_unavailable(*digest.unavailable_detail(),stop);return;}
        if(!unchanged(n.metadata,proof.snapshot().basic)){fail(AdapterError::MetadataChanged,"reviewed_tree.capture_version",ObservationState::Changed);close_capture();return;}
        auto fact=empty_fact(n);fact.state=ComparisonDigestState::CompleteStable;fact.bytes=*digest.value();
        if(fact.ownership==ComparisonMetadataOwnership::CurrentCaller){auto owner=metadata_ownership_digest(proof.snapshot());if(owner.value())fact.canonical_owner_digest=*owner.value();}
        n.all_stream_bytes=proof.progress().all_stream_logical_bytes;
        if(*n.metadata.kind.value()==ObjectKind::RegularFile){if(!proof.main_digest()){fail(AdapterError::InvalidNativeResult,"reviewed_tree.capture_main_missing");close_capture();return;}
            ComparisonDigest main;main.state=ComparisonDigestState::CompleteStable;main.algorithm=ComparisonDigestAlgorithm::Sha256;
            main.bytes=*proof.main_digest();main.bytes_read=*n.metadata.logical_size.value();main.before=main.after=n.entry.object;n.entry.digest=main;}
        if(!close_checked())return;
        if(!membership(stop))return;
        n.entry.metadata_digest=std::move(fact);finish_read();
    }
    void read_content_step(std::stop_token stop){
        if(!content_){fail(AdapterError::InvalidNativeResult,"reviewed_tree.content_owner_missing");return;}
        auto advanced=content_->advance(stop);
        if(!advanced.value()){failure=*advanced.unavailable_detail();close_capture();return;}
        if(content_->progress().phase!=NativeMainContentPhase::DataReady)return;
        // Producer exposes no proof before actual native read handles close.
        auto closed=content_->finish_read();
        if(!closed.value()||!*closed.value()){
            if(!close_checked())return;
            failure=closed.unavailable_detail()?*closed.unavailable_detail():error(AdapterError::InvalidNativeResult,"reviewed_tree.content_close_false");return;
        }
        auto result=content_->result();
        if(!result.value()){failure=*result.unavailable_detail();close_capture();return;}
        const auto& proof=**result.value();auto& n=node();
        if(!unchanged(n.metadata,proof.before())||!unchanged(n.metadata,proof.after())){
            fail(AdapterError::MetadataChanged,"reviewed_tree.main_content_version",ObservationState::Changed);close_capture();return;}
        ComparisonDigest main;main.state=ComparisonDigestState::CompleteStable;main.algorithm=ComparisonDigestAlgorithm::Sha256;
        main.bytes=proof.main_digest();main.bytes_read=proof.main_bytes();main.before=main.after=n.entry.object;
        if(!close_checked()||!membership(stop))return;
        n.entry.digest=std::move(main);finish_read();
    }
    HeldChild::Pointer root_;
    const ReviewedTreePlanRequest& request_;
    std::vector<Frame> frames_;
    std::set<std::string> folded_;
    std::optional<std::string> reading_;
    std::size_t path_bytes_ = 0;
    JournalScopeGuard::Pointer scope_guard_;
    MetadataReplayPolicy policy_;
    std::shared_ptr<MetadataCaptureBudget> budget_;
    std::shared_ptr<TreeCaptureLatch> latch_;
    std::unique_ptr<MetadataCaptureJob> capture_;
    std::unique_ptr<NativeMainContentJob> content_;
    std::uint64_t loss_main_bytes_=0,node_admission_start_=0;
    bool content_attempted_=false;
    Node root_node_;
    bool capture_attempted_=false;
};
bool equal_tree(const Tree& a, const Tree& b) {
    if (!unchanged(a.root_metadata, b.root_metadata) || !equal_metadata(a.root_metadata_digest,b.root_metadata_digest) || a.nodes.size() != b.nodes.size()) return false;
    auto i = a.nodes.begin(), j = b.nodes.begin();
    for (; i != a.nodes.end(); ++i, ++j) {
        if (i->first != j->first || i->second.names != j->second.names || !unchanged(i->second.metadata, j->second.metadata)) return false;
        if(!equal_metadata(i->second.entry.metadata_digest,j->second.entry.metadata_digest)||i->second.all_stream_bytes!=j->second.all_stream_bytes||
           i->second.metadata_failure.has_value()!=j->second.metadata_failure.has_value())return false;
        if(i->second.metadata_failure&&(i->second.metadata_failure->state!=j->second.metadata_failure->state||
           i->second.metadata_failure->error!=j->second.metadata_failure->error))return false;
        const auto& x = i->second.entry.digest; const auto& y = j->second.entry.digest;
        if (x.has_value() != y.has_value() || (x && (x->bytes != y->bytes || x->bytes_read != y->bytes_read))) return false;
    }
    return true;
}
std::vector<ComparisonEntry> entries(const Tree& t) {
    std::vector<ComparisonEntry> out; out.reserve(t.nodes.size());
    for (const auto& [key, n] : t.nodes) out.push_back(n.entry);
    return out;
}
ReviewedTreeAction action(ComparisonAction a) {
    switch (a) {
    case ComparisonAction::Report: return ReviewedTreeAction::Report;
    case ComparisonAction::Skip: return ReviewedTreeAction::Skip;
    case ComparisonAction::CopyToDestination: return ReviewedTreeAction::Copy;
    case ComparisonAction::CreateDestinationDirectory: return ReviewedTreeAction::CreateDirectory;
    case ComparisonAction::MergeDirectories: return ReviewedTreeAction::MergeDirectory;
    case ComparisonAction::ReplaceDestination: return ReviewedTreeAction::Replace;
    case ComparisonAction::RemoveDestinationFile: return ReviewedTreeAction::RemoveFile;
    case ComparisonAction::RemoveDestinationDirectory: return ReviewedTreeAction::RemoveDirectory;
    default: return ReviewedTreeAction::Report;
    }
}
bool removal(ReviewedTreeAction a) { return a == ReviewedTreeAction::RemoveFile || a == ReviewedTreeAction::RemoveDirectory; }
bool mutation(ReviewedTreeAction a) {
    return a == ReviewedTreeAction::Copy || a == ReviewedTreeAction::CreateDirectory || a == ReviewedTreeAction::Replace || removal(a);
}
}

struct ReviewedTreeReceiptState {
    ComparisonPlanIdentity plan;
    std::vector<ReviewedTreeItem> items;
    std::shared_ptr<const ReviewedTreeDeletionState> deletion;
    std::shared_ptr<const unsigned char> revision;
};
struct ReviewedTreeDeletionState { ComparisonPlanIdentity plan; std::vector<ComparisonDecisionToken> rows; };

struct ReviewedTreePlanJob::Impl {
    explicit Impl(ReviewedTreePlanRequest r) : request(std::move(r)) {}
    ReviewedTreePlanRequest request;
    ReviewedTreeProgress progress;
    ComparisonPlan::Pointer plan;
    Tree source, target;
    std::unique_ptr<Scanner> scanner;
    unsigned scan_phase = 0;
    std::optional<std::map<std::string, Node>::const_iterator> name_check;
    // Held ancestry: two full native walks, both must reach the same actual
    // self-parent namespace endpoint. Repeated non-endpoint ancestors fail.
    std::unique_ptr<OpenedEntry> ancestor;
    std::vector<ObjectIdentity> ancestors;
    std::optional<ObjectIdentity> endpoint;
    unsigned ancestry_side = 0;
    bool topology_done = false;
    std::vector<ReviewedTreeItem> items;
    std::shared_ptr<const ReviewedTreeReceiptState> receipt;
    std::shared_ptr<const unsigned char> revision = std::make_shared<const unsigned char>(0);
    std::vector<ConflictRule> assessed_rules;
    bool assessed = false;
    std::vector<ReviewedTreeNameChoice> assessed_names;
    std::optional<std::vector<ReviewedTreeItem>> last_assessment;
    RetainedTarget::Pointer retained;
    bool replacement_prepared = false;
    std::size_t current = 0;
    std::vector<std::size_t> order;
    std::size_t index() const { return order.empty() ? current : (current < order.size() ? order[current] : items.size()); }
    struct Deletion {
        Node node;
        std::shared_ptr<const DirectoryCursor> parent;
        OperationJournal::Pointer journal;
        std::shared_ptr<OperationJournalFile> file;
        std::vector<std::byte> evidence;
        unsigned phase = 0;
    };
    std::optional<Deletion> deleting;
    bool mutated = false;
    NativeOperationCopyJob::Pointer copy;
    OpenedEntry* staging = nullptr;
    OperationMetadataJob* metadata_phase = nullptr;
    std::optional<BasicMetadata> staging_before;
    bool staging_verified = false;
    std::optional<UnavailableObservation> failure;

    bool private_root_initialized=false,owns_private_root=false;
    std::array<JournalScopeGuard::Pointer,2> scope_guards;
    detail::PreparedJournalConsumerFailure finish_failure{};
    bool finish_failed=false,native_drained=false;
    void record_finish(PreparedJournalRoot* root,ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view op)noexcept {
        if(!finish_failed){finish_failed=true;finish_failure.state=state;finish_failure.domain=domain;finish_failure.code=code;
            const auto n=std::min(op.size(),finish_failure.operation.size()-1);std::copy_n(op.data(),n,finish_failure.operation.data());finish_failure.operation[n]=0;}
        if(root)detail::record_prepared_journal_consumer_failure(*root,state,domain,code,op);
    }
    void read_finish(PreparedJournalRoot* root)noexcept {
        detail::PreparedJournalConsumerFailure first;
        if(root&&detail::read_prepared_journal_consumer_failure(*root,first)){finish_failure=first;finish_failed=true;}
    }

    Observation<bool> initialize_private_root(std::stop_token stop) {
        if(private_root_initialized)return Observation<bool>::available(true);
        if(request.comparison.profile==ComparisonProfile::Compare) {
            private_root_initialized=true;return Observation<bool>::available(true);
        }
        if(!request.prepared_journal_root) {
            if(!request.journal_root)return unavailable<bool>(error(AdapterError::UnsupportedQuery,
                "reviewed_tree.private_journal_root_required",ObservationState::Unsupported));
            // The legacy address is used once, on this worker, as initial
            // navigation. No checked pathname is later reopened as authority.
            auto prepared=acquire_native_journal_root(*request.journal_root,stop);
            if(!prepared.value())return unavailable<bool>(*prepared.unavailable_detail());
            request.prepared_journal_root=std::move(prepared).take_value();owns_private_root=true;
        }
        auto valid=request.prepared_journal_root->revalidate();
        if(!valid.value())return valid;
        if(!*valid.value())return unavailable<bool>(error(AdapterError::ProviderReviewRequired,
            "reviewed_tree.private_journal_root_false",ObservationState::Unsupported));
        if(!request.journal_root&&request.prepared_journal_root->navigation_address())
            request.journal_root=*request.prepared_journal_root->navigation_address();
        // All current call sites, including retained replacement, now use the
        // SAME retained owner. The address argument is a navigation hint only.
        request.open_journal=[root=request.prepared_journal_root](const NativeAbsolutePath&,const NativeName& name,bool create) {
            return root->open_journal(name,create);
        };
        unsigned side=0;
        for(const auto& root:{request.source_root,request.destination_root}) {
            auto opened=root->parent()->open_directory_child(root->name());
            if(!opened.value())return unavailable<bool>(*opened.unavailable_detail());
            auto cursor=std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
            auto observed=cursor->inspect_basic();
            if(!observed.value())return unavailable<bool>(*observed.unavailable_detail());
            if(!qualified(*observed.value())||*observed.value()->kind.value()!=ObjectKind::Directory||
                !same(*root->metadata().identity.value(),*observed.value()->identity.value())||
                !equal(root->metadata().mount_id,observed.value()->mount_id))
                return unavailable<bool>(error(AdapterError::PlanDecisionStale,"reviewed_tree.private_scope_scan_root_changed",ObservationState::Changed));
            auto scoped=JournalScopeGuard::create(request.prepared_journal_root,std::move(cursor),stop);
            if(!scoped.value())return unavailable<bool>(*scoped.unavailable_detail());
            scope_guards[side++]=std::move(scoped).take_value();
        }
        private_root_initialized=true;return Observation<bool>::available(true);
    }
    Observation<bool> private_scope_guard(std::stop_token stop={}) const {
        if(request.comparison.profile==ComparisonProfile::Compare)return Observation<bool>::available(true);
        if(!private_root_initialized||!request.prepared_journal_root)
            return unavailable<bool>(error(AdapterError::ProviderReviewRequired,"reviewed_tree.private_journal_root_unbound",ObservationState::Unsupported));
        if(!roots_current())return unavailable<bool>(error(AdapterError::PlanDecisionStale,"reviewed_tree.private_scan_membership_changed",ObservationState::Changed));
        for(const auto& guard:scope_guards) {
            if(!guard)return unavailable<bool>(error(AdapterError::ProviderReviewRequired,"reviewed_tree.private_guard_missing",ObservationState::Unsupported));
        }
        return JournalScopeGuard::check_pair(scope_guards[0],scope_guards[1],stop);
    }
    Observation<std::unique_ptr<OperationJournalFile>> open_bound_journal(const NativeName& name,bool create) {
        if(!request.prepared_journal_root)return unavailable<std::unique_ptr<OperationJournalFile>>(
            error(AdapterError::ProviderReviewRequired,"reviewed_tree.private_journal_root_unbound",ObservationState::Unsupported));
        return request.prepared_journal_root->open_journal(name,create);
    }
    void release_scanned_handles()noexcept {
        TreeCaptureLatch latch(request.prepared_journal_root);detail::MetadataCaptureCleanupScope scope(&latch);
        if(scanner){if(auto e=scanner->finish_io())record_finish(request.prepared_journal_root.get(),e->state,e->domain,e->code,e->operation);scanner.reset();}
        scope_guards={};ancestor.reset();
        for(auto* tree:{&source,&target}){for(auto& [key,node]:tree->nodes){node.held.reset();node.directory.reset();}tree->root.reset();}
        request.source_root.reset();request.destination_root.reset();
        if(latch.first){const auto&e=*latch.first;record_finish(request.prepared_journal_root.get(),e.state,e.domain,e.code,e.operation);}
        read_finish(request.prepared_journal_root.get());
    }
    void finish_owned_private_root() {
        if(progress.state<ReviewedTreeState::Complete||native_drained)return;
        // Scope ALL operation-owned native releases, not only capture dupes.
        // The stack latch retains the exact Root without allocating. Its POD
        // event survives DTO allocation failure and caller-owned Root teardown.
        auto kept=request.prepared_journal_root;auto* owner=kept.get();
        TreeCaptureLatch latch(kept);detail::MetadataCaptureCleanupScope scope(&latch);
        read_finish(owner);
        const auto returned=[&](const Observation<bool>& result,const char* op)noexcept {
            if(const auto* e=result.unavailable_detail())record_finish(owner,e->state,e->error.domain,e->error.code,e->error.operation);
            else if(!result.value()||!*result.value())record_finish(owner,ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),op);
        };
        if(copy) {
            try{std::stop_source stop;stop.request_stop();const auto state=copy->advance(stop.get_token());
                if(const auto& e=copy->result().failure;e)record_finish(owner,e->state,e->error.domain,e->error.code,e->error.operation);
                else if(state==OperationExecutionState::NeedsReconciliation||state==OperationExecutionState::RetainedSource)
                    record_finish(owner,ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"reviewed_tree.private_copy_terminal");
            }catch(...){record_finish(owner,ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"reviewed_tree.copy_finish_exception");}
            copy.reset();staging=nullptr;metadata_phase=nullptr;
        }
        retained.reset();release_scanned_handles();
        if(deleting){try{returned(deleting->file->finish_io(),"reviewed_tree.private_delete_finish_false");}
            catch(...){record_finish(owner,ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"reviewed_tree.delete_finish_exception");}deleting.reset();}
        request.open_journal={};auto root=std::move(request.prepared_journal_root);
        if(owns_private_root){
            // All consumers are drained. This local owner now protects the
            // Root during its own finalization; extra shared observer owners
            // must not masquerade as active consumers.
            owns_private_root=false;latch.release_root();kept.reset();
            try{returned(root->finish_io(),"reviewed_tree.private_root_finish_false");}
            catch(...){record_finish(owner,ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"reviewed_tree.root_finish_exception");}}
        if(latch.first){const auto&e=*latch.first;record_finish(owner,e.state,e.domain,e.code,e.operation);}
        // Always read back before public success, including borrowed Roots.
        // Consumer teardown never finishes a caller-owned Root.
        read_finish(owner);native_drained=true;
        if(finish_failed){
            progress.state=ReviewedTreeState::NeedsReconciliation;progress.recovery_required=true;
            for(auto& item:items)if(mutation(item.action)&&item.state==ReviewedTreeItemState::Complete){
                item.state=ReviewedTreeItemState::NeedsReconciliation;item.recovery_required=true;--progress.completed_items;++progress.failed_items;}
            fail({finish_failure.state,{finish_failure.domain,finish_failure.code,finish_failure.operation.data()}},true);
        }
    }
    void cancel_step(std::stop_token stop) {
        const auto copy_state=copy?copy->advance(stop):OperationExecutionState::Cancelled;
        const bool ambiguous=copy_state==OperationExecutionState::NeedsReconciliation||copy_state==OperationExecutionState::Complete||
            (deleting&&deleting->phase>=3);
        if(copy&&copy->result().failure) {
            const auto& e=*copy->result().failure;
            if(!interrupted_for_stop(e,stop)||ambiguous){fail(e,true);return;}
        }
        progress.state=ambiguous?ReviewedTreeState::NeedsReconciliation:mutated?ReviewedTreeState::Partial:ReviewedTreeState::Cancelled;
        progress.partial=mutated;progress.recovery_required=progress.recovery_required||mutated||ambiguous;
        if(current<items.size()){
            items[index()].state=ambiguous?ReviewedTreeItemState::NeedsReconciliation:ReviewedTreeItemState::Cancelled;
            items[index()].recovery_required=progress.recovery_required;
        }
    }
    void failure_or_cancel(const UnavailableObservation& e,std::stop_token stop,bool reconcile=false) {
        if(interrupted_for_stop(e,stop))cancel_step(stop);
        else fail(e,reconcile);
    }
    void fail(UnavailableObservation e, bool reconcile = false) {
        failure = e; progress.failure = e;
        progress.partial = mutated;
        progress.recovery_required = progress.recovery_required || reconcile || mutated;
        progress.state = reconcile ? ReviewedTreeState::NeedsReconciliation :
            mutated ? ReviewedTreeState::Partial : ReviewedTreeState::Failed;
        if (current < items.size()) {
            items[index()].failure = std::move(e);
            items[index()].state = reconcile ? ReviewedTreeItemState::NeedsReconciliation : ReviewedTreeItemState::Failed;
            items[index()].recovery_required = progress.recovery_required;
            ++progress.failed_items;
        }
    }
    bool roots_current() const {
        for (const auto& root : {request.source_root, request.destination_root}) {
            auto live = root->refresh();
            if (!live.value() || !(*live.value())->metadata().identity.value() ||
                !(*live.value())->metadata().mount_id.value() ||
                !same(*root->metadata().identity.value(), *(*live.value())->metadata().identity.value()) ||
                !equal(root->metadata().mount_id, (*live.value())->metadata().mount_id)) return false;
        }
        return true;
    }
    void topology_step() {
        const auto& root = ancestry_side == 0 ? request.source_root : request.destination_root;
        const auto& other = ancestry_side == 0 ? request.destination_root : request.source_root;
        if (!ancestor) {
            auto opened = root->parent()->open_directory_child(root->name());
            if (!opened.value()) { fail(*opened.unavailable_detail()); return; }
            auto metadata = (*opened.value())->inspect_basic();
            if (!metadata.value() || !qualified(*metadata.value()) ||
                !same(*root->metadata().identity.value(), *metadata.value()->identity.value())) {
                fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.root_identity")); return;
            }
            ancestors.push_back(*metadata.value()->identity.value());
            auto parent = (*opened.value())->open_parent_directory();
            if (!parent.value()) { fail(*parent.unavailable_detail()); return; }
            ancestor = std::move(parent).take_value(); return;
        }
        auto metadata = ancestor->inspect_basic();
        if (!metadata.value() || !qualified(*metadata.value())) {
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.ancestry_metadata")); return;
        }
        const auto id = *metadata.value()->identity.value();
        if (same(id, *other->metadata().identity.value())) {
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.overlap")); return;
        }
        if (same(id, ancestors.back())) {
            if (ancestors.size() == 1) { fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.namespace_root")); return; }
            if (ancestry_side == 1) {
                if (!endpoint || !same(*endpoint, id)) { fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.namespace_boundary")); return; }
                topology_done = true;
            } else { endpoint = id; ++ancestry_side; }
            ancestor.reset(); ancestors.clear(); return;
        }
        if (ancestors.size() >= 1024 || std::any_of(ancestors.begin(), ancestors.end(), [&](const auto& old) { return same(old, id); })) {
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.ancestry_cycle")); return;
        }
        ancestors.push_back(id);
        auto parent = ancestor->open_parent_directory();
        if (!parent.value()) { fail(*parent.unavailable_detail()); return; }
        ancestor = std::move(parent).take_value();
    }
    void reset_topology() {
        topology_done = false; ancestor.reset(); ancestors.clear(); endpoint.reset(); ancestry_side = 0;
    }
    void start_scan(unsigned phase) {
        scan_phase = phase;
        scanner = std::make_unique<Scanner>((phase % 2 == 0) ? request.source_root : request.destination_root,
            request,scope_guards[phase%2]);
    }
    void scan_step(std::stop_token stop) {
        if (!scanner) {
            if (name_check) { check_one_name(); return; }
            start_scan(0); return;
        }
        scanner->step(stop);
        if (scanner->failure) { failure_or_cancel(*scanner->failure,stop); return; }
        if (!scanner->complete) return;
        if(auto e=scanner->finish_io()){fail({e->state,{e->domain,e->code,e->operation}});return;}
        auto observed = std::move(scanner->tree);
        if (progress.state == ReviewedTreeState::Inventory) {
            if (scan_phase == 0) { source = std::move(observed); start_scan(1); }
            else if (scan_phase == 1) { target = std::move(observed); start_scan(2); }
            else if (scan_phase == 2) {
                if (!equal_tree(source, observed)) { fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.source_unstable", ObservationState::Changed)); return; }
                source = std::move(observed); start_scan(3);
            } else {
                if (!equal_tree(target, observed) || !roots_current()) { fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.target_unstable", ObservationState::Changed)); return; }
                target = std::move(observed); scanner.reset(); name_check = source.nodes.cbegin();
            }
            return;
        }
        if (!equal_tree(scan_phase == 0 ? source : target, observed) || !roots_current()) {
            fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.receipt_evidence_changed", ObservationState::Changed)); return;
        }
        if (scan_phase == 0) { start_scan(1); return; }
        scanner.reset();
        progress.state = ReviewedTreeState::Executing;
        if (current == items.size()) { progress.state = ReviewedTreeState::Complete; progress.partial = false; progress.recovery_required = false; }
    }
    void check_one_name() {
        if (*name_check == source.nodes.cend()) { name_check.reset(); seal(); return; }
        const auto& [key, n] = **name_check;
        ++*name_check;
        auto parent = parent_for(n, false);
        if (!parent.value()) {
            // A missing reviewed destination ancestor is expected for a new
            // subtree; any failure along an existing parent chain is not.
            std::vector<NativeName> prefix;
            for (std::size_t i = 0; i + 1 < n.names.size(); ++i) {
                prefix.push_back(n.names[i]);
                if (!target.nodes.contains(key_path(prefix))) return;
            }
            fail(*parent.unavailable_detail()); return;
        }
        auto lookup = (*parent.value())->lookup_child(n.names.back(), ChildLookupMode::NativeDefault);
        if (!lookup.value()) { fail(*lookup.unavailable_detail()); return; }
        if (lookup.value()->state() == ChildLookupState::Found) {
            auto exact = target.nodes.find(key);
            auto metadata = lookup.value()->entry()->inspect_basic();
            if (!metadata.value() || !metadata.value()->identity.value() || exact == target.nodes.end() ||
                !same(*exact->second.metadata.identity.value(), *metadata.value()->identity.value()))
                fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.native_name_collision"));
        } else if (lookup.value()->state() != ChildLookupState::Missing)
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.name_lookup_unknown"));
    }
    void seal() {
        auto protected_scope=private_scope_guard();
        if(!protected_scope.value()){fail(*protected_scope.unavailable_detail());return;}
        if (source.nodes.size() > request.limits.max_entries - target.nodes.size()) {
            fail(error(AdapterError::InventoryLimit, "reviewed_tree.combined_entries")); return;
        }
        std::map<std::string, std::string> folded;
        for (const auto* t : {&source, &target}) for (const auto& [key, n] : t->nodes) {
            const auto f = key_path(n.names, true);
            const auto [it, added] = folded.emplace(f, key);
            if (!added && it->second != key) { fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.cross_tree_case_collision")); return; }
        }
        using IdentityKey = std::tuple<IdentityScheme, std::array<std::byte,16>, std::array<std::byte,16>>;
        std::set<IdentityKey> source_ids;
        for (const auto& [key, n] : source.nodes) {
            const auto& id = *n.metadata.identity.value();
            source_ids.emplace(id.scheme, id.volume.bytes, id.object.bytes);
        }
        for (const auto& [key, n] : target.nodes) {
            const auto& id = *n.metadata.identity.value();
            if (source_ids.contains({id.scheme, id.volume.bytes, id.object.bytes})) {
                fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.cross_tree_alias")); return;
            }
        }
        auto s = entries(source), d = entries(target);
        request.comparison.topology = ComparisonTopology::Disjoint;
        auto created = ComparisonPlan::create(request.comparison,
            {ComparisonInventoryState::CompleteStable, *source.root_metadata.identity.value(), s},
            {ComparisonInventoryState::CompleteStable, *target.root_metadata.identity.value(), d}, {}, request.limits);
        if (!created.value()) { fail(*created.unavailable_detail()); return; }
        plan = *created.value();
        for (std::size_t offset = 0;;) {
            auto page = plan->page(offset, request.limits.max_page_rows);
            if (!page.value()) { fail(*page.unavailable_detail()); return; }
            for (const auto& row : page.value()->rows) {
                const auto& tree = source.nodes.contains(row.relative_path) ? source : target;
                ReviewedTreeItem item;
                item.row = row; item.relative_components = tree.nodes.at(row.relative_path).names;
                item.action = action(row.action);
                fill_facts(item);
                items.push_back(std::move(item));
            }
            if (!page.value()->next_offset) break;
            offset = *page.value()->next_offset;
        }
        progress.known_items = items.size(); progress.counts_complete = true;
        progress.known_copy_bytes = plan->aggregate().proposed_copy_bytes;
        progress.state = ReviewedTreeState::AwaitingReview;
    }
    // Rewalk exact native components from the held root; a retained child ID
    // alone cannot certify that its reviewed ancestor/name chain still exists.
    Observation<std::shared_ptr<const DirectoryCursor>> parent_for(const Node& n, bool incoming) const {
        const auto& t = incoming ? source : target;
        auto cursor = t.root;
        std::vector<NativeName> prefix;
        for (std::size_t i = 0; i + 1 < n.names.size(); ++i) {
            prefix.push_back(n.names[i]);
            auto known = t.nodes.find(key_path(prefix));
            if (known == t.nodes.end() || !known->second.directory) return invalid<std::shared_ptr<const DirectoryCursor>>("reviewed_tree.parent_map");
            auto opened = cursor->open_directory_child(n.names[i]);
            if (!opened.value()) return unavailable<std::shared_ptr<const DirectoryCursor>>(*opened.unavailable_detail());
            cursor = std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
            auto m = cursor->inspect_basic();
            if (!m.value() || !m.value()->identity.value() || !m.value()->mount_id.value() ||
                !same(*known->second.metadata.identity.value(), *m.value()->identity.value()) ||
                *m.value()->mount_id.value() != *t.root_metadata.mount_id.value())
                return unavailable<std::shared_ptr<const DirectoryCursor>>(error(AdapterError::PlanDecisionStale, "reviewed_tree.parent_substituted", ObservationState::Changed));
        }
        return Observation<std::shared_ptr<const DirectoryCursor>>::available(std::move(cursor));
    }
    const NativeName& publication_name(const Node& n) const {
        const auto& item = items[index()];
        return item.name_side == ReviewedTreeNameSide::Incoming && item.proposed_name ? *item.proposed_name : n.names.back();
    }
    Observation<bool> guard(const Node& n) const {
        auto private_scope=private_scope_guard();if(!private_scope.value())return private_scope;
        if (!roots_current_const()) return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.root_substituted", ObservationState::Changed));
        auto s = parent_for(n, true), d = parent_for(n, false);
        if (!s.value()) return unavailable<bool>(*s.unavailable_detail());
        if (!d.value()) return unavailable<bool>(*d.unavailable_detail());
        auto now = HeldChild::observe_with_access(*s.value(), n.names.back(), EntryAccess::ContentRead);
        if (!now.value()) return unavailable<bool>(*now.unavailable_detail());
        if (!unchanged(n.metadata, (*now.value())->metadata()))
            return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.source_changed", ObservationState::Changed));
        if (items[index()].action == ReviewedTreeAction::Replace && !replacement_prepared) {
            const auto old = target.nodes.find(n.entry.relative_path);
            if (old == target.nodes.end()) return invalid<bool>("reviewed_tree.replacement_target");
            return target_guard(old->second);
        }
        if (items[index()].name_side == ReviewedTreeNameSide::Incoming && items[index()].row.destination_index) {
            const auto old = target.nodes.find(n.entry.relative_path);
            if (old == target.nodes.end()) return invalid<bool>("reviewed_tree.incoming_target_evidence");
            auto valid = target_guard(old->second, false);
            if (!valid.value()) return valid;
        }
        auto missing = (*d.value())->lookup_child(publication_name(n), ChildLookupMode::NativeDefault);
        if (!missing.value()) return unavailable<bool>(*missing.unavailable_detail());
        if (missing.value()->state() != ChildLookupState::Missing)
            return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.destination_occupied", ObservationState::Changed));
        return Observation<bool>::available(true);
    }
    bool roots_current_const() const { return roots_current(); }
    static bool expected_directory_change(const BasicMetadata& before, const BasicMetadata& now) {
        return qualified(now) && *now.kind.value() == ObjectKind::Directory &&
            same(*before.identity.value(), *now.identity.value()) && equal(before.mount_id, now.mount_id) &&
            equal(before.posix_permissions, now.posix_permissions) && equal(before.posix_uid, now.posix_uid) &&
            equal(before.posix_gid, now.posix_gid) && equal(before.bsd_flags, now.bsd_flags) &&
            equal(before.windows_attributes, now.windows_attributes);
    }
    void refresh_target_ancestors(const Node& n) {
        auto metadata = target.root->inspect_basic();
        if (!metadata.value()) { fail(*metadata.unavailable_detail(), true); return; }
        if (!expected_directory_change(target.root_metadata, *metadata.value())) {
            fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.destination_metadata_changed", ObservationState::Changed), true); return;
        }
        target.root_metadata = *metadata.value();
        std::vector<NativeName> prefix;
        for (std::size_t i = 0; i + 1 < n.names.size(); ++i) {
            prefix.push_back(n.names[i]); auto& parent = target.nodes.at(key_path(prefix));
            auto now = parent.directory->inspect_basic();
            if (!now.value()) { fail(*now.unavailable_detail(), true); return; }
            if (!expected_directory_change(parent.metadata, *now.value())) {
                fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.parent_metadata_changed", ObservationState::Changed), true); return;
            }
            parent.metadata = *now.value(); parent.entry.object = comparison_object(parent.metadata);
        }
    }
    bool record_retained(const Node& incoming) {
        auto found = target.nodes.find(incoming.entry.relative_path);
        if (found == target.nodes.end() || !items[index()].retained_name) {
            fail(error(AdapterError::InvalidNativeResult, "reviewed_tree.retained_record"), true); return false;
        }
        Node old = found->second;
        auto parent = parent_for(old, false);
        if (!parent.value()) { fail(*parent.unavailable_detail(), true); return false; }
        auto observed = HeldChild::observe_with_access(*parent.value(), *items[index()].retained_name, EntryAccess::ContentRead);
        if (!observed.value()) { fail(*observed.unavailable_detail(), true); return false; }
        const auto metadata = (*observed.value())->metadata();
        if (!qualified(metadata) || !same(*old.metadata.identity.value(), *metadata.identity.value()) ||
            !equal(old.metadata.logical_size, metadata.logical_size) || !equal(old.metadata.mount_id, metadata.mount_id)) {
            fail(error(AdapterError::MetadataChanged, "reviewed_tree.retained_identity", ObservationState::Changed), true); return false;
        }
        old.names.back() = *items[index()].retained_name;
        old.held = *observed.value(); old.metadata = metadata;
        old.entry.relative_path = key_path(old.names); old.entry.object = comparison_object(metadata);
        if (old.entry.digest) { old.entry.digest->before = old.entry.object; old.entry.digest->after = old.entry.object; }
        target.nodes.erase(found);
        const auto key = old.entry.relative_path;
        if (!target.nodes.emplace(key, std::move(old)).second) {
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.retained_collision"), true); return false;
        }
        return true;
    }
    void record_created(const Node& incoming, bool directory) {
        auto parent = parent_for(incoming, false);
        if (!parent.value()) { fail(*parent.unavailable_detail(), true); return; }
        auto held = directory ? HeldChild::observe(*parent.value(), publication_name(incoming)) :
            HeldChild::observe_with_access(*parent.value(), publication_name(incoming), EntryAccess::ContentRead);
        if (!held.value()) { fail(*held.unavailable_detail(), true); return; }
        Node n{incoming.names, *held.value(), {}, (*held.value())->metadata(), {}};
        n.names.back() = publication_name(incoming);
        if (!qualified(n.metadata) || *n.metadata.mount_id.value() != *target.root_metadata.mount_id.value() ||
            *n.metadata.kind.value() != (directory ? ObjectKind::Directory : ObjectKind::RegularFile)) {
            fail(error(AdapterError::MetadataChanged, "reviewed_tree.created_kind", ObservationState::Changed), true); return;
        }
        n.entry.relative_path = key_path(n.names); n.entry.object = comparison_object(n.metadata);
        if (directory) {
            auto opened = (*parent.value())->open_directory_child(incoming.names.back());
            if (!opened.value()) { fail(*opened.unavailable_detail(), true); return; }
            n.directory = std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
            if (!n.directory->identity().value() || !same(*n.directory->identity().value(), *n.metadata.identity.value())) {
                fail(error(AdapterError::MetadataChanged, "reviewed_tree.created_identity", ObservationState::Changed), true); return;
            }
        } else {
            if (!staging_before || !same(*staging_before->identity.value(), *n.metadata.identity.value()) ||
                !equal(staging_before->logical_size, n.metadata.logical_size)) {
                fail(error(AdapterError::MetadataChanged, "reviewed_tree.published_identity", ObservationState::Changed), true); return;
            }
            ComparisonDigest digest = *incoming.entry.digest;
            digest.before = n.entry.object; digest.after = n.entry.object;
            n.entry.digest = digest;
        }
        const auto created_key = n.entry.relative_path;
        if (!target.nodes.emplace(created_key, std::move(n)).second) {
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.output_name_occupied"), true); return;
        }
        items[index()].resulting_name = publication_name(incoming);
        refresh_target_ancestors(incoming);
    }
    void finish_item() {
        items[index()].state = ReviewedTreeItemState::Complete; ++progress.completed_items;
        ++current; progress.current_row.reset();
        progress.state = ReviewedTreeState::Revalidating;
        reset_topology(); start_scan(0);
    }
    void staging_step() {
        // The native stream copier binds its complete source/destination
        // digests to reviewed_content_digest BEFORE metadata application. Do
        // not read data after final timestamps: relatime can change atime and
        // invalidate otherwise correct strict metadata preservation.
        auto now=staging->inspect_basic();
        if(!now.value()) { fail(*now.unavailable_detail(),true);return; }
        const auto& incoming=source.nodes.at(items[index()].row.relative_path);
        if(!qualified(*now.value()) || *now.value()->kind.value()!=ObjectKind::RegularFile ||
            !equal(now.value()->logical_size,incoming.metadata.logical_size)) {
            fail(error(AdapterError::MetadataChanged,"reviewed_tree.staging_identity_size",ObservationState::Changed),true);return;
        }
        staging_before=*now.value();staging_verified=true;
    }
    std::optional<NativeAbsolutePath> address_for(const Node& n) const {
        auto address = request.destination_address;
        if (address) for (std::size_t i = 0; i + 1 < n.names.size(); ++i) {
            auto child = address->child_address(n.names[i]);
            if (!child.value()) return std::nullopt;
            address = std::move(child).take_value();
        }
        return address;
    }
    void start_copy(const Node& n, std::stop_token stop) {
        auto parent = parent_for(n, false);
        if (!parent.value()) { fail(*parent.unavailable_detail()); return; }
        auto preservation = preservation_for(n.held, request.copy_policy, stop);
        if (!preservation.value()) { fail(*preservation.unavailable_detail()); return; }
        if(!request.copy_policy.allow_unhandled_metadata_loss){
            // Existing execution capture is native-authenticated; this is a
            // memory-only check against the closed, reviewed source facts.
            // Never let a later ADS/security capture silently supersede review.
            const auto* captured=(*preservation.value())->captured_metadata();
            const auto& expected=n.entry.metadata_digest;
            if(!captured||!expected||expected->state!=ComparisonDigestState::CompleteStable){fail(error(AdapterError::PlanDecisionStale,"reviewed_tree.required_metadata_capture_missing",ObservationState::Changed));return;}
            const auto digest=detail::metadata_snapshot_semantic_digest(*captured,stop);
            const auto owner=captured->policy.ownership==MetadataOwnership::CurrentCaller?metadata_ownership_digest(*captured):Observation<SyncDigest>::available({});
            if(!digest.value()||*digest.value()!=expected->bytes||metadata_binding(captured->policy)!=expected->policy_binding||
               (captured->policy.ownership==MetadataOwnership::CurrentCaller&&(!owner.value()||!expected->canonical_owner_digest||*owner.value()!=*expected->canonical_owner_digest))){
                fail(error(AdapterError::PlanDecisionStale,"reviewed_tree.source_metadata_capture_changed",ObservationState::Changed));return;}
        }
        auto id = request.journal_id;
        for (unsigned i = 0; i < 8; ++i) id.bytes[8 + i] = std::byte((items[index()].row.id >> (8 * i)) & 255);
        std::string suffix;
        constexpr char hex[] = "0123456789abcdef";
        for (auto b : id.bytes) { unsigned v = std::to_integer<unsigned>(b); suffix += hex[v >> 4]; suffix += hex[v & 15]; }
        auto name = [&](std::string prefix) -> NativeName {
            prefix += suffix;
            if (n.names.back().posix_bytes()) return *NativeName::from_posix(std::move(prefix));
            return *NativeName::from_windows(std::u16string(prefix.begin(), prefix.end()));
        };
        if (items[index()].action == ReviewedTreeAction::Replace && !retained) {
            const auto& old = target.nodes.at(n.entry.relative_path);
            const auto retention_id = items[index()].retention_journal_id;
            if (!items[index()].retained_name || !retention_id) {
                fail(error(AdapterError::PlanInvalid, "reviewed_tree.retained_receipt_name")); return;
            }
            RetainedTargetRequest retention{old.held, *items[index()].retained_name, old.entry.digest->bytes,
                *request.journal_root, *retention_id, address_for(old), [this, &old] { return target_guard(old); }, request.digest_chunk_bytes};
            retention.open_journal=request.open_journal;
            retention.prepared_journal_root=request.prepared_journal_root;
            auto prepared = RetainedTarget::create(std::move(retention));
            if (!prepared.value()) { fail(*prepared.unavailable_detail(), prepared.state() == ObservationState::Unknown); return; }
            retained = *prepared.value(); progress.recovery_required = true; items[index()].recovery_required = true;
            return;
        }
        items[index()].journal_id = id;
        items[index()].journal_name = name(".ck-reviewed-journal-");
        items[index()].staging_name = name(".ck-reviewed-staging-");
        items[index()].recovery_required = true;
        auto file = open_bound_journal(*items[index()].journal_name, true);
        if (!file.value()) { fail(*file.unavailable_detail(), true); return; }
        auto journal = OperationJournal::create(FileOperation::Copy, id, request.copy_policy.journal_limits);
        if (!journal.value()) { fail(*journal.unavailable_detail(), true); return; }
        auto appended = append_operation_journal_file(**file.value(), **journal.value(), {1, 0, OperationJournalState::Planned, {}});
        if (!appended.value()) { fail(*appended.unavailable_detail(), true); return; }
        std::optional<NativeAbsolutePath> address = request.destination_address;
        if (address) for (std::size_t i = 0; i + 1 < n.names.size(); ++i) {
            auto child = address->child_address(n.names[i]);
            if (!child.value()) { fail(*child.unavailable_detail(), true); return; }
            address = std::move(child).take_value();
        }
        NativeOperationCopyRequest r{
            .journal = *journal.value(),
            .journal_file = std::shared_ptr<OperationJournalFile>(std::move(file).take_value()),
            .item = 0,
            .source_parent = n.held->parent(),
            .source_parent_identity = *n.held->parent_identity().value(),
            .source_name = n.names.back(),
            .source_identity = *n.metadata.identity.value(),
            .destination = *parent.value(),
            .destination_identity = *(*parent.value())->identity().value(),
            .destination_address = address,
            .staging_name = name(".ck-reviewed-staging-"),
            .destination_name = publication_name(n),
            .copy_limits = request.copy_policy.copy_limits,
            .prepare_metadata = {},
            .operation = FileOperation::Copy,
            .verify_metadata_before_publication = {}};
        r.reviewed_content_digest=n.entry.digest->bytes;
        auto policy = *preservation.value();
        r.prepare_metadata = [this, policy](OpenedEntry& stage, std::stop_token token) {
            staging = &stage;
            auto prepared = policy->prepare(stage, token);
            if (prepared.value()) metadata_phase = prepared.value()->get();
            return prepared;
        };
        r.verify_metadata_before_publication = [this, policy, &n](OpenedEntry& stage, std::stop_token token) {
            auto valid = guard(n);
            if (!valid.value()) return valid;
            if (!staging_verified || !staging_before) return invalid<bool>("reviewed_tree.staging_not_verified");
            auto now = stage.inspect_basic();
            if (!now.value() || !unchanged(*staging_before, *now.value()))
                return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.staging_changed", ObservationState::Changed));
            return policy->verify(stage, token);
        };
        if (items[index()].action == ReviewedTreeAction::Replace) {
            r.prepare_destination_before_publication = [this](std::stop_token token) {
                if (!retained || retained->state() != RetainedTargetState::Ready) return invalid<bool>("reviewed_tree.retention_not_ready");
                auto retained_result = retained->retain(token);
                if (retained_result.value() && *retained_result.value()) {
                    replacement_prepared = true; mutated = true; progress.partial = true;
                    items[index()].target_retained = true;
                }
                return retained_result;
            };
        }
        auto job = NativeOperationCopyJob::create(std::move(r));
        if (!job.value()) { fail(*job.unavailable_detail(), true); return; }
        copy = std::move(job).take_value(); progress.recovery_required = true;
    }
    Observation<bool> qualify_new_names(std::span<const ReviewedTreeItem> resolved) const {
        struct Candidate { NativeName name; const Node* context; };
        std::map<std::string, std::vector<Candidate>> groups;
        std::set<std::string> exact, folded;
        for (const auto& item : resolved) {
            if (item.action != ReviewedTreeAction::Copy && item.action != ReviewedTreeAction::CreateDirectory && item.action != ReviewedTreeAction::Replace) continue;
            const auto& n = source.nodes.at(item.row.relative_path);
            if (item.action == ReviewedTreeAction::Replace && !item.retained_name) return invalid<bool>("reviewed_tree.retained_receipt_name");
            const auto& candidate = item.action == ReviewedTreeAction::Replace ? *item.retained_name :
                (item.name_side == ReviewedTreeNameSide::Incoming && item.proposed_name ? *item.proposed_name : n.names.back());
            auto names = n.names; names.back() = candidate;
            if (key_path(names).size() > request.limits.max_path_bytes) return invalid<bool>("reviewed_tree.proposed_name_limit");
            if (!exact.insert(key_path(names)).second || !folded.insert(key_path(names, true)).second)
                return unavailable<bool>(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.planned_name_collision"));
            names.pop_back(); groups[key_path(names)].push_back({candidate, &n});
            auto parent = parent_for(n, false);
            if (parent.value()) {
                auto lookup = (*parent.value())->lookup_child(candidate, ChildLookupMode::NativeDefault);
                if (!lookup.value()) return unavailable<bool>(*lookup.unavailable_detail());
                if (lookup.value()->state() != ChildLookupState::Missing)
                    return unavailable<bool>(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.native_name_collision", ObservationState::Changed));
            }
        }
        for (const auto& [key, nodes] : groups) {
            if (nodes.size() < 2 || std::all_of(nodes.begin(), nodes.end(), [](const Candidate& n) { return ascii_units(n.name); })) continue;
            auto parent = parent_for(*nodes.front().context, false);
            if (!parent.value()) return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.future_directory_name_policy", ObservationState::Unsupported));
            auto policy = DirectoryNameRulesProbe::inspect(*parent.value());
            if (!policy.value()) return unavailable<bool>(*policy.unavailable_detail());
            if (!(*policy.value())->rule().value()) return unavailable<bool>(*(*policy.value())->rule().unavailable_detail());
            if ((*policy.value())->rule().value()->rule != DirectoryNameRule::LinuxExtendedFsBytewise)
                return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.unqualified_name_policy", ObservationState::Unsupported));
        }
        return Observation<bool>::available(true);
    }
    void update_rules(std::span<const ConflictRule> rules, std::span<const ReviewedTreeNameChoice> names) {
        const auto equal_rule = [](const ConflictRule& a, const ConflictRule& b) {
            return a.plan == b.plan && a.kind == b.kind && a.choice == b.choice && a.tie == b.tie &&
                a.scope == b.scope && a.selected_rows == b.selected_rows && a.subtree == b.subtree &&
                a.protect_nonempty == b.protect_nonempty && a.retain_replaced == b.retain_replaced && a.direction == b.direction;
        };
        const auto equal_name = [](const ReviewedTreeNameChoice& a, const ReviewedTreeNameChoice& b) {
            return a.token == b.token && a.name == b.name && a.side == b.side;
        };
        if (!assessed || rules.size() != assessed_rules.size() || names.size() != assessed_names.size() ||
            !std::equal(rules.begin(), rules.end(), assessed_rules.begin(), equal_rule) ||
            !std::equal(names.begin(), names.end(), assessed_names.begin(), equal_name)) {
            revision = std::make_shared<const unsigned char>(0);
            assessed_rules.assign(rules.begin(), rules.end()); assessed_names.assign(names.begin(), names.end());
            assessed = true; last_assessment.reset();
        }
    }
    static std::uint64_t choice_bit(ConflictChoice c) { return std::uint64_t{1} << static_cast<unsigned>(c); }
    void fill_facts(ReviewedTreeItem& item) const {
        auto& out = item.facts;
        out = {}; out.timestamp_quantum_ns = request.comparison.timestamp_quantum_ns;
        const auto s = source.nodes.find(item.row.relative_path), d = target.nodes.find(item.row.relative_path);
        out.source_present = s != source.nodes.end(); out.destination_present = d != target.nodes.end();
        if(s!=source.nodes.end()){out.source_metadata=s->second.entry.metadata_digest;out.source_metadata_failure=s->second.metadata_failure;}
        if(d!=target.nodes.end()){out.destination_metadata=d->second.entry.metadata_digest;out.destination_metadata_failure=d->second.metadata_failure;}
        if (out.source_present) { out.source_kind = s->second.entry.object.kind; out.source_size = s->second.entry.object.size; out.source_modified = s->second.entry.object.modified; }
        if (out.destination_present) { out.destination_kind = d->second.entry.object.kind; out.destination_size = d->second.entry.object.size; out.destination_modified = d->second.entry.object.modified; }
        out.allowed_choices = choice_bit(ConflictChoice::Ask) | choice_bit(ConflictChoice::Skip) | choice_bit(ConflictChoice::Cancel) | choice_bit(ConflictChoice::Compare);
        if (out.destination_present) out.allowed_choices |= choice_bit(ConflictChoice::KeepTarget);
        const auto known=[](const auto& value){return value&&value->state==ComparisonDigestState::CompleteStable&&
            (value->ownership!=ComparisonMetadataOwnership::CurrentCaller||value->canonical_owner_digest.has_value());};
        const bool source_allowed=request.copy_policy.allow_unhandled_metadata_loss||known(out.source_metadata);
        if (source_allowed && out.source_kind == ObjectKind::RegularFile && (!out.destination_present || out.destination_kind == ObjectKind::RegularFile))
            out.allowed_choices |= choice_bit(ConflictChoice::KeepBothIncoming) | choice_bit(ConflictChoice::Rename);
        if (request.copy_policy.allow_unhandled_metadata_loss && out.source_kind == ObjectKind::Directory && out.destination_kind == ObjectKind::Directory)
            out.allowed_choices |= choice_bit(ConflictChoice::MergeFolders);
    }
    const std::vector<ReviewedTreeItem>& assessment(std::span<const ConflictRule> rules,
        std::span<const ReviewedTreeNameChoice> names = {}) {
        update_rules(rules, names);
        if (last_assessment) return *last_assessment;
        auto resolved = items;
        const bool reporting = request.comparison.profile == ComparisonProfile::Compare;
        bool invalid_selection = rules.size() > 100'000 || names.size() > items.size();
        std::map<std::uint64_t, const ReviewedTreeNameChoice*> chosen;
        for (const auto& name : names) {
            if (!name.token.is_valid() || name.token.plan_identity() != plan->identity() || name.token.row_id() > items.size() ||
                !name.name.is_valid() || name.name.encoding() != request.destination_root->name().encoding() ||
                static_cast<unsigned>(name.side) > static_cast<unsigned>(ReviewedTreeNameSide::Target) ||
                !chosen.emplace(name.token.row_id(), &name).second) invalid_selection = true;
        }
        for (const auto& rule : rules) {
            for (auto id : rule.selected_rows) if (!id || id > items.size()) invalid_selection = true;
            if (rule.scope == ConflictScope::Subtree && std::none_of(items.begin(), items.end(),
                [&](const auto& item) { return item.row.relative_path == rule.subtree; })) invalid_selection = true;
        }
        for (auto& item : resolved) {
            fill_facts(item);
            const auto d = target.nodes.find(item.row.relative_path);
            ConflictFacts facts;
            facts.token = item.row.token; facts.relative_path = item.row.relative_path;
            facts.relation = item.row.relation; facts.evidence_current = true;
            const bool both = item.facts.source_present && item.facts.destination_present;
            facts.kind = !both ? ConflictClass::Unavailable :
                item.row.relation == ComparisonRelation::DirectoryPair ? ConflictClass::DirectoryPair :
                item.row.relation == ComparisonRelation::TypeConflict ? ConflictClass::TypeMismatch : ConflictClass::ExistingRegular;
            item.facts.conflict_class = facts.kind;
            if (both) {
                facts.compatible_regular_files = item.facts.source_kind == ObjectKind::RegularFile && item.facts.destination_kind == ObjectKind::RegularFile;
                facts.compatible_directories = item.facts.source_kind == ObjectKind::Directory && item.facts.destination_kind == ObjectKind::Directory;
                facts.source_size = item.facts.source_size; facts.target_size = item.facts.destination_size;
                const auto quantum = request.comparison.timestamp_quantum_ns;
                const auto rounded = [quantum](const FileTimestamp& t) {
                    if (quantum <= 1'000'000'000) return std::pair(t.seconds(), std::uint64_t(t.nanoseconds()) / quantum);
                    const auto seconds = static_cast<std::int64_t>(quantum / 1'000'000'000);
                    auto count = t.seconds() / seconds; if (t.seconds() % seconds < 0) --count;
                    return std::pair(count, std::uint64_t{0});
                };
                const auto st = rounded(*item.facts.source_modified), dt = rounded(*item.facts.destination_modified);
                facts.time_order = st > dt ? ConflictTimeOrder::SourceNewer : st < dt ? ConflictTimeOrder::TargetNewer : ConflictTimeOrder::Equal;
                facts.equal_time = facts.time_order == ConflictTimeOrder::Equal;
                if (!reporting && facts.compatible_regular_files && request.journal_root && request.open_journal) {
                    const auto qualified = qualify_namespace(*d->second.held->parent());
                    if (qualified.value() && *qualified.value() && d->second.metadata.link_count.value() && *d->second.metadata.link_count.value() == 1) {
                        // Provider rename support alone is not a content freeze.
                        // Probe the same owning guard required by RetainedTarget;
                        // execution reacquires/revalidates it before any hashing.
                        auto guard = HeldChild::observe_with_access(d->second.held->parent(), d->second.held->name(),
                            EntryAccess::ContentRead | EntryAccess::RenameSource);
                        if (guard.value() && unchanged(d->second.metadata, (*guard.value())->metadata())) {
                            const auto stable = (*guard.value())->qualify_stable_content();
                            if (stable.value() && *stable.value()) {
                                const auto current = (*guard.value())->inspect_basic();
                                const auto membership = d->second.held->refresh();
                                facts.retention_available = current.value() && membership.value() &&
                                    unchanged(d->second.metadata, *current.value()) &&
                                    unchanged(d->second.metadata, (*membership.value())->metadata());
                            }
                        }
                    }
                }
            }
            item.facts.retained_target_available = facts.retention_available;
            if (facts.retention_available) for (const auto c : {ConflictChoice::UseSource, ConflictChoice::KeepBothTarget,
                ConflictChoice::Newest, ConflictChoice::SourceIfNewer, ConflictChoice::NewerOrDifferentSizeAtEqualTime,
                ConflictChoice::SizeDiffers, ConflictChoice::PreferLarger, ConflictChoice::PreferSmaller}) item.facts.allowed_choices |= choice_bit(c);
            auto result = evaluate_conflict_rules(rules, facts);
            const auto selected = chosen.find(item.row.id);
            const auto* native = selected == chosen.end() ? nullptr : selected->second;
            if (native) { item.proposed_name = native->name; item.name_side = native->side; }
            if (!both && native && native->side == ReviewedTreeNameSide::Incoming && item.facts.source_kind == ObjectKind::RegularFile &&
                item.row.action == ComparisonAction::CopyToDestination &&
                (result.state == ConflictRuleState::NoMatch || result.choice == ConflictChoice::Rename || result.choice == ConflictChoice::KeepBothIncoming)) {
                result = {}; result.state = ConflictRuleState::Apply; result.choice = ConflictChoice::Rename;
            }
            if (result.state == ConflictRuleState::NoMatch && item.row.requires_review) {
                result.state = ConflictRuleState::NeedsReview; result.reason = ConflictRuleReason::NoMatchingRule;
            }
            if (!reporting && result.state == ConflictRuleState::Apply) {
                switch (result.choice) {
                case ConflictChoice::KeepTarget: case ConflictChoice::Skip: item.action = ReviewedTreeAction::Skip; break;
                case ConflictChoice::UseSource: item.action = ReviewedTreeAction::Replace; break;
                case ConflictChoice::MergeFolders: item.action = ReviewedTreeAction::MergeDirectory; break;
                case ConflictChoice::KeepBothIncoming: case ConflictChoice::Rename: case ConflictChoice::KeepBothTarget: {
                    const auto side = result.choice == ConflictChoice::KeepBothTarget ? ReviewedTreeNameSide::Target : ReviewedTreeNameSide::Incoming;
                    if (!native || native->side != side || item.facts.source_kind != ObjectKind::RegularFile ||
                        (side == ReviewedTreeNameSide::Target && item.facts.destination_kind != ObjectKind::RegularFile)) {
                        result.state = ConflictRuleState::NeedsReview; result.reason = ConflictRuleReason::AwaitingChoice; break;
                    }
                    item.action = side == ReviewedTreeNameSide::Incoming ? ReviewedTreeAction::Copy : ReviewedTreeAction::Replace;
                    result.requires_native_name_allocation = false; break;
                }
                default: result.state = ConflictRuleState::NeedsReview; result.reason = ConflictRuleReason::SeparatePolicyRequired; break;
                }
            }
            if (native && result.choice != ConflictChoice::KeepBothIncoming && result.choice != ConflictChoice::KeepBothTarget && result.choice != ConflictChoice::Rename) {
                result.state = ConflictRuleState::Invalid; result.reason = ConflictRuleReason::InvalidRule;
            }
            const bool needs_retention = item.action == ReviewedTreeAction::Replace ||
                result.choice == ConflictChoice::UseSource || result.choice == ConflictChoice::KeepBothTarget;
            if (!reporting && needs_retention && !facts.retention_available &&
                result.state != ConflictRuleState::Invalid && result.state != ConflictRuleState::Stale) {
                result.state = ConflictRuleState::NeedsReview; result.reason = ConflictRuleReason::RetentionUnavailable;
            }
            // A Compare rule remains descriptive evidence. Never turn its
            // preference into a mutation or synthesize retention capability.
            if (reporting && native) { result.state = ConflictRuleState::Invalid; result.reason = ConflictRuleReason::InvalidRule; }
            if (invalid_selection) { result.state = ConflictRuleState::Invalid; result.reason = ConflictRuleReason::InvalidRule; }
            item.decision = result;
        }
        for (auto& item : resolved) if (item.action == ReviewedTreeAction::Replace) {
            auto id = request.journal_id;
            for (unsigned i = 0; i < 8; ++i) id.bytes[8 + i] = std::byte((item.row.id >> (8 * i)) & 255);
            constexpr char hex[] = "0123456789abcdef";
            std::string text = ".ck-reviewed-retained-";
            for (auto b : id.bytes) { auto v = std::to_integer<unsigned>(b); text += hex[v >> 4]; text += hex[v & 15]; }
            if (item.name_side == ReviewedTreeNameSide::Target && item.proposed_name) item.retained_name = item.proposed_name;
            else item.retained_name = item.relative_components.back().posix_bytes() ? NativeName::from_posix(text) : NativeName::from_windows(std::u16string(text.begin(), text.end()));
            id.bytes[0] ^= std::byte{0x80}; item.retention_journal_id = id;
        }
        for (const auto& parent : resolved) if (parent.action == ReviewedTreeAction::Skip) {
            const auto n = source.nodes.find(parent.row.relative_path);
            if (n != source.nodes.end() && *n->second.metadata.kind.value() == ObjectKind::Directory)
                for (auto& child : resolved) if (child.row.relative_path.starts_with(parent.row.relative_path + '/')) child.action = ReviewedTreeAction::Skip;
        }
        last_assessment = std::move(resolved);
        return *last_assessment;
    }
    Observation<bool> target_guard(const Node& n, bool require_native_rename = true) const {
        auto private_scope=private_scope_guard();if(!private_scope.value())return private_scope;
        if (!roots_current_const()) return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.deletion_root_changed", ObservationState::Changed));
        auto parent = parent_for(n, false);
        if (!parent.value()) return unavailable<bool>(*parent.unavailable_detail());
        auto now = HeldChild::observe(*parent.value(), n.names.back());
        if (!now.value()) return unavailable<bool>(*now.unavailable_detail());
        if (!unchanged(n.metadata, (*now.value())->metadata()))
            return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.deletion_changed", ObservationState::Changed));
        if (!require_native_rename) return Observation<bool>::available(true);
        auto capability = qualify_namespace(**parent.value());
        if (!capability.value()) return capability;
        if (!*capability.value()) return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.deletion_provider", ObservationState::Unsupported));
        return Observation<bool>::available(true);
    }
    void delete_step() {
        auto& item = items[index()];
        if (!deleting) {
            const auto& n = target.nodes.at(item.row.relative_path);
            auto valid = target_guard(n);
            if (!valid.value()) { fail(*valid.unavailable_detail()); return; }
            auto parent = parent_for(n, false);
            if (!parent.value()) { fail(*parent.unavailable_detail()); return; }
            auto id = request.journal_id;
            for (unsigned i = 0; i < 8; ++i) id.bytes[8 + i] = std::byte((item.row.id >> (8 * i)) & 255);
            constexpr char hex[] = "0123456789abcdef";
            std::string text = ".ck-reviewed-delete-";
            for (auto byte : id.bytes) { auto v = std::to_integer<unsigned>(byte); text += hex[v >> 4]; text += hex[v & 15]; }
            auto journal_name = n.names.back().posix_bytes() ? NativeName::from_posix(text) : NativeName::from_windows(std::u16string(text.begin(), text.end()));
            item.journal_id = id; item.journal_name = journal_name; item.recovery_required = true;
            auto file = open_bound_journal(*journal_name, true);
            if (!file.value()) { fail(*file.unavailable_detail(), true); return; }
            auto journal = OperationJournal::create(FileOperation::Delete, id, request.copy_policy.journal_limits);
            if (!journal.value()) { fail(*journal.unavailable_detail(), true); return; }
            auto parent_id = NativeDurableIdentity::from_live(*(*parent.value())->identity().value());
            auto object_id = NativeDurableIdentity::from_live(*n.metadata.identity.value());
            if (!parent_id || !object_id) { fail(error(AdapterError::UnqualifiedIdentity, "reviewed_tree.deletion_identity"), true); return; }
            auto evidence = encode_native_delete_recovery_evidence({n.names.back(), *parent_id, *object_id});
            if (!evidence.value()) { fail(*evidence.unavailable_detail(), true); return; }
            deleting.emplace(Deletion{n, *parent.value(), *journal.value(),
                std::shared_ptr<OperationJournalFile>(std::move(file).take_value()), std::move(evidence).take_value(), 0});
            progress.recovery_required = true;
            return;
        }
        auto& d = *deleting;
        auto append = [&](OperationJournalState state) {
            auto written = append_operation_journal_file(*d.file, *d.journal,
                {d.journal->records().size() + 1, 0, state, d.evidence});
            if (!written.value()) { fail(*written.unavailable_detail(), true); return false; }
            ++d.phase; return true;
        };
        switch (d.phase) {
        case 0: append(OperationJournalState::Planned); return;
        case 1: append(OperationJournalState::Prepared); return;
        case 2: {
            auto valid = target_guard(d.node);
            if (!valid.value()) { fail(*valid.unavailable_detail(), true); return; }
            append(OperationJournalState::SourceRemovalIntended); return;
        }
        case 3: {
            auto valid = target_guard(d.node);
            if (!valid.value()) { fail(*valid.unavailable_detail(), true); return; }
            auto retired = d.parent->retire_child(d.node.names.back(), *d.node.metadata.identity.value());
            if (!retired.value() || !*retired.value()) {
                fail(retired.value() ? error(AdapterError::InvalidNativeResult, "reviewed_tree.retire_false") : *retired.unavailable_detail(), true); return;
            }
            mutated = true; progress.partial = true;
            target.nodes.erase(item.row.relative_path);
            // Windows disposition may remain pending until all our duplicate
            // child/directory handles are retired. No borrowed owner escapes.
            d.node.held.reset(); d.node.directory.reset();
            ++d.phase; return;
        }
        case 4: {
            auto missing = d.parent->lookup_child(d.node.names.back(), ChildLookupMode::NativeDefault);
            if (!missing.value() || missing.value()->state() != ChildLookupState::Missing) {
                fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.retirement_not_confirmed", ObservationState::Unknown), true); return;
            }
            refresh_target_ancestors(d.node);
            if (progress.state == ReviewedTreeState::Executing) append(OperationJournalState::SourceRetired);
            return;
        }
        case 5: append(OperationJournalState::Complete); return;
        default: {
            auto finished=d.file->finish_io();
            if(!finished.value() || !*finished.value()) {
                fail(finished.value() ? error(AdapterError::InvalidNativeResult,"reviewed_tree.delete_finish_false") :
                    *finished.unavailable_detail(),true);return;
            }
            deleting.reset(); progress.recovery_required = false; item.recovery_required = false; finish_item(); return;
        }
        }
    }
    void execute_step(std::stop_token stop) {
        if (current == items.size()) {
            // Even a plan containing only skips/reports must finish with a
            // fresh whole-tree check against the exact reviewed evidence.
            progress.state = ReviewedTreeState::Revalidating; reset_topology(); start_scan(0); return;
        }
        auto& item = items[index()]; progress.current_row = item.row.id;
        if (item.action == ReviewedTreeAction::Skip || item.action == ReviewedTreeAction::Report || item.action == ReviewedTreeAction::MergeDirectory) {
            item.state = item.action == ReviewedTreeAction::Skip ? ReviewedTreeItemState::Skipped : ReviewedTreeItemState::Complete;
            if (item.action == ReviewedTreeAction::Skip) ++progress.skipped_items; else ++progress.completed_items;
            ++current; return;
        }
        if (removal(item.action)) { delete_step(); return; }
        const auto& n = source.nodes.at(item.row.relative_path);
        if (retained && retained->state() == RetainedTargetState::Verifying) {
            const auto state = retained->advance(stop);
            if (state == RetainedTargetState::Failed || state == RetainedTargetState::Cancelled || state == RetainedTargetState::NeedsReconciliation)
                fail(retained->failure().value_or(error(AdapterError::InvalidNativeResult, "reviewed_tree.retention_failed")), state == RetainedTargetState::NeedsReconciliation);
            return;
        }
        if (copy) {
            // Capture finalized staging identity/version/size without reading
            // data after metadata replay. Native copy verified the frozen
            // content digest before its metadata phase began.
            if (staging && metadata_phase && metadata_phase->state() == OperationMetadataState::Complete && !staging_verified) {
                staging_step(); return;
            }
            auto state = copy->advance(stop);
            if(copy->staging_namespace()==StagingNamespace::Anonymous)
                item.staging_name.reset(); // Hint only; anonymous objects have no recoverable pathname.
            if (state == OperationExecutionState::Complete) {
                mutated = true; progress.partial = true;
                if (replacement_prepared && !record_retained(n)) return;
                record_created(n, false);
                if (progress.state != ReviewedTreeState::Executing) return;
                progress.copied_bytes += *n.metadata.logical_size.value();
                copy.reset(); retained.reset(); replacement_prepared = false; staging = nullptr; metadata_phase = nullptr; staging_before.reset(); staging_verified = false;
                progress.recovery_required = false; items[index()].recovery_required = false;
                finish_item();
            } else if (state == OperationExecutionState::Failed || state == OperationExecutionState::Cancelled ||
                       state == OperationExecutionState::NeedsReconciliation || state == OperationExecutionState::RetainedSource) {
                fail(copy->result().failure.value_or(error(AdapterError::InvalidNativeResult, "reviewed_tree.copy_failed")), true);
            }
            return;
        }
        auto valid = guard(n);
        if (!valid.value()) { fail(*valid.unavailable_detail()); return; }
        if (item.action == ReviewedTreeAction::CreateDirectory) {
            auto parent = parent_for(n, false);
            if (!parent.value()) { fail(*parent.unavailable_detail()); return; }
            auto created = (*parent.value())->create_child_directory(n.names.back());
            if (!created.value()) { fail(*created.unavailable_detail(), true); return; }
            mutated = true; progress.partial = true;
            const auto created_identity = (*created.value())->identity();
            record_created(n, true);
            auto recorded = target.nodes.find(n.entry.relative_path);
            if (progress.state == ReviewedTreeState::Executing && (!created_identity.value() || recorded == target.nodes.end() ||
                !same(*created_identity.value(), *recorded->second.metadata.identity.value()))) {
                fail(error(AdapterError::MetadataChanged, "reviewed_tree.mkdir_substituted", ObservationState::Changed), true); return;
            }
            if (progress.state == ReviewedTreeState::Executing) finish_item();
            return;
        }
        start_copy(n, stop);
    }
};

ReviewedTreePlanJob::ReviewedTreePlanJob(std::unique_ptr<Impl> p) noexcept : impl_(std::move(p)) {}
ReviewedTreePlanJob::~ReviewedTreePlanJob() {
    if(!impl_||impl_->native_drained)return;
    if(impl_->progress.state<ReviewedTreeState::Complete)impl_->progress.state=impl_->mutated?ReviewedTreeState::Partial:ReviewedTreeState::Cancelled;
    try{impl_->finish_owned_private_root();}catch(...){impl_->release_scanned_handles();}
}
Observation<ReviewedTreePlanJob::Pointer> ReviewedTreePlanJob::create(ReviewedTreePlanRequest r) {
    if (!r.source_root || !r.destination_root || !r.source_root->parent() || !r.destination_root->parent() ||
        !qualified(r.source_root->metadata()) || !qualified(r.destination_root->metadata()) ||
        *r.source_root->metadata().kind.value() != ObjectKind::Directory || *r.destination_root->metadata().kind.value() != ObjectKind::Directory)
        return invalid<Pointer>("reviewed_tree.roots");
    for (const auto& root : {r.source_root, r.destination_root}) {
        auto parent = root->parent()->inspect_basic();
        if (!parent.value()) return unavailable<Pointer>(*parent.unavailable_detail());
        if (!parent.value()->mount_id.value() || !equal(parent.value()->mount_id, root->metadata().mount_id))
            return unavailable<Pointer>(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.mount_root", ObservationState::Unsupported));
    }
    if (compare_identity(*r.source_root->metadata().identity.value(), *r.destination_root->metadata().identity.value()) == IdentityComparison::Unknown)
        return unavailable<Pointer>(error(AdapterError::UnqualifiedIdentity, "reviewed_tree.root_namespace"));
    if (same(*r.source_root->metadata().identity.value(), *r.destination_root->metadata().identity.value()))
        return unavailable<Pointer>(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.same_root"));
    if (r.source_root->name().encoding() != r.destination_root->name().encoding())
        return unavailable<Pointer>(error(AdapterError::UnrepresentableName, "reviewed_tree.root_encoding", ObservationState::Unsupported));
    if (r.comparison.mode != ComparisonMode::CompleteDigest || r.comparison.profile == ComparisonProfile::Move)
        return unavailable<Pointer>(error(AdapterError::UnsupportedQuery, "reviewed_tree.profile_or_digest", ObservationState::Unsupported));
    if (!capture_policy(r).valid() || !r.metadata_limits.valid() || !r.copy_policy.copy_limits.valid() || r.digest_chunk_bytes == 0 || r.digest_chunk_bytes > ContentReadLimits::hard_max_bytes ||
        r.limits.max_entries == 0 || r.limits.max_entries > ComparisonLimits::hard_max_entries ||
        r.limits.max_page_rows == 0 || r.limits.max_page_rows > ComparisonLimits::hard_max_page_rows ||
        r.limits.max_path_bytes == 0 || r.limits.max_path_bytes > ComparisonLimits::hard_max_path_bytes ||
        r.limits.max_total_path_bytes == 0 || r.limits.max_total_path_bytes > ComparisonLimits::hard_max_total_path_bytes ||
        r.comparison.filters.maximum_depth == 0 || r.comparison.filters.maximum_depth > 1024)
        return invalid<Pointer>("reviewed_tree.limits");
        // Native strict comparison requires the actual preservation contract.
    // This changes no pure/C comparison defaults.
    r.comparison.compare_preserved_metadata=r.comparison.compare_preserved_metadata||!r.copy_policy.allow_unhandled_metadata_loss;
    return Observation<Pointer>::available(Pointer(new ReviewedTreePlanJob(std::make_unique<Impl>(std::move(r)))));
}
ReviewedTreeState ReviewedTreePlanJob::state() const noexcept { return impl_->progress.state; }
ReviewedTreeProgress ReviewedTreePlanJob::progress() const {
    auto out = impl_->progress;
    if(impl_->finish_failed){const auto&e=impl_->finish_failure;out.failure=UnavailableObservation{e.state,{e.domain,e.code,e.operation.data()}};out.state=ReviewedTreeState::NeedsReconciliation;out.recovery_required=true;}
    if (impl_->copy) out.copied_bytes += impl_->copy->progress().observed_bytes;
    return out;
}
ComparisonPlan::Pointer ReviewedTreePlanJob::preview() const noexcept { return impl_->plan; }
Observation<ReviewedTreePage> ReviewedTreePlanJob::page(std::size_t offset, std::size_t limit) const {
    if (!impl_->plan) return invalid<ReviewedTreePage>("reviewed_tree.preview_not_ready");
    auto p = impl_->plan->page(offset, limit);
    if (!p.value()) return unavailable<ReviewedTreePage>(*p.unavailable_detail());
    ReviewedTreePage out{impl_->plan->identity(), {}, p.value()->total_rows, p.value()->next_offset};
    for (std::size_t i = 0; i < p.value()->rows.size(); ++i) out.items.push_back(impl_->items[offset + i]);
    return Observation<ReviewedTreePage>::available(std::move(out));
}
Observation<ReviewedTreePage> ReviewedTreePlanJob::reviewed_page(const ReviewedTreeReceipt& receipt,
    std::size_t offset, std::size_t limit) const {
    if (!impl_->plan || !receipt.state_ || receipt.state_->plan != impl_->plan->identity() || receipt.state_->revision != impl_->revision)
        return invalid<ReviewedTreePage>("reviewed_tree.foreign_receipt_page");
    auto p = impl_->plan->page(offset, limit);
    if (!p.value()) return unavailable<ReviewedTreePage>(*p.unavailable_detail());
    ReviewedTreePage out{impl_->plan->identity(), {}, p.value()->total_rows, p.value()->next_offset};
    for (std::size_t i = 0; i < p.value()->rows.size(); ++i) out.items.push_back(receipt.state_->items[offset + i]);
    return Observation<ReviewedTreePage>::available(std::move(out));
}
Observation<ReviewedTreeNativeBinding> ReviewedTreePlanJob::native_binding(const ComparisonDecisionToken& token) const {
    if(state()>=ReviewedTreeState::Complete)return invalid<ReviewedTreeNativeBinding>("reviewed_tree.native_binding_drained");
    if (impl_->mutated) return unavailable<ReviewedTreeNativeBinding>(error(AdapterError::PlanDecisionStale, "reviewed_tree.native_binding_after_mutation", ObservationState::Changed));
    if (!impl_->plan || !token.is_valid() || token.plan_identity() != impl_->plan->identity() ||
        token.row_id() > impl_->items.size()) return invalid<ReviewedTreeNativeBinding>("reviewed_tree.native_binding_token");
    const auto& item = impl_->items[token.row_id() - 1];
    if (item.row.token != token) return invalid<ReviewedTreeNativeBinding>("reviewed_tree.native_binding_row");
    ReviewedTreeNativeBinding out; out.token = token;
    auto source = impl_->source.nodes.find(item.row.relative_path), target = impl_->target.nodes.find(item.row.relative_path);
    if (source != impl_->source.nodes.end()) {
        out.source = source->second.held; out.source_parent = source->second.held->parent();
        out.relative_components = source->second.names;
        if (source->second.entry.digest) out.source_digest = source->second.entry.digest->bytes;
    }
    if (target != impl_->target.nodes.end()) {
        out.destination = target->second.held; out.destination_parent = target->second.held->parent();
        out.relative_components = target->second.names;
        if (target->second.entry.digest) out.destination_digest = target->second.entry.digest->bytes;
    } else if (source != impl_->source.nodes.end()) {
        auto parent = impl_->parent_for(source->second, false);
        if (!parent.value()) return unavailable<ReviewedTreeNativeBinding>(*parent.unavailable_detail());
        out.destination_parent = *parent.value();
    }
    return Observation<ReviewedTreeNativeBinding>::available(std::move(out));
}
Observation<std::vector<NativeName>> ReviewedTreePlanJob::native_components(std::uint64_t id, bool incoming) const {
    if (!impl_->plan || !id || id > impl_->items.size()) return invalid<std::vector<NativeName>>("reviewed_tree.native_components_row");
    const auto& item = impl_->items[id - 1];
    if (!(incoming ? item.row.source_index : item.row.destination_index))
        return unavailable<std::vector<NativeName>>(error(AdapterError::NotApplicable, "reviewed_tree.native_components_absent", ObservationState::Gone));
    return Observation<std::vector<NativeName>>::available(item.relative_components);
}
Observation<ReviewedTreeDeletionReceipt> ReviewedTreePlanJob::review_deletions(std::span<const ComparisonDecisionToken> rows) const {
    if (state() != ReviewedTreeState::AwaitingReview) return invalid<ReviewedTreeDeletionReceipt>("reviewed_tree.review_state");
    std::vector<ComparisonDecisionToken> expected;
    for (const auto& item : impl_->items) if (removal(item.action)) expected.push_back(item.row.token);
    if (rows.size() != expected.size()) return invalid<ReviewedTreeDeletionReceipt>("reviewed_tree.deletion_set");
    std::set<std::uint64_t> ids;
    for (const auto& row : rows) if (std::find(expected.begin(), expected.end(), row) == expected.end() || !ids.insert(row.row_id()).second)
        return invalid<ReviewedTreeDeletionReceipt>("reviewed_tree.deletion_token");
    ReviewedTreeDeletionReceipt out;
    out.state_ = std::make_shared<const ReviewedTreeDeletionState>(ReviewedTreeDeletionState{impl_->plan->identity(), std::move(expected)});
    return Observation<ReviewedTreeDeletionReceipt>::available(std::move(out));
}
Observation<ReviewedTreePage> ReviewedTreePlanJob::assess_rules(std::span<const ConflictRule> rules,
    std::size_t offset, std::size_t limit) const {
    return assess_rules(rules,{},offset,limit);
}
Observation<ReviewedTreePage> ReviewedTreePlanJob::assess_rules(std::span<const ConflictRule> rules,
    std::span<const ReviewedTreeNameChoice> names, std::size_t offset, std::size_t limit) const {
    if (state() != ReviewedTreeState::AwaitingReview || rules.size() > 100'000 || names.size() > impl_->items.size())
        return invalid<ReviewedTreePage>("reviewed_tree.assessment_state_or_limit");
    impl_->assessment(rules,names);
    return assessment_page(offset,limit);
}
Observation<ReviewedTreePage> ReviewedTreePlanJob::assessment_page(std::size_t offset,std::size_t limit) const {
    if (!impl_->plan || !impl_->last_assessment) return invalid<ReviewedTreePage>("reviewed_tree.assessment_not_ready");
    auto p = impl_->plan->page(offset, limit);
    if (!p.value()) return unavailable<ReviewedTreePage>(*p.unavailable_detail());
    ReviewedTreePage out{impl_->plan->identity(), {}, p.value()->total_rows, p.value()->next_offset};
    for (std::size_t i = 0; i < p.value()->rows.size(); ++i) out.items.push_back((*impl_->last_assessment)[offset + i]);
    return Observation<ReviewedTreePage>::available(std::move(out));
}
Observation<ReviewedTreeReceipt> ReviewedTreePlanJob::review(std::span<const ConflictRule> rules, const ReviewedTreeDeletionReceipt& deletion) const {
    return review(rules,{},deletion);
}
Observation<ReviewedTreeReceipt> ReviewedTreePlanJob::review(std::span<const ConflictRule> rules,
    std::span<const ReviewedTreeNameChoice> names,const ReviewedTreeDeletionReceipt& deletion) const {
    if (state() != ReviewedTreeState::AwaitingReview || rules.size() > 100'000 || names.size() > impl_->items.size())
        return invalid<ReviewedTreeReceipt>("reviewed_tree.review_state_or_limit");
    impl_->revision = std::make_shared<const unsigned char>(0); // every review supersedes older receipts, even on rejection
    if (deletion.state_ && deletion.state_->plan != impl_->plan->identity()) return invalid<ReviewedTreeReceipt>("reviewed_tree.foreign_deletion_receipt");
    if (!rules.empty() && impl_->items.empty()) return invalid<ReviewedTreeReceipt>("reviewed_tree.rules_without_rows");
    const auto& resolved = impl_->assessment(rules,names);
    const bool report_only = impl_->request.comparison.profile == ComparisonProfile::Compare &&
        std::all_of(resolved.begin(), resolved.end(), [](const auto& item) {
            return item.action == ReviewedTreeAction::Report && item.row.action == ComparisonAction::Report;
        });
    if (impl_->request.comparison.profile == ComparisonProfile::Compare && !report_only)
        return invalid<ReviewedTreeReceipt>("reviewed_tree.compare_requires_all_report");
    for (const auto& item : resolved) {
        if (removal(item.action) && !deletion.state_) return invalid<ReviewedTreeReceipt>("reviewed_tree.deletion_receipt_required");
        if (item.decision && item.decision->state != ConflictRuleState::Apply && item.decision->state != ConflictRuleState::NoMatch &&
            !(report_only && item.decision->state == ConflictRuleState::NeedsReview))
            return unavailable<ReviewedTreeReceipt>(error(AdapterError::ProviderReviewRequired, "reviewed_tree.unresolved_choice", ObservationState::Unsupported));
    }
    ReviewedTreeReceipt out;
    out.state_ = std::make_shared<const ReviewedTreeReceiptState>(ReviewedTreeReceiptState{impl_->plan->identity(), resolved, deletion.state_, impl_->revision});
    return Observation<ReviewedTreeReceipt>::available(std::move(out));
}
Observation<bool> ReviewedTreePlanJob::begin_execution(const ReviewedTreeReceipt& receipt) {
    if (state() != ReviewedTreeState::AwaitingReview || !receipt.state_ || receipt.state_->plan != impl_->plan->identity() || receipt.state_->revision != impl_->revision)
        return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.receipt", ObservationState::Changed));
    auto private_scope=impl_->private_scope_guard();
    if(!private_scope.value()) {
        impl_->fail(*private_scope.unavailable_detail());impl_->finish_owned_private_root();return private_scope;
    }
    // Compare acknowledgement is bound to this immutable plan instance and
    // profile. Its descriptive unresolved choices grant no mutation authority.
    if (impl_->request.comparison.profile == ComparisonProfile::Compare &&
        std::any_of(receipt.state_->items.begin(), receipt.state_->items.end(), [](const auto& item) {
            return item.action != ReviewedTreeAction::Report || item.row.action != ComparisonAction::Report;
        })) return invalid<bool>("reviewed_tree.compare_requires_all_report");
    for (const auto& item : receipt.state_->items) {
        if(!impl_->request.copy_policy.allow_unhandled_metadata_loss&&(mutation(item.action)||item.action==ReviewedTreeAction::MergeDirectory)) {
            const auto known=[](const auto& value){return value&&value->state==ComparisonDigestState::CompleteStable&&
                (value->ownership!=ComparisonMetadataOwnership::CurrentCaller||value->canonical_owner_digest.has_value());};
            const auto s=impl_->source.nodes.find(item.row.relative_path),d=impl_->target.nodes.find(item.row.relative_path);
            if((s!=impl_->source.nodes.end()&&!known(s->second.entry.metadata_digest))||
               (d!=impl_->target.nodes.end()&&!known(d->second.entry.metadata_digest)))
                return unavailable<bool>(error(AdapterError::ProviderReviewRequired,"reviewed_tree.required_metadata_unknown",ObservationState::Unsupported));
            if(item.action==ReviewedTreeAction::CreateDirectory||item.action==ReviewedTreeAction::MergeDirectory)
                return unavailable<bool>(error(AdapterError::UnsupportedQuery,"reviewed_tree.postorder_directory_contract",ObservationState::Unsupported));
        }
        if (item.action == ReviewedTreeAction::Replace) {
            if(!impl_->request.journal_root)
                return unavailable<bool>(error(AdapterError::UnsupportedQuery,"reviewed_tree.retention_navigation_contract",ObservationState::Unsupported));
            const auto s = impl_->source.nodes.find(item.row.relative_path), d = impl_->target.nodes.find(item.row.relative_path);
            if (s == impl_->source.nodes.end() || d == impl_->target.nodes.end() || !s->second.entry.digest || !d->second.entry.digest ||
                *s->second.metadata.kind.value() != ObjectKind::RegularFile || *d->second.metadata.kind.value() != ObjectKind::RegularFile)
                return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.replacement_kind", ObservationState::Unsupported));
            const auto qualified = qualify_namespace(*d->second.held->parent());
            if (!qualified.value()) return qualified;
            if (!*qualified.value()) return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.retention_unqualified", ObservationState::Unsupported));
        }
        if (removal(item.action)) {
            auto binding = native_binding(item.row.token);
            if (!binding.value()) return unavailable<bool>(*binding.unavailable_detail());
            auto capability = qualify_namespace(*binding.value()->destination_parent);
            if (!capability.value()) return capability;
            if (!*capability.value()) return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.identity_bound_deletion_unavailable", ObservationState::Unsupported));
        }
        if ((item.action == ReviewedTreeAction::CreateDirectory && !impl_->request.copy_policy.allow_unhandled_metadata_loss) ||
            (mutation(item.action) && !impl_->request.prepared_journal_root))
            return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.tree_metadata_or_journal_contract", ObservationState::Unsupported));
    }
    auto names = impl_->qualify_new_names(receipt.state_->items);
    if (!names.value()) return names;
    impl_->receipt = receipt.state_; impl_->items = receipt.state_->items;
    for (std::size_t i = 0; i < impl_->items.size(); ++i) if (!removal(impl_->items[i].action)) impl_->order.push_back(i);
    // Children sort after their parent. Reverse order retires files and empty
    // directories only after their explicitly reviewed descendants.
    for (std::size_t i = impl_->items.size(); i; --i) if (removal(impl_->items[i - 1].action)) impl_->order.push_back(i - 1);
    impl_->progress.known_copy_bytes = 0;
    for (const auto& item : impl_->items) if (item.action == ReviewedTreeAction::Copy || item.action == ReviewedTreeAction::Replace)
        impl_->progress.known_copy_bytes += *impl_->source.nodes.at(item.row.relative_path).metadata.logical_size.value();
    impl_->progress.state = ReviewedTreeState::Revalidating;
    impl_->reset_topology(); impl_->start_scan(0);
    return Observation<bool>::available(true);
}
ReviewedTreeState ReviewedTreePlanJob::advance(std::stop_token stop) {
    auto& p = *impl_;
    try {
    const auto state = p.progress.state;
    if (state >= ReviewedTreeState::Complete || (state == ReviewedTreeState::AwaitingReview && !stop.stop_requested())) return state;
    if(stop.stop_requested()){p.cancel_step(stop);p.finish_owned_private_root();return p.progress.state;}
    auto initialized=p.initialize_private_root(stop);
    if(!initialized.value()){p.failure_or_cancel(*initialized.unavailable_detail(),stop);p.finish_owned_private_root();return p.progress.state;}
    TreeCaptureLatch work_latch(p.request.prepared_journal_root);
    detail::MetadataCaptureCleanupScope work_scope(&work_latch);
    auto private_scope=p.private_scope_guard(stop);
    if(!private_scope.value()){p.failure_or_cancel(*private_scope.unavailable_detail(),stop,p.mutated||bool(p.copy)||bool(p.deleting));work_latch.release_root();p.finish_owned_private_root();return p.progress.state;}
    if (!p.topology_done) p.topology_step();
    else if (state == ReviewedTreeState::Inventory || state == ReviewedTreeState::Revalidating) p.scan_step(stop);
    else p.execute_step(stop);
    if(work_latch.first){const auto&e=*work_latch.first;p.record_finish(p.request.prepared_journal_root.get(),e.state,e.domain,e.code,e.operation);}
    p.read_finish(p.request.prepared_journal_root.get());
    if(p.finish_failed){p.progress.state=ReviewedTreeState::NeedsReconciliation;p.progress.recovery_required=true;}
    if(!p.finish_failed&&stop.stop_requested()&&(state==ReviewedTreeState::Inventory||state==ReviewedTreeState::Revalidating)&&
       p.progress.state<ReviewedTreeState::Complete)p.cancel_step(stop);
    work_latch.release_root();p.finish_owned_private_root();return p.progress.state;
    }catch(...){
        // Establish failure and drain first, without formatting an allocating
        // error DTO. Root's original POD event wins even under repeated OOM.
        p.progress.state=(p.finish_failed||p.mutated)?ReviewedTreeState::NeedsReconciliation:ReviewedTreeState::Failed;
        p.progress.partial=p.mutated;p.progress.recovery_required=p.progress.recovery_required||p.mutated;
        try{p.finish_owned_private_root();}catch(...){p.release_scanned_handles();}
        if(!p.finish_failed)try{p.fail(error(AdapterError::InvalidNativeResult,"reviewed_tree.worker_exception"),p.mutated);}catch(...){}
        throw;
    }
}
} // namespace ck::files
