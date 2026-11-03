// SPDX-License-Identifier: LGPL-2.0-or-later
#include "action_jobs.hpp"
#include "directory_name_rules.hpp"
#include "prepared_journal_root.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace ck::files {
namespace {
uint64_t next_id() {
    static std::atomic<uint64_t> sequence{1};
    auto id = sequence.load();
    while (id != UINT64_MAX) if (sequence.compare_exchange_weak(id, id + 1)) return id;
    throw std::overflow_error("action identities exhausted");
}
ckfea_identity identity(const ObjectIdentity* id) noexcept {
    ckfea_identity out{};
    if (id) {
        out.scheme = static_cast<uint32_t>(id->scheme);
        out.has_generation = id->generation.has_value();
        out.generation = id->generation.value_or(0);
        std::memcpy(out.volume, id->volume.bytes.data(), 16);
        std::memcpy(out.object, id->object.bytes.data(), 16);
    }
    return out;
}
class NativeBoundary final : public ActionNativeBoundary {
public:
    bool source_bound_rename() const noexcept override {
#ifdef _WIN32
        return true; // SetFileInformationByHandle on the verified source handle.
#else
        // POSIX stat_metadata + renameat[2/x_np] is not conditional on source ID.
        return false;
#endif
    }
    Observation<bool> qualify(const HeldChild& source) const override {
        if (!source_bound_rename()) return Observation<bool>::unavailable(ObservationState::Unsupported);
        return source.parent()->qualify_identity_bound_rename();
    }
    Observation<bool> distinct_targets(const HeldChild& source,const NativeName& a,const NativeName& b) const override {
        auto probe=DirectoryNameRulesProbe::inspect(source.parent());
        if (!probe.value()) { const auto& e=*probe.unavailable_detail(); return Observation<bool>::unavailable(e.state,e.error); }
        auto compared=(*probe.value())->compare(a,b);
        if (!compared.value()) { const auto& e=*compared.unavailable_detail(); return Observation<bool>::unavailable(e.state,e.error); }
        return Observation<bool>::available(compared.value()->relation==ComponentNameRelation::DistinctUnderReportedRules);
    }
    Observation<bool> rename(const HeldChild& source, const NativeName& target, bool case_only) const override {
        if (!source_bound_rename()) return Observation<bool>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<int64_t>(AdapterError::UnsupportedQuery), "actions.source_bound_rename"});
        auto qualified=qualify(source);
        if (!qualified.value()) return qualified;
        if (!*qualified.value()) return Observation<bool>::unavailable(ObservationState::Unsupported);
        const auto* id = source.metadata().identity.value();
        if (!id) return Observation<bool>::unavailable(ObservationState::Unknown);
        return case_only ? source.parent()->rename_child_case_only(source.name(), *id, target) :
            source.parent()->rename_child_noreplace(source.name(), *id, *source.parent(), target);
    }
};
bool retryable(const UnavailableObservation& e) noexcept {
    // Only the failed native atomic call itself has an unambiguous no-effect
    // result. Never infer this from a general Denied/Unknown/Gone state.
    return e.error.domain == ErrorDomain::Win32 && (e.error.code == 32 || e.error.code == 33) &&
        (e.error.operation == "rename_child_noreplace.atomic_primitive" ||
         e.error.operation == "rename_child_case_only.atomic_primitive");
}
bool same_parent(const HeldChild& a, const HeldChild& b) {
    const auto* x = a.parent_identity().value(); const auto* y = b.parent_identity().value();
    return x && y && compare_identity(*x, *y) == IdentityComparison::Same;
}
}
Observation<bool> ActionNativeBoundary::qualify(const HeldChild&) const {
    return Observation<bool>::available(source_bound_rename());
}
Observation<bool> ActionNativeBoundary::distinct_targets(const HeldChild&,const NativeName&,const NativeName&) const {
    return Observation<bool>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::UnsupportedQuery),"actions.target_equivalence"});
}
std::shared_ptr<const ActionNativeBoundary> native_action_boundary() { return std::make_shared<NativeBoundary>(); }
ActionJob::ActionJob(ActionRequest request, std::shared_ptr<const ActionNativeBoundary> native, std::shared_ptr<const NativeTrashBackend> trash)
    : request_(std::move(request)), native_(std::move(native)), trash_backend_(std::move(trash)), id_(next_id()) {
    const auto count = request_.operation == CKFEA_VERIFY_RECOVERY ? 1 :
        !request_.restore_items.empty() ? request_.restore_items.size() : request_.items.size();
    if (!native_ || !count || count > CKFEA_MAX_ITEMS || request_.retry_limit > 2)
        throw std::invalid_argument("invalid action bounds");
    results_.resize(count);
    journal_affected_.assign(count,false);
    trash_finish_attempted_.assign(count,false);
    if(!request_.open_journal) request_.open_journal=[](const NativeAbsolutePath& p,const NativeName& n,bool create){return open_native_operation_journal_file(p,n,create);};
    trash_transactions_.resize(count); trash_receipts_.resize(count);
    scope_guards_.resize(count);
    // Every item has at most preview + intent + result + two retries.
    events_.reserve(count * 8);
    dependencies_.assign(count, -1);
    order_.reserve(count);
    for (size_t i=0; i<count; ++i) {
        results_[i].version = CKFEA_VERSION; results_[i].struct_size = sizeof(ckfea_result);
        if (!request_.restore_items.empty()) {
            if(!request_.restore_items[i].receipt||!request_.restore_items[i].original_parent) throw std::invalid_argument("invalid restore input");
        } else if (request_.operation != CKFEA_VERIFY_RECOVERY) {
            const auto& s = request_.items[i].source;
            if (!s || (request_.operation == CKFEA_RENAME && !request_.items[i].destination))
                throw std::invalid_argument("invalid held action input");
            results_[i].source_identity = identity(s->metadata().identity.value());
            results_[i].parent_identity = identity(s->parent_identity().value());
        }
    }
}
void ActionJob::start() {
    auto self = shared_from_this();
    std::thread worker([self=std::move(self)] { self->run(); });
    try { worker.detach(); }
    catch (...) {
        cancel();
        if (worker.joinable()) worker.join();
        throw;
    }
}
ckfea_summary ActionJob::summary() const {
    std::lock_guard lock(mutex_);
    ckfea_summary out{CKFEA_VERSION, sizeof(ckfea_summary), phase_, static_cast<uint32_t>(results_.size()), id_, events_.size(), 0, 0, 0, 0};
    for (const auto& r : results_) {
        out.ready_count += r.state == CKFEA_READY;
        out.verified_count += r.state == CKFEA_VERIFIED;
        out.review_count += r.state == CKFEA_REVIEW_REQUIRED;
    }
    return out;
}
ckfea_result ActionJob::row(size_t i) const { std::lock_guard lock(mutex_); return results_[i]; }
ckfea_status ActionJob::item(uint32_t i, ckfea_result& out) const {
    std::lock_guard lock(mutex_);
    if (i >= results_.size()) return CKFEA_INVALID_ARGUMENT;
    out = results_[i]; return CKFEA_OK;
}
ckfea_status ActionJob::evidence(uint64_t i, ckfea_evidence& out) const {
    std::lock_guard lock(mutex_);
    if (i >= events_.size()) return CKFEA_INVALID_ARGUMENT;
    out = events_[static_cast<size_t>(i)]; return CKFEA_OK;
}
ckfea_status ActionJob::receipt(ckfea_receipt& out) const {
    std::lock_guard lock(mutex_);
    if (phase_ != CKFEA_AWAITING_RECEIPT || cancelled()) return CKFEA_NOT_READY;
    out = {CKFEA_VERSION, sizeof(ckfea_receipt), id_, id_, {0,0}};
    return CKFEA_OK;
}
ckfea_status ActionJob::trash_receipt(uint32_t i,std::shared_ptr<const NativeTrashReceipt>& out) const {
    std::lock_guard lock(mutex_);
    if(i>=results_.size()||request_.operation!=CKFEA_TRASH) return CKFEA_INVALID_ARGUMENT;
    const bool terminal=phase_==CKFEA_FINISHED||phase_==CKFEA_CANCELLED||phase_==CKFEA_JOB_FAILED;
    if(!terminal||!journal_finish_attempted_||!journal_finish_ok_||results_[i].state!=CKFEA_VERIFIED||!trash_receipts_[i]) return CKFEA_NOT_READY;
    out=trash_receipts_[i]; return CKFEA_OK;
}
ckfea_status ActionJob::execute(const ckfea_receipt& in) {
    std::lock_guard lock(mutex_);
    if (in.job_id != id_ || in.preview_id != id_) return CKFEA_STALE_RECEIPT;
    if (phase_ != CKFEA_AWAITING_RECEIPT || approved_ || cancelled()) return CKFEA_NOT_READY;
    approved_ = true; phase_ = CKFEA_RUNNING; cv_.notify_all(); return CKFEA_OK;
}
void ActionJob::cancel() { std::lock_guard lock(mutex_); stop_.request_stop(); cv_.notify_all(); }
ckfea_status ActionJob::wait(uint32_t ms) {
    std::unique_lock lock(mutex_);
    auto ready = [&] { return phase_ != CKFEA_PREVIEWING && phase_ != CKFEA_RUNNING; };
    return cv_.wait_for(lock, std::chrono::milliseconds(ms), ready) ? CKFEA_OK : CKFEA_NOT_READY;
}
void ActionJob::set(size_t i, uint32_t state, uint32_t reason) {
    std::lock_guard lock(mutex_); results_[i].state = state; results_[i].reason = reason;
}
void ActionJob::unavailable(size_t i, const UnavailableObservation& e, bool started) {
    std::lock_guard lock(mutex_); auto& r = results_[i];
    r.observation = static_cast<uint32_t>(e.state);
    r.error_domain = static_cast<uint32_t>(e.error.domain); r.error_code = e.error.code;
    r.state = started ? CKFEA_REVIEW_REQUIRED : e.state == ObservationState::Unsupported ? CKFEA_UNSUPPORTED :
        e.state == ObservationState::Denied ? CKFEA_DENIED :
        (e.state == ObservationState::Changed || e.state == ObservationState::Gone) ? CKFEA_CHANGED :
        e.state == ObservationState::Failed ? CKFEA_FAILED : CKFEA_REVIEW_REQUIRED;
}
void ActionJob::event(size_t i, uint32_t kind) {
    std::lock_guard lock(mutex_);
    events_.push_back({CKFEA_VERSION, sizeof(ckfea_evidence), kind, static_cast<uint32_t>(i),
        events_.size()+1, id_, results_[i], {0,0}});
}
bool ActionJob::revalidate(size_t i) {
    if (cancelled()) { set(i, CKFEA_ITEM_CANCELLED); return false; }
    if (!check_private_scope(i)) return false;
    const auto& s = request_.items[i].source;
    const auto* parent_id = s->parent_identity().value();
    const auto* source_id = s->metadata().identity.value();
    if (!parent_id || !source_id || compare_identity(*source_id,*source_id) != IdentityComparison::Same ||
        compare_identity(*parent_id,*parent_id) != IdentityComparison::Same) {
        set(i, CKFEA_REVIEW_REQUIRED); return false;
    }
    const auto parent = s->parent()->inspect_basic();
    if (!parent.value()) { unavailable(i, *parent.unavailable_detail()); return false; }
    if (!parent.value()->identity.value() ||
        compare_identity(*parent.value()->identity.value(), *parent_id) != IdentityComparison::Same) {
        set(i, CKFEA_CHANGED); return false;
    }
    const auto refreshed = s->refresh(stop_.get_token());
    if (!refreshed.value()) { unavailable(i, *refreshed.unavailable_detail()); return false; }
    if (!(*refreshed.value())->continues(*s)) { set(i, CKFEA_CHANGED); return false; }
    return true;
}
bool ActionJob::destination_clear(size_t i) {
    const auto& input = request_.items[i];
    auto found = input.source->parent()->lookup_child(*input.destination, ChildLookupMode::NativeDefault);
    if (!found.value()) { unavailable(i, *found.unavailable_detail()); return false; }
    if (!input.case_only && found.value()->state() == ChildLookupState::Missing && found.value()->missing_witness()) return true;
    if (input.case_only && found.value()->entry()) {
        auto m = found.value()->entry()->inspect_basic();
        const auto* expected = input.source->metadata().identity.value();
        if (m.value() && m.value()->identity.value() && expected &&
            compare_identity(*m.value()->identity.value(), *expected) == IdentityComparison::Same &&
            m.value()->link_count.value() && *m.value()->link_count.value() == 1) return true;
    }
    set(i, CKFEA_COLLISION); return false;
}
void ActionJob::preview_rename() {
    const auto n = request_.items.size();
    std::vector<bool> missing(n,false);
    for (size_t i=0; i<n; ++i) {
        if (!revalidate(i)) continue;
        const auto& a = request_.items[i];
        if (a.source->name() == *a.destination) { set(i, CKFEA_NO_CHANGE); continue; }
        set(i, CKFEA_READY);
        auto found = a.source->parent()->lookup_child(*a.destination, ChildLookupMode::NativeDefault);
        if (!found.value()) { unavailable(i, *found.unavailable_detail()); continue; }
        if (found.value()->state() == ChildLookupState::Missing && found.value()->missing_witness()) {
            missing[i]=true;
            if (a.case_only) set(i, CKFEA_UNSUPPORTED);
            continue;
        }
        if (!found.value()->entry()) { set(i, CKFEA_REVIEW_REQUIRED); continue; }
        auto m = found.value()->entry()->inspect_basic();
        if (!m.value() || !m.value()->identity.value()) { set(i, CKFEA_REVIEW_REQUIRED); continue; }
        bool dependency = false;
        for (size_t j=0; j<n; ++j) {
            const auto& b = request_.items[j]; const auto* id = b.source->metadata().identity.value();
            if (!id || !same_parent(*a.source,*b.source) ||
                compare_identity(*m.value()->identity.value(),*id) != IdentityComparison::Same) continue;
            if (j == i && a.case_only && m.value()->link_count.value() && *m.value()->link_count.value() == 1) {
                dependency = true; break;
            }
            if (j != i && *a.destination == b.source->name()) {
                dependencies_[i] = static_cast<int>(j); dependency = true; break;
            }
        }
        if (!dependency) set(i, CKFEA_COLLISION);
    }
    // A duplicate source ID (including hard-link aliases) is never an independent
    // authority. Exact duplicate targets are detected without display folding.
    for (size_t i=0; i<n; ++i) for (size_t j=i+1; j<n; ++j) {
        const auto& a=request_.items[i]; const auto& b=request_.items[j];
        const auto* x=a.source->metadata().identity.value(); const auto* y=b.source->metadata().identity.value();
        if ((x && y && compare_identity(*x,*y)==IdentityComparison::Same) ||
            (same_parent(*a.source,*b.source) && *a.destination==*b.destination)) {
            set(i,CKFEA_COLLISION); set(j,CKFEA_COLLISION);
        }
    }
    std::vector<bool> emitted(n,false);
    for (size_t pass=0; pass<n; ++pass) {
        bool progress=false;
        for (size_t i=0; i<n; ++i) if (!emitted[i] && row(i).state==CKFEA_READY) {
            const auto d=dependencies_[i];
            if (d>=0 && !emitted[static_cast<size_t>(d)]) {
                const auto state=row(static_cast<size_t>(d)).state;
                if (state!=CKFEA_READY) { set(i,CKFEA_COLLISION,CKFEA_REASON_DEPENDENCY); progress=true; }
                continue;
            }
            emitted[i]=true; order_.push_back(i); progress=true;
        }
        if (!progress) break;
    }
    for (size_t i=0; i<n; ++i) if (!emitted[i] && row(i).state==CKFEA_READY)
        set(i,CKFEA_CYCLE,CKFEA_REASON_DEPENDENCY);
    for (auto i:order_) {
        auto qualified=native_->qualify(*request_.items[i].source);
        if (!qualified.value() || !*qualified.value()) {
            if (!qualified.value()) unavailable(i,*qualified.unavailable_detail());
            else set(i,CKFEA_UNSUPPORTED);
            if (row(i).state==CKFEA_UNSUPPORTED) set(i,CKFEA_UNSUPPORTED,CKFEA_REASON_SOURCE_NOT_BOUND);
        }
        else if ((!request_.prepared_journal_root&&!request_.journal_directory) || !request_.journal_name)
            set(i,CKFEA_UNSUPPORTED,CKFEA_REASON_JOURNAL_REQUIRED);
    }
    // Native lookup proves distinctness when at least one target already exists.
    // Two absent names need a qualified equivalence rule; exact byte inequality
    // alone is insufficient on a case/normalization-aware filesystem.
    for (size_t i=0;i<n;++i) for (size_t j=i+1;j<n;++j) {
        if (!missing[i] || !missing[j] || row(i).state!=CKFEA_READY || row(j).state!=CKFEA_READY ||
            !same_parent(*request_.items[i].source,*request_.items[j].source)) continue;
        auto distinct=native_->distinct_targets(*request_.items[i].source,*request_.items[i].destination,*request_.items[j].destination);
        if (!distinct.value()) {
            unavailable(i,*distinct.unavailable_detail()); unavailable(j,*distinct.unavailable_detail());
            set(i,CKFEA_REVIEW_REQUIRED); set(j,CKFEA_REVIEW_REQUIRED);
        } else if (!*distinct.value()) { set(i,CKFEA_COLLISION); set(j,CKFEA_COLLISION); }
    }
}
bool ActionJob::initialize_private_root() {
    if(model_boundary_) {
        // Native cursors always expose a native adapter namespace. The model
        // entry point cannot consume one, even if a test policy mistakenly
        // accepts it. A real prepared Root is never a model input either.
        bool model_inputs=!request_.prepared_journal_root;
        for(const auto& item:request_.items)if(item.source) {
            const auto scope=item.source->parent()->source_scope();
            model_inputs=model_inputs&&!scope.value()&&scope.state()==ObservationState::Unsupported;
        }
        if(request_.recovery_destination) {
            const auto scope=request_.recovery_destination->source_scope();
            model_inputs=model_inputs&&!scope.value()&&scope.state()==ObservationState::Unsupported;
        }
        if(!model_inputs) {
            for(size_t i=0;i<results_.size();++i){set(i,CKFEA_UNSUPPORTED);event(i,CKFEA_EVIDENCE_PREVIEW);}
            return false;
        }
        auto checked=model_boundary_->check_request(request_);
        if(checked.value()&&*checked.value())return true;
        for(size_t i=0;i<results_.size();++i) {
            if(!checked.value())unavailable(i,*checked.unavailable_detail());else set(i,CKFEA_UNSUPPORTED);
            event(i,CKFEA_EVIDENCE_PREVIEW);
        }
        return false;
    }
    if(request_.operation==CKFEA_VERIFY_RECOVERY)return true; // Read-only inspection.
    if(!request_.prepared_journal_root&&request_.journal_directory) {
        // Initial worker navigation only. Every subsequent journal open uses
        // this retained owner, including legacy pathname callers.
        auto acquired=acquire_native_journal_root(*request_.journal_directory,stop_.get_token());
        if(!acquired.value()) {
            for(size_t i=0;i<results_.size();++i) {
                unavailable(i,*acquired.unavailable_detail());event(i,CKFEA_EVIDENCE_PREVIEW);
            }
            return false;
        }
        request_.prepared_journal_root=std::move(acquired).take_value();owns_private_root_=true;
    }
    if(request_.prepared_journal_root) {
        // A prepared capability is checked on this worker before any backend
        // preview, including Trash's possible native-bin provisioning.
        const auto valid=request_.prepared_journal_root->revalidate();
        if(!valid.value()||!*valid.value()) {
            for(size_t i=0;i<results_.size();++i) {
                if(!valid.value())unavailable(i,*valid.unavailable_detail());
                else unavailable(i,{ObservationState::Changed,{ErrorDomain::Adapter,
                    static_cast<int64_t>(AdapterError::PlanDecisionStale),"actions.prepared_journal_root"}});
                event(i,CKFEA_EVIDENCE_PREVIEW);
            }
            return false;
        }
        request_.open_journal=[root=request_.prepared_journal_root](const NativeAbsolutePath&,const NativeName& name,bool create) {
            return root->open_journal(name,create);
        };
    }
    return true;
}
bool ActionJob::check_private_scope(size_t i) {
    if(model_boundary_) {
        const auto checked=model_boundary_->check_source(*request_.items[i].source);
        if(checked.value()&&*checked.value())return true;
        if(!checked.value())unavailable(i,*checked.unavailable_detail());else set(i,CKFEA_UNSUPPORTED);
        return false;
    }
    if(!request_.prepared_journal_root) {
        set(i,CKFEA_UNSUPPORTED,CKFEA_REASON_JOURNAL_REQUIRED);return false;
    }
    if(!scope_guards_[i]) {
        auto guarded=JournalScopeGuard::create_for_entry(request_.prepared_journal_root,
            *request_.items[i].source,stop_.get_token());
        if(!guarded.value()) {unavailable(i,*guarded.unavailable_detail());return false;}
        scope_guards_[i]=std::move(guarded).take_value();
    }
    auto root=scope_guards_[i]->check_root(stop_.get_token());
    if(!root.value()) {unavailable(i,*root.unavailable_detail());return false;}
    auto entry=scope_guards_[i]->check_entry(*request_.items[i].source,stop_.get_token());
    if(!entry.value()) {unavailable(i,*entry.unavailable_detail());return false;}
    if(!*root.value()||!*entry.value()) {set(i,CKFEA_REVIEW_REQUIRED);return false;}
    return true;
}
Observation<std::unique_ptr<OperationJournalFile>> ActionJob::open_action_journal() {
    if(request_.prepared_journal_root)return request_.prepared_journal_root->open_journal(*request_.journal_name,true);
    return request_.open_journal(*request_.journal_directory,*request_.journal_name,true);
}
void ActionJob::preview() {
    if(!initialize_private_root())return;
    if (request_.operation==CKFEA_RENAME) preview_rename();
    else if (request_.operation==CKFEA_VERIFY_RECOVERY) {
        if (!request_.recovery || !request_.recovery_destination ||
            request_.recovery->has_untrusted_evidence || request_.recovery->report.has_untrusted_tail) {
            set(0,CKFEA_REVIEW_REQUIRED,CKFEA_REASON_UNTRUSTED_RECOVERY);
        } else {
            for (const auto& a:request_.recovery->artifacts) if (a.item==request_.recovery_item) {
                if (artifact_) { artifact_.reset(); break; }
                artifact_=a;
            }
            if (!artifact_ || !artifact_->evidence || !artifact_->evidence->content_digest ||
                !artifact_->evidence->published_identity ||
                (artifact_->state!=OperationJournalState::DestinationCommitted &&
                 artifact_->state!=OperationJournalState::SourceRetired && artifact_->state!=OperationJournalState::Complete))
                set(0,CKFEA_REVIEW_REQUIRED,CKFEA_REASON_UNTRUSTED_RECOVERY);
            else {
                const auto& d=request_.recovery_destination->identity();
                if (!d.value() || !artifact_->evidence->destination_identity.matches_live(*d.value())) set(0,CKFEA_CHANGED);
                else {
                    { std::lock_guard lock(mutex_);
                      results_[0].source_identity.scheme=static_cast<uint32_t>(artifact_->evidence->published_identity->scheme);
                      const auto& p=*artifact_->evidence->published_identity;
                      std::memcpy(results_[0].source_identity.volume,p.volume.bytes.data(),16);
                      std::memcpy(results_[0].source_identity.object,p.object.bytes.data(),16);
                      results_[0].source_identity.has_generation=p.generation.has_value();
                      results_[0].source_identity.generation=p.generation.value_or(0);
                      results_[0].parent_identity=identity(d.value()); }
                    set(0,CKFEA_READY);
                }
            }
        }
    } else preview_trash();
    for (size_t i=0;i<results_.size();++i) event(i,CKFEA_EVIDENCE_PREVIEW);
}
void ActionJob::preview_trash() {
    const bool restore=request_.operation==CKFEA_RESTORE;
    const auto capability=restore?CKFEA_ALLOW_NATIVE_RESTORE:CKFEA_ALLOW_NATIVE_TRASH;
    for(size_t i=0;i<results_.size();++i) {
        if(cancelled()) { set(i,CKFEA_ITEM_CANCELLED); continue; }
        if(!(request_.capabilities&capability)) { set(i,CKFEA_UNSUPPORTED,CKFEA_REASON_CAPABILITY_REQUIRED); continue; }
        if(restore&&request_.restore_items.empty()) { set(i,CKFEA_UNSUPPORTED,CKFEA_REASON_NATIVE_RECEIPT_UNAVAILABLE); continue; }
        if((!request_.prepared_journal_root&&!request_.journal_directory)||!request_.journal_name) { set(i,CKFEA_UNSUPPORTED,CKFEA_REASON_JOURNAL_REQUIRED); continue; }
        if(!restore) {
            bool duplicate=false;
            for(size_t j=0;j<request_.items.size();++j) if(i!=j) {
                const auto* a=request_.items[i].source->metadata().identity.value();
                const auto* b=request_.items[j].source->metadata().identity.value();
                if(a&&b&&compare_identity(*a,*b)==IdentityComparison::Same) duplicate=true;
            }
            if(duplicate) { set(i,CKFEA_COLLISION); continue; }
            if(!revalidate(i)) continue;
        }
        if(restore) {
            const auto& input=request_.restore_items[i]; bool duplicate=false;
            for(size_t j=0;j<request_.restore_items.size();++j)
                if(i!=j&&input.receipt->object==request_.restore_items[j].receipt->object&&
                    input.receipt->original_parent==request_.restore_items[j].receipt->original_parent) duplicate=true;
            if(duplicate) { set(i,CKFEA_COLLISION); continue; }
        }
        auto prepared=model_boundary_ ? (restore ? trash_backend_->prepare_restore(*request_.restore_items[i].receipt,
            request_.restore_items[i].original_parent,stop_.get_token()):trash_backend_->prepare_trash(request_.items[i].source,stop_.get_token())) :
            (restore ? trash_backend_->prepare_restore_scoped(*request_.restore_items[i].receipt,
                request_.restore_items[i].original_parent,request_.prepared_journal_root,stop_.get_token()) :
                trash_backend_->prepare_trash_scoped(request_.items[i].source,request_.prepared_journal_root,stop_.get_token()));
        if(!prepared.value()) { unavailable(i,*prepared.unavailable_detail());
            if(row(i).state==CKFEA_UNSUPPORTED) set(i,CKFEA_UNSUPPORTED,CKFEA_REASON_SOURCE_NOT_BOUND); continue; }
        trash_transactions_[i]=std::move(prepared).take_value();
        if(!trash_transactions_[i]) { set(i,CKFEA_REVIEW_REQUIRED); continue; }
        if(!revalidate_trash_scope(i))continue;
        if(restore) {
            const auto& r=trash_transactions_[i]->receipt();
            auto copy_id=[](const NativeDurableIdentity& id) { ckfea_identity c{}; c.scheme=static_cast<uint32_t>(id.scheme);
                c.has_generation=id.generation.has_value();c.generation=id.generation.value_or(0);
                std::memcpy(c.volume,id.volume.bytes.data(),16);std::memcpy(c.object,id.object.bytes.data(),16);return c; };
            std::lock_guard lock(mutex_); results_[i].source_identity=copy_id(r.object);results_[i].parent_identity=copy_id(r.original_parent);
        }
        set(i,CKFEA_READY);
    }
}
bool ActionJob::revalidate_trash_scope(size_t i) {
    if(cancelled()){set(i,CKFEA_ITEM_CANCELLED);return false;}
    if(model_boundary_) {
        if(request_.operation==CKFEA_RESTORE){set(i,CKFEA_UNSUPPORTED,CKFEA_REASON_NATIVE_RECEIPT_UNAVAILABLE);return false;}
        return check_private_scope(i);
    }
    const auto valid=trash_transactions_[i]->revalidate_private_scope(stop_.get_token());
    if(!valid.value()){unavailable(i,*valid.unavailable_detail(),trash_transactions_[i]->mutation_attempted());return false;}
    if(!*valid.value()){set(i,CKFEA_REVIEW_REQUIRED);return false;}
    return true;
}
void ActionJob::perform_trash() {
    for(size_t i=0;i<results_.size();++i)if(row(i).state==CKFEA_READY)
        if((request_.operation==CKFEA_TRASH&&!revalidate(i))||!revalidate_trash_scope(i))event(i,CKFEA_EVIDENCE_RESULT);
    bool any=false; for(size_t i=0;i<results_.size();++i) any|=row(i).state==CKFEA_READY;
    if(!any) return;
    auto file=open_action_journal();
    if(!file.value()) {
        for(size_t i=0;i<results_.size();++i) if(row(i).state==CKFEA_READY) {
            unavailable(i,*file.unavailable_detail());event(i,CKFEA_EVIDENCE_RESULT);
        }
        return;
    }
    journal_file_=std::move(file).take_value(); OperationJournalId jid{};
    for(unsigned i=0;i<8;++i) jid.bytes[i]=std::byte(static_cast<unsigned char>(id_>>(i*8)));
    auto journal=OperationJournal::create(FileOperation::Move,jid,{CKFEA_MAX_ITEMS,CKFEA_MAX_ITEMS*8,256*1024});
    if(!journal.value()) throw std::runtime_error("trash journal unavailable"); journal_=*journal.value();
    for(size_t i=0;i<results_.size();++i) {
        if(row(i).state!=CKFEA_READY) continue;
        if(cancelled()) { set(i,CKFEA_ITEM_CANCELLED);event(i,CKFEA_EVIDENCE_RESULT);continue; }
        if(request_.operation==CKFEA_TRASH&&!revalidate(i)) {event(i,CKFEA_EVIDENCE_RESULT);continue;}
        if(!revalidate_trash_scope(i)){event(i,CKFEA_EVIDENCE_RESULT);continue;}
        event(i,CKFEA_EVIDENCE_INTENT);
        { std::lock_guard lock(mutex_);results_[i].state=CKFEA_EXECUTING;results_[i].attempts=1; }
        const NativeTrashJournal append=[&](OperationJournalState state,const NativeTrashReceipt& receipt) {
            journal_affected_[i]=true;
            auto bytes=encode_native_trash_receipt(receipt); if(!bytes.value()) return Observation<bool>::unavailable(bytes.state(),bytes.unavailable_detail()->error);
            return append_operation_journal_file(*journal_file_,*journal_,{journal_->records().size()+1,i,state,std::move(bytes).take_value()},{64*1024*1024});
        };
        auto result=trash_transactions_[i]->commit(append,stop_.get_token());
        if(result.value()&&*result.value()) {
            if(request_.operation==CKFEA_TRASH) {
                auto receipt=std::make_shared<const NativeTrashReceipt>(trash_transactions_[i]->receipt());
                std::lock_guard lock(mutex_);trash_receipts_[i]=std::move(receipt);
            }
            set(i,CKFEA_VERIFIED);
        } else if(!result.value()) unavailable(i,*result.unavailable_detail(),trash_transactions_[i]->mutation_attempted());
        else set(i,CKFEA_REVIEW_REQUIRED);
        event(i,CKFEA_EVIDENCE_RESULT);
        if(row(i).state==CKFEA_REVIEW_REQUIRED) break;
    }
    for(size_t i=0;i<results_.size();++i) if(row(i).state==CKFEA_READY) {
        set(i,cancelled()?CKFEA_ITEM_CANCELLED:CKFEA_REVIEW_REQUIRED);event(i,CKFEA_EVIDENCE_RESULT);
    }
}
bool ActionJob::append_journal(size_t i, OperationJournalState state) {
    journal_affected_[i]=true;
    const auto& a=request_.items[i]; const auto* s=a.source->metadata().identity.value();
    const auto* p=a.source->parent_identity().value();
    if (!journal_ || !journal_file_ || !s || !p) { set(i,CKFEA_REVIEW_REQUIRED); return false; }
    auto sid=NativeDurableIdentity::from_live(*s); auto pid=NativeDurableIdentity::from_live(*p);
    if (!sid || !pid) { set(i,CKFEA_REVIEW_REQUIRED); return false; }
    NativeOperationRecoveryEvidence evidence{a.source->name(),*a.destination,*pid,*sid,*pid,{},{},{},{}};
    // Rename preserves source identity but does not certify file content. The
    // shared codec requires a digest for published receipts, so retain native
    // source/parent/name evidence without fabricating a content receipt.
    auto encoded=encode_native_operation_recovery_evidence(evidence,{256*1024,CKFEA_MAX_NAME_BYTES});
    if (!encoded.value()) { unavailable(i,*encoded.unavailable_detail(),true); return false; }
    auto appended=append_operation_journal_file(*journal_file_,*journal_,
        {journal_->records().size()+1,i,state,std::move(encoded).take_value()}, {8*1024*1024});
    if (!appended.value() || !*appended.value()) {
        if (!appended.value()) unavailable(i,*appended.unavailable_detail(),true);
        else set(i,CKFEA_REVIEW_REQUIRED);
        return false;
    }
    return true;
}
void ActionJob::perform() {
    if(request_.operation==CKFEA_TRASH||request_.operation==CKFEA_RESTORE) { perform_trash(); return; }
    if (request_.operation==CKFEA_VERIFY_RECOVERY) {
        if (row(0).state!=CKFEA_READY) return;
        if (cancelled()) { set(0,CKFEA_ITEM_CANCELLED); return; }
        event(0,CKFEA_EVIDENCE_INTENT);
        const auto& d=request_.recovery_destination;
        auto parent=d->inspect_basic();
        if (!parent.value()) unavailable(0,*parent.unavailable_detail());
        else if (!parent.value()->identity.value() || !d->identity().value() ||
            compare_identity(*parent.value()->identity.value(),*d->identity().value())!=IdentityComparison::Same) set(0,CKFEA_CHANGED);
        else {
            { std::lock_guard lock(mutex_); results_[0].attempts=1; }
            auto verified=verify_native_published_destination({*artifact_,d,*parent.value()->identity.value(),request_.max_verify_bytes});
            if (!verified.value()) unavailable(0,*verified.unavailable_detail());
            else set(0,*verified.value()?CKFEA_VERIFIED:CKFEA_CHANGED);
        }
        event(0,CKFEA_EVIDENCE_RESULT); return;
    }
    bool any=false;
    for(auto i:order_)if(row(i).state==CKFEA_READY&&!revalidate(i))event(i,CKFEA_EVIDENCE_RESULT);
    for (auto i:order_) any |= row(i).state==CKFEA_READY;
    if (!any) return;
    auto file=open_action_journal();
    if (!file.value()) {
        for (auto i:order_) if (row(i).state==CKFEA_READY) { unavailable(i,*file.unavailable_detail()); event(i,CKFEA_EVIDENCE_RESULT); }
        return;
    }
    journal_file_=std::move(file).take_value();
    OperationJournalId jid{};
    for (unsigned i=0;i<8;++i) jid.bytes[i]=std::byte(static_cast<unsigned char>(id_>>(i*8)));
    auto journal=OperationJournal::create(FileOperation::Move,jid,{CKFEA_MAX_ITEMS,CKFEA_MAX_ITEMS*10,256*1024});
    if (!journal.value()) throw std::runtime_error("action journal unavailable");
    journal_=*journal.value();
    for (auto i:order_) {
        if (row(i).state!=CKFEA_READY) continue;
        if (cancelled()) { set(i,CKFEA_ITEM_CANCELLED); event(i,CKFEA_EVIDENCE_RESULT); continue; }
        const auto d=dependencies_[i];
        if (d>=0 && row(static_cast<size_t>(d)).state!=CKFEA_VERIFIED) {
            set(i,CKFEA_COLLISION,CKFEA_REASON_DEPENDENCY); event(i,CKFEA_EVIDENCE_RESULT); continue;
        }
        if (!revalidate(i) || !destination_clear(i)) { event(i,CKFEA_EVIDENCE_RESULT); continue; }
        if (!append_journal(i,OperationJournalState::Planned) || !append_journal(i,OperationJournalState::Prepared) ||
            !append_journal(i,OperationJournalState::CommitIntended)) { event(i,CKFEA_EVIDENCE_RESULT); break; }
        event(i,CKFEA_EVIDENCE_INTENT);
        bool success=false;
        for (uint32_t attempt=0;attempt<=request_.retry_limit;++attempt) {
            if (!revalidate(i) || !destination_clear(i) || cancelled()) break;
            auto qualified=native_->qualify(*request_.items[i].source);
            if (!qualified.value()) { unavailable(i,*qualified.unavailable_detail()); break; }
            if (!*qualified.value()) { set(i,CKFEA_UNSUPPORTED,CKFEA_REASON_SOURCE_NOT_BOUND); break; }
            { std::lock_guard lock(mutex_); results_[i].state=CKFEA_EXECUTING; ++results_[i].attempts; }
            const auto& a=request_.items[i];
            auto renamed=native_->rename(*a.source,*a.destination,a.case_only);
            if (renamed.value() && *renamed.value()) { success=true; break; }
            if (!renamed.value() && retryable(*renamed.unavailable_detail()) && attempt<request_.retry_limit) {
                event(i,CKFEA_EVIDENCE_RETRY); continue;
            }
            if (!renamed.value()) {
                unavailable(i,*renamed.unavailable_detail(),
                    renamed.state()!=ObservationState::Unsupported && !retryable(*renamed.unavailable_detail()));
                if (retryable(*renamed.unavailable_detail())) set(i,CKFEA_FAILED);
            }
            else set(i,CKFEA_REVIEW_REQUIRED);
            break;
        }
        if (success) {
            // Adapter reports flush + identity success; independently check the
            // published membership again. Never attempt rollback or unlink.
            const auto& a=request_.items[i];
            auto dest=a.source->parent()->open_child(*a.destination);
            auto metadata=dest.value()?(*dest.value())->inspect_basic():Observation<BasicMetadata>{};
            const auto* expected=a.source->metadata().identity.value();
            if (!metadata.value() || !metadata.value()->identity.value() || !expected ||
                compare_identity(*metadata.value()->identity.value(),*expected)!=IdentityComparison::Same) set(i,CKFEA_REVIEW_REQUIRED);
            else if (append_journal(i,OperationJournalState::DestinationCommitted) &&
                append_journal(i,OperationJournalState::SourceRemovalIntended) &&
                append_journal(i,OperationJournalState::SourceRetired) && append_journal(i,OperationJournalState::Complete)) {
                // The native rename already moved the source atomically. These
                // journal transitions record its outcome; no retire API is used.
                set(i,CKFEA_VERIFIED);
            }
        } else if (row(i).state==CKFEA_EXECUTING) set(i,CKFEA_REVIEW_REQUIRED);
        event(i,CKFEA_EVIDENCE_RESULT);
        if (row(i).state==CKFEA_REVIEW_REQUIRED) break; // ambiguous job cannot keep mutating
    }
    for (auto i:order_) if (row(i).state==CKFEA_READY) {
        set(i,cancelled()?CKFEA_ITEM_CANCELLED:CKFEA_REVIEW_REQUIRED); event(i,CKFEA_EVIDENCE_RESULT);
    }
}
void ActionJob::journal_finish_failed(ObservationState observation,ErrorDomain domain,int64_t code) noexcept {
    // Emergency finalization must work even after allocation failure. Only
    // cached POD rows and already-reserved event storage may be touched here.
    std::lock_guard lock(mutex_);
    if(journal_finish_ok_) {
        finish_observation_=observation;finish_domain_=domain;finish_code_=code;journal_finish_ok_=false;
    } else {observation=finish_observation_;domain=finish_domain_;code=finish_code_;}
    const bool any=std::any_of(journal_affected_.begin(),journal_affected_.end(),[](bool b){return b;});
    for(size_t i=0;i<results_.size();++i) {
        auto& r=results_[i];
        if(!journal_affected_[i]&&(any||(r.state!=CKFEA_READY&&r.state!=CKFEA_EXECUTING&&r.state!=CKFEA_VERIFIED)))continue;
        // A delayed close failure invalidates even previously verified rows.
        r.state=CKFEA_REVIEW_REQUIRED;
        r.observation=static_cast<uint32_t>(observation);
        r.error_domain=static_cast<uint32_t>(domain);r.error_code=code;
        if(events_.size()<events_.capacity())
            events_.push_back({CKFEA_VERSION,sizeof(ckfea_evidence),CKFEA_EVIDENCE_RESULT,
                static_cast<uint32_t>(i),events_.size()+1,id_,r,{0,0}});
    }
}
void ActionJob::finish_trash_transactions() noexcept {
    for(size_t i=0;i<trash_transactions_.size();++i) {
        if(!trash_transactions_[i]||trash_finish_attempted_[i])continue;
        trash_finish_attempted_[i]=true;
        try {
            const auto result=trash_transactions_[i]->finish_io();
            if(result.value()&&*result.value())continue;
            journal_affected_[i]=true;
            if(!result.value()) {
                const auto& failure=*result.unavailable_detail();
                journal_finish_failed(failure.state,failure.error.domain,failure.error.code);
            } else journal_finish_failed(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidNativeResult));
        } catch(...) {
            journal_affected_[i]=true;
            detail::PreparedJournalConsumerFailure failure;
            if(request_.prepared_journal_root&&detail::read_prepared_journal_consumer_failure(*request_.prepared_journal_root,failure)&&!failure.pending)
                journal_finish_failed(failure.state,failure.domain,failure.code);
            else journal_finish_failed(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidNativeResult));
        }
    }
}
bool ActionJob::finish_journal() noexcept {
    {
        std::lock_guard lock(mutex_);
        if(!journal_file_||journal_finish_attempted_)return journal_finish_ok_;
        journal_finish_attempted_=true;
    }
    try {
        const auto result=journal_file_->finish_io();
        if(result.value()&&*result.value())return true;
        if(!result.value()) {
            const auto& failure=*result.unavailable_detail();
            journal_finish_failed(failure.state,failure.error.domain,failure.error.code);
        } else journal_finish_failed(ObservationState::Failed,ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidNativeResult));
    } catch(...) {
        journal_finish_failed(ObservationState::Failed,ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidNativeResult));
    }
    return false;
}
void ActionJob::release_native_inputs() noexcept {
    // Public handles retain cached state only after completion. Close native
    // owners here on the worker, including the last-reference close path.
    trash_transactions_.clear(); trash_backend_.reset();
    request_.restore_items.clear();
    journal_file_.reset(); journal_.reset(); artifact_.reset();
    scope_guards_.clear();
    request_.open_journal={};
    if(owns_private_root_) {
        owns_private_root_=false;
        const auto failed=[this](ObservationState state,ErrorDomain domain,int64_t code) noexcept {
            if(!journal_finish_ok_)return; // Preserve the first real close failure.
            std::fill(journal_affected_.begin(),journal_affected_.end(),true);
            journal_finish_failed(state,domain,code);
        };
        try {
            const auto finished=request_.prepared_journal_root->finish_io();
            if(!finished.value()) {
                const auto& error=*finished.unavailable_detail();
                failed(error.state,error.error.domain,error.error.code);
            } else if(!*finished.value())failed(ObservationState::Failed,ErrorDomain::Adapter,
                static_cast<int64_t>(AdapterError::InvalidNativeResult));
        } catch(...) {failed(ObservationState::Failed,ErrorDomain::Adapter,
            static_cast<int64_t>(AdapterError::InvalidNativeResult));}
    }
    request_.prepared_journal_root.reset();
    request_.items.clear(); request_.recovery_destination.reset(); request_.recovery.reset();
    native_.reset();
    model_boundary_.reset();
}
void ActionJob::run() noexcept {
    try {
        preview();
        { std::unique_lock lock(mutex_);
          if (!cancelled()) { phase_=CKFEA_AWAITING_RECEIPT; cv_.notify_all();
              cv_.wait(lock,[&]{return approved_||cancelled();}); } }
        if (!cancelled()) perform();
        if (cancelled()) for (size_t i=0;i<results_.size();++i)
            if (row(i).state==CKFEA_READY || row(i).state==CKFEA_PENDING) {
                set(i,CKFEA_ITEM_CANCELLED); event(i,CKFEA_EVIDENCE_RESULT);
            }
        finish_trash_transactions();finish_journal();
        release_native_inputs();
        { std::lock_guard lock(mutex_); phase_=!journal_finish_ok_?CKFEA_JOB_FAILED:cancelled()?CKFEA_CANCELLED:CKFEA_FINISHED; cv_.notify_all(); }
    } catch (...) {
        finish_trash_transactions();finish_journal();
        detail::PreparedJournalConsumerFailure failure;
        if(request_.prepared_journal_root&&detail::read_prepared_journal_consumer_failure(*request_.prepared_journal_root,failure)&&!failure.pending) {
            std::fill(journal_affected_.begin(),journal_affected_.end(),true);
            journal_finish_failed(failure.state,failure.domain,failure.code);
        }
        release_native_inputs();
        std::lock_guard lock(mutex_);
        for (auto& r:results_) if (r.state==CKFEA_READY || r.state==CKFEA_PENDING || r.state==CKFEA_EXECUTING) {
            r.state=CKFEA_REVIEW_REQUIRED;
            if(!r.error_domain) {
                r.observation=static_cast<uint32_t>(ObservationState::Unknown);
                r.error_domain=static_cast<uint32_t>(ErrorDomain::Adapter);
                r.error_code=static_cast<int64_t>(AdapterError::InvalidNativeResult);
            }
        }
        phase_=CKFEA_JOB_FAILED; cv_.notify_all();
    }
}
} // namespace ck::files
