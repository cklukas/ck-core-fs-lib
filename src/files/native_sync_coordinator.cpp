#include "native_sync_hierarchy_binding.hpp"
// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_coordinator.hpp"
#include "native_sync_internal.hpp"
#include "native_operation_journal_id.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "native_filesystem.hpp"
#include "retained_target.hpp"
#include "regular_metadata_preservation.hpp"
#include "metadata_ownership_digest.hpp"
#include "sha256.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif
namespace ck::files {
namespace {
using namespace sync_detail;
SyncDigest policy_digest(const NativeSyncCoordinatorRequest& r) {
    return native_sync_policy_binding(r.application_policy,r.metadata);
}
NativeName generated_name(std::string prefix,OperationJournalId id,NameEncoding encoding) {
    constexpr char hex[]="0123456789abcdef";for(auto byte:id.bytes) {auto b=std::to_integer<unsigned>(byte);prefix+=hex[b>>4];prefix+=hex[b&15];}
    if(encoding==NameEncoding::PosixBytes)return *NativeName::from_posix(std::move(prefix));
    return *NativeName::from_windows(std::u16string(prefix.begin(),prefix.end()));
}
bool bound_to(const SyncSessionIdentity& a,const SyncSessionIdentity& b) {
    return a.left_root==b.left_root&&a.right_root==b.right_root&&a.policy==b.policy&&a.pair==b.pair;
}
SyncEntryStatus absent() {return {SyncPresence::Absent,SyncKind::Unknown,{},{}};}
bool is_copy(SyncAction action) {return action==SyncAction::CopyLeftToRight||action==SyncAction::CopyRightToLeft;}
bool is_delete(SyncAction action) {return action==SyncAction::DeleteLeft||action==SyncAction::DeleteRight;}
bool destination_right(SyncAction action) {return action==SyncAction::CopyLeftToRight||action==SyncAction::DeleteRight;}
}
struct NativeSyncRuleAssessmentState {
    std::shared_ptr<const int> owner,revision;
    SyncSessionIdentity identity;
    ComparisonPlanIdentity plan;
    std::uint64_t generation=0;
    std::vector<NativeSyncRuleRow> rows;
    SyncDigest rules_digest{};
    bool consumed=false;
};
struct NativeSyncCoordinator::State {
    NativeSyncCoordinatorRequest request;
    NativeFileSystem filesystem;
    std::unique_ptr<SyncSession> session;
    std::array<NativeSyncInventory,2> inventories;
    std::vector<NativeSyncReviewedRow> reviewed;
    ComparisonPlan::Pointer fact_plan;
    std::vector<NativeSyncRawFacts> raw_facts;
    std::shared_ptr<const int> rule_owner=std::make_shared<const int>(0),rule_revision=std::make_shared<const int>(0);
    SyncDigest selected_rules_digest{};
    std::vector<NativeSyncArtifact> catalog;
    std::vector<NativeSyncProtectedEvidence> protected_evidence;
    // Labels index native records; they are never decoded into addresses.
    std::map<std::string,std::vector<NativeName>> paths;
    struct Selected {std::string key;SyncAction action;bool skip;std::optional<NativeSyncArtifact> artifact;};
    std::vector<Selected> selected;
    std::vector<std::size_t> execution_order;
    NativeSyncCoordinatorResult result;
    std::optional<OperationJournalId> transaction;
    std::optional<NativeName> ledger_name;
    std::unique_ptr<NativeSyncLedger> ledger;
    NativeSyncLedgerEvidence evidence;
    NativeOperationCopyJob::Pointer copy;
    RetainedTarget::Pointer retained;
    bool first_run=false,approved_first=false,mutated=false;
    std::size_t current=0,stored_ledger_count=0,stored_ledger_bytes=0;
    bool finished=false,finish_failed=false,reported_finish_pending=false;
    PreparedJournalRoot* finish_root=nullptr;
    detail::PreparedJournalConsumerFailure finish_failure;
    void record_finish(PreparedJournalRoot* owner,ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view operation) noexcept {
        if(!finish_failed) {
            finish_failed=true;finish_failure.state=state;finish_failure.domain=domain;finish_failure.code=code;
            const auto size=std::min(operation.size(),finish_failure.operation.size()-1);
            std::copy_n(operation.begin(),size,finish_failure.operation.begin());
        }
        if(owner)detail::record_prepared_journal_consumer_failure(*owner,state,domain,code,operation);
    }
    void close_native() noexcept {
        if(finished)return;finished=true;rule_revision.reset();
        // The backend/request retains this owner throughout teardown. Avoid
        // an extra shared reference: a legacy factory is itself the lifecycle
        // owner and must be able to finish its internally minted original root.
        PreparedJournalRoot* owner=nullptr;
        if(session){auto kept=session->storage_root();owner=kept.get();}
        else owner=request.prepared_journal_root.get();
        finish_root=owner;
        if(owner&&detail::read_prepared_journal_consumer_failure(*owner,finish_failure))finish_failed=true;
        // These jobs are serialized native worker objects, with no concurrent
        // advance here. Native journal destructors close+latch on this worker.
        copy.reset();retained.reset();
        if(ledger) {
            try {auto close_result=ledger->finish_io();if(!close_result.value()||!*close_result.value()) {
                if(auto* failure=close_result.unavailable_detail())record_finish(owner,failure->state,failure->error.domain,failure->error.code,failure->error.operation);
                else record_finish(owner,ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"native_sync.ledger_finish_false");
            }}catch(...) {record_finish(owner,ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"native_sync.ledger_finish_exception");}
            ledger.reset();
        }
        for(auto& inventory:inventories){inventory.files.clear();inventory.directories.clear();inventory.root.reset();}
        if(session)try {auto close_result=session->finish_io();if(!close_result.value()||!*close_result.value()) {
            if(auto* failure=close_result.unavailable_detail())record_finish(owner,failure->state,failure->error.domain,failure->error.code,failure->error.operation);
            else record_finish(owner,ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"native_sync.session_finish_false");
        }}catch(...) {record_finish(owner,ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"native_sync.session_finish_exception");}
        detail::PreparedJournalConsumerFailure first;
        if(owner&&detail::read_prepared_journal_consumer_failure(*owner,first)){finish_failure=first;finish_failed=true;}
        if(finish_failed||(result.state!=NativeSyncCoordinatorState::Complete&&ledger_name))result.state=NativeSyncCoordinatorState::NeedsReview;
        else if(result.state!=NativeSyncCoordinatorState::Complete)result.state=NativeSyncCoordinatorState::Cancelled;
    }
    explicit State(NativeSyncCoordinatorRequest r):request(std::move(r)) {}
    ~State(){close_native();}
    void require_open() {if(finished)fail("native_sync.finished",ObservationState::Changed,AdapterError::InvalidAccess);}

    std::shared_ptr<DirectoryCursor> cursor(bool right) {
        require(session->revalidate());
        auto root=std::shared_ptr<DirectoryCursor>(value(filesystem.open_native_directory(right?request.right:request.left)));
        auto now=value(root->inspect_basic());if(!now.identity.value()||!now.kind.value()||*now.kind.value()!=ObjectKind::Directory)
            fail("native_sync.root_identity",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
        const auto& id=*now.identity.value();auto handle=session->root_handle(right);
#ifdef _WIN32
        FILE_ID_INFO raw{};if(!GetFileInformationByHandleEx(reinterpret_cast<HANDLE>(handle),FileIdInfo,&raw,sizeof(raw)))
            fail("native_sync.held_root_id",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
        NativeIdentifier object;std::memcpy(object.bytes.data(),raw.FileId.Identifier,16);
        if(id.scheme!=IdentityScheme::WindowsFileId128||id.volume!=NativeIdentifier::from_u64(raw.VolumeSerialNumber)||id.object!=object)
            fail("native_sync.root_mismatch");
#else
        struct stat raw{};if(fstat(static_cast<int>(handle),&raw))fail("native_sync.held_root_id");
        if(id.scheme!=IdentityScheme::PosixDeviceInode||id.volume!=NativeIdentifier::from_u64(raw.st_dev)||id.object!=NativeIdentifier::from_u64(raw.st_ino))
            fail("native_sync.root_mismatch");
#endif
        require(session->revalidate());return root;
    }
    std::array<NativeSyncInventory,2> scan(std::stop_token token) {
        NativeSyncProofBudget budget;
        std::array<NativeSyncInventory,2> out;
        const std::size_t depth=request.recursive_trees?request.max_depth:1;
        for(unsigned side=0;side<2;++side) {
            auto observed=value(observe_native_sync_root(cursor(side!=0),request.metadata,request.proof_limits,budget,token,depth));
            // Observation transfers only the unique owner. Map assignment and
            // any allocation remain ordinary throwing work, before publication
            // of this fresh inventory or baseline advancement.
            if(!observed)fail("native_sync.null_inventory",ObservationState::Unknown,AdapterError::InvalidNativeResult);
            out[side]=std::move(*observed);
        }
        for(const auto& root:out) {
            for(const auto& [key,proof]:root.files) {
                auto [it,inserted]=paths.emplace(key,proof.components);
                if(!inserted&&it->second!=proof.components)fail("native_sync.opaque_label_collision",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            }
            for(const auto& [key,dproof]:root.directories) {
                auto [it,inserted]=paths.emplace(key,dproof.components);
                if(!inserted&&it->second!=dproof.components)fail("native_sync.opaque_label_collision",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            }
        }
        require(session->revalidate());return out;
    }
    void protect(std::array<NativeSyncInventory,2>& data,const std::vector<NativeSyncArtifact>& artifacts) {
        std::set<std::pair<bool,std::string>> seen;
        std::vector<NativeSyncProtectedEvidence> visible;
        for(const auto& a:artifacts) {
            auto key=native_sync_key(a.components);if(!seen.emplace(a.right,key).second)continue;
            auto& root=data[a.right?1:0];auto it=root.files.find(key);
            if(it==root.files.end()||it->second.status!=a.status||!it->second.metadata.basic.identity.value()||
                !a.object.matches_live(*it->second.metadata.basic.identity.value())||!root.root_metadata.identity.value()||
                !a.parent.matches_live(*root.root_metadata.identity.value()))fail("native_sync.protected_artifact_changed",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            visible.push_back({a,it->second.metadata.basic});root.files.erase(it);
        }
        protected_evidence=std::move(visible);
    }
    SyncEntryStatus status(const NativeSyncInventory& root,const std::string& key) {
        auto it=root.files.find(key);if(it!=root.files.end())return it->second.status;
        auto dit=root.directories.find(key);if(dit!=root.directories.end())return dit->second.status;
        auto binding=paths.find(key);
        if(binding==paths.end())fail("native_sync.baseline_missing_native_record",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        const auto& names=binding->second;
        if(!request.recursive_trees) {
            if(names.size()!=1)fail("native_sync.structural_path",ObservationState::Unsupported,AdapterError::UnsupportedQuery);
            auto before=value(root.root->inspect_basic());if(!native_sync_same_version(root.root_metadata,before))fail("native_sync.absence_parent_changed");
            for(unsigned i=0;i<2;++i) {
                auto lookup=value(root.root->lookup_child(names.front(),ChildLookupMode::NativeDefault));
                if(lookup.state()!=ChildLookupState::Missing||!lookup.missing_witness())fail("native_sync.absence_unproved",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            }
            auto after=value(root.root->inspect_basic());if(!native_sync_same_version(before,after))fail("native_sync.absence_parent_changed");
            return absent();
        }
        auto current_cursor=root.root;
        BasicMetadata current_meta=root.root_metadata;
        for(std::size_t idx=0;idx<names.size();++idx) {
            auto before=value(current_cursor->inspect_basic());
            if(!native_sync_same_version(current_meta,before))fail("native_sync.absence_parent_changed");
            if(idx+1<names.size()) {
                const auto prefix_key=native_sync_key(std::span(names).first(idx+1));
                auto sub=root.directories.find(prefix_key);
                if(sub!=root.directories.end()) {
                    current_cursor=sub->second.cursor;
                    current_meta=sub->second.metadata;
                    continue;
                }
                if(root.files.contains(prefix_key))return absent();
            }
            for(unsigned pass=0;pass<2;++pass) {
                auto lookup=value(current_cursor->lookup_child(names[idx],ChildLookupMode::NativeDefault));
                if(lookup.state()!=ChildLookupState::Missing||!lookup.missing_witness())
                    fail("native_sync.absence_unproved",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            }
            auto after=value(current_cursor->inspect_basic());
            if(!native_sync_same_version(before,after))fail("native_sync.absence_parent_changed");
            return absent();
        }
        return absent();
    }
    bool pair_equal(const std::array<NativeSyncInventory,2>& data,const std::string& key) {
        if(status(data[0],key)!=status(data[1],key))return false;
        if(request.metadata.ownership!=MetadataOwnership::CurrentCaller)return true;
        auto left=data[0].files.find(key),right=data[1].files.find(key);
        return left==data[0].files.end()&&right==data[1].files.end()?true:
            left!=data[0].files.end()&&right!=data[1].files.end()&&native_sync_same_ownership(left->second.metadata,right->second.metadata);
    }
    std::vector<SyncBaselineRow> current_rows(const std::array<NativeSyncInventory,2>& data) {
        std::set<std::string> keys;
        for(const auto& root:data) {
            for(const auto& [key,proof]:root.files){(void)proof;keys.insert(key);}
            for(const auto& [key,dproof]:root.directories){(void)dproof;keys.insert(key);}
        }
        if(session->snapshot().baseline)for(const auto& row:session->snapshot().baseline->rows)keys.insert(row.relative_path);
        if(keys.size()>request.proof_limits.baseline.max_rows)fail("native_sync.row_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        std::vector<SyncBaselineRow> rows;
        for(const auto& key:keys)rows.push_back({key,status(data[0],key),status(data[1],key)});
        return rows;
    }
    void stable_scan(std::stop_token token) {
        auto first=scan(token);protect(first,catalog);auto second=scan(token);protect(second,catalog);
        for(unsigned side=0;side<2;++side)require(compare_native_sync_inventories(first[side],second[side]));
        inventories=std::move(second);
    }
    void revalidate_inventory(std::stop_token token) {
        auto now=scan(token);protect(now,catalog);
        for(unsigned side=0;side<2;++side)require(compare_native_sync_inventories(inventories[side],now[side]));
        inventories=std::move(now);
    }
    void seal_ledger(NativeSyncLoadedLedger& loaded) {
        auto opened=value(NativeSyncLedger::reopen(session->storage_root(),loaded.name,loaded.journal->id(),request.ledger_limits));
        auto state=opened->journal().state(0);
        if(state==OperationJournalState::CommitIntended)require(opened->append(OperationJournalState::DestinationCommitted,loaded.evidence));
        if(opened->journal().state(0)==OperationJournalState::DestinationCommitted)require(opened->append(OperationJournalState::Complete,loaded.evidence));
        require(opened->finish_io());
    }
    void load_history(std::stop_token token) {
        auto loaded=value(load_native_sync_ledgers(session->storage_root(),request.ledger_limits,token));
        stored_ledger_count=loaded.size();for(const auto& record:loaded)stored_ledger_bytes+=record.wire_bytes;
        // At most one unresolved transaction may exist for this exact session.
        std::vector<NativeSyncLoadedLedger*> unresolved;
        std::set<std::pair<bool,std::string>> artifacts;
        std::set<std::uint64_t> committed_generations;
        for(auto& l:loaded) {
            if(!bound_to(l.evidence.session,session->identity())) {
                const auto& old=l.evidence.session;const auto& live=session->identity();
                if(old.left_root==live.left_root||old.left_root==live.right_root||old.right_root==live.left_root||old.right_root==live.right_root)
                    fail("native_sync.related_history_changed",ObservationState::Changed,AdapterError::ProviderReviewRequired);
                continue;
            }
            for(const auto& path:l.evidence.paths) {
                auto [it,inserted]=paths.emplace(path.opaque_key,path.components);
                if(!inserted&&it->second!=path.components)fail("native_sync.native_path_record_conflict",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            }
            const auto state=l.journal->state(0);
            if(state!=OperationJournalState::Complete) {unresolved.push_back(&l);continue;}
            if(!l.evidence.proposed_baseline||l.evidence.expected_generation>=session->snapshot().generation)
                fail("native_sync.completed_ledger_generation",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            if(!committed_generations.insert(l.evidence.expected_generation).second)
                fail("native_sync.duplicate_committed_generation",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            if(l.evidence.expected_generation+1==session->snapshot().generation&&
                (!session->snapshot().baseline||*session->snapshot().baseline!=*l.evidence.proposed_baseline))
                fail("native_sync.committed_ledger_baseline_mismatch",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            for(const auto& a:l.evidence.artifacts) {
                auto key=std::pair(a.right,native_sync_key(a.components));
                if(artifacts.insert(key).second)catalog.push_back(a);
                else {auto old=std::find_if(catalog.begin(),catalog.end(),[&](const auto& b){return b.right==a.right&&native_sync_key(b.components)==key.second;});
                    if(old==catalog.end()||old->object!=a.object||old->parent!=a.parent||old->status!=a.status)
                        fail("native_sync.artifact_catalog_collision",ObservationState::Changed,AdapterError::ProviderReviewRequired);}
            }
        }
        if(unresolved.empty())return;
        if(unresolved.size()!=1)fail("native_sync.multiple_unresolved_intents",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        auto& l=*unresolved.front();auto state=l.journal->state(0);
        if((state!=OperationJournalState::CommitIntended&&state!=OperationJournalState::DestinationCommitted)||!l.evidence.proposed_baseline)
            fail("native_sync.unresolved_intent",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        const auto& snapshot=session->snapshot();
        if(snapshot.generation==l.evidence.expected_generation+1&&snapshot.baseline&&*snapshot.baseline==*l.evidence.proposed_baseline) {
            // SyncSession recovered/published exactly this generation. No data
            // mutation is replayed; close/mark the durable ledger idempotently.
            seal_ledger(l);
        } else if(snapshot.generation==l.evidence.expected_generation) {
            // A durable coordinator intent can finish only after new native
            // convergence evidence, never by trusting stored digest assertions.
            auto combined=catalog;for(const auto& a:l.evidence.artifacts) {
                if(std::none_of(combined.begin(),combined.end(),[&](const auto& b){return b.right==a.right&&b.components==a.components;}))combined.push_back(a);
            }
            catalog=std::move(combined);stable_scan(token);
            std::vector<SyncBaselineUpdate> updates;
            for(const auto& record:l.evidence.paths) {
                const auto left=status(inventories[0],record.opaque_key),right=status(inventories[1],record.opaque_key);
                if(record.skipped) {
                    updates.push_back({{record.opaque_key,left,right},SyncBaselineUpdateState::Pending});continue;
                }
                SyncEntryStatus expected;
                switch(record.action) {
                case SyncAction::Unchanged:
                    if(record.left!=record.right)fail("native_sync.recovery_unequal_unchanged",ObservationState::Changed,AdapterError::ProviderReviewRequired);
                    expected=record.left;break;
                case SyncAction::CopyLeftToRight:expected=record.left;break;
                case SyncAction::CopyRightToLeft:expected=record.right;break;
                case SyncAction::DeleteLeft:case SyncAction::DeleteRight:expected=absent();break;
                default:fail("native_sync.recovery_unresolved_selection",ObservationState::Changed,AdapterError::ProviderReviewRequired);
                }
                if(left!=expected||right!=expected||!pair_equal(inventories,record.opaque_key))
                    fail("native_sync.recovery_convergence_changed",ObservationState::Changed,AdapterError::ProviderReviewRequired);
                updates.push_back({{record.opaque_key,left,right},SyncBaselineUpdateState::ConfirmedEqual});
            }
            auto prospective=value(advance_sync_baseline(snapshot.baseline?&*snapshot.baseline:nullptr,updates,session->identity().policy,request.proof_limits.baseline));
            if(prospective.baseline!=*l.evidence.proposed_baseline)fail("native_sync.recovery_convergence_changed",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            // Fresh version/membership check follows the full stable hash pass.
            revalidate_inventory(token);
            auto committed=value(session->commit(snapshot.generation,updates,snapshot.state==SyncSessionState::FirstRun));
            if(committed.baseline!=prospective.baseline)fail("native_sync.recovery_baseline_mismatch",ObservationState::Unknown,AdapterError::InvalidNativeResult);
            seal_ledger(l);
        } else fail("native_sync.unresolved_generation",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        for(const auto& a:l.evidence.artifacts)if(std::none_of(catalog.begin(),catalog.end(),[&](const auto& b){return b.right==a.right&&b.components==a.components;}))catalog.push_back(a);
    }
    void event(NativeSyncCoordinatorEvent event) {
        if(request.before_event&&!request.before_event(event))fail("native_sync.injected_event",ObservationState::Failed,AdapterError::InterruptedRead);
    }
    void initialize(std::stop_token token) {
        if(!request.metadata.valid()||!request.proof_limits.chunk_bytes||request.proof_limits.chunk_bytes>ContentReadLimits::hard_max_bytes||
            !request.proof_limits.max_file_bytes||!request.proof_limits.max_total_bytes||!request.proof_limits.max_entries||!request.proof_limits.max_metadata_bytes)
            fail("native_sync.request_limits",ObservationState::Failed,AdapterError::InvalidLimit);
        request.ledger_limits.baseline=request.proof_limits.baseline;
        if(!request.prepared_journal_root&&!request.coordinator)fail("native_sync.storage_owner_required",ObservationState::Failed,AdapterError::InvalidAccess);
        auto backend=value(request.prepared_journal_root?
            open_native_sync_session_backend(request.prepared_journal_root,request.left,request.right,request.storage_faults):
            open_native_sync_session_backend(*request.coordinator,request.left,request.right,request.storage_faults));
        session=value(SyncSession::open(std::move(backend),policy_digest(request),request.proof_limits.baseline));
        if(session->snapshot().state==SyncSessionState::HistoryChanged)
            fail("native_sync.history_changed",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        if(session->snapshot().state==SyncSessionState::ReviewRequired)
            fail("native_sync.history_review",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        load_history(token);first_run=session->snapshot().state==SyncSessionState::FirstRun;
        stable_scan(token);auto rows=current_rows(inventories);
        auto plan=value(reconcile_sync(session->snapshot().baseline?&*session->snapshot().baseline:nullptr,
            {true,true,rows},session->identity().policy,request.deletion_guard,request.proof_limits.baseline));
        if(plan.state==SyncReconcileState::ReconcileRequired)fail("native_sync.reconcile_required",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        for(std::size_t i=0;i<rows.size();++i) {
            if(plan.rows[i].relative_path!=rows[i].relative_path)fail("native_sync.plan_order",ObservationState::Unknown,AdapterError::InvalidNativeResult);
            if(rows[i].left==rows[i].right&&!pair_equal(inventories,rows[i].relative_path))
                reviewed.push_back({rows[i].relative_path,rows[i].left,rows[i].right,SyncAction::Conflict,SyncReason::RequiredMetadataDifference});
            else reviewed.push_back({rows[i].relative_path,rows[i].left,rows[i].right,plan.rows[i].action,plan.rows[i].reason});
        }
        result.generation=session->snapshot().generation;
    }
    void build_facts() {
        require_open();
        if(fact_plan)return;
        const auto rows=reviewed.size();
        if(rows>ComparisonLimits::hard_max_entries/2||rows>request.proof_limits.max_metadata_bytes/(sizeof(NativeSyncRawFacts)+2*sizeof(ComparisonEntry)+256))
            fail("native_sync.facts_budget",ObservationState::Unknown,AdapterError::InventoryLimit);
        std::array<std::vector<ComparisonEntry>,2> entries;
        // The main-data digest stays the digest of unnamed DATA. Preserved
        // metadata and named streams have an independent, versioned schema.
        Sha256 schema_hash;
        constexpr char schema_domain[]="ck-core-fs-lib/native-preserved-metadata";
        schema_hash.update(std::as_bytes(std::span(schema_domain,sizeof(schema_domain)-1)));
        std::array<std::byte,8> schema_version{};
        for(unsigned i=0;i<schema_version.size();++i)
            schema_version[i]=std::byte((native_sync_metadata_digest_version>>(8*i))&255);
        schema_hash.update(schema_version);
        const auto metadata_schema=schema_hash.digest();
        for(unsigned side=0;side<2;++side)for(const auto& row:reviewed) {
            ComparisonEntry e;e.relative_path=row.exact_key;auto it=inventories[side].files.find(row.exact_key);
            if(it==inventories[side].files.end()) {
                auto dit=inventories[side].directories.find(row.exact_key);
                if(dit==inventories[side].directories.end())e.object.state=ComparisonObjectState::Gone;
                else {
                    const auto& db=dit->second.metadata;
                    e.object={ComparisonObjectState::Stable,*db.identity.value(),ObjectKind::Directory,{},*db.modified.value(),1,{}};
                }
            } else {
                const auto& p=it->second;const auto& b=p.metadata.basic;
                e.object={ComparisonObjectState::Stable,*b.identity.value(),*b.kind.value(),*b.logical_size.value(),*b.modified.value(),1,{}};
                ComparisonDigest d;d.state=ComparisonDigestState::CompleteStable;d.algorithm=ComparisonDigestAlgorithm::Sha256;
                d.bytes=p.status.content_digest;d.bytes_read=*b.logical_size.value();d.before=e.object;d.after=e.object;e.digest=std::move(d);
                ComparisonMetadataDigest metadata;
                metadata.state=ComparisonDigestState::CompleteStable;
                metadata.algorithm=ComparisonDigestAlgorithm::Sha256;
                metadata.schema=metadata_schema;metadata.policy_binding=session->identity().policy;
                metadata.bytes=p.status.required_metadata_digest;
                metadata.ownership=p.metadata.policy.ownership==MetadataOwnership::Original?
                    ComparisonMetadataOwnership::Original:ComparisonMetadataOwnership::CurrentCaller;
                if(metadata.ownership==ComparisonMetadataOwnership::CurrentCaller) {
                    auto owner=metadata_ownership_digest(p.metadata);
                    if(owner.value())metadata.canonical_owner_digest=*owner.value();
                }
                metadata.before=metadata.after=e.object;
                e.metadata_digest=std::move(metadata);
            }
            entries[side].push_back(std::move(e));
        }
        ComparisonOptions options;options.profile=ComparisonProfile::Compare;options.mode=ComparisonMode::CompleteDigest;options.topology=ComparisonTopology::Disjoint;
        options.compare_preserved_metadata=true;
        ComparisonLimits limits;limits.max_entries=std::max<std::size_t>(1,rows*2);limits.max_path_bytes=request.proof_limits.baseline.max_path_bytes;
        limits.max_total_path_bytes=std::min<std::size_t>(ComparisonLimits::hard_max_total_path_bytes,request.proof_limits.baseline.max_total_path_bytes*2);
        fact_plan=value(ComparisonPlan::create(options,{ComparisonInventoryState::CompleteStable,*inventories[0].root_metadata.identity.value(),entries[0]},
            {ComparisonInventoryState::CompleteStable,*inventories[1].root_metadata.identity.value(),entries[1]},{},limits));
        std::size_t offset=0;
        while(offset<rows) {
            auto page=value(fact_plan->page(offset,std::min<std::size_t>(256,rows-offset)));
            if(page.rows.empty())fail("native_sync.facts_plan_rows",ObservationState::Unknown,AdapterError::InvalidNativeResult);
            for(const auto& comparison:page.rows) {
                const auto index=raw_facts.size();if(index>=reviewed.size()||comparison.relative_path!=reviewed[index].exact_key)
                    fail("native_sync.facts_plan_order",ObservationState::Unknown,AdapterError::InvalidNativeResult);
                const auto& reviewed_row=reviewed[index];NativeSyncRawFacts f;f.token=comparison.token;f.relation=comparison.relation;
                auto side_facts=[&](unsigned side,NativeSyncObservedFacts& output,Observation<bool>& retention) {
                    output.status=side?reviewed_row.right:reviewed_row.left;auto it=inventories[side].files.find(reviewed_row.exact_key);
                    if(it==inventories[side].files.end()) {
                        auto dit=inventories[side].directories.find(reviewed_row.exact_key);
                        if(dit==inventories[side].directories.end()){retention=Observation<bool>::available(false);return;}
                        const auto& dproof=dit->second;
                        output.kind=ObjectKind::Directory;
                        output.modified=*dproof.metadata.modified.value();
                        retention=attempt<bool>([&]{
                            auto strict=dproof.held->parent()->qualify_identity_bound_rename();
                            if(!strict.value()&&request.allow_held_posix_namespace&&strict.state()==ObservationState::Unsupported)
                                strict=qualify_held_posix_namespace(*dproof.held->parent());
                            return value(std::move(strict));
                        });
                        return;
                    }
                    const auto& proof=it->second;output.kind=*proof.metadata.basic.kind.value();output.size=*proof.metadata.basic.logical_size.value();output.modified=*proof.metadata.basic.modified.value();
                    output.all_stream_size=proof.channel_facts.all_stream_logical_bytes;
                    output.named_stream_count=proof.channel_facts.coverage==DataChannelCoverage::WindowsFileStreamInfo?
                        std::optional<std::uint64_t>(proof.channel_facts.named_stream_count):std::nullopt;
                    output.channel_coverage=proof.channel_facts.coverage;
                    retention=attempt<bool>([&]{
                        auto strict=HeldChild::observe_with_access(proof.held->parent(),proof.held->name(),EntryAccess::ContentRead|EntryAccess::RenameSource);
                        if(strict.value()) {
                            auto guard=std::move(strict).take_value();
                            if(!native_sync_same_version(proof.metadata.basic,guard->metadata()))fail("native_sync.retention_probe_changed");
                            require(guard->qualify_stable_content());require(source_guard(proof));return true;
                        }
                        if(request.allow_held_posix_namespace&&strict.state()==ObservationState::Unsupported) {
                            if(!proof.metadata.basic.link_count.value()||*proof.metadata.basic.link_count.value()!=1)
                                fail("native_sync.retention_hard_link",ObservationState::Unsupported,AdapterError::UnsupportedQuery);
                            require(qualify_held_posix_namespace(*proof.held->parent()));
                            if(proof.held->parent().get()!=inventories[side].root.get())
                                require(qualify_held_posix_namespace(*inventories[side].root));
                            auto guard=value(HeldChild::observe_with_access(proof.held->parent(),proof.held->name(),EntryAccess::ContentRead));
                            if(!native_sync_same_version(proof.metadata.basic,guard->metadata()))fail("native_sync.retention_probe_changed");
                            require(source_guard(proof));return true;
                        }
                        throw Failure{*strict.unavailable_detail()};
                    });
                };
                side_facts(0,f.left,f.left_retention);side_facts(1,f.right,f.right_retention);
                const bool both=f.left.status.presence==SyncPresence::Present&&f.right.status.presence==SyncPresence::Present;
                f.conflict_class=reviewed_row.reason==SyncReason::DirectoryDeleteChangedSubtree?ConflictClass::DirectoryDeleteEditedChild:
                    reviewed_row.reason==SyncReason::DeleteEdit?ConflictClass::DeleteEdit:!both?ConflictClass::Unavailable:
                    (f.left.kind&&f.right.kind&&*f.left.kind!=*f.right.kind)?ConflictClass::TypeMismatch:
                    (f.left.kind==ObjectKind::Directory&&f.right.kind==ObjectKind::Directory)?ConflictClass::DirectoryPair:
                    f.relation==ComparisonRelation::Unknown?ConflictClass::RequiredMetadata:
                    reviewed_row.reason==SyncReason::ConcurrentEdit?ConflictClass::BothEdited:
                        ConflictClass::ExistingRegular;
                for(auto choice:{ConflictChoice::Ask,ConflictChoice::Skip,ConflictChoice::KeepTarget,ConflictChoice::Compare})f.allowed_choices|=1ULL<<static_cast<unsigned>(choice);
                if(f.right.status.presence==SyncPresence::Absent||pair_equal(inventories,reviewed_row.exact_key)||(f.right_retention.value()&&*f.right_retention.value()))f.allowed_choices|=1ULL<<static_cast<unsigned>(ConflictChoice::KeepLeft);
                if(f.left.status.presence==SyncPresence::Absent||pair_equal(inventories,reviewed_row.exact_key)||(f.left_retention.value()&&*f.left_retention.value()))f.allowed_choices|=1ULL<<static_cast<unsigned>(ConflictChoice::KeepRight);
                raw_facts.push_back(std::move(f));
            }
            offset+=page.rows.size();
        }
    }
    static bool valid_quantum(std::uint64_t q) {
        return q&&q<=86400ULL*1000000000&&(q<=1000000000?1000000000%q==0:q%1000000000==0);
    }
    static ConflictTimeOrder time_order(const NativeSyncObservedFacts& source,const NativeSyncObservedFacts& target,std::uint64_t q) {
        if(!source.modified||!target.modified)return ConflictTimeOrder::Unknown;
        const auto rounded=[q](FileTimestamp t) {
            if(q<=1000000000)return std::pair(t.seconds(),std::uint64_t(t.nanoseconds())/q);
            auto seconds=static_cast<std::int64_t>(q/1000000000);auto count=t.seconds()/seconds;if(t.seconds()%seconds<0)--count;return std::pair(count,std::uint64_t{0});
        };
        const auto s=rounded(*source.modified),t=rounded(*target.modified);
        return s>t?ConflictTimeOrder::SourceNewer:s<t?ConflictTimeOrder::TargetNewer:ConflictTimeOrder::Equal;
    }
    ConflictFacts conflict_facts(const NativeSyncRawFacts& f,const std::string& key,ConflictDirection direction,std::uint64_t quantum) {
        ConflictFacts out;out.token=f.token;out.relative_path=key;out.kind=f.conflict_class;out.relation=f.relation;out.evidence_current=true;out.direction=direction;
        const bool reverse=direction==ConflictDirection::RightToLeft;const auto& source=reverse?f.right:f.left;const auto& target=reverse?f.left:f.right;
        out.compatible_regular_files=source.status.presence==SyncPresence::Present&&target.status.presence==SyncPresence::Present;
        out.source_size=source.size;out.target_size=target.size;out.time_order=time_order(source,target,quantum);out.equal_time=out.time_order==ConflictTimeOrder::Equal;
        const auto& retained_status=reverse?f.left_retention:f.right_retention;out.retention_available=retained_status.value()&&*retained_status.value();
        // Relational labels remain tied to their source/target orientation.
        if(reverse) {
            if(out.relation==ComparisonRelation::SourceOnly)out.relation=ComparisonRelation::DestinationOnly;
            else if(out.relation==ComparisonRelation::DestinationOnly)out.relation=ComparisonRelation::SourceOnly;
            else if(out.relation==ComparisonRelation::SourceNewer)out.relation=ComparisonRelation::DestinationNewer;
            else if(out.relation==ComparisonRelation::DestinationNewer)out.relation=ComparisonRelation::SourceNewer;
        }
        return out;
    }
    std::shared_ptr<NativeSyncRuleAssessmentState> assess(std::span<const ConflictRule> rules,std::uint64_t quantum,std::stop_token token) {
        require_open();
        rule_revision=std::make_shared<const int>(0); // rejection also revokes old receipts
        if(result.state!=NativeSyncCoordinatorState::AwaitingReview||rules.size()>4096||!valid_quantum(quantum))
            fail("native_sync.rule_state_or_bounds",ObservationState::Failed,AdapterError::PlanInvalid);
        stop(token);build_facts();revalidate_inventory(token);
        auto assessment=std::make_shared<NativeSyncRuleAssessmentState>();assessment->owner=rule_owner;assessment->revision=rule_revision;
        assessment->generation=session->snapshot().generation;assessment->identity=session->identity();assessment->plan=fact_plan->identity();
        // Scope/choice parameters are preferences. The shared engine alone
        // decides their consequences against these native frozen facts.
        for(std::size_t index=0;index<reviewed.size();++index) {
            const auto& row=reviewed[index];const auto& f=raw_facts[index];
            ConflictRuleResult selected_result;selected_result.state=ConflictRuleState::NoMatch;selected_result.reason=ConflictRuleReason::NoMatchingRule;
            // Direction is a rule matching dimension; evaluate each family
            // with the same precedence/contradiction engine, then reject mixed
            // matching directions instead of silently picking an orientation.
            bool matched=false;
            for(auto direction:{ConflictDirection::SourceToTarget,ConflictDirection::LeftToRight,ConflictDirection::RightToLeft}) {
                auto facts=conflict_facts(f,row.exact_key,direction,quantum);auto decision=evaluate_conflict_rules(rules,facts);
                const Observation<bool>* loser=nullptr;
                if(decision.choice==ConflictChoice::KeepLeft||decision.choice==ConflictChoice::UseSource)loser=&f.right_retention;
                else if(decision.choice==ConflictChoice::KeepRight)loser=&f.left_retention;
                if(loser) {facts.retention_available=loser->value()&&*loser->value();decision=evaluate_conflict_rules(rules,facts);}
                if(decision.state==ConflictRuleState::Invalid||decision.state==ConflictRuleState::Stale){selected_result=decision;matched=true;break;}
                if(decision.state==ConflictRuleState::NoMatch)continue;
                if(matched){selected_result.state=ConflictRuleState::Invalid;selected_result.reason=ConflictRuleReason::ContradictoryRules;break;}
                selected_result=decision;matched=true;
            }
            NativeSyncDecision native{row.exact_key,NativeSyncChoice::Proposal};
            if(!matched&&(row.proposal==SyncAction::Conflict||row.proposal==SyncAction::Blocked)) {
                selected_result.state=ConflictRuleState::NeedsReview;selected_result.reason=ConflictRuleReason::NoMatchingRule;
            }
            if(selected_result.state==ConflictRuleState::Apply) {
                switch(selected_result.choice) {
                case ConflictChoice::Skip:case ConflictChoice::KeepTarget:native.choice=NativeSyncChoice::Skip;break;
                case ConflictChoice::UseSource:native.choice=NativeSyncChoice::LeftWins;break;
                case ConflictChoice::KeepLeft:native.choice=NativeSyncChoice::LeftWins;break;
                case ConflictChoice::KeepRight:native.choice=NativeSyncChoice::RightWins;break;
                case ConflictChoice::KeepBoth:case ConflictChoice::KeepBothIncoming:case ConflictChoice::KeepBothTarget:case ConflictChoice::Rename:
                    selected_result.state=ConflictRuleState::NeedsReview;selected_result.reason=ConflictRuleReason::SeparatePolicyRequired;break;
                default:selected_result.state=ConflictRuleState::NeedsReview;selected_result.reason=ConflictRuleReason::SeparatePolicyRequired;break;
                }
            }
            if(selected_result.state==ConflictRuleState::Apply&&!pair_equal(inventories,row.exact_key)) {
                const auto* retention=native.choice==NativeSyncChoice::LeftWins?&f.right_retention:native.choice==NativeSyncChoice::RightWins?&f.left_retention:nullptr;
                const auto& loser=native.choice==NativeSyncChoice::LeftWins?f.right:f.left;
                if(retention&&loser.status.presence==SyncPresence::Present&&(!retention->value()||!*retention->value())) {
                    selected_result.state=ConflictRuleState::NeedsReview;selected_result.reason=ConflictRuleReason::RetentionUnavailable;
                }
            }
            assessment->rows.push_back({selected_result,std::move(native)});
        }
        Sha256 digest;auto hash_number=[&](std::uint64_t n){std::array<std::byte,8> b{};for(unsigned i=0;i<8;++i)b[i]=std::byte((n>>(8*i))&255);digest.update(b);};
        hash_number(quantum);hash_number(rules.size());
        for(const auto& rule:rules) {
            for(auto n:{std::uint64_t(rule.kind),std::uint64_t(rule.choice),std::uint64_t(rule.tie),std::uint64_t(rule.scope),std::uint64_t(rule.direction),std::uint64_t(rule.protect_nonempty),std::uint64_t(rule.retain_replaced)})hash_number(n);
            hash_number(rule.selected_rows.size());for(auto id:rule.selected_rows)hash_number(id);hash_number(rule.subtree.size());digest.update(std::as_bytes(std::span(rule.subtree)));
        }
        assessment->rules_digest=digest.digest();return assessment;
    }
    void check_deletion_guard() {
        std::array<std::size_t,2> count{},based{};
        for(const auto& s:selected)if(is_delete(s.action)&&!s.skip)++count[destination_right(s.action)?1:0];
        if(count[0]+count[1]>request.deletion_guard.max_deletions)fail("native_sync.deletion_count_review",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        if(session->snapshot().baseline)for(const auto& r:session->snapshot().baseline->rows) {
            if(r.left.presence==SyncPresence::Present)++based[0];if(r.right.presence==SyncPresence::Present)++based[1];}
        for(unsigned side=0;side<2;++side)if(count[side]&&(!based[side]||count[side]*std::uint64_t(10000)>based[side]*std::uint64_t(request.deletion_guard.max_basis_points)))
            fail("native_sync.deletion_ratio_review",ObservationState::Changed,AdapterError::ProviderReviewRequired);
    }
    void approve(std::span<const NativeSyncDecision> decisions,bool approve_first_run,std::stop_token token={}) {
        if(result.state!=NativeSyncCoordinatorState::AwaitingReview||decisions.size()!=reviewed.size())
            fail("native_sync.review_state",ObservationState::Failed,AdapterError::PlanInvalid);
        if(first_run&&!approve_first_run)fail("native_sync.first_run_review",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        // Review receipts do not authorize stale main/ADS facts, even for an
        // Unchanged proposal. Refresh before selecting no-op execution.
        revalidate_inventory(token);
        std::map<std::string,NativeSyncChoice> choices;
        for(const auto& d:decisions)if(!choices.emplace(d.exact_key,d.choice).second)fail("native_sync.duplicate_decision",ObservationState::Failed,AdapterError::PlanInvalid);
        std::vector<Selected> next;
        for(const auto& row:reviewed) {
            auto it=choices.find(row.exact_key);if(it==choices.end())fail("native_sync.missing_decision",ObservationState::Failed,AdapterError::PlanInvalid);
            auto action=row.proposal;bool skip=it->second==NativeSyncChoice::Skip;
            switch(it->second) {
            case NativeSyncChoice::Skip:action=SyncAction::Unchanged;break;
            case NativeSyncChoice::Proposal:if(action==SyncAction::Conflict||action==SyncAction::Blocked)fail("native_sync.conflict_decision_required",ObservationState::Changed,AdapterError::ProviderReviewRequired);break;
            case NativeSyncChoice::LeftWins:action=pair_equal(inventories,row.exact_key)?SyncAction::Unchanged:row.left.presence==SyncPresence::Present?SyncAction::CopyLeftToRight:SyncAction::DeleteRight;break;
            case NativeSyncChoice::RightWins:action=pair_equal(inventories,row.exact_key)?SyncAction::Unchanged:row.right.presence==SyncPresence::Present?SyncAction::CopyRightToLeft:SyncAction::DeleteLeft;break;
            default:fail("native_sync.choice",ObservationState::Failed,AdapterError::PlanInvalid);
            }
            next.push_back({row.exact_key,action,skip,{}});
        }
        if(request.recursive_trees) {
            for(std::size_t i=0;i<next.size();++i) {
                if(next[i].skip) {
                    const std::string prefix=next[i].key+"/";
                    const bool left_dir=reviewed[i].left.presence==SyncPresence::Present&&reviewed[i].left.kind==SyncKind::Directory;
                    const bool right_dir=reviewed[i].right.presence==SyncPresence::Present&&reviewed[i].right.kind==SyncKind::Directory;
                    if(!left_dir||!right_dir) {
                        for(std::size_t j=0;j<next.size();++j)if(next[j].key.starts_with(prefix)) {
                            if((!right_dir&&next[j].action==SyncAction::CopyLeftToRight)||
                               (!left_dir&&next[j].action==SyncAction::CopyRightToLeft)) {
                                next[j].skip=true;next[j].action=SyncAction::Unchanged;
                            }
                        }
                    }
                }
            }
            for(std::size_t i=next.size();i-->0;) {
                const bool keeps_right=(next[i].skip&&reviewed[i].right.presence==SyncPresence::Present)||next[i].action==SyncAction::CopyLeftToRight;
                const bool keeps_left=(next[i].skip&&reviewed[i].left.presence==SyncPresence::Present)||next[i].action==SyncAction::CopyRightToLeft;
                if(!keeps_left&&!keeps_right)continue;
                for(auto slash=next[i].key.rfind('/');slash!=std::string::npos;slash=slash==0?std::string::npos:next[i].key.rfind('/',slash-1)) {
                    const std::string_view anc_key(next[i].key.data(),slash);
                    for(std::size_t p=0;p<i;++p)if(next[p].key==anc_key) {
                        if((keeps_right&&next[p].action==SyncAction::DeleteRight)||
                           (keeps_left&&next[p].action==SyncAction::DeleteLeft)) {
                            next[p].skip=true;next[p].action=SyncAction::Unchanged;
                        }
                        break;
                    }
                }
            }
        }
        selected=std::move(next);check_deletion_guard();approved_first=approve_first_run;
        rule_revision=std::make_shared<const int>(0);selected_rules_digest={};
        result.state=NativeSyncCoordinatorState::Executing;
    }
    bool is_directory_row(const std::string& key) const {
        return inventories[0].directories.contains(key)||inventories[1].directories.contains(key);
    }
    void prepare_ledger(std::stop_token token) {
        revalidate_inventory(token);
        if(stored_ledger_count>=request.ledger_limits.max_ledgers)fail("native_sync.ledger_capacity_review",ObservationState::Unknown,AdapterError::InventoryLimit);
        transaction=value(new_native_operation_journal_id());ledger_name=generated_name(".ck-sync-ledger-",*transaction,session->storage_root()->encoding());
        evidence.session=session->identity();evidence.expected_generation=session->snapshot().generation;evidence.artifacts=catalog;
        // Frozen exact records, side identities/digests and directional rules
        // are durable evidence. Labels remain indices; never parsed addresses.
        for(const auto& s:selected) {
            auto it=paths.find(s.key);if(it==paths.end())fail("native_sync.selection_native_record",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            NativeSyncPathRecord record;record.opaque_key=s.key;record.components=it->second;record.action=s.action;record.skipped=s.skip;
            record.left=status(inventories[0],s.key);record.right=status(inventories[1],s.key);
            for(unsigned side=0;side<2;++side) {
                auto file=inventories[side].files.find(s.key);
                if(file!=inventories[side].files.end()) {
                    auto id=NativeDurableIdentity::from_live(*file->second.metadata.basic.identity.value());
                    if(!id)fail("native_sync.plan_file_identity",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
                    (side?record.right_object:record.left_object)=*id;
                    continue;
                }
                auto dir=inventories[side].directories.find(s.key);
                if(dir!=inventories[side].directories.end()) {
                    auto id=NativeDurableIdentity::from_live(*dir->second.metadata.identity.value());
                    if(!id)fail("native_sync.plan_directory_identity",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
                    (side?record.right_object:record.left_object)=*id;
                }
            }
            evidence.paths.push_back(std::move(record));
        }
        for(auto& s:selected)if(!s.skip&&(is_copy(s.action)||is_delete(s.action))) {
            const bool side=destination_right(s.action);const auto& dest=inventories[side?1:0];auto it=dest.files.find(s.key);
            if(it==dest.files.end())continue;
            auto artifact_name=generated_name(".ck-sync-retained-",value(new_native_operation_journal_id()),it->second.components.back().encoding());
            auto native_lookup=value(dest.root->lookup_child(artifact_name,ChildLookupMode::NativeDefault));
            if(native_lookup.state()!=ChildLookupState::Missing||!native_lookup.missing_witness())fail("native_sync.artifact_name_collision");
            auto parent=NativeDurableIdentity::from_live(*dest.root_metadata.identity.value());
            auto object=NativeDurableIdentity::from_live(*it->second.metadata.basic.identity.value());
            if(!parent||!object)fail("native_sync.artifact_identity",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
            s.artifact=NativeSyncArtifact{side,{artifact_name},*parent,*object,it->second.status};evidence.artifacts.push_back(*s.artifact);
        }
        execution_order.clear();
        if(!request.recursive_trees) {
            for(std::size_t i=0;i<selected.size();++i)execution_order.push_back(i);
        } else {
            std::vector<std::size_t> dir_creates,file_ops,dir_deletes;
            for(std::size_t i=0;i<selected.size();++i) {
                const auto& s=selected[i];
                if(s.skip||s.action==SyncAction::Unchanged)continue;
                if(is_directory_row(s.key)) {
                    if(is_delete(s.action))dir_deletes.push_back(i);
                    else dir_creates.push_back(i);
                } else file_ops.push_back(i);
            }
            std::sort(dir_creates.begin(),dir_creates.end(),[&](std::size_t a,std::size_t b){
                const auto da=paths.at(selected[a].key).size(),db=paths.at(selected[b].key).size();
                return da!=db?da<db:a<b;
            });
            std::sort(dir_deletes.begin(),dir_deletes.end(),[&](std::size_t a,std::size_t b){
                const auto da=paths.at(selected[a].key).size(),db=paths.at(selected[b].key).size();
                return da!=db?da>db:a<b;
            });
            execution_order.insert(execution_order.end(),dir_creates.begin(),dir_creates.end());
            execution_order.insert(execution_order.end(),file_ops.begin(),file_ops.end());
            execution_order.insert(execution_order.end(),dir_deletes.begin(),dir_deletes.end());
        }
        const auto encode_fn=[&](const NativeSyncLedgerEvidence& ev){
            return request.recursive_trees
                ? encode_native_sync_hierarchy_ledger(ev,request.ledger_limits)
                : encode_native_sync_ledger(ev,request.ledger_limits);
        };
        // One opaque receipt binds this complete immutable plan/rules record
        // to the session generation/policy and exclusive durable ledger ID.
        Sha256 receipt;receipt.update(transaction->bytes);receipt.update(selected_rules_digest);receipt.update(value(encode_fn(evidence)));evidence.reviewed_plan=receipt.digest();
        // Preflight the entire predicted ledger's bounded wire size before
        // data mutation. Prediction is for allocation/capacity ONLY; it never
        // supplies convergence authority or replaces final native verification.
        std::vector<SyncBaselineUpdate> predicted;
        for(const auto& record:evidence.paths) {
            SyncEntryStatus expected=record.left;
            if(record.action==SyncAction::CopyRightToLeft)expected=record.right;
            else if(is_delete(record.action))expected=absent();
            predicted.push_back({{record.opaque_key,record.skipped?record.left:expected,record.skipped?record.right:expected},
                record.skipped?SyncBaselineUpdateState::Pending:SyncBaselineUpdateState::ConfirmedEqual});
        }
        auto proposal=evidence;proposal.proposed_baseline=value(advance_sync_baseline(session->snapshot().baseline?&*session->snapshot().baseline:nullptr,predicted,session->identity().policy,request.proof_limits.baseline)).baseline;
        auto sizing=value(OperationJournal::create(FileOperation::Copy,*transaction,{1,16,request.ledger_limits.max_total_wire_bytes}));
        std::size_t wire_size=0;
        for(auto phase:{OperationJournalState::Planned,OperationJournalState::Prepared,OperationJournalState::Copied,OperationJournalState::Verified,
            OperationJournalState::CommitIntended,OperationJournalState::DestinationCommitted,OperationJournalState::Complete}) {
            auto payload=value(encode_fn(phase==OperationJournalState::Planned||phase==OperationJournalState::Prepared?evidence:proposal));
            OperationJournalRecord record{sizing->records().size()+1,0,phase,std::move(payload)};
            auto frame=value(encode_operation_journal_frame(*sizing,record,{request.ledger_limits.max_total_wire_bytes}));
            if(stored_ledger_bytes>request.ledger_limits.max_total_wire_bytes||wire_size>request.ledger_limits.max_total_wire_bytes-stored_ledger_bytes||
                frame.size()>request.ledger_limits.max_total_wire_bytes-stored_ledger_bytes-wire_size)
                fail("native_sync.ledger_wire_capacity_review",ObservationState::Unknown,AdapterError::InventoryLimit);
            wire_size+=frame.size();require(sizing->append(std::move(record)));
        }
        ledger=value(request.recursive_trees
            ? NativeSyncLedger::create_hierarchy(session->storage_root(),*ledger_name,*transaction,evidence,request.ledger_limits)
            : NativeSyncLedger::create(session->storage_root(),*ledger_name,*transaction,evidence,request.ledger_limits));
        require(ledger->append(OperationJournalState::Prepared,evidence));
    }
    Observation<bool> source_guard(const NativeSyncFileProof& proof,std::stop_token token={}) {
        return attempt<bool>([&]{require(session->revalidate());auto fresh=value(proof.held->refresh());
            if(!fresh->continues(*proof.held)||!native_sync_same_version(proof.metadata.basic,fresh->metadata()))fail("native_sync.reviewed_source_changed");
            require(proof.held->verify_metadata_source(proof.metadata,token));return true;});
    }
    void start_retention(Selected& s,std::stop_token token) {
        const bool side=destination_right(s.action);auto& dest=inventories[side?1:0];auto& old=dest.files.at(s.key);
        auto parent_addr=side?request.right:request.left;
        for(std::size_t i=0;i+1<old.components.size();++i)parent_addr=value(parent_addr.child_address(old.components[i]));
        const auto key=s.key;
        RetainedTargetRequest r{old.held,s.artifact->components.back(),old.status.content_digest,request.coordinator.value_or(request.left),value(new_native_operation_journal_id()),
            parent_addr,[this,side,key,token]{
                const auto& current_dest=inventories[side?1:0];
                auto it=current_dest.files.find(key);
                if(it==current_dest.files.end())return Observation<bool>::unavailable(ObservationState::Changed,
                    {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::PlanDecisionStale),"native_sync.retained_target_missing"});
                return source_guard(it->second,token);
            },request.proof_limits.chunk_bytes};
        r.prepared_journal_root=session->storage_root();
        r.allow_held_posix_namespace=request.allow_held_posix_namespace;
        r.retained_destination=dest.root;
        retained=value(RetainedTarget::create(std::move(r)));stop(token);
    }
    void start_copy(Selected& s,std::stop_token token) {
        const bool side=destination_right(s.action);auto& source=inventories[side?0:1].files.at(s.key);
        if(!source.native_source)fail("native_sync.native_source_missing",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
        auto& dest=inventories[side?1:0];auto policy=value(RegularMetadataPreservation::create_with_policy(source.held,false,request.metadata,token));
        if(!policy->captured_metadata()||value(native_sync_metadata_digest(*source.native_source,*policy->captured_metadata(),token))!=source.status.required_metadata_digest||
            !native_sync_same_version(source.metadata.basic,policy->captured_metadata()->basic))fail("native_sync.metadata_review_changed");
        std::shared_ptr<const DirectoryCursor> dest_parent=dest.root;
        ObjectIdentity dest_parent_id=*dest.root_metadata.identity.value();
        auto dest_addr=side?request.right:request.left;
        if(source.components.size()>1) {
            const auto parent_key=native_sync_key(std::span(source.components).first(source.components.size()-1));
            auto dit=dest.directories.find(parent_key);
            if(dit==dest.directories.end())fail("native_sync.destination_parent_missing",ObservationState::Changed,AdapterError::PlanDecisionStale);
            dest_parent=dit->second.cursor;
            dest_parent_id=*dit->second.metadata.identity.value();
            for(std::size_t i=0;i+1<source.components.size();++i)dest_addr=value(dest_addr.child_address(source.components[i]));
        }
        auto id=value(new_native_operation_journal_id());auto name=generated_name(".ck-sync-copy-",id,session->storage_root()->encoding());
        auto f=value(open_prepared_operation_journal_file(*session->storage_root(),name,true));auto j=value(OperationJournal::create(FileOperation::Copy,id));
        require(append_operation_journal_file(*f,*j,{1,0,OperationJournalState::Planned,{}}));
        const auto key=s.key;
        NativeOperationCopyRequest r{
            .journal=j,.journal_file=std::shared_ptr<OperationJournalFile>(std::move(f)),.item=0,
            .source_parent=source.held->parent(),.source_parent_identity=*source.held->parent_identity().value(),
            .source_name=source.components.back(),.source_identity=*source.metadata.basic.identity.value(),
            .destination=dest_parent,.destination_identity=dest_parent_id,
            .destination_address=dest_addr,.staging_name=generated_name(".ck-sync-stage-",id,source.components.back().encoding()),
            .destination_name=source.components.back(),.copy_limits={request.proof_limits.chunk_bytes,request.proof_limits.max_file_bytes,1024},
            .prepare_metadata={},.operation=FileOperation::Copy,.verify_metadata_before_publication={}};
        r.reviewed_content_digest=source.status.content_digest;
        r.prepare_metadata=[policy](OpenedEntry& stage,std::stop_token t){return policy->prepare(stage,t);};
        r.verify_metadata_before_publication=[this,policy,side,key](OpenedEntry& stage,std::stop_token t){
            return attempt<bool>([&]{
                const auto& current_src=inventories[side?0:1];
                auto it=current_src.files.find(key);
                if(it==current_src.files.end())fail("native_sync.source_missing");
                require(source_guard(it->second,t));
                require(policy->verify(stage,t));
                return true;
            });};
        if(s.artifact)r.prepare_destination_before_publication=[this](std::stop_token t){
            return attempt<bool>([&]{require(retained->retain(t));mutated=true;return true;});};
        copy=value(NativeOperationCopyJob::create(std::move(r)));
    }
    void execute_directory(Selected& s,std::stop_token token) {
        revalidate_inventory(token);
        const bool side=destination_right(s.action);
        auto& dest=inventories[side?1:0];
        if(is_copy(s.action)) {
            const auto& src_dir=inventories[side?0:1].directories.at(s.key);
            if(!dest.directories.contains(s.key)) {
                std::shared_ptr<const DirectoryCursor> dest_parent=dest.root;
                if(src_dir.components.size()>1) {
                    const auto parent_key=native_sync_key(std::span(src_dir.components).first(src_dir.components.size()-1));
                    auto dit=dest.directories.find(parent_key);
                    if(dit==dest.directories.end())fail("native_sync.destination_parent_missing",ObservationState::Changed,AdapterError::PlanDecisionStale);
                    dest_parent=dit->second.cursor;
                }
                auto created=value(dest_parent->create_child_directory(src_dir.components.back()));
                mutated=true;
#ifndef _WIN32
                if(src_dir.metadata.posix_permissions.value()) {
                    const auto wanted=0700U|(*src_dir.metadata.posix_permissions.value()&0777U);
                    auto held=value(HeldChild::observe(dest_parent,src_dir.components.back(),token));
                    auto writer=held->open_directory_metadata_target(request.metadata);
                    if(writer.value()) {
                        BasicMetadata basic=(*writer.value())->inspect_basic().value()?*(*writer.value())->inspect_basic().value():src_dir.metadata;
                        basic.posix_permissions=Observation<std::uint32_t>::available(wanted);
                        (void)(*writer.value())->apply_replay_basic(basic,request.metadata);
                        require((*writer.value())->finish_content_writes());
                    }
                }
#endif
                (void)created;
            }
            accept_transition(s,token);
            return;
        }
        if(is_delete(s.action)) {
            auto dit=dest.directories.find(s.key);
            if(dit==dest.directories.end())fail("native_sync.directory_delete_missing",ObservationState::Changed,AdapterError::PlanDecisionStale);
            auto parent=dit->second.held->parent();
            const NativeName leaf=dit->second.components.back();
            const ObjectIdentity expected_id=*dit->second.metadata.identity.value();
            auto strict=parent->qualify_identity_bound_rename();
            if(!strict.value()&&request.allow_held_posix_namespace&&strict.state()==ObservationState::Unsupported)
                strict=qualify_held_posix_namespace(*parent);
            require(std::move(strict));
            dit->second.cursor.reset();
            dit->second.held.reset();
            require(parent->retire_child(leaf,expected_id));
            mutated=true;
            accept_transition(s,token);
            return;
        }
        fail("native_sync.directory_action",ObservationState::Failed,AdapterError::PlanInvalid);
    }
    void accept_transition(Selected& s,std::stop_token token) {
        auto after=scan(token);auto next_catalog=catalog;if(s.artifact)next_catalog.push_back(*s.artifact);protect(after,next_catalog);
        const unsigned dest=destination_right(s.action)?1:0;
        for(unsigned side=0;side<2;++side) {
            auto& old=inventories[side];auto& fresh=after[side];
            for(const auto& [key,proof]:old.files) {
                if(side==dest&&key==s.key)continue;
                auto it=fresh.files.find(key);if(it==fresh.files.end()||it->second.status!=proof.status||!native_sync_same_version(proof.metadata.basic,it->second.metadata.basic))
                    fail("native_sync.unrelated_file_changed",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            }
            for(const auto& [key,proof]:fresh.files) {
                (void)proof;if(side==dest&&key==s.key)continue;
                if(!old.files.contains(key))fail("native_sync.unrelated_file_appeared",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            }
            for(const auto& [key,dproof]:old.directories) {
                if(side==dest&&key==s.key)continue;
                auto it=fresh.directories.find(key);
                if(it==fresh.directories.end()||compare_identity(*dproof.metadata.identity.value(),*it->second.metadata.identity.value())!=IdentityComparison::Same)
                    fail("native_sync.unrelated_directory_changed",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            }
            for(const auto& [key,dproof]:fresh.directories) {
                (void)dproof;if(side==dest&&key==s.key)continue;
                if(!old.directories.contains(key))fail("native_sync.unrelated_directory_appeared",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            }
        }
        auto expected=is_delete(s.action)?absent():
            (inventories[1-dest].files.contains(s.key)?inventories[1-dest].files.at(s.key).status:inventories[1-dest].directories.at(s.key).status);
        if(status(after[dest],s.key)!=expected||!pair_equal(after,s.key))fail("native_sync.publication_not_converged",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        inventories=std::move(after);catalog=std::move(next_catalog);++result.completed_operations;++current;copy.reset();retained.reset();
    }
    void execute(std::stop_token token) {
        stop(token);if(!ledger) {prepare_ledger(token);return;}
        while(current<execution_order.size()&&(selected[execution_order[current]].skip||selected[execution_order[current]].action==SyncAction::Unchanged))++current;
        if(current==execution_order.size()) {result.state=NativeSyncCoordinatorState::Verifying;return;}
        auto& s=selected[execution_order[current]];
        if(copy) {
            auto state=copy->advance(token);
            if(state==OperationExecutionState::Complete) {mutated=true;accept_transition(s,token);return;}
            if(state==OperationExecutionState::Failed||state==OperationExecutionState::Cancelled||state==OperationExecutionState::NeedsReconciliation||state==OperationExecutionState::RetainedSource) {
                if(copy->result().failure)throw Failure{*copy->result().failure};fail("native_sync.copy_incomplete",ObservationState::Changed,AdapterError::ProviderReviewRequired);}
            return;
        }
        if(retained&&retained->state()==RetainedTargetState::Verifying) {
            auto state=retained->advance(token);if(state!=RetainedTargetState::Ready&&state!=RetainedTargetState::Verifying) {
                if(retained->failure())throw Failure{*retained->failure()};fail("native_sync.retention_incomplete",ObservationState::Changed,AdapterError::ProviderReviewRequired);}
            return;
        }
        if(is_directory_row(s.key)) {execute_directory(s,token);return;}
        if(s.artifact&&!retained) {revalidate_inventory(token);start_retention(s,token);return;}
        if(is_delete(s.action)) {require(retained->retain(token));mutated=true;accept_transition(s,token);return;}
        revalidate_inventory(token);start_copy(s,token);
    }
    void verify(std::stop_token token) {
        revalidate_inventory(token);
        // A second complete native pass binds convergence to fresh content,
        // metadata, membership, and parent versions just before baseline intent.
        auto fresh=scan(token);protect(fresh,catalog);
        for(unsigned side=0;side<2;++side)require(compare_native_sync_inventories(inventories[side],fresh[side]));
        inventories=std::move(fresh);std::vector<SyncBaselineUpdate> updates;
        for(const auto& s:selected) {
            auto left=status(inventories[0],s.key),right=status(inventories[1],s.key);
            if(!s.skip&&!pair_equal(inventories,s.key))fail("native_sync.final_convergence",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            updates.push_back({{s.key,left,right},s.skip?SyncBaselineUpdateState::Pending:SyncBaselineUpdateState::ConfirmedEqual});
        }
        auto advanced=value(advance_sync_baseline(session->snapshot().baseline?&*session->snapshot().baseline:nullptr,updates,session->identity().policy,request.proof_limits.baseline));
        result.pending_keys=advanced.pending_paths;evidence.proposed_baseline=std::move(advanced.baseline);evidence.artifacts=catalog;
        require(ledger->append(OperationJournalState::Copied,evidence));require(ledger->append(OperationJournalState::Verified,evidence));
        stop(token);require(ledger->append(OperationJournalState::CommitIntended,evidence));
        // Fallible explicit journal close precedes baseline CAS. A failure here
        // leaves old baseline and durable evidence for explicit reconciliation.
        event(NativeSyncCoordinatorEvent::BeforeLedgerClose);require(ledger->finish_io());ledger.reset();result.state=NativeSyncCoordinatorState::Committing;
    }
    void commit(std::stop_token token) {
        // Coordinator intent is durable. Cancellation now preserves an intent
        // for idempotent recovery; no incomplete/cancelled execution is blessed.
        stop(token);revalidate_inventory(token);std::vector<SyncBaselineUpdate> updates;
        for(const auto& s:selected) {
            auto left=status(inventories[0],s.key),right=status(inventories[1],s.key);
            if(!s.skip&&!pair_equal(inventories,s.key))fail("native_sync.commit_convergence",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            updates.push_back({{s.key,left,right},s.skip?SyncBaselineUpdateState::Pending:SyncBaselineUpdateState::ConfirmedEqual});
        }
        event(NativeSyncCoordinatorEvent::BeforeBaselineCommit);
        // A deterministic boundary hook can expose edits after the previous
        // scan. Observe again before CAS; this still is not cross-root atomic
        // content/metadata exclusion against arbitrary later external writes.
        revalidate_inventory(token);
        auto committed=value(session->commit(evidence.expected_generation,updates,approved_first,[token]{return token.stop_requested();}));
        event(NativeSyncCoordinatorEvent::AfterBaselineCommit);
        if(!evidence.proposed_baseline||committed.baseline!=*evidence.proposed_baseline)fail("native_sync.baseline_result",ObservationState::Unknown,AdapterError::InvalidNativeResult);
        auto reopened=value(NativeSyncLedger::reopen(session->storage_root(),*ledger_name,*transaction,request.ledger_limits));
        require(reopened->append(OperationJournalState::DestinationCommitted,evidence));require(reopened->append(OperationJournalState::Complete,evidence));require(reopened->finish_io());
        result.generation=session->snapshot().generation;result.state=NativeSyncCoordinatorState::Complete;
    }
};
NativeSyncCoordinator::NativeSyncCoordinator(std::unique_ptr<State> state):state_(std::move(state)) {}
NativeSyncCoordinator::~NativeSyncCoordinator()=default;
Observation<bool> NativeSyncCoordinator::finish_io() {
    state_->close_native();
    // A pending first writer revokes authority immediately but must not hide
    // its exact native error once publication finishes. Backend/request keeps
    // this borrowed root alive through worker-side coordinator destruction.
    detail::PreparedJournalConsumerFailure first;
    if(state_->finish_root&&detail::read_prepared_journal_consumer_failure(*state_->finish_root,first)&&
        (!state_->finish_failed||state_->finish_failure.pending)) {state_->finish_failure=first;state_->finish_failed=true;}
    if(state_->finish_failed) {
        const auto& f=state_->finish_failure;
        // Native teardown and the fixed failure latch are already complete.
        // A reporting allocation failure cannot resume or promote execution.
        UnavailableObservation detail{f.state,{f.domain,f.code,f.operation.data()}};
        if(!state_->result.failure||state_->reported_finish_pending){state_->result.failure=detail;state_->reported_finish_pending=f.pending;}
        return Observation<bool>::unavailable(detail.state,std::move(detail.error));
    }
    return Observation<bool>::available(true);
}
Observation<NativeSyncCoordinator::Pointer> NativeSyncCoordinator::open(NativeSyncCoordinatorRequest request,std::stop_token token) {
    return sync_detail::attempt<Pointer>([&]{auto state=std::make_unique<State>(std::move(request));state->initialize(token);return Pointer(new NativeSyncCoordinator(std::move(state)));});
}
const SyncSessionIdentity& NativeSyncCoordinator::identity() const noexcept {return state_->session->identity();}
const std::vector<NativeSyncReviewedRow>& NativeSyncCoordinator::rows() const noexcept {return state_->reviewed;}
const NativeSyncCoordinatorResult& NativeSyncCoordinator::result() const noexcept {return state_->result;}
const std::vector<NativeSyncProtectedEvidence>& NativeSyncCoordinator::protected_artifacts() const noexcept {return state_->protected_evidence;}
const std::vector<NativeName>& NativeSyncCoordinator::components(std::size_t row) const {return state_->paths.at(state_->reviewed.at(row).exact_key);}
Observation<bool> NativeSyncCoordinator::approve(std::span<const NativeSyncDecision> decisions,bool first,std::stop_token stop) {
    return sync_detail::attempt<bool>([&]{state_->require_open();state_->approve(decisions,first,stop);return true;});
}
const std::vector<NativeSyncRuleRow>& NativeSyncRuleAssessment::rows() const noexcept {return state_->rows;}
bool NativeSyncRuleAssessment::consumed() const noexcept {return state_->consumed;}
void NativeSyncCoordinator::invalidate_rule_receipts() noexcept {state_->rule_revision.reset();}
Observation<NativeSyncRawFacts> NativeSyncCoordinator::facts(std::size_t row) {
    return sync_detail::attempt<NativeSyncRawFacts>([&]{state_->build_facts();if(row>=state_->raw_facts.size())sync_detail::fail("native_sync.fact_index",ObservationState::Failed,AdapterError::PlanInvalid);return state_->raw_facts[row];});
}
Observation<ComparisonPlanIdentity> NativeSyncCoordinator::rule_plan_identity() {
    return sync_detail::attempt<ComparisonPlanIdentity>([&]{state_->build_facts();return state_->fact_plan->identity();});
}
Observation<NativeSyncRuleAssessment::Pointer> NativeSyncCoordinator::assess_rules(std::span<const ConflictRule> rules,std::uint64_t quantum,std::stop_token stop) {
    return sync_detail::attempt<NativeSyncRuleAssessment::Pointer>([&]{return NativeSyncRuleAssessment::Pointer(new NativeSyncRuleAssessment(state_->assess(rules,quantum,stop)));});
}
Observation<bool> NativeSyncCoordinator::approve_rules(const NativeSyncRuleAssessment& receipt,bool first,std::stop_token stop) {
    return sync_detail::attempt<bool>([&]{auto& s=*state_;auto& proof=*receipt.state_;s.require_open();
        if(proof.consumed||proof.owner!=s.rule_owner||proof.revision!=s.rule_revision||proof.plan!=s.fact_plan->identity()||
            proof.generation!=s.session->snapshot().generation||!bound_to(proof.identity,s.session->identity()))
            sync_detail::fail("native_sync.foreign_stale_rule_receipt");
        std::vector<NativeSyncDecision> decisions;
        for(const auto& row:proof.rows) {
            if(row.decision.state!=ConflictRuleState::Apply&&row.decision.state!=ConflictRuleState::NoMatch)
                sync_detail::fail("native_sync.unresolved_rule_choice",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            decisions.push_back(row.selected);
        }
        s.approve(decisions,first,stop);s.selected_rules_digest=proof.rules_digest;proof.consumed=true;return true;
    });
}
NativeSyncCoordinatorState NativeSyncCoordinator::advance(std::stop_token token) {
    auto& s=*state_;
    if(s.finished)return s.result.state;
    try {
        if(s.result.state==NativeSyncCoordinatorState::Executing)s.execute(token);
        else if(s.result.state==NativeSyncCoordinatorState::Verifying)s.verify(token);
        else if(s.result.state==NativeSyncCoordinatorState::Committing)s.commit(token);
    } catch(const sync_detail::Failure& e) {
        try{s.result.failure=e.detail;}catch(...){s.close_native();throw;}
        s.result.state=token.stop_requested()&&!s.mutated&&!s.ledger_name?NativeSyncCoordinatorState::Cancelled:NativeSyncCoordinatorState::NeedsReview;
    } catch(...) {
        // No retry after an exception from a partially executed native phase.
        // The C boundary reports OOM/exception; durable journals remain intact.
        s.result.state=NativeSyncCoordinatorState::NeedsReview;
        s.close_native(); // no allocating error construction while unwinding
        throw;
    }
    return s.result.state;
}
Observation<NativeHierarchyContext::Pointer> NativeHierarchyContext::borrow(NativeSyncCoordinator& worker,NativeHierarchyLimits limits,std::stop_token stop) {
    try {
    if(!worker.state_||worker.state_->finished||!worker.state_->session)return Observation<Pointer>::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::PlanDecisionStale),"hierarchy.worker_closed"});
    // Read-only opt-in; no re-lock, rule evaluation, approval or mutation.
    return borrow(*worker.state_->session,limits,stop);
    }catch(...){if(worker.state_)worker.state_->close_native();throw;}
}
} // namespace ck::files
