#include "native_sync_hierarchy_binding.hpp"
// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_resolution.hpp"
#include "directory_name_rules.hpp"
#include "native_sync_internal.hpp"
#include "native_operation_journal_id.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "native_filesystem.hpp"
#include "retained_target.hpp"
#include "regular_metadata_preservation.hpp"
#include "sha256.hpp"
#include "metadata_capture_job.hpp"
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
// Native observation already authenticates the complete catalog and its readers.
// Never infer complete DATA coverage from a main-stream length alone.
std::uint64_t admitted_data_bytes(const NativeSyncFileProof& proof) {
    const auto& metadata=proof.metadata;
    if(!metadata.basic.logical_size.value())
        fail("resolution.logical_size",ObservationState::Unsupported,AdapterError::UnsupportedQuery);
    const auto main=*metadata.basic.logical_size.value();
#ifdef _WIN32
    if(metadata.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo||
       proof.channel_facts.coverage!=metadata.channel_coverage||
       !proof.channel_facts.all_stream_logical_bytes||
       proof.channel_facts.named_stream_count!=metadata.channels.size())
        fail("resolution.named_stream_accounting_unqualified",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    require(verify_native_metadata_replay_channels(metadata));
    auto logical=main;
    for(const auto& channel:metadata.channels) {
        if(channel.logical_size>std::numeric_limits<std::uint64_t>::max()-logical)
            fail("resolution.logical_size_overflow",ObservationState::Unknown,AdapterError::InventoryLimit);
        logical+=channel.logical_size;
    }
    if(logical!=*proof.channel_facts.all_stream_logical_bytes)
        fail("resolution.channel_accounting_changed");
    return logical;
#else
    if(!metadata.channels.empty())fail("resolution.named_stream_accounting_unqualified",ObservationState::Unsupported,AdapterError::UnsupportedQuery);
    return main;
#endif
}
#ifdef _WIN32
// A conservative subset with invariant native upcasing. Arbitrary Unicode
// case tables are volume-specific; locale/ordinal folding is not authority.
// Excluding '~' also excludes generated 8.3 spellings of future long names.
// Existing short aliases are independently covered by native missing witnesses.
std::u16string windows_name_key(const NativeName& name) {
    const auto* units=name.windows_units();
    if(!name.is_valid()||!units)fail("resolution.windows_name",ObservationState::Failed,AdapterError::InvalidIdentifier);
    auto key=*units;
    for(auto& u:key) {
        if(u>=u'a'&&u<=u'z')u-=u'a'-u'A';
        else if(!((u>=u'A'&&u<=u'Z')||(u>=u'0'&&u<=u'9')||u==u'.'||u==u'_'||u==u'-'||(u>=0xd800&&u<=0xdfff)))
            fail("resolution.windows_name_rules_unqualified",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    }
    // Treat DOS trailing-dot spellings as potential aliases even where the
    // counted native namespace can distinguish them; never reserve both.
    while(!key.empty()&&key.back()==u'.')key.pop_back();
    if(key.empty())fail("resolution.windows_name_rules_unqualified",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    return key;
}
#endif

}
struct NativeSyncResolutionReceiptState {
    std::shared_ptr<const int> owner,revision;
    SyncSessionIdentity identity;
    std::uint64_t generation=0;
    OperationJournalId transaction;
    NativeName ledger_name;
    NativeSyncLedgerEvidence evidence;
    std::vector<NativeSyncResolutionOperation> operations;
    std::vector<NativeSyncResolutionStreamFactsV1> stream_facts;
    SyncDigest digest{};
    bool consumed=false;
    NativeSyncResolutionReceiptState(NativeName name):ledger_name(std::move(name)){}
};
struct NativeSyncResolution::State final : MetadataCaptureFailureLatch {
    NativeSyncCoordinatorRequest request;
    NativeSyncResolutionLimits limits;
    NativeFileSystem filesystem;
    std::unique_ptr<SyncSession> session;
    std::array<NativeSyncInventory,2> inventories;
    std::vector<NativeSyncReviewedRow> rows;
    std::map<std::string,std::vector<NativeName>> paths;
    std::vector<NativeSyncProtectedEvidence> originals;
    std::vector<NativeSyncArtifact> catalog;
    std::shared_ptr<const int> owner=std::make_shared<const int>(0),revision=std::make_shared<const int>(0);
    std::shared_ptr<NativeSyncResolutionReceiptState> approved;
    std::unique_ptr<NativeSyncLedger> ledger;
    NativeOperationCopyJob::Pointer copy;
    OpenedEntry* active_stage=nullptr; // Borrowed only while copy owns its State.
    std::shared_ptr<OperationJournalFile> active_copy_journal;
    RegularMetadataPreservation::Pointer copy_metadata;
    std::optional<NativeDurableIdentity> published_object;
    bool durable_intent=false;
    NativeSyncCoordinatorResult result;
    std::size_t current=0,stored_bytes=0,stored_count=0;
    std::uint64_t proof_bytes=0;
    bool finished=false,approve_first=false;
    bool close_failed=false;
    PreparedJournalRoot* finish_root=nullptr;
    detail::PreparedJournalConsumerFailure close_failure;
    State(NativeSyncCoordinatorRequest r,NativeSyncResolutionLimits l):request(std::move(r)),limits(l){}
    ~State(){detail::MetadataCaptureCleanupScope scope(this);close_native();}
    void record_first(MetadataCaptureCleanupError e) const noexcept override {
        auto* self=const_cast<State*>(this);
        if(self->session){auto root=self->session->storage_root();self->finish_root=root.get();}
        else self->finish_root=self->request.prepared_journal_root.get();
        self->remember_close(e.state,e.domain,e.code,e.operation);
    }
    void require_clean() {
        detail::PreparedJournalConsumerFailure failure;
        // Session finish revokes storage_root(), while this worker retains its
        // immutable result and first close error for later API calls.
        const auto root=session?session->storage_root():PreparedJournalRoot::Pointer{};
        if(root&&detail::read_prepared_journal_consumer_failure(*root,failure))
            remember_close(failure.state,failure.domain,failure.code,failure.operation.data());
        if(close_failed)throw Failure{{close_failure.state,{close_failure.domain,close_failure.code,close_failure.operation.data()}}};
    }
    void drain(std::array<NativeSyncInventory,2>& data) noexcept {
        detail::MetadataCaptureCleanupScope scope(this);
        // Each query is an independently opened readonly native entry, not a
        // borrowed session root. Consume its own handle once on every platform.
        for(auto& root:data)for(auto& [key,proof]:root.files)
            detail::finish_native_metadata_capture(proof.native_source.get(),proof.metadata);
    }
    void discard_observations(std::array<NativeSyncInventory,2>& data) noexcept {
        detail::MetadataCaptureCleanupScope scope(this);
        drain(data);
        // HeldChild owns a separate child entry and retains its parent cursor;
        // these destructors must also report close errors before any CAS. The
        // session's distinct root/lock handles remain alive in session.
        for(auto& root:data){root.files.clear();root.root.reset();}
    }
    void replace(std::array<NativeSyncInventory,2>& next) {
        discard_observations(inventories);require_clean();inventories=std::move(next);require_clean();
    }
    void active(){require_clean();if(finished)fail("resolution.finished",ObservationState::Changed,AdapterError::InvalidAccess);}
    void event(NativeSyncCoordinatorEvent e){if(request.before_event&&!request.before_event(e))fail("resolution.injected_event",ObservationState::Failed,AdapterError::InterruptedRead);}
    void charge(std::uint64_t& used,std::uint64_t n,std::uint64_t bound,const char* op){if(used>bound||n>bound-used)fail(op,ObservationState::Unknown,AdapterError::InventoryLimit);used+=n;}
    std::shared_ptr<const DirectoryCursor> cursor(bool right) {
        require(session->revalidate());
        auto root=std::shared_ptr<DirectoryCursor>(value(filesystem.open_native_directory(right?request.right:request.left)));
        auto metadata=value(root->inspect_basic());if(!metadata.identity.value())fail("resolution.root_identity",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
        const auto& id=*metadata.identity.value();auto handle=session->root_handle(right);
#ifdef _WIN32
        FILE_ID_INFO raw{};if(!GetFileInformationByHandleEx(reinterpret_cast<HANDLE>(handle),FileIdInfo,&raw,sizeof(raw)))fail("resolution.held_root_identity");
        NativeIdentifier object;std::memcpy(object.bytes.data(),raw.FileId.Identifier,16);
        if(id.scheme!=IdentityScheme::WindowsFileId128||id.volume!=NativeIdentifier::from_u64(raw.VolumeSerialNumber)||id.object!=object)fail("resolution.root_mismatch");
#else
        struct stat raw{};if(fstat(static_cast<int>(handle),&raw))fail("resolution.held_root_identity");
        if(id.scheme!=IdentityScheme::PosixDeviceInode||id.volume!=NativeIdentifier::from_u64(raw.st_dev)||id.object!=NativeIdentifier::from_u64(raw.st_ino))fail("resolution.root_mismatch");
#endif
        require(session->revalidate());return root;
    }
    std::array<NativeSyncInventory,2> scan(std::stop_token token) {
        active();NativeSyncProofBudget budget;std::array<NativeSyncInventory,2> out;
        // Each native observer charges payload before hashing. A per-pass cap
        // derived from the remaining aggregate cap prevents overspending here.
        auto bounded=request.proof_limits;
        if(proof_bytes>=limits.max_proof_bytes)fail("resolution.proof_budget",ObservationState::Unknown,AdapterError::InventoryLimit);
        bounded.max_total_bytes=std::min(bounded.max_total_bytes,limits.max_proof_bytes-proof_bytes);
        try {
            for(unsigned side=0;side<2;++side){auto inventory=value(observe_native_sync_root(cursor(side!=0),request.metadata,bounded,budget,token));out[side]=std::move(*inventory);}
        }catch(...){proof_bytes+=budget.bytes;drain(out);throw;}
        proof_bytes+=budget.bytes;
        try {
        for(const auto& root:out)for(const auto& [key,proof]:root.files){(void)admitted_data_bytes(proof);auto [it,added]=paths.emplace(key,proof.components);if(!added&&it->second!=proof.components)fail("resolution.label_collision");}
        require(session->revalidate());require_clean();return out;
        }catch(...){drain(out);throw;}
    }
    void verify_catalog(const std::array<NativeSyncInventory,2>& data) {
        std::vector<NativeSyncProtectedEvidence> visible;
        for(const auto& artifact:catalog){const auto& inventory=data[artifact.right?1:0];auto it=inventory.files.find(native_sync_key(artifact.components));
            if(it==inventory.files.end()||it->second.status!=artifact.status||!it->second.metadata.basic.identity.value()||
                !inventory.root_metadata.identity.value()||!artifact.object.matches_live(*it->second.metadata.basic.identity.value())||
                !artifact.parent.matches_live(*inventory.root_metadata.identity.value()))fail("resolution.protected_original_changed",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            visible.push_back({artifact,it->second.metadata.basic});
        }
        originals=std::move(visible);
    }
    void fresh(std::stop_token token) {
        auto next=scan(token);
        try {verify_catalog(next);
            for(unsigned side=0;side<2;++side)require(compare_native_sync_inventories(inventories[side],next[side]));
            replace(next);
        }catch(...){drain(next);throw;}
    }
    const NativeSyncFileProof& file(bool side,const std::string& key){auto it=inventories[side?1:0].files.find(key);if(it==inventories[side?1:0].files.end())fail("resolution.source_missing");return it->second;}
    bool pair_equal(const NativeSyncFileProof& a,const NativeSyncFileProof& b){return a.status==b.status&&
        (request.metadata.ownership!=MetadataOwnership::CurrentCaller||native_sync_same_ownership(a.metadata,b.metadata));}
    void absent_name(const NativeSyncInventory& root,const NativeName& name) {
        auto before=value(root.root->inspect_basic());if(!native_sync_same_version(before,root.root_metadata))fail("resolution.absence_parent_changed");
        for(unsigned pass=0;pass<2;++pass){auto lookup=value(root.root->lookup_child(name,ChildLookupMode::NativeDefault));if(lookup.state()!=ChildLookupState::Missing||!lookup.missing_witness())fail("resolution.destination_not_absent",ObservationState::Changed,AdapterError::ProviderReviewRequired);}
        if(!native_sync_same_version(before,value(root.root->inspect_basic())))fail("resolution.absence_parent_changed");
    }
    void prove_names(const std::vector<NativeSyncResolutionOperation>& operations,std::stop_token token,bool all_missing) {
        std::vector<NativeName> names;
        for(const auto& op:operations)if(op.kind==NativeSyncResolutionOperationKind::PublishVersion&&op.destination_right==false)names.push_back(op.components.front());
        for(unsigned side=0;side<2;++side){
#ifdef _WIN32
            require(inventories[side].root->qualify_identity_bound_rename());
            auto distinct=[&](const NativeName& a,const NativeName& b){return windows_name_key(a)!=windows_name_key(b);};
#else
            auto rules=value(DirectoryNameRulesProbe::inspect(inventories[side].root,token));
            auto distinct=[&](const NativeName& a,const NativeName& b){return value(rules->compare(a,b)).relation==ComponentNameRelation::DistinctUnderReportedRules;};
#endif
            for(std::size_t i=0;i<names.size();++i){
#ifdef _WIN32
                (void)windows_name_key(names[i]);
#endif
                for(std::size_t j=0;j<i;++j)if(!distinct(names[i],names[j]))fail("resolution.variant_alias");
#ifndef _WIN32
                for(const auto& row:rows){auto found=inventories[side].files.find(row.exact_key);if(found==inventories[side].files.end())continue;
                    if(!distinct(names[i],found->second.components.front()))fail("resolution.original_alias");}
#else
                // Actual native absence covers all existing names, including
                // their provider-specific Unicode and 8.3 aliases. Only the
                // two future names need the conservative lexical subset.
                if(!all_missing)fail("resolution.windows_absence_proof_required",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
#endif
                if(all_missing)absent_name(inventories[side],names[i]);
            }
        }
    }
    void seal(NativeSyncLoadedLedger& loaded){auto opened=value(NativeSyncLedger::reopen(session->storage_root(),loaded.name,loaded.journal->id(),request.ledger_limits));
        if(opened->journal().state(0)==OperationJournalState::CommitIntended)require(opened->append(OperationJournalState::DestinationCommitted,loaded.evidence));
        if(opened->journal().state(0)==OperationJournalState::DestinationCommitted){require(opened->append(OperationJournalState::Complete,loaded.evidence));}
        require(opened->finish_io());}
    std::vector<SyncBaselineUpdate> updates(const NativeSyncLedgerEvidence& evidence) {
        std::vector<SyncBaselineUpdate> out;
        for(const auto& record:evidence.paths){if(record.skipped){out.push_back({{record.opaque_key,record.left,record.right},SyncBaselineUpdateState::Pending});continue;}
            const auto& left=file(false,record.opaque_key);const auto& right=file(true,record.opaque_key);
            if(!evidence.proposed_baseline)fail("resolution.expected_baseline_missing");
            const auto& desired=evidence.proposed_baseline->rows;
            auto expected_row=std::find_if(desired.begin(),desired.end(),[&](const auto& p){return p.relative_path==record.opaque_key;});
            if(expected_row==desired.end()||expected_row->left!=expected_row->right||expected_row->left.presence!=SyncPresence::Present)fail("resolution.expected_version_missing");
            const auto expected=expected_row->left;
            if(!pair_equal(left,right)||left.status!=expected||
               (record.left_object&&(!left.metadata.basic.identity.value()||!record.left_object->matches_live(*left.metadata.basic.identity.value())))||
               (record.right_object&&(!right.metadata.basic.identity.value()||!record.right_object->matches_live(*right.metadata.basic.identity.value()))))
                fail("resolution.convergence_changed",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            out.push_back({{record.opaque_key,left.status,right.status},SyncBaselineUpdateState::ConfirmedEqual});}
        return out;
    }
    void history(std::stop_token token) {
        auto loaded=value(load_native_sync_ledgers(session->storage_root(),request.ledger_limits,token));stored_count=loaded.size();
        NativeSyncLoadedLedger* pending=nullptr;
        for(auto& l:loaded){stored_bytes+=l.wire_bytes;if(!bound_to(l.evidence.session,session->identity())){
                const auto& a=l.evidence.session;const auto& b=session->identity();if(a.left_root==b.left_root||a.left_root==b.right_root||a.right_root==b.left_root||a.right_root==b.right_root)fail("resolution.history_changed",ObservationState::Changed,AdapterError::ProviderReviewRequired);continue;}
            for(const auto& p:l.evidence.paths){auto [it,added]=paths.emplace(p.opaque_key,p.components);if(!added&&it->second!=p.components)fail("resolution.history_path_conflict");}
            if(l.journal->state(0)!=OperationJournalState::Complete){if(pending)fail("resolution.multiple_intents");pending=&l;}
            else if(!l.evidence.proposed_baseline||l.evidence.expected_generation>=session->snapshot().generation||
                (l.evidence.expected_generation+1==session->snapshot().generation&&(!session->snapshot().baseline||*session->snapshot().baseline!=*l.evidence.proposed_baseline)))fail("resolution.history_baseline_mismatch");
            for(const auto& a:l.evidence.artifacts){auto found=std::find_if(catalog.begin(),catalog.end(),[&](const auto& b){return b.right==a.right&&b.components==a.components;});
                if(found==catalog.end())catalog.push_back(a);else if(found->object!=a.object||found->parent!=a.parent||found->status!=a.status)fail("resolution.catalog_conflict");}
        }
        inventories=scan(token);verify_catalog(inventories);fresh(token);
        if(!pending)return;
        auto& l=*pending;const auto phase=l.journal->state(0);
        if((phase!=OperationJournalState::CommitIntended&&phase!=OperationJournalState::DestinationCommitted)||!l.evidence.proposed_baseline)fail("resolution.unresolved_intent",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        // Stored identity/digests only protect artifacts and describe intent.
        // They never authorize replay of a publication/rename after restart.
        auto live_updates=updates(l.evidence);fresh(token);
        if(session->snapshot().generation==l.evidence.expected_generation){auto proposal=value(advance_sync_baseline(session->snapshot().baseline?&*session->snapshot().baseline:nullptr,live_updates,session->identity().policy,request.proof_limits.baseline));
            if(proposal.baseline!=*l.evidence.proposed_baseline)fail("resolution.recovery_baseline_changed");
            discard_observations(inventories);
            require_clean();stop(token);
            auto committed=value(session->commit(l.evidence.expected_generation,live_updates,session->snapshot().state==SyncSessionState::FirstRun,[token]{return token.stop_requested();}));if(committed.baseline!=proposal.baseline)fail("resolution.recovery_cas_result");
        }else if(session->snapshot().generation!=l.evidence.expected_generation+1||!session->snapshot().baseline||*session->snapshot().baseline!=*l.evidence.proposed_baseline)fail("resolution.recovery_generation");
        seal(l);
        // Recovery consumed the pre-CAS observations on every platform.
        // Reacquire fresh native evidence for the newly opened worker's rows.
        auto next=scan(token);
        try{verify_catalog(next);replace(next);}catch(...){drain(next);throw;}
    }
    void initialize(std::stop_token token) {
#if !defined(__linux__) && !defined(_WIN32)
        // Mac has no qualified strong-publication primitive.
        fail("resolution.provider_not_qualified",ObservationState::Unsupported,AdapterError::UnsupportedQuery);
#endif
        if(!request.metadata.valid()||!request.proof_limits.chunk_bytes||request.proof_limits.chunk_bytes>ContentReadLimits::hard_max_bytes||
            !request.proof_limits.max_entries||!request.proof_limits.max_total_bytes||!request.proof_limits.max_file_bytes||!request.proof_limits.max_metadata_bytes||
            !limits.max_resolutions||limits.max_resolutions>128||!limits.max_added_paths||limits.max_added_paths>256||!limits.max_protected_objects||limits.max_protected_objects>256||
            !limits.max_name_bytes||limits.max_name_bytes>1024*1024||!limits.max_transfer_bytes||!limits.max_proof_bytes)fail("resolution.invalid_limits",ObservationState::Failed,AdapterError::InvalidLimit);
        if(!request.prepared_journal_root&&!request.coordinator)fail("resolution.storage_owner",ObservationState::Failed,AdapterError::InvalidAccess);
        request.ledger_limits.baseline=request.proof_limits.baseline;
        auto backend=value(request.prepared_journal_root?open_native_sync_session_backend(request.prepared_journal_root,request.left,request.right,request.storage_faults):
            open_native_sync_session_backend(*request.coordinator,request.left,request.right,request.storage_faults));
        session=value(SyncSession::open(std::move(backend),policy_digest(request),request.proof_limits.baseline));
        if(session->snapshot().state==SyncSessionState::ReviewRequired||session->snapshot().state==SyncSessionState::HistoryChanged)fail("resolution.history_review",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        history(token);
#ifdef _WIN32
        // Qualify both actual held destination adapters before a reviewed
        // resolution can write its ledger or create private staging.
        for(const auto& inventory:inventories)require(inventory.root->qualify_identity_bound_rename());
        require_clean();
#endif
        std::set<std::string> keys;for(const auto& root:inventories)for(const auto& [key,p]:root.files){(void)p;keys.insert(key);}
        for(const auto& key:keys){auto a=inventories[0].files.find(key),b=inventories[1].files.find(key);
            const auto left=a==inventories[0].files.end()?absent():a->second.status,right=b==inventories[1].files.end()?absent():b->second.status;
            rows.push_back({key,left,right,left==right?SyncAction::Unchanged:SyncAction::Conflict,SyncReason::RequiredMetadataDifference});}
        result.generation=session->snapshot().generation;
    }
    std::shared_ptr<NativeSyncResolutionReceiptState> assess(std::span<const NativeSyncNamedResolution> choices,std::stop_token token) {
        active();if(result.state!=NativeSyncCoordinatorState::AwaitingReview||choices.empty()||choices.size()>limits.max_resolutions||choices.size()>limits.max_added_paths/2||choices.size()>limits.max_protected_objects/2)fail("resolution.choice_bound",ObservationState::Failed,AdapterError::InvalidLimit);
        fresh(token);revision=std::make_shared<const int>(0);auto id=value(new_native_operation_journal_id());auto receipt=std::make_shared<NativeSyncResolutionReceiptState>(generated_name(".ck-sync-ledger-",id,session->storage_root()->encoding()));
        receipt->owner=owner;receipt->revision=revision;receipt->identity=session->identity();receipt->generation=session->snapshot().generation;receipt->transaction=id;
        auto& e=receipt->evidence;e.session=session->identity();e.expected_generation=receipt->generation;e.artifacts=catalog;
        // Every retained baseline key keeps its separate native component
        // record. Labels are never parsed, even for an absent old entry.
        std::set<std::string> old_keys;
        for(const auto& row:rows)old_keys.insert(row.exact_key);
        if(session->snapshot().baseline)for(const auto& row:session->snapshot().baseline->rows)old_keys.insert(row.relative_path);
        for(const auto& key:old_keys){auto binding=paths.find(key);if(binding==paths.end()||binding->second.size()!=1)fail("resolution.old_native_record_missing",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            NativeSyncPathRecord record;record.opaque_key=key;record.components=binding->second;record.action=SyncAction::Blocked;record.skipped=true;
            for(unsigned side=0;side<2;++side){auto found=inventories[side].files.find(key);SyncEntryStatus status=absent();std::optional<NativeDurableIdentity> identity;
                if(found==inventories[side].files.end())absent_name(inventories[side],binding->second.front());
                else{status=found->second.status;identity=NativeDurableIdentity::from_live(*found->second.metadata.basic.identity.value());if(!identity)fail("resolution.old_identity",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);}
                if(side){record.right=status;record.right_object=identity;}else{record.left=status;record.left_object=identity;}}
            e.paths.push_back(std::move(record));}
        std::set<std::size_t> selected;std::map<std::string,SyncEntryStatus> expected_versions;std::uint64_t name_bytes=0,transfer=0;
        for(const auto& choice:choices){stop(token);if(choice.row>=rows.size()||!selected.insert(choice.row).second)fail("resolution.row_index",ObservationState::Failed,AdapterError::PlanInvalid);
            const auto& row=rows[choice.row];const auto& left=file(false,row.exact_key);const auto& right=file(true,row.exact_key);
            if(pair_equal(left,right))fail("resolution.not_a_conflict",ObservationState::Changed,AdapterError::ProviderReviewRequired);
            if(std::any_of(catalog.begin(),catalog.end(),[&](const auto& a){return a.components==left.components||a.components==right.components;}))fail("resolution.already_protected");
            const std::array names{choice.left_version_name,choice.right_version_name};
            for(unsigned side=0;side<2;++side){const auto& source=side?right:left;const auto& root=inventories[side];auto parent=NativeDurableIdentity::from_live(*root.root_metadata.identity.value()),object=NativeDurableIdentity::from_live(*source.metadata.basic.identity.value());
                if(!parent||!object)fail("resolution.durable_identity",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
                e.artifacts.push_back({side!=0,source.components,*parent,*object,source.status});
                receipt->operations.push_back({NativeSyncResolutionOperationKind::ProtectOriginal,choice.row,side!=0,side!=0,source.components,*source.metadata.basic.logical_size.value()});
                auto key=native_sync_key(std::span(&names[side],1));if(key.size()>request.proof_limits.baseline.max_path_bytes)fail("resolution.name_bound",ObservationState::Unknown,AdapterError::InventoryLimit);
                const auto bytes=names[side].posix_bytes()?names[side].posix_bytes()->size():names[side].windows_units()->size()*2;
                charge(name_bytes,bytes,limits.max_name_bytes,"resolution.name_bound");
                const auto logical=admitted_data_bytes(source);
                charge(transfer,logical,limits.max_transfer_bytes,"resolution.transfer_bound");charge(transfer,logical,limits.max_transfer_bytes,"resolution.transfer_bound");
                e.paths.push_back({key,{names[side]},absent(),absent(),{},{},SyncAction::Unchanged,false});
                if(old_keys.contains(key)||!expected_versions.emplace(key,source.status).second)fail("resolution.variant_old_key_collision",ObservationState::Changed,AdapterError::ProviderReviewRequired);
                for(unsigned dest=0;dest<2;++dest)receipt->operations.push_back({NativeSyncResolutionOperationKind::PublishVersion,choice.row,side!=0,dest!=0,{names[side]},*source.metadata.basic.logical_size.value()});
            }
        }
        if(e.artifacts.size()>request.ledger_limits.max_artifacts||e.paths.size()>request.proof_limits.baseline.max_rows)fail("resolution.evidence_bound",ObservationState::Unknown,AdapterError::InventoryLimit);
        std::sort(e.paths.begin(),e.paths.end(),[](const auto& a,const auto& b){return a.opaque_key<b.opaque_key;});
        prove_names(receipt->operations,token,true);
        std::vector<SyncBaselineUpdate> predicted;for(const auto& p:e.paths)predicted.push_back({{p.opaque_key,p.skipped?p.left:expected_versions.at(p.opaque_key),p.skipped?p.right:expected_versions.at(p.opaque_key)},p.skipped?SyncBaselineUpdateState::Pending:SyncBaselineUpdateState::ConfirmedEqual});
        e.proposed_baseline=value(advance_sync_baseline(session->snapshot().baseline?&*session->snapshot().baseline:nullptr,predicted,session->identity().policy,request.proof_limits.baseline)).baseline;
        // Preflight ALL seven coordinator frames before any durable effect.
        auto sizing=value(OperationJournal::create(FileOperation::Copy,id));std::size_t bytes=stored_bytes;
        auto wire=value(encode_native_sync_ledger(e,request.ledger_limits));
        for(auto phase:{OperationJournalState::Planned,OperationJournalState::Prepared,OperationJournalState::Copied,OperationJournalState::Verified,OperationJournalState::CommitIntended,OperationJournalState::DestinationCommitted,OperationJournalState::Complete}){
            auto phased=e;if(phase==OperationJournalState::Planned||phase==OperationJournalState::Prepared)phased.proposed_baseline.reset();

            OperationJournalRecord record{sizing->records().size()+1,0,phase,value(encode_native_sync_ledger(phased,request.ledger_limits))};auto frame=value(encode_operation_journal_frame(*sizing,record));
            if(bytes>request.ledger_limits.max_total_wire_bytes||frame.size()>request.ledger_limits.max_total_wire_bytes-bytes){fail("resolution.ledger_budget",ObservationState::Unknown,AdapterError::InventoryLimit);}
            bytes+=frame.size();require(sizing->append(std::move(record)));}
        if(stored_count>=request.ledger_limits.max_ledgers)fail("resolution.ledger_count",ObservationState::Unknown,AdapterError::InventoryLimit);
        Sha256 hash;hash.update(std::as_bytes(std::span("ckfs-resolution-0.5-named",25)));hash.update(id.bytes);hash.update(wire);
        auto number=[&](std::uint64_t n){std::array<std::byte,8> bytes{};for(unsigned i=0;i<8;++i)bytes[i]=std::byte((n>>(8*i))&255);hash.update(bytes);};
        number(limits.max_resolutions);number(limits.max_added_paths);number(limits.max_protected_objects);number(limits.max_name_bytes);number(limits.max_transfer_bytes);number(limits.max_proof_bytes);
        for(const auto& op:receipt->operations) {
            const auto& proof=file(op.source_right,rows.at(op.source_row).exact_key);
            const auto& facts=proof.channel_facts;
            receipt->stream_facts.push_back({1,facts.coverage,facts.named_stream_count,facts.all_stream_logical_bytes});
        }
        number(receipt->operations.size());for(const auto& op:receipt->operations){number(static_cast<unsigned>(op.kind));number(op.source_row);number(op.source_right);number(op.destination_right);number(op.main_data_bytes);const auto key=native_sync_key(op.components);number(key.size());hash.update(std::as_bytes(std::span(key)));}
        number(1);number(receipt->stream_facts.size());
        for(const auto& facts:receipt->stream_facts){number(facts.version);number(static_cast<unsigned>(facts.coverage));number(facts.named_stream_count);number(facts.all_stream_logical_bytes.has_value());number(facts.all_stream_logical_bytes.value_or(0));}
        receipt->digest=hash.digest();e.reviewed_plan=receipt->digest;
        return receipt;
    }
    void approve(const NativeSyncResolutionReceipt& receipt,bool first,std::stop_token token) {
        active();const auto& r=*receipt.state_;
        if(result.state!=NativeSyncCoordinatorState::AwaitingReview||r.consumed||r.owner!=owner||r.revision!=revision||!bound_to(r.identity,session->identity())||r.generation!=session->snapshot().generation)fail("resolution.foreign_stale_receipt");
        if(session->snapshot().state==SyncSessionState::FirstRun&&!first)fail("resolution.first_run_review",ObservationState::Changed,AdapterError::ProviderReviewRequired);
        fresh(token);prove_names(r.operations,token,true);require_clean();approved=receipt.state_;approved->consumed=true;approve_first=first;catalog=approved->evidence.artifacts;verify_catalog(inventories);result.state=NativeSyncCoordinatorState::Executing;
    }
    void source_guard(const NativeSyncFileProof& proof,std::stop_token token) {
        require(session->revalidate());auto fresh=value(proof.held->refresh(token));if(!fresh->continues(*proof.held)||!native_sync_same_version(proof.metadata.basic,fresh->metadata()))fail("resolution.source_changed");require(proof.held->verify_metadata_source(proof.metadata,token));
    }
    void start_copy(const NativeSyncResolutionOperation& op,std::stop_token token) {
        fresh(token);const auto& source=file(op.source_right,rows.at(op.source_row).exact_key);auto& dest=inventories[op.destination_right?1:0];absent_name(dest,op.components.front());source_guard(source,token);
        auto policy=value(RegularMetadataPreservation::create_with_policy(source.held,false,request.metadata,token));
        if(!source.native_source||!policy->captured_metadata()||value(native_sync_metadata_digest(*source.native_source,*policy->captured_metadata(),token))!=source.status.required_metadata_digest||!native_sync_same_version(source.metadata.basic,policy->captured_metadata()->basic))fail("resolution.metadata_changed");
        copy_metadata=policy;published_object.reset();
        auto id=value(new_native_operation_journal_id());auto jf=value(open_prepared_operation_journal_file(*session->storage_root(),generated_name(".ck-resolution-copy-",id,session->storage_root()->encoding()),true));auto journal=value(OperationJournal::create(FileOperation::Copy,id));require(append_operation_journal_file(*jf,*journal,{1,0,OperationJournalState::Planned,{}}));
        NativeOperationCopyRequest r{.journal=journal,.journal_file=std::shared_ptr<OperationJournalFile>(std::move(jf)),.item=0,
            .source_parent=source.held->parent(),.source_parent_identity=*source.held->parent_identity().value(),.source_name=source.components.back(),.source_identity=*source.metadata.basic.identity.value(),
            .destination=dest.root,.destination_identity=*dest.root_metadata.identity.value(),.destination_address=op.destination_right?request.right:request.left,
            .staging_name=generated_name(".ck-resolution-stage-",id,source.components.back().encoding()),.destination_name=op.components.front(),
            .copy_limits={request.proof_limits.chunk_bytes,request.proof_limits.max_file_bytes,1024},.prepare_metadata={},.operation=FileOperation::Copy,.verify_metadata_before_publication={}};
        active_copy_journal=r.journal_file;
        r.prepare_stream=[this](OpenedEntry& source,OpenedEntry& stage,StreamCopyLimits limits){
            active_stage=&stage;return create_stream_copy_job(source,stage,limits);
        };
        r.reviewed_content_digest=source.status.content_digest;
        r.prepare_metadata=[policy](OpenedEntry& stage,std::stop_token t){return policy->prepare(stage,t);};
        // No post-final-metadata DATA read (atime). Native stream digests are
        // compared with the frozen digest before final metadata is applied.
        r.verify_metadata_before_publication=[this,policy,&source](OpenedEntry& stage,std::stop_token t){return attempt<bool>([&]{source_guard(source,t);require(policy->verify(stage,t));
            auto basic=value(stage.inspect_basic());
            if(!basic.identity.value())fail("resolution.stage_identity",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
            auto object=NativeDurableIdentity::from_live(*basic.identity.value());
            if(!object||(published_object&&*published_object!=*object))fail("resolution.stage_identity_changed");
            published_object=object;return true;});};
        copy=value(NativeOperationCopyJob::create(std::move(r)));
    }
    void accept(const NativeSyncResolutionOperation& op,std::stop_token token) {
        auto next=scan(token);
        try {verify_catalog(next);const auto key=native_sync_key(op.components);const auto expected=file(op.source_right,rows.at(op.source_row).exact_key).status;
        for(unsigned side=0;side<2;++side){const auto& old=inventories[side];const auto& now=next[side];
            for(const auto& [name,proof]:old.files){auto found=now.files.find(name);if(found==now.files.end()||found->second.status!=proof.status||!native_sync_same_version(proof.metadata.basic,found->second.metadata.basic))fail("resolution.unrelated_change");}
            for(const auto& [name,proof]:now.files)if(!old.files.contains(name)&&(side!=unsigned(op.destination_right)||name!=key||proof.status!=expected))fail("resolution.unexpected_publication");
        }
        auto found=next[op.destination_right?1:0].files.find(key);if(found==next[op.destination_right?1:0].files.end()||found->second.status!=expected||!published_object||!found->second.metadata.basic.identity.value()||
           !published_object->matches_live(*found->second.metadata.basic.identity.value()))fail("resolution.publication_not_verified");
        replace(next);++result.completed_operations;++current;release_copy();require_clean();
        }catch(...){drain(next);throw;}
    }
    void finish_copy_metadata() noexcept {
#ifdef _WIN32
        if(copy_metadata&&copy_metadata->captured_metadata())detail::finish_native_metadata_capture(nullptr,*copy_metadata->captured_metadata());
#endif
        copy_metadata.reset();
    }
    void release_copy() noexcept {
        // NativeOperationCopyJob finalizes before exposing a terminal state.
        // Query the actual cached writer/journal results while their owners
        // are still alive; a protocol collision is not a close failure.
        auto closed=[&](auto&& finish){try{auto result=finish();
                if(auto* e=result.unavailable_detail())remember_close(e->state,e->error.domain,e->error.code,e->error.operation);
                else if(!*result.value())remember_close(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"resolution.copy_close_false");
            }catch(...){remember_close(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"resolution.copy_close_exception");}};
        if(active_stage)closed([&]{return active_stage->finish_content_writes();});
        if(active_copy_journal)closed([&]{return active_copy_journal->finish_io();});
        active_stage=nullptr;copy.reset();active_copy_journal.reset();finish_copy_metadata();
    }
    void drain_copy() noexcept {
        if(copy)try {
            std::stop_source stopped;stopped.request_stop();
            const auto state=copy->advance(stopped.get_token());
            if(state!=OperationExecutionState::Complete&&copy->result().failure&&!result.failure)
                result.failure=copy->result().failure;
        }catch(...){remember_close(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"resolution.copy_drain_exception");}
        release_copy();
    }
    void execute(std::stop_token token) {
        // Let the child consume cancellation and finalize its actual writer
        // and journal before exposing a terminal parent result.
        if(token.stop_requested()&&copy){drain_copy();require_clean();}
        stop(token);if(!ledger){auto planned=approved->evidence;planned.proposed_baseline.reset();durable_intent=true;ledger=value(NativeSyncLedger::create(session->storage_root(),approved->ledger_name,approved->transaction,planned,request.ledger_limits));require(ledger->append(OperationJournalState::Prepared,planned));return;}
        while(current<approved->operations.size()&&approved->operations[current].kind==NativeSyncResolutionOperationKind::ProtectOriginal)++current;
        if(current==approved->operations.size()){result.state=NativeSyncCoordinatorState::Verifying;return;}
        const auto& op=approved->operations[current];if(!copy){start_copy(op,token);return;}
        const auto state=copy->advance(token);if(state==OperationExecutionState::Complete){accept(op,token);return;}
        if(state==OperationExecutionState::Cancelled||state==OperationExecutionState::Failed||state==OperationExecutionState::NeedsReconciliation||state==OperationExecutionState::RetainedSource){if(copy->result().failure)throw Failure{*copy->result().failure};fail("resolution.copy_incomplete",ObservationState::Changed,AdapterError::ProviderReviewRequired);}
    }
    void verify(std::stop_token token) {
        fresh(token);auto live=updates(approved->evidence);fresh(token);
        auto proposal=value(advance_sync_baseline(session->snapshot().baseline?&*session->snapshot().baseline:nullptr,live,session->identity().policy,request.proof_limits.baseline));if(proposal.baseline!=*approved->evidence.proposed_baseline)fail("resolution.baseline_prediction_changed");result.pending_keys=proposal.pending_paths;
        require(ledger->append(OperationJournalState::Copied,approved->evidence));require(ledger->append(OperationJournalState::Verified,approved->evidence));stop(token);require(ledger->append(OperationJournalState::CommitIntended,approved->evidence));
        event(NativeSyncCoordinatorEvent::BeforeLedgerClose);require(ledger->finish_io());ledger.reset();result.state=NativeSyncCoordinatorState::Committing;
    }
    void commit(std::stop_token token) {
        stop(token);event(NativeSyncCoordinatorEvent::BeforeBaselineCommit);fresh(token);auto live=updates(approved->evidence);
        // Consume every retained native observation reader before baseline CAS.
        // Digests remain evidence; closed readers cannot authorize later replay.
        discard_observations(inventories);
        require_clean();stop(token);
        auto committed=value(session->commit(approved->generation,live,approve_first,[token]{return token.stop_requested();}));
        event(NativeSyncCoordinatorEvent::AfterBaselineCommit);if(committed.baseline!=*approved->evidence.proposed_baseline)fail("resolution.cas_result");
        auto reopened=value(NativeSyncLedger::reopen(session->storage_root(),approved->ledger_name,approved->transaction,request.ledger_limits));require(reopened->append(OperationJournalState::DestinationCommitted,approved->evidence));require(reopened->append(OperationJournalState::Complete,approved->evidence));require(reopened->finish_io());
        result.generation=session->snapshot().generation;result.state=NativeSyncCoordinatorState::Complete;
    }
    void remember_close(ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view operation) noexcept {
        if(!close_failed){close_failed=true;close_failure.state=state;close_failure.domain=domain;close_failure.code=code;
            const auto count=std::min(operation.size(),close_failure.operation.size()-1);std::copy_n(operation.begin(),count,close_failure.operation.begin());}
        if(finish_root)detail::record_prepared_journal_consumer_failure(*finish_root,state,domain,code,operation);
    }
    void close_native() noexcept {
        if(finished)return;
        finished=true;revision.reset();
        if(session){auto kept=session->storage_root();finish_root=kept.get();}else finish_root=request.prepared_journal_root.get();
        if(finish_root&&detail::read_prepared_journal_consumer_failure(*finish_root,close_failure))close_failed=true;
        drain_copy();
        auto closing=[&](auto&& close){try{auto outcome=close();if(!outcome.value()||!*outcome.value()){
                if(auto* d=outcome.unavailable_detail())remember_close(d->state,d->error.domain,d->error.code,d->error.operation);
                else remember_close(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"resolution.close_false");}}
            catch(...){remember_close(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"resolution.close_exception");}};
        if(ledger){closing([&]{return ledger->finish_io();});ledger.reset();}
        discard_observations(inventories);
        if(session)closing([&]{return session->finish_io();});
        if(finish_root&&detail::read_prepared_journal_consumer_failure(*finish_root,close_failure))close_failed=true;
        if(result.state!=NativeSyncCoordinatorState::Complete)result.state=approved?NativeSyncCoordinatorState::NeedsReview:NativeSyncCoordinatorState::Cancelled;
        if(close_failed)result.state=NativeSyncCoordinatorState::NeedsReview;
    }
    Observation<bool> close() {
        close_native();
        detail::PreparedJournalConsumerFailure first;
        if(finish_root&&detail::read_prepared_journal_consumer_failure(*finish_root,first)&&(!close_failed||close_failure.pending)){close_failed=true;close_failure=first;}
        if(close_failed)return Observation<bool>::unavailable(close_failure.state,{close_failure.domain,close_failure.code,close_failure.operation.data()});
        return Observation<bool>::available(true);
    }
};
NativeSyncResolution::NativeSyncResolution(std::unique_ptr<State> s):state_(std::move(s)){}
NativeSyncResolution::~NativeSyncResolution()=default;
Observation<NativeSyncResolution::Pointer> NativeSyncResolution::open(NativeSyncCoordinatorRequest request,NativeSyncResolutionLimits limits,std::stop_token stop){return attempt<Pointer>([&]{auto s=std::make_unique<State>(std::move(request),limits);detail::MetadataCaptureCleanupScope scope(s.get());s->initialize(stop);s->require_clean();return Pointer(new NativeSyncResolution(std::move(s)));});}
const std::vector<NativeSyncReviewedRow>& NativeSyncResolution::rows() const noexcept{return state_->rows;}
const std::vector<NativeName>& NativeSyncResolution::components(std::size_t row) const{return state_->paths.at(state_->rows.at(row).exact_key);}
const std::vector<NativeSyncProtectedEvidence>& NativeSyncResolution::protected_originals() const noexcept{return state_->originals;}
const NativeSyncCoordinatorResult& NativeSyncResolution::result() const noexcept{return state_->result;}
const SyncSessionSnapshot& NativeSyncResolution::snapshot() const noexcept{return state_->session->snapshot();}
const std::vector<NativeSyncResolutionOperation>& NativeSyncResolutionReceipt::operations() const noexcept{return state_->operations;}
const NativeSyncResolutionStreamFactsV1& NativeSyncResolutionReceipt::stream_facts_v1(std::size_t operation) const{return state_->stream_facts.at(operation);}
const SyncDigest& NativeSyncResolutionReceipt::digest() const noexcept{return state_->digest;}
Observation<NativeSyncResolutionReceipt::Pointer> NativeSyncResolution::assess(std::span<const NativeSyncNamedResolution> choices,std::stop_token stop){return attempt<NativeSyncResolutionReceipt::Pointer>([&]{detail::MetadataCaptureCleanupScope scope(state_.get());return NativeSyncResolutionReceipt::Pointer(new NativeSyncResolutionReceipt(state_->assess(choices,stop)));});}
Observation<bool> NativeSyncResolution::approve(const NativeSyncResolutionReceipt& receipt,bool first,std::stop_token stop){return attempt<bool>([&]{detail::MetadataCaptureCleanupScope scope(state_.get());state_->approve(receipt,first,stop);return true;});}
NativeSyncCoordinatorState NativeSyncResolution::advance(std::stop_token token){auto& s=*state_;detail::MetadataCaptureCleanupScope scope(&s);if(s.finished)return s.result.state;try{switch(s.result.state){case NativeSyncCoordinatorState::Executing:s.require_clean();s.execute(token);break;case NativeSyncCoordinatorState::Verifying:s.verify(token);break;case NativeSyncCoordinatorState::Committing:s.commit(token);break;default:break;}s.require_clean();}
    catch(const Failure& e){try{s.result.failure=e.detail;}catch(...){s.close_native();throw;}s.result.state=token.stop_requested()&&!s.durable_intent?NativeSyncCoordinatorState::Cancelled:NativeSyncCoordinatorState::NeedsReview;}
    catch(...){s.result.state=NativeSyncCoordinatorState::NeedsReview;s.close_native();throw;}return s.result.state;}
Observation<bool> NativeSyncResolution::finish_io(){detail::MetadataCaptureCleanupScope scope(state_.get());return state_->close();}
Observation<NativeHierarchyContext::Pointer> NativeHierarchyContext::borrow(NativeSyncResolution& worker,NativeHierarchyLimits limits,std::stop_token stop) {
    try {
    if(!worker.state_||worker.state_->finished||!worker.state_->session)return Observation<Pointer>::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::PlanDecisionStale),"hierarchy.worker_closed"});
    // Read-only opt-in; no re-lock, rule evaluation, approval or mutation.
    return borrow(*worker.state_->session,limits,stop);
    }catch(...){if(worker.state_)worker.state_->close_native();throw;}
}
} // namespace ck::files
