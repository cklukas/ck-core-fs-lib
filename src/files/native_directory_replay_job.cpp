// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_directory_replay_job.hpp"
#include "directory_metadata_apply.hpp"
#include "directory_metadata_verify.hpp"
#include "metadata_semantic_digest.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <algorithm>
#include <limits>

namespace ck::files {
namespace {
Observation<bool> reject(const char* operation,ObservationState state=ObservationState::Unsupported,
    AdapterError code=AdapterError::ProviderReviewRequired) {
    return Observation<bool>::unavailable(state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),operation});
}
template<class T> Observation<bool> propagate(const Observation<T>& value) {
    const auto& error=*value.unavailable_detail();return Observation<bool>::unavailable(error.state,error.error);
}
bool same(const BasicMetadata& a,const BasicMetadata& b) {
    return a.identity.value()&&b.identity.value()&&
        compare_identity(*a.identity.value(),*b.identity.value())==IdentityComparison::Same&&
        a.kind.value()&&b.kind.value()&&*a.kind.value()==ObjectKind::Directory&&*a.kind.value()==*b.kind.value();
}
bool same_owner(const Observation<ObjectIdentity>& a,const Observation<ObjectIdentity>& b) {
    return a.value()&&b.value()&&compare_identity(*a.value(),*b.value())==IdentityComparison::Same;
}
Observation<bool> replay_preflight(OpenedEntry& target,const MetadataReplaySnapshot& snapshot) {
    const auto qualified=target.qualify_metadata_replay(snapshot.policy);if(!qualified.value()||!*qualified.value())return qualified;
    for(std::size_t i=0;i<snapshot.attributes.size();++i) {
        if(!same_owner(snapshot.attributes[i].owner,snapshot.basic.identity))return reject("directory_replay.attribute_owner",ObservationState::Changed,AdapterError::UnqualifiedIdentity);
        for(std::size_t j=0;j<i;++j)if(snapshot.attributes[i].identifier==snapshot.attributes[j].identifier)
            return reject("directory_replay.duplicate_attribute",ObservationState::Failed,AdapterError::InvalidIdentifier);
    }
    for(const auto& security:snapshot.security)if(!same_owner(security.owner,snapshot.basic.identity))
        return reject("directory_replay.security_owner",ObservationState::Changed,AdapterError::UnqualifiedIdentity);
    if(snapshot.channel_coverage==DataChannelCoverage::WindowsFileStreamInfo) {
        auto proof=verify_native_metadata_replay_channels(snapshot);if(!proof.value()||!*proof.value())return proof;
    }else if(!snapshot.channels.empty())return reject("directory_replay.channel_coverage");
    if(snapshot.policy.scope==RegularMetadataScope::CompleteMetadataV1) {
        if(!snapshot.security_coverage)return reject("directory_replay.security_coverage");
        auto proof=target.preflight_metadata_security_coverage(snapshot);if(!proof.value()||!*proof.value())return proof;
    }
    auto current=target.inspect_basic();if(!current.value())return propagate(current);
    if(!current.value()->kind.value()||*current.value()->kind.value()!=ObjectKind::Directory)
        return reject("directory_replay.target_kind",ObservationState::Changed,AdapterError::NotDirectory);
    if(current.value()->windows_attributes.value()&&snapshot.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo)
        return reject("directory_replay.windows_channel_coverage");
    return Observation<bool>::available(true);
}
bool security_attribute(const AttributeValue& attribute) {
    if(attribute_role(attribute.identifier,attribute.native_flags.value()?*attribute.native_flags.value():0)==AttributeRole::Security)return true;
    const auto* name=attribute.identifier.posix_bytes();
    return name&&(name->starts_with("security.")||name->starts_with("trusted.")||*name=="com.apple.macl"||*name=="com.apple.rootless");
}
Observation<bool> replay_attributes(OpenedEntry& target,const MetadataReplaySnapshot& snapshot,bool security,std::stop_token stop) {
    auto catalog=target.inspect_attributes(snapshot.policy.limits);if(!catalog.value())return propagate(catalog);
    for(const auto& attribute:snapshot.attributes) {
        if(security_attribute(attribute)!=security)continue;
        if(stop.stop_requested())return reject("directory_replay.cancelled",ObservationState::Changed,AdapterError::InterruptedRead);
        const auto known=std::find_if(catalog.value()->attributes.begin(),catalog.value()->attributes.end(),
            [&](const auto& item){return item.identifier==attribute.identifier;});
        if(known!=catalog.value()->attributes.end()) {
            auto current=target.read_attribute(attribute.identifier,snapshot.policy.limits);if(!current.value())return propagate(current);
            auto basic=target.inspect_basic();if(!basic.value())return propagate(basic);
            if(!same_owner(current.value()->owner,basic.value()->identity))return reject("directory_replay.attribute_binding",ObservationState::Changed,AdapterError::MetadataChanged);
            const auto& actual=current.value()->native_flags;const auto& wanted=attribute.native_flags;
            const bool flags=(actual.value()&&wanted.value())?*actual.value()==*wanted.value():!actual.value()&&!wanted.value()&&actual.state()==wanted.state();
            if(current.value()->bytes==attribute.bytes&&flags)continue;
        }
        auto applied=target.apply_replay_attribute(attribute,snapshot.policy);if(!applied.value()||!*applied.value())return applied;
    }
    return Observation<bool>::available(true);
}
Observation<bool> replay_final_metadata(OpenedEntry& target,const MetadataReplaySnapshot& snapshot,std::stop_token stop) {
    auto existing=target.inspect_attributes(snapshot.policy.limits);if(!existing.value())return propagate(existing);
    for(const auto& attribute:existing.value()->attributes) {
        if(stop.stop_requested())return reject("directory_replay.cancelled",ObservationState::Changed,AdapterError::InterruptedRead);
        if(std::none_of(snapshot.attributes.begin(),snapshot.attributes.end(),[&](const auto& source){return source.identifier==attribute.identifier;})) {
            auto removed=target.remove_replay_attribute(attribute.identifier,snapshot.policy);if(!removed.value()||!*removed.value())return removed;
        }
    }
    // Ordinary EAs/xattrs need the current writable permissions. Privilege
    // attributes (including Linux capabilities) must instead follow fchown and
    // initial mode, which may clear them. No temporary write-mode workaround.
    auto result=replay_attributes(target,snapshot,false,stop);if(!result.value()||!*result.value())return result;
    result=target.apply_replay_ownership(snapshot.basic,snapshot.policy);if(!result.value()||!*result.value())return result;
    result=target.apply_replay_basic(snapshot.basic,snapshot.policy);if(!result.value()||!*result.value())return result;
    for(const auto& security:snapshot.security) {
        if(stop.stop_requested())return reject("directory_replay.cancelled",ObservationState::Changed,AdapterError::InterruptedRead);
        result=target.apply_replay_security(security,snapshot.policy);if(!result.value()||!*result.value())return result;
    }
    result=replay_attributes(target,snapshot,true,stop);if(!result.value()||!*result.value())return result;
    if(stop.stop_requested())return reject("directory_replay.cancelled",ObservationState::Changed,AdapterError::InterruptedRead);
    // Native basic replay avoids chmod when the mode is already exact, so
    // this final timestamp/flag phase does not rewrite the established ACL.
    return target.apply_replay_basic(snapshot.basic,snapshot.policy);
}

void integer(std::vector<std::byte>& out,std::uint64_t n) {
    for(unsigned i=0;i<8;++i)out.push_back(std::byte((n>>(i*8))&255));
}
void identity(std::vector<std::byte>& out,const BasicMetadata& metadata) {
    const auto* id=metadata.identity.value();integer(out,id?static_cast<std::uint64_t>(id->scheme):0);
    for(const auto* bytes:{id?&id->volume.bytes:nullptr,id?&id->object.bytes:nullptr}) {
        integer(out,bytes?bytes->size():0);
        if(bytes)out.insert(out.end(),bytes->begin(),bytes->end());
    }
}
}
struct NativeDirectoryReplayJob::Bounded {
    class Latch final:public MetadataCaptureFailureLatch {
    public:
        explicit Latch(PreparedJournalRoot::Pointer root):root_(std::move(root)){}
        void record_first(MetadataCaptureCleanupError error)const noexcept override {
            if(!first)first=error;
            if(root_)detail::record_prepared_journal_consumer_failure(*root_,error.state,error.domain,error.code,error.operation);
        }
        void release()noexcept{root_.reset();}
        mutable std::optional<MetadataCaptureCleanupError> first;
    private:PreparedJournalRoot::Pointer root_;
    };
    explicit Bounded(PreparedJournalRoot::Pointer root):latch(std::make_shared<Latch>(std::move(root))){}
    std::shared_ptr<Latch> latch;
    std::unique_ptr<MetadataCaptureJob> target_initial,target_after_children,source_check;
    std::shared_ptr<const NativeMetadataProof> target_before;
    std::optional<std::array<std::byte,32>> target_payload;
    DirectoryMetadataApplyJob::Pointer apply;
    DirectoryMetadataVerifyJob::Pointer verify;
};
NativeDirectoryReplayJob::NativeDirectoryReplayJob(NativeDirectoryReplayRequest request):request_(std::move(request)) {
    if(request_.source_proof){bounded_=std::make_unique<Bounded>(request_.journal_root);
        if(!request_.metadata_budget)request_.metadata_budget=std::make_shared<MetadataCaptureBudget>(request_.metadata_limits);}
}
Observation<NativeDirectoryReplayJob::Pointer> NativeDirectoryReplayJob::create(NativeDirectoryReplayRequest request) {
    using R=Observation<Pointer>;
    if(!request.source||!request.journal_root||!request.journal_name||!request.journal_name->is_valid()||
        !request.verify_children||!request.verify_plan||!request.reviewed_metadata.policy.valid()||
        !request.reviewed_metadata.basic.kind.value()||*request.reviewed_metadata.basic.kind.value()!=ObjectKind::Directory||
        (!request.existing_destination&&(!request.destination_parent||!request.destination_name||!request.destination_name->is_valid())))
        return R::unavailable(ObservationState::Failed,{ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidIdentifier),"directory_replay.request"});
    if(request.existing_destination) {
        request.destination_parent=request.existing_destination->parent();request.destination_name=request.existing_destination->name();
    }
    return R::available(Pointer(new NativeDirectoryReplayJob(std::move(request))));
}
bool NativeDirectoryReplayJob::terminal() const noexcept {
    return progress_.worker_drained;
}
NativeDirectoryReplayJob::~NativeDirectoryReplayJob() {
    if(!terminal())try {finish(false,true);}catch(...) {}
}
void NativeDirectoryReplayJob::remember(const UnavailableObservation& error,bool finish_error) noexcept {
    remember_raw(error.state,error.error.domain,error.error.code,error.error.operation,finish_error);
}
void NativeDirectoryReplayJob::remember_raw(ObservationState state,ErrorDomain domain,std::int64_t code,
    std::string_view operation,bool finish_error) noexcept {
    auto& first=finish_error?progress_.finish_failure:progress_.failure;
    if(!first.present) {
        first.present=true;first.state=state;first.domain=domain;first.code=code;
        std::copy_n(operation.data(),std::min(operation.size(),first.operation.size()-1),first.operation.data());
    }
    if(finish_error&&request_.journal_root)detail::record_prepared_journal_consumer_failure(*request_.journal_root,
        state,domain,code,operation);
}
void NativeDirectoryReplayJob::finish_exception(const char* operation) noexcept {
    detail::PreparedJournalConsumerFailure failure;
    if(request_.journal_root&&detail::read_prepared_journal_consumer_failure(*request_.journal_root,failure)&&!failure.pending)
        remember_raw(failure.state,failure.domain,failure.code,failure.operation.data(),true);
    else remember_raw(ObservationState::Unknown,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidNativeResult),operation,true);
}
Observation<bool> NativeDirectoryReplayJob::revalidate(std::stop_token stop,bool children) {
    if(stop.stop_requested())return reject("directory_replay.cancelled",ObservationState::Changed,AdapterError::InterruptedRead);
    auto valid=request_.journal_root->revalidate();if(!valid.value()||!*valid.value())return valid;
    valid=request_.verify_plan(stop);if(!valid.value()||!*valid.value())return valid;
    valid=JournalScopeGuard::check_pair(source_scope_,target_scope_,stop);if(!valid.value()||!*valid.value())return valid;
    auto source=request_.source->refresh(stop);if(!source.value())return propagate(source);
    if(!(*source.value())->continues(*request_.source))return reject("directory_replay.source_membership",ObservationState::Changed,AdapterError::MetadataChanged);
    if(request_.source_proof) {
        const auto& reviewed=request_.source_proof->snapshot().basic;
        const auto current=request_.source->inspect_basic();if(!current.value())return propagate(current);
        if(!same(*current.value(),reviewed)||current.value()->modified.value()==nullptr||reviewed.modified.value()==nullptr||
           *current.value()->modified.value()!=*reviewed.modified.value()||!current.value()->changed.value()||!reviewed.changed.value()||
           *current.value()->changed.value()!=*reviewed.changed.value())return reject("directory_replay.source_version",ObservationState::Changed,AdapterError::MetadataChanged);
    }else {valid=request_.source->verify_metadata_source(request_.reviewed_metadata,stop);if(!valid.value()||!*valid.value())return valid;}
    if(destination_) {
        if(request_.source->metadata().identity.value()&&destination_->metadata().identity.value()&&
            compare_identity(*request_.source->metadata().identity.value(),*destination_->metadata().identity.value())==IdentityComparison::Same)
            return reject("directory_replay.source_is_destination",ObservationState::Unsupported,AdapterError::PlanTopologyUnsafe);
        auto current=destination_->refresh(stop);if(!current.value())return propagate(current);
        if(!(*current.value())->continues(*destination_))return reject("directory_replay.destination_membership",ObservationState::Changed,AdapterError::MetadataChanged);
        valid=target_scope_->check_entry(**current.value(),stop);if(!valid.value()||!*valid.value())return valid;
    }
    if(children)return request_.verify_children(stop);
    return Observation<bool>::available(true);
}
Observation<bool> NativeDirectoryReplayJob::prepare(std::stop_token stop) {
    auto valid=request_.journal_root->revalidate();if(!valid.value()||!*valid.value())return valid;
    auto source=JournalScopeGuard::create_for_entry(request_.journal_root,*request_.source,stop);
    if(!source.value())return propagate(source);source_scope_=std::move(source).take_value();
    auto target=request_.existing_destination?
        JournalScopeGuard::create_for_entry(request_.journal_root,*request_.existing_destination,stop):
        JournalScopeGuard::create_for_namespace_child(request_.journal_root,request_.destination_parent,stop);
    if(!target.value())return propagate(target);target_scope_=std::move(target).take_value();
    destination_=request_.existing_destination;
    if(bounded_) {
        if(request_.source_proof->io_finished())return reject("directory_replay.source_proof_closed",ObservationState::Changed,AdapterError::InvalidAccess);
        valid=qualify_directory_metadata_source(*request_.source_proof);if(!valid.value()||!*valid.value())return valid;
        if(!same(request_.source_proof->snapshot().basic,request_.source->metadata()))return reject("directory_replay.source_proof_binding",ObservationState::Changed,AdapterError::MetadataChanged);
        auto reviewed=detail::metadata_snapshot_semantic_digest(request_.reviewed_metadata,stop);
        auto fresh=detail::metadata_snapshot_semantic_digest(request_.source_proof->snapshot(),stop);
        if(!reviewed.value())return propagate(reviewed);if(!fresh.value())return propagate(fresh);
        if(*reviewed.value()!=*fresh.value())return reject("directory_replay.source_proof_digest",ObservationState::Changed,AdapterError::PlanDecisionStale);
        if(destination_) {
            if(!request_.destination_review_proof||request_.destination_review_proof->io_finished()||
               !same(request_.destination_review_proof->snapshot().basic,destination_->metadata()))
                return reject("directory_replay.destination_review_proof",ObservationState::Changed,AdapterError::PlanDecisionStale);
            bounded_->target_before=request_.destination_review_proof;
        }
    }
    valid=revalidate(stop,false);if(!valid.value()||!*valid.value())return valid;
    // Independent read-only verifiers cannot impersonate the native writer's
    // CurrentCaller security context. Original-owner ADS has a native reader
    // factory below; no caller-created source/evidence is accepted by it.
    if(!request_.reviewed_metadata.channels.empty()&&request_.reviewed_metadata.policy.ownership!=MetadataOwnership::Original)
        return reject("directory_replay.ads_caller_context_unqualified");
    if(destination_) {
        if(request_.reviewed_metadata.policy.ownership==MetadataOwnership::CurrentCaller)
            return reject("directory_replay.existing_caller_verifier_unqualified");
        const auto access=request_.reviewed_metadata.policy.scope==RegularMetadataScope::CompleteMetadataV1?
            EntryAccess::MetadataAndFullSecurity|EntryAccess::MetadataAndAttributes:EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity;
        auto verifier=request_.destination_parent->open_child(*request_.destination_name,access);
        if(!verifier.value())return propagate(verifier);verifier_=std::move(verifier).take_value();
        auto metadata=verifier_->inspect_basic();if(!metadata.value())return propagate(metadata);
        if(!same(*metadata.value(),destination_->metadata()))return reject("directory_replay.verifier_identity",ObservationState::Changed,AdapterError::MetadataChanged);
        auto writer=destination_->open_directory_metadata_target(request_.reviewed_metadata.policy);
        if(!writer.value())return propagate(writer);writer_=std::move(writer).take_value();
        auto cursor=request_.destination_parent->open_directory_child(*request_.destination_name);
        if(!cursor.value())return propagate(cursor);cursor_=std::shared_ptr<const DirectoryCursor>(std::move(cursor).take_value());
        metadata=cursor_->inspect_basic();if(!metadata.value())return propagate(metadata);
        if(!same(*metadata.value(),destination_->metadata()))return reject("directory_replay.child_cursor_identity",ObservationState::Changed,AdapterError::MetadataChanged);
    } else {
        valid=qualify_native_directory_creation(*request_.destination_parent,request_.reviewed_metadata.policy);
        if(!valid.value()||!*valid.value())return valid;
    }
    auto file=request_.journal_root->open_journal(*request_.journal_name,true);
    if(!file.value())return propagate(file);journal_file_=std::move(file).take_value();
    auto journal=OperationJournal::create(FileOperation::Copy,request_.journal_id,{1,16,256*1024});
    if(!journal.value())return propagate(journal);journal_=std::move(journal).take_value();
    valid=append(OperationJournalState::Planned,0);if(!valid.value()||!*valid.value())return valid;
    // Prepared+phase1 is a durable creation/metadata intent. Creation publishes
    // an incomplete retained directory; no later state implies it was atomic.
    valid=append(OperationJournalState::Prepared,1);if(!valid.value()||!*valid.value())return valid;
    valid=revalidate(stop,false);if(!valid.value()||!*valid.value())return valid;
    if(!destination_) {
        progress_.creation_attempted=true;
        auto created=create_native_directory(request_.destination_parent,*request_.destination_name,request_.reviewed_metadata.policy);
        if(!created.value())return propagate(created);creator_=std::move(created).take_value();progress_.created=true;
        cursor_=creator_->cursor();
        auto held=HeldChild::observe(request_.destination_parent,*request_.destination_name,stop);
        if(!held.value())return propagate(held);destination_=std::move(held).take_value();
        if(!same(destination_->metadata(),creator_->created_metadata()))return reject("directory_replay.creator_membership",ObservationState::Changed,AdapterError::MetadataChanged);
        auto guarded=JournalScopeGuard::create_for_entry(request_.journal_root,*destination_,stop);
        if(!guarded.value())return propagate(guarded);target_scope_=std::move(guarded).take_value();
        if(bounded_||!request_.reviewed_metadata.channels.empty()) {
            const auto access=request_.reviewed_metadata.policy.scope==RegularMetadataScope::CompleteMetadataV1?
                EntryAccess::MetadataAndFullSecurity|EntryAccess::MetadataAndAttributes:EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity;
            auto reader=request_.destination_parent->open_child(*request_.destination_name,access);
            if(!reader.value())return propagate(reader);verifier_=std::move(reader).take_value();
        }
    }
    // Copied+phase2 records the held base directory identity, not subtree or
    // metadata completion. Children and final replay are still pending.
    return append(OperationJournalState::Copied,2);
}
void NativeDirectoryReplayJob::finish_bounded()noexcept {
    if(!bounded_)return;
    detail::MetadataCaptureCleanupScope cleanup(bounded_->latch.get());
    auto remember_child=[&](const DirectorySourceFailure& error,bool finishing){if(error.present)
        remember_raw(error.state,error.domain,error.code,error.operation.data(),finishing);};
    if(bounded_->verify){remember_child(bounded_->verify->progress().failure,false);bounded_->verify->release_readers();}
    if(bounded_->apply){remember_child(bounded_->apply->progress().failure,false);
        try{auto finished=bounded_->apply->finish_io();if(!finished.value())remember(*finished.unavailable_detail(),true);}
        catch(...){finish_exception("directory_replay.apply_finish_exception");}
        remember_child(bounded_->apply->progress().finish_failure,true);}
    auto close=[&](std::unique_ptr<MetadataCaptureJob>& capture){if(!capture)return;
        try{auto finished=capture->finish_io();if(!finished.value())remember(*finished.unavailable_detail(),true);
            else if(!*finished.value())remember_raw(ObservationState::Unknown,ErrorDomain::Adapter,2,"directory_replay.capture_finish_false",true);}
        catch(...){finish_exception("directory_replay.capture_finish_exception");}capture.reset();};
    close(bounded_->source_check);close(bounded_->target_after_children);close(bounded_->target_initial);
    for(const auto& proof:{bounded_->target_before,request_.source_proof,request_.destination_review_proof})if(proof)try{
        auto finished=proof->finish_io();if(!finished.value())remember(*finished.unavailable_detail(),true);
        else if(!*finished.value())remember_raw(ObservationState::Unknown,ErrorDomain::Adapter,2,"directory_replay.proof_finish_false",true);
    }catch(...){finish_exception("directory_replay.proof_finish_exception");}
    if(bounded_->latch->first){const auto& e=*bounded_->latch->first;remember_raw(e.state,e.domain,e.code,e.operation,true);}
}
Observation<bool> NativeDirectoryReplayJob::bounded_step(std::stop_token stop) {
    auto& state=*bounded_;
    auto valid=revalidate(stop,progress_.phase!=DirectoryReplayPhase::CapturingDestination);
    if(!valid.value()||!*valid.value())return valid;
    auto close=[&](std::unique_ptr<MetadataCaptureJob>& capture)->Observation<bool>{auto result=capture->finish_io();capture.reset();return result;};
    auto read=[&](std::unique_ptr<MetadataCaptureJob>& capture,std::shared_ptr<const NativeMetadataProof>& result)->Observation<bool>{
        const auto before=capture->progress();auto step=capture->advance(stop);const auto& after=capture->progress();
        progress_.content_reads+=after.read_calls-before.read_calls;progress_.content_bytes+=after.read_bytes-before.read_bytes;
        if(!step.value())return propagate(step);
        if(capture->progress().phase==MetadataCapturePhase::Complete){auto finished=capture->result();if(!finished.value())return propagate(finished);result=*finished.value();}
        return Observation<bool>::available(true);
    };
    auto began=[&](Observation<std::unique_ptr<MetadataCaptureJob>> producer,std::unique_ptr<MetadataCaptureJob>& target)->Observation<bool>{
        if(!producer.value())return propagate(producer);target=std::move(producer).take_value();return Observation<bool>::available(true);};
    auto check_source=[&]()->Observation<bool>{
        if(!state.source_check)return began(MetadataCaptureJob::verify(request_.source_proof,request_.metadata_limits,request_.metadata_budget,state.latch),state.source_check);
        std::shared_ptr<const NativeMetadataProof> proof;auto step=read(state.source_check,proof);if(!step.value()||!*step.value()||!proof)return step;
        auto before=detail::metadata_snapshot_semantic_digest(request_.source_proof->snapshot(),stop);
        auto after=detail::metadata_snapshot_semantic_digest(proof->snapshot(),stop);
        if(!before.value())return propagate(before);if(!after.value())return propagate(after);
        if(*before.value()!=*after.value())return reject("directory_replay.source_metadata_changed",ObservationState::Changed,AdapterError::MetadataChanged);
        auto finished=close(state.source_check);if(!finished.value()||!*finished.value())return finished;
        progress_.phase=progress_.phase==DirectoryReplayPhase::RecheckingFinalSource?DirectoryReplayPhase::Finalizing:DirectoryReplayPhase::RecheckingDestination;
        return Observation<bool>::available(true);
    };
    switch(progress_.phase){
    case DirectoryReplayPhase::CapturingDestination:{
        if(!state.target_before){
            if(!state.target_initial)return began(MetadataCaptureJob::begin_held(destination_,request_.reviewed_metadata.policy,
                request_.metadata_limits,request_.metadata_budget,state.latch),state.target_initial);
            auto step=read(state.target_initial,state.target_before);if(!step.value()||!*step.value()||!state.target_before)return step;
        }
        if(!same(state.target_before->snapshot().basic,destination_->metadata()))return reject("directory_replay.initial_target_identity",ObservationState::Changed,AdapterError::MetadataChanged);
        auto payload=directory_metadata_payload_digest(*state.target_before);if(!payload.value())return propagate(payload);
        state.target_payload=*payload.value();progress_.phase=DirectoryReplayPhase::AwaitingChildren;return Observation<bool>::available(true);
    }
    case DirectoryReplayPhase::RecheckingSource:case DirectoryReplayPhase::RecheckingFinalSource:{
        const auto final=progress_.phase==DirectoryReplayPhase::RecheckingFinalSource;
        auto result=check_source();if(!result.value()||!*result.value())return result;
        if(final&&progress_.phase==DirectoryReplayPhase::Finalizing)return append(OperationJournalState::Verified,3);
        return result;
    }
    case DirectoryReplayPhase::RecheckingDestination:{
        if(!state.target_after_children)return began(MetadataCaptureJob::begin_held(destination_,request_.reviewed_metadata.policy,
            request_.metadata_limits,request_.metadata_budget,state.latch),state.target_after_children);
        std::shared_ptr<const NativeMetadataProof> proof;auto step=read(state.target_after_children,proof);if(!step.value()||!*step.value()||!proof)return step;
        auto payload=directory_metadata_payload_digest(*proof);if(!payload.value())return propagate(payload);
        if(!state.target_payload||*payload.value()!=*state.target_payload)return reject("directory_replay.target_payload_changed",ObservationState::Changed,AdapterError::MetadataChanged);
        auto finished=close(state.target_after_children);if(!finished.value()||!*finished.value())return finished;
        // Retire old destination stream readers before disposition of extras.
        // The real base object stays pinned by creator/writer/cursor/HeldChild.
        if(state.target_initial){finished=close(state.target_initial);if(!finished.value()||!*finished.value())return finished;}
        if(state.target_before){finished=state.target_before->finish_io();if(!finished.value()||!*finished.value())return finished;}
        progress_.metadata_attempted=true;
        auto apply=DirectoryMetadataApplyJob::create(creator_?creator_->metadata_writer():*writer_,destination_,cursor_,request_.source_proof,
            request_.journal_root,request_.metadata_limits.read,[this](std::stop_token token){return revalidate(token,true);});
        if(!apply.value())return propagate(apply);state.apply=std::move(apply).take_value();progress_.phase=DirectoryReplayPhase::ApplyingBoundedMetadata;
        return Observation<bool>::available(true);
    }
    case DirectoryReplayPhase::ApplyingBoundedMetadata:{
        const auto before=state.apply->progress();auto progress=state.apply->advance(stop);
        progress_.content_reads+=progress.read_calls-before.read_calls;progress_.content_bytes+=progress.read_bytes-before.read_bytes;
        progress_.write_calls+=progress.write_calls-before.write_calls;progress_.write_bytes+=progress.write_bytes-before.write_bytes;
        if(progress.failure.present)return Observation<bool>::unavailable(progress.failure.state,{progress.failure.domain,progress.failure.code,progress.failure.operation.data()});
        if(progress.finish_failure.present){remember_raw(progress.finish_failure.state,progress.finish_failure.domain,progress.finish_failure.code,progress.finish_failure.operation.data(),true);
            return reject("directory_replay.apply_close_failed",ObservationState::Unknown,AdapterError::InvalidNativeResult);}
        if(progress.phase==DirectoryApplyPhase::Cancelled)return reject("directory_replay.apply_cancelled",ObservationState::Unknown,AdapterError::InterruptedRead);
        if(progress.phase==DirectoryApplyPhase::AwaitingVerifier){
            if(!request_.reviewed_metadata.channels.empty()){
                auto independent=create_directory_replay_verifier(destination_,cursor_,std::move(verifier_),request_.reviewed_metadata,request_.journal_root,stop);
                if(!independent.value())return propagate(independent);stream_verifier_=std::move(independent).take_value();}
            return state.apply->continue_metadata();
        }
        if(progress.phase==DirectoryApplyPhase::Complete){applied_=state.apply->applied_basic();progress_.phase=DirectoryReplayPhase::ClosingWriter;}
        return Observation<bool>::available(true);
    }
    case DirectoryReplayPhase::VerifyingBoundedMetadata:{
        if(!state.verify){
            const OpenedEntry* target=stream_verifier_?&stream_verifier_->entry():verifier_.get();
            // Created directories with no ADS already retain an independent
            // native verifier in their creator object. Obtain its prepared
            // read-only view before final metadata below (never a path reopen).
            if(!target)return reject("directory_replay.independent_target_view_missing",ObservationState::Failed,AdapterError::InvalidNativeResult);
            auto verify=DirectoryMetadataVerifyJob::create(*target,request_.source_proof,applied_,request_.metadata_limits.read,
                [this](std::stop_token token){return revalidate(token,true);});
            if(!verify.value())return propagate(verify);state.verify=std::move(verify).take_value();return Observation<bool>::available(true);
        }
        const auto before=state.verify->progress();auto progress=state.verify->advance(stop);
        progress_.content_reads+=progress.read_calls-before.read_calls;progress_.content_bytes+=progress.read_bytes-before.read_bytes;
        if(progress.failure.present)return Observation<bool>::unavailable(progress.failure.state,{progress.failure.domain,progress.failure.code,progress.failure.operation.data()});
        if(progress.phase==DirectoryVerifyPhase::Cancelled)return reject("directory_replay.verify_cancelled",ObservationState::Unknown,AdapterError::InterruptedRead);
        if(progress.phase==DirectoryVerifyPhase::Complete)progress_.phase=DirectoryReplayPhase::ClosingVerifier;
        return Observation<bool>::available(true);
    }
    default:return reject("directory_replay.bounded_phase",ObservationState::Failed,AdapterError::InvalidAccess);
    }
}
Observation<bool> NativeDirectoryReplayJob::append(OperationJournalState state,std::uint8_t phase) {
    std::vector<std::byte> evidence{std::byte{'C'},std::byte{'K'},std::byte{'D'},std::byte{'R'},std::byte{1},std::byte{phase}};
    evidence.insert(evidence.end(),request_.review_digest.begin(),request_.review_digest.end());
    identity(evidence,request_.reviewed_metadata.basic);
    identity(evidence,destination_?destination_->metadata():BasicMetadata{});
    evidence.push_back(std::byte(progress_.creation_attempted));evidence.push_back(std::byte(progress_.metadata_attempted));
    return append_operation_journal_file(*journal_file_,*journal_,{journal_->records().size()+1,0,state,std::move(evidence)});
}
Observation<std::shared_ptr<const DirectoryCursor>> NativeDirectoryReplayJob::child_cursor() const {
    using R=Observation<std::shared_ptr<const DirectoryCursor>>;
    if(progress_.phase!=DirectoryReplayPhase::AwaitingChildren||!cursor_)
        return R::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"directory_replay.children_phase"});
    return R::available(cursor_);
}
Observation<bool> NativeDirectoryReplayJob::children_finished(std::stop_token stop) {
    if(progress_.phase!=DirectoryReplayPhase::AwaitingChildren)return reject("directory_replay.children_phase",ObservationState::Changed,AdapterError::InvalidAccess);
    auto valid=revalidate(stop,true);
    if(!valid.value()){remember(*valid.unavailable_detail());finish(false,stop.stop_requested());return valid;}
    if(!*valid.value())return valid;
    children_finished_=true;return Observation<bool>::available(true);
}
Observation<bool> NativeDirectoryReplayJob::close_writer() {
    auto result=creator_?creator_->finish_io():writer_?writer_->finish_content_writes():Observation<bool>::available(true);
    writer_finish_observed_=true;return result;
}
void NativeDirectoryReplayJob::release_inputs() noexcept {
    auto observer=bounded_?bounded_->latch:nullptr;
    if(bounded_){bounded_->verify.reset();bounded_->apply.reset();bounded_->target_before.reset();}
    request_.source_proof.reset();request_.destination_review_proof.reset();request_.metadata_budget.reset();
    stream_verifier_.reset();creator_.reset();writer_.reset();verifier_.reset();cursor_.reset();destination_.reset();
    journal_file_.reset();journal_.reset();source_scope_.reset();target_scope_.reset();
    request_.source.reset();request_.existing_destination.reset();request_.destination_parent.reset();
    request_.verify_children={};request_.verify_plan={};
    // Emergency release must not default-construct a fresh BasicMetadata (its
    // diagnostic strings can allocate). Scalar review values may stay cached.
    request_.reviewed_metadata.channels.clear();request_.reviewed_metadata.channel_evidence.reset();
    request_.reviewed_metadata.security_coverage.reset();request_.reviewed_metadata.attributes.clear();request_.reviewed_metadata.security.clear();
    if(observer)observer->release();bounded_.reset();request_.journal_root.reset();
}
void NativeDirectoryReplayJob::finish(bool success,bool cancelled) {
    auto observer=bounded_?bounded_->latch:nullptr;
    detail::MetadataCaptureCleanupScope cleanup(observer.get());
    const auto effects=progress_.creation_attempted||progress_.metadata_attempted;
    finish_bounded();
    if(!writer_finish_observed_)try {
        auto closed=close_writer();
        if(!closed.value())remember(*closed.unavailable_detail(),true);
        else if(!*closed.value())remember_raw(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"directory_replay.writer_finish_false",true);
    }catch(...) {
        // Native writers consume their handles once even when diagnostic
        // construction throws. Never mark the operation successful here.
        finish_exception("directory_replay.writer_finish_exception");
    }
    if(stream_verifier_)try {
        auto closed=stream_verifier_->finish_io();if(!closed.value())remember(*closed.unavailable_detail(),true);
        else if(!*closed.value())remember_raw(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"directory_replay.verifier_finish_false",true);
    }catch(...) {finish_exception("directory_replay.verifier_finish_exception");}
    if(!success&&journal_file_&&journal_&&!journal_->terminal(0))try {
        auto saved=append(effects?OperationJournalState::NeedsReconciliation:cancelled?OperationJournalState::Cancelled:OperationJournalState::Failed,255);
        if(!saved.value())remember(*saved.unavailable_detail());
    }catch(...) {}
    if(journal_file_)try {
        auto closed=journal_file_->finish_io();if(!closed.value())remember(*closed.unavailable_detail(),true);
        else if(!*closed.value())remember_raw(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"directory_replay.journal_finish_false",true);
    }catch(...) {finish_exception("directory_replay.journal_finish_exception");}
    progress_.recovery_required=(effects&&!success)||progress_.finish_failure.present;
    const auto final=progress_.finish_failure.present?DirectoryReplayPhase::ReviewRequired:
        success?DirectoryReplayPhase::Complete:cancelled&&!effects?DirectoryReplayPhase::Cancelled:
        !effects&&progress_.failure.state==ObservationState::Unsupported?DirectoryReplayPhase::Unsupported:DirectoryReplayPhase::ReviewRequired;
    release_inputs();progress_.worker_drained=true;progress_.phase=final;
}
DirectoryReplayProgress NativeDirectoryReplayJob::advance(std::stop_token stop) {
    if(terminal())return progress_;
    if(stop.stop_requested()){finish(false,true);return progress_;}
    try {
        auto observer=bounded_?bounded_->latch:nullptr;
        detail::MetadataCaptureCleanupScope cleanup(observer.get());
        Observation<bool> result=Observation<bool>::available(true);
        switch(progress_.phase) {
        case DirectoryReplayPhase::Preparing:
            result=prepare(stop);if(result.value()&&*result.value())progress_.phase=bounded_?DirectoryReplayPhase::CapturingDestination:DirectoryReplayPhase::AwaitingChildren;break;
        case DirectoryReplayPhase::AwaitingChildren:
            if(children_finished_)progress_.phase=bounded_?DirectoryReplayPhase::RecheckingSource:DirectoryReplayPhase::ReplayingMetadata;return progress_;
        case DirectoryReplayPhase::ReplayingMetadata:
            result=revalidate(stop,true);if(!result.value()||!*result.value())break;
            result=replay_preflight(creator_?creator_->metadata_writer():*writer_,request_.reviewed_metadata);
            if(!result.value()||!*result.value())break;
            progress_.metadata_attempted=true;
            if(request_.reviewed_metadata.channel_coverage==DataChannelCoverage::WindowsFileStreamInfo) {
                auto& target=creator_?creator_->metadata_writer():*writer_;
                result=target.apply_replay_channels(request_.reviewed_metadata,stop);if(!result.value()||!*result.value())break;
            }
            if(!request_.reviewed_metadata.channels.empty()) {
                auto independent=create_directory_replay_verifier(destination_,cursor_,std::move(verifier_),request_.reviewed_metadata,request_.journal_root,stop);
                if(!independent.value()){result=propagate(independent);break;}stream_verifier_=std::move(independent).take_value();
            }
            result=replay_final_metadata(creator_?creator_->metadata_writer():*writer_,request_.reviewed_metadata,stop);
            if(!result.value()||!*result.value())break;
            {auto applied=(creator_?creator_->metadata_writer():*writer_).inspect_basic();
             if(!applied.value()){result=propagate(applied);break;}applied_=*applied.value();}
            result=verify_metadata_replay(creator_?creator_->metadata_writer():*writer_,request_.reviewed_metadata,applied_,stop);
            if(result.value()&&*result.value())progress_.phase=DirectoryReplayPhase::ClosingWriter;break;
        case DirectoryReplayPhase::ClosingWriter:
            result=close_writer();if(!result.value())remember(*result.unavailable_detail(),true);
            if(result.value()&&*result.value())progress_.phase=bounded_?DirectoryReplayPhase::VerifyingBoundedMetadata:DirectoryReplayPhase::Verifying;break;
        case DirectoryReplayPhase::CapturingDestination:case DirectoryReplayPhase::RecheckingSource:
        case DirectoryReplayPhase::RecheckingDestination:case DirectoryReplayPhase::ApplyingBoundedMetadata:
        case DirectoryReplayPhase::VerifyingBoundedMetadata:case DirectoryReplayPhase::RecheckingFinalSource:
            result=bounded_step(stop);break;
        case DirectoryReplayPhase::Verifying:
            result=revalidate(stop,true);if(!result.value()||!*result.value())break;
            result=stream_verifier_?verify_metadata_replay(stream_verifier_->entry(),request_.reviewed_metadata,applied_,stop):
                creator_?creator_->verify_metadata(request_.reviewed_metadata,applied_,stop):
                verify_metadata_replay(*verifier_,request_.reviewed_metadata,applied_,stop);
            if(!result.value()||!*result.value())break;
            progress_.phase=DirectoryReplayPhase::ClosingVerifier;break;
        case DirectoryReplayPhase::ClosingVerifier:
            if(stream_verifier_) {
                result=stream_verifier_->finish_io();if(!result.value()){remember(*result.unavailable_detail(),true);break;}
                if(!*result.value())break;
            }
            {auto current=destination_->inspect_basic();if(!current.value()){result=propagate(current);break;}
             const auto& basic=*current.value();const auto& expected=request_.reviewed_metadata.basic;
             if(!same(basic,applied_)||!basic.accessed.value()||!expected.accessed.value()||*basic.accessed.value()!=*expected.accessed.value()||
                !basic.modified.value()||!expected.modified.value()||*basic.modified.value()!=*expected.modified.value()||
                !basic.changed.value()||!applied_.changed.value()||*basic.changed.value()!=*applied_.changed.value()) {
                 result=reject("directory_replay.after_verifier_close",ObservationState::Changed,AdapterError::MetadataChanged);break;
             }
             if(bounded_){
                 const auto* values=bounded_->verify?bounded_->verify->observed_values():nullptr;
                 if(!values){result=reject("directory_replay.target_values_missing",ObservationState::Failed,AdapterError::InvalidNativeResult);break;}
                 verified_values_=*values;verified_values_->basic=basic;
             }}
            if(bounded_){progress_.phase=DirectoryReplayPhase::RecheckingFinalSource;break;}
            result=append(OperationJournalState::Verified,3);
            if(result.value()&&*result.value())progress_.phase=DirectoryReplayPhase::Finalizing;break;
        case DirectoryReplayPhase::Finalizing:
            if(bounded_){finish_bounded();if(progress_.finish_failure.present){finish(false,false);return progress_;}}
            result=revalidate(stop,true);if(!result.value()||!*result.value())break;
            for(auto state:{OperationJournalState::CommitIntended,OperationJournalState::DestinationCommitted,OperationJournalState::Complete}) {
                result=append(state,4);if(!result.value()||!*result.value())break;
            }
            if(result.value()&&*result.value()){finish(true,false);return progress_;}break;
        default:return progress_;
        }
        if(!result.value()||!*result.value()) {
            if(!result.value())remember(*result.unavailable_detail());
            else remember(*reject("directory_replay.unexpected_false",ObservationState::Unknown,AdapterError::InvalidNativeResult).unavailable_detail());
            finish(false,stop.stop_requested());
        }
    }catch(...) {
        remember_raw(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"directory_replay.worker_exception");
        finish(false,stop.stop_requested());
    }
    return progress_;
}
} // namespace ck::files
