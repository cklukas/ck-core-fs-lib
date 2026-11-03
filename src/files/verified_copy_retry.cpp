// SPDX-License-Identifier: LGPL-2.0-or-later
#include "verified_copy_retry.hpp"
#include <algorithm>
#include <array>

namespace ck::files {
namespace {
Observation<bool> denied(const char* operation,ObservationState state=ObservationState::Unknown,
                         AdapterError code=AdapterError::PlanDecisionStale) {
    return Observation<bool>::unavailable(state,{ErrorDomain::Adapter,static_cast<int64_t>(code),operation});
}
Observation<bool> forwarded(const UnavailableObservation& e) {
    return Observation<bool>::unavailable(e.state,e.error);
}
bool same(const ObjectIdentity* a,const ObjectIdentity* b) {
    return a&&b&&compare_identity(*a,*b)==IdentityComparison::Same;
}
}
Observation<VerifiedCopyRetryJob::Pointer> VerifiedCopyRetryJob::create(VerifiedCopyRetryRequest request) {
    if(!request.source||!request.destination||
        bool(request.original_journal_root)==bool(request.original_prepared_root)||
        bool(request.attempt_journal_root)==bool(request.attempt_prepared_root)||
        (request.original_journal_root&&!request.original_journal_root->is_valid())||
        (request.attempt_journal_root&&!request.attempt_journal_root->is_valid())||!request.original_journal_name.is_valid()||
        !request.attempt_journal_name.is_valid()||!request.staging_hint.is_valid()||!request.destination_name.is_valid()||
        !request.max_content_bytes||request.max_content_bytes>4ULL*1024*1024*1024||
        !request.max_journal_bytes||request.max_journal_bytes>4*1024*1024||!request.metadata_policy.valid()||
        (bool(request.candidate)!=(request.candidate_prefix_bytes!=0))||
        request.candidate_prefix_bytes>request.max_content_bytes||
        (request.destination_address&&!request.destination_address->is_valid())||
        std::all_of(request.attempt_id.bytes.begin(),request.attempt_id.bytes.end(),[](std::byte b){return b==std::byte{};}))
        return Observation<Pointer>::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::PlanInvalid),"copy_retry.request"});
    return Observation<Pointer>::available(Pointer(new VerifiedCopyRetryJob(std::move(request))));
}
VerifiedCopyRetryJob::~VerifiedCopyRetryJob()=default;
VerifiedCopyRetryState VerifiedCopyRetryJob::reject(const UnavailableObservation& e) {
    failure_=e;phase_=VerifiedCopyRetryState::ReviewRequired;return phase_;
}
Observation<bool> VerifiedCopyRetryJob::load_original_step() {
    if(!original_file_) {
        auto valid=revalidate_roots();if(!valid.value()||!*valid.value())return valid;
        auto opened=request_.original_prepared_root?
            request_.original_prepared_root->open_journal(request_.original_journal_name,false):
            open_native_operation_journal_file(*request_.original_journal_root,request_.original_journal_name,false);
        if(!opened.value())return forwarded(*opened.unavailable_detail());
        original_file_=std::move(opened).take_value();
        auto size=original_file_->size();if(!size.value())return forwarded(*size.unavailable_detail());
        if(!*size.value()||*size.value()>request_.max_journal_bytes)
            return denied("copy_retry.journal_bound",ObservationState::Unknown,AdapterError::InventoryLimit);
        original_size_=*size.value();original_bytes_.reserve(static_cast<size_t>(original_size_));
    }
    std::array<std::byte,64*1024> bytes{};
    auto count=original_file_->read_at(original_bytes_.size(),std::span(bytes).first(
        static_cast<size_t>(std::min<uint64_t>(bytes.size(),original_size_-original_bytes_.size()))));
    if(!count.value())return forwarded(*count.unavailable_detail());
    if(!*count.value()||*count.value()>std::min<uint64_t>(bytes.size(),original_size_-original_bytes_.size()))
        return denied("copy_retry.journal_read",ObservationState::Changed);
    original_bytes_.insert(original_bytes_.end(),bytes.begin(),bytes.begin()+static_cast<ptrdiff_t>(*count.value()));
    if(original_bytes_.size()!=original_size_)return Observation<bool>::available(false);
    auto size=original_file_->size();if(!size.value())return forwarded(*size.unavailable_detail());
    if(*size.value()!=original_size_)return denied("copy_retry.journal_changed",ObservationState::Changed);
    OperationJournalCodecLimits codec;codec.max_bytes=request_.max_journal_bytes;
    OperationJournalLimits limits;limits.max_items=256;limits.max_records=65536;
    auto decoded=decode_operation_journal(original_bytes_,limits,codec);
    if(!decoded.value())return forwarded(*decoded.unavailable_detail());
    if(decoded.value()->tail)return denied("copy_retry.journal_tail");
    original_journal_=decoded.value()->journal;
    Sha256 origin;origin.update(original_bytes_);origin_digest_=origin.digest();
    return validate_history();
}
Observation<bool> VerifiedCopyRetryJob::validate_history() {
    if(!original_journal_||original_journal_->operation()!=FileOperation::Copy||
        original_journal_->id()==request_.attempt_id||!original_journal_->state(request_.original_item))
        return denied("copy_retry.original_operation");
    // Inspect every transition. Failed after CommitIntended is still ambiguous.
    for(const auto& r:original_journal_->records())if(r.item==request_.original_item) {
        switch(r.state) {
        case OperationJournalState::Planned:case OperationJournalState::Prepared:case OperationJournalState::Copied:
        case OperationJournalState::Verified:case OperationJournalState::Failed:case OperationJournalState::Cancelled:break;
        default:return denied("copy_retry.publication_history");
        }
        if(!r.evidence.empty()) {
            // V1 retry provenance is diagnostic, not a native operation fact.
            // Only the first Planned record may contain this exact envelope.
            if(r.state==OperationJournalState::Planned&&
                ((r.evidence.size()==92&&r.evidence[3]==std::byte{1})||
                 (r.evidence.size()==164&&r.evidence[3]==std::byte{2}))&&
                r.evidence[0]==std::byte{'C'}&&r.evidence[1]==std::byte{'K'}&&
                r.evidence[2]==std::byte{'R'})continue;
            auto evidence=decode_native_operation_recovery_evidence(r.evidence,{256*1024,32768});
            if(!evidence.value())return forwarded(*evidence.unavailable_detail());
            if(evidence.value()->staging_namespace!=StagingNamespace::Named&&
                evidence.value()->staging_namespace!=StagingNamespace::Anonymous)
                return denied("copy_retry.unknown_namespace");
            if(original_evidence_&&(
                original_evidence_->source_parent_identity!=evidence.value()->source_parent_identity||
                original_evidence_->source_identity!=evidence.value()->source_identity||
                original_evidence_->destination_identity!=evidence.value()->destination_identity||
                original_evidence_->destination_name!=evidence.value()->destination_name||
                original_evidence_->staging_name!=evidence.value()->staging_name||
                (original_evidence_->content_digest&&evidence.value()->content_digest&&
                 original_evidence_->content_digest!=evidence.value()->content_digest)||
                (original_evidence_->staging_identity&&evidence.value()->staging_identity&&
                 original_evidence_->staging_identity!=evidence.value()->staging_identity)))
                return denied("copy_retry.inconsistent_history");
            auto next=std::move(evidence).take_value();
            if(original_evidence_) {
                if(!next.content_digest)next.content_digest=original_evidence_->content_digest;
                if(!next.staging_identity)next.staging_identity=original_evidence_->staging_identity;
            }
            original_evidence_=std::move(next);
        }
    }
    if(!original_evidence_)return denied("copy_retry.missing_native_evidence");
    if(original_evidence_->destination_name!=request_.destination_name||
        !request_.source->metadata().identity.value()||!request_.source->parent_identity().value()||
        !original_evidence_->source_identity.matches_live(*request_.source->metadata().identity.value())||
        !original_evidence_->source_parent_identity.matches_live(*request_.source->parent_identity().value()))
        return denied("copy_retry.selected_source",ObservationState::Changed);
    auto dest=request_.destination->inspect_basic();if(!dest.value())return forwarded(*dest.unavailable_detail());
    if(!dest.value()->identity.value()||!original_evidence_->destination_identity.matches_live(*dest.value()->identity.value()))
        return denied("copy_retry.selected_destination",ObservationState::Changed);
    destination_identity_=*dest.value()->identity.value();
    return check_destination();
}
Observation<bool> VerifiedCopyRetryJob::revalidate_roots() const {
    for(const auto& root:{request_.original_prepared_root,request_.attempt_prepared_root})if(root) {
        auto valid=root->revalidate();if(!valid.value())return forwarded(*valid.unavailable_detail());
        if(!*valid.value())return denied("copy_retry.prepared_root_false",ObservationState::Changed);
    }
    return Observation<bool>::available(true);
}
Observation<bool> VerifiedCopyRetryJob::check_original() const {
    auto valid=revalidate_roots();if(!valid.value()||!*valid.value())return valid;
    auto size=original_file_->size();if(!size.value())return forwarded(*size.unavailable_detail());
    if(*size.value()!=original_size_)return denied("copy_retry.journal_changed",ObservationState::Changed);
    std::array<std::byte,64*1024> bytes{};
    size_t offset=0;
    while(offset<original_bytes_.size()) {
        const auto wanted=std::min(bytes.size(),original_bytes_.size()-offset);
        auto count=original_file_->read_at(offset,std::span(bytes).first(wanted));
        if(!count.value())return forwarded(*count.unavailable_detail());
        if(!*count.value()||*count.value()>wanted||!std::equal(bytes.begin(),bytes.begin()+static_cast<ptrdiff_t>(*count.value()),original_bytes_.begin()+static_cast<ptrdiff_t>(offset)))
            return denied("copy_retry.journal_changed",ObservationState::Changed);
        offset+=*count.value();
    }
    size=original_file_->size();if(!size.value())return forwarded(*size.unavailable_detail());
    return *size.value()==original_size_?Observation<bool>::available(true):denied("copy_retry.journal_changed",ObservationState::Changed);
}
Observation<bool> VerifiedCopyRetryJob::check_destination() const {
    auto current=request_.destination->inspect_basic();if(!current.value())return forwarded(*current.unavailable_detail());
    if(!same(current.value()->identity.value(),destination_identity_?&*destination_identity_:nullptr))
        return denied("copy_retry.destination_identity",ObservationState::Changed);
    auto lookup=request_.destination->lookup_child(request_.destination_name,ChildLookupMode::NativeDefault);
    if(!lookup.value())return forwarded(*lookup.unavailable_detail());
    if(lookup.value()->state()!=ChildLookupState::Missing||!lookup.value()->missing_witness())
        return denied("copy_retry.destination_exists",ObservationState::Changed);
    return Observation<bool>::available(true);
}
Observation<bool> VerifiedCopyRetryJob::check_membership(std::stop_token stop) const {
    auto fresh=request_.source->refresh(stop);if(!fresh.value())return forwarded(*fresh.unavailable_detail());
    if(!(*fresh.value())->continues(*request_.source)||
        !same((*fresh.value())->metadata().identity.value(),readable_source_->metadata().identity.value()))
        return denied("copy_retry.source_membership",ObservationState::Changed);
    if(request_.candidate) {
        auto candidate=request_.candidate->refresh(stop);if(!candidate.value())return forwarded(*candidate.unavailable_detail());
        if(!(*candidate.value())->continues(*request_.candidate)||
            !same((*candidate.value())->metadata().identity.value(),readable_candidate_->metadata().identity.value()))
            return denied("copy_retry.candidate_membership",ObservationState::Changed);
        auto m=readable_candidate_->inspect_basic();if(!m.value())return forwarded(*m.unavailable_detail());
        if(!m.value()->logical_size.value()||*m.value()->logical_size.value()<request_.candidate_prefix_bytes||
            !m.value()->kind.value()||*m.value()->kind.value()!=ObjectKind::RegularFile)
            return denied("copy_retry.candidate_size",ObservationState::Changed);
    }
    return readable_source_->verify_metadata_source(*metadata_->captured_metadata(),stop);
}
Observation<bool> VerifiedCopyRetryJob::source_step(std::stop_token stop) {
    if(!readable_source_) {
        auto source=HeldChild::observe_with_access(request_.source->parent(),request_.source->name(),EntryAccess::ContentRead,stop);
        if(!source.value())return forwarded(*source.unavailable_detail());
        if(!same((*source.value())->metadata().identity.value(),request_.source->metadata().identity.value()))
            return denied("copy_retry.source_changed",ObservationState::Changed);
        readable_source_=std::move(source).take_value();
        auto preservation=RegularMetadataPreservation::create_with_policy(readable_source_,false,request_.metadata_policy,stop);
        if(!preservation.value())return forwarded(*preservation.unavailable_detail());
        metadata_=std::move(preservation).take_value();
        if(!metadata_->captured_metadata())return denied("copy_retry.metadata_missing");
        const auto& m=readable_source_->metadata();
        if(!m.logical_size.value()||!m.kind.value()||*m.kind.value()!=ObjectKind::RegularFile||*m.logical_size.value()>request_.max_content_bytes)
            return denied("copy_retry.source_bound",ObservationState::Unknown,AdapterError::InventoryLimit);
        source_size_=*m.logical_size.value();
        if(request_.candidate_prefix_bytes>source_size_)return denied("copy_retry.prefix_bound",ObservationState::Changed);
        if(request_.candidate) {
            auto candidate=HeldChild::observe_with_access(request_.candidate->parent(),request_.candidate->name(),EntryAccess::ContentRead,stop);
            if(!candidate.value())return forwarded(*candidate.unavailable_detail());
            if(!same((*candidate.value())->metadata().identity.value(),request_.candidate->metadata().identity.value()))
                return denied("copy_retry.candidate_changed",ObservationState::Changed);
            readable_candidate_=std::move(candidate).take_value();
            const auto& cm=readable_candidate_->metadata();
            if(!cm.kind.value()||*cm.kind.value()!=ObjectKind::RegularFile||!cm.logical_size.value()||
                *cm.logical_size.value()<request_.candidate_prefix_bytes)
                return denied("copy_retry.candidate_bound",ObservationState::Changed);
        }
    }
    auto content=readable_source_->read_content({64*1024},source_offset_,stop);
    if(!content.value())return forwarded(*content.unavailable_detail());
    if(content.value()->bytes.size()>64*1024||content.value()->bytes.size()>source_size_-source_offset_)
        return denied("copy_retry.source_size",ObservationState::Changed);
    if(source_offset_<request_.candidate_prefix_bytes) {
        const auto wanted=static_cast<size_t>(std::min<uint64_t>(content.value()->bytes.size(),request_.candidate_prefix_bytes-source_offset_));
        auto candidate=readable_candidate_->read_content({wanted},source_offset_,stop);
        if(!candidate.value())return forwarded(*candidate.unavailable_detail());
        if(candidate.value()->bytes.size()!=wanted||!std::equal(candidate.value()->bytes.begin(),candidate.value()->bytes.end(),content.value()->bytes.begin()))
            return denied("copy_retry.prefix_mismatch",ObservationState::Changed);
    }
    source_hash_.update(content.value()->bytes);source_offset_+=content.value()->bytes.size();
    if(!content.value()->complete) {
        if(content.value()->bytes.empty())return denied("copy_retry.source_no_progress");
        return Observation<bool>::available(false);
    }
    if(source_offset_!=source_size_)return denied("copy_retry.source_size",ObservationState::Changed);
    const auto digest=source_hash_.digest();
    if((reviewed_digest_&&digest!=*reviewed_digest_)||
        (original_evidence_->content_digest&&digest!=*original_evidence_->content_digest))
        return denied("copy_retry.source_digest",ObservationState::Changed);
    auto member=check_membership(stop);if(!member.value())return member;
    if(!*member.value())return denied("copy_retry.source_metadata_false",ObservationState::Changed,AdapterError::MetadataChanged);
    auto original=check_original();if(!original.value())return original;
    if(!*original.value())return denied("copy_retry.original_proof_false",ObservationState::Changed);
    auto dest=check_destination();if(!dest.value())return dest;
    if(!*dest.value())return denied("copy_retry.destination_proof_false",ObservationState::Changed);
    if(!reviewed_digest_)reviewed_digest_=digest;
    return Observation<bool>::available(true);
}
Observation<bool> VerifiedCopyRetryJob::approve() {
    if(phase_!=VerifiedCopyRetryState::AwaitingReview)return denied("copy_retry.review_required");
    phase_=VerifiedCopyRetryState::RevalidatingSource;source_offset_=0;source_hash_.reset();
    return Observation<bool>::available(true);
}
Observation<bool> VerifiedCopyRetryJob::begin_copy(std::stop_token stop) {
    auto valid=revalidate_roots();if(!valid.value()||!*valid.value())return valid;
    auto opened=request_.attempt_prepared_root?
        request_.attempt_prepared_root->open_journal(request_.attempt_journal_name,true):
        open_native_operation_journal_file(*request_.attempt_journal_root,request_.attempt_journal_name,true);
    if(!opened.value())return forwarded(*opened.unavailable_detail());
    attempt_file_=std::shared_ptr<OperationJournalFile>(std::move(opened).take_value());
    auto journal=OperationJournal::create(FileOperation::Copy,request_.attempt_id);
    if(!journal.value())return forwarded(*journal.unavailable_detail());
    // Durable provenance is diagnostic, never a delete/publication capability.
    // Preserve the complete original journal and its digest without modifying it.
    std::vector<std::byte> provenance{std::byte{'C'},std::byte{'K'},std::byte{'R'},std::byte{2}};
    provenance.insert(provenance.end(),original_journal_->id().bytes.begin(),original_journal_->id().bytes.end());
    provenance.insert(provenance.end(),origin_digest_->begin(),origin_digest_->end());
    for(unsigned i=0;i<8;++i)provenance.push_back(std::byte((static_cast<uint64_t>(request_.original_item)>>(8*i))&255));
    provenance.insert(provenance.end(),reviewed_digest_->begin(),reviewed_digest_->end());
    const auto integer=[&provenance](uint64_t value,unsigned bytes) {
        for(unsigned i=0;i<bytes;++i)provenance.push_back(std::byte((value>>(8*i))&255));
    };
    integer(request_.candidate_prefix_bytes,8);
    const auto candidate=readable_candidate_?NativeDurableIdentity::from_live(*readable_candidate_->metadata().identity.value()):std::nullopt;
    integer(candidate?static_cast<uint32_t>(candidate->scheme):0,4);integer(candidate&&candidate->generation?1:0,4);
    const std::array<std::byte,16> absent{};
    const auto& volume=candidate?candidate->volume.bytes:absent;
    const auto& object=candidate?candidate->object.bytes:absent;
    provenance.insert(provenance.end(),volume.begin(),volume.end());provenance.insert(provenance.end(),object.begin(),object.end());
    integer(candidate?candidate->generation.value_or(0):0,8);
    integer(request_.metadata_policy.version,4);integer(static_cast<uint32_t>(request_.metadata_policy.scope),4);
    integer(static_cast<uint32_t>(request_.metadata_policy.ownership),4);integer(request_.metadata_policy.allow_privilege_metadata?1:0,4);
    auto appended=append_operation_journal_file(*attempt_file_,**journal.value(),{1,0,OperationJournalState::Planned,std::move(provenance)});
    if(!appended.value()||!*appended.value())return appended;
    NativeOperationCopyRequest copy_request{*journal.value(),attempt_file_,0,readable_source_->parent(),
        *readable_source_->parent_identity().value(),readable_source_->name(),*readable_source_->metadata().identity.value(),
        request_.destination,*destination_identity_,request_.destination_address,request_.staging_hint,request_.destination_name,
        {}, {},FileOperation::Copy,{}, {}, {}, {}, {}};
    copy_request.copy_limits.max_bytes=request_.max_content_bytes;
    copy_request.prepare_metadata=[this](OpenedEntry& entry,std::stop_token token){return metadata_->prepare(entry,token);};
    copy_request.verify_metadata_before_publication=[this](OpenedEntry& entry,std::stop_token token){
        auto original=check_original();if(!original.value()||!*original.value())return original;
        auto member=check_membership(token);if(!member.value()||!*member.value())return member;
        auto dest=check_destination();if(!dest.value()||!*dest.value())return dest;
        return metadata_->verify(entry,token);
    };
    copy_request.reviewed_content_digest=reviewed_digest_;
    copy_request.prepare_stream=[this](OpenedEntry& source,OpenedEntry& stage,StreamCopyLimits limits) {
        attempt_stage_=&stage;
        StreamCopyRequest stream;
        stream.limits=limits;
        stream.read_source=[this,&source](uint64_t offset,size_t maximum,std::stop_token token) {
            using R=Observation<ContentRead>;
            if(offset>source_size_)return R::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::MetadataChanged),"copy_retry.stream_offset"});
            const bool prefix=offset<request_.candidate_prefix_bytes;
            auto count=std::min<uint64_t>(maximum,source_size_-offset);
            if(prefix)count=std::min(count,request_.candidate_prefix_bytes-offset);
            if(!count)return R::available({{},offset==source_size_});
            auto read=prefix?readable_candidate_->read_content({static_cast<size_t>(count)},offset,token):
                source.read_content({static_cast<size_t>(count)},offset,token);
            if(!read.value())return R::unavailable(read.state(),read.unavailable_detail()->error);
            if(read.value()->bytes.empty()||read.value()->bytes.size()>count)
                return R::unavailable(ObservationState::Changed,
                    {ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::MetadataChanged),"copy_retry.stream_short"});
            // Candidate EOF is a prefix boundary, never the whole-copy EOF.
            auto content=std::move(read).take_value();
            content.complete=offset+content.bytes.size()==source_size_;
            if(prefix)copied_prefix_bytes_+=content.bytes.size();
            return R::available(std::move(content));
        };
        stream.write_destination=[&stage](uint64_t offset,std::span<const std::byte> bytes,std::stop_token token){return stage.write_content(offset,bytes,{},token);};
        stream.read_destination=[&stage](uint64_t offset,size_t count,std::stop_token token){return stage.read_content({count},offset,token);};
        stream.flush_destination=[&stage](std::stop_token){return stage.flush_content();};
        return StreamCopyJob::create(std::move(stream));
    };
    auto created=NativeOperationCopyJob::create(std::move(copy_request));
    if(!created.value())return forwarded(*created.unavailable_detail());
    copy_=std::move(created).take_value();
    (void)stop;return Observation<bool>::available(true);
}
VerifiedCopyRetryState VerifiedCopyRetryJob::advance(std::stop_token stop) {
    if(phase_==VerifiedCopyRetryState::Complete||
        phase_==VerifiedCopyRetryState::ReviewRequired||phase_==VerifiedCopyRetryState::Cancelled)return phase_;
    if(stop.stop_requested()&&phase_!=VerifiedCopyRetryState::Copying) {
        phase_=VerifiedCopyRetryState::Cancelled;return phase_;
    }
    if(phase_==VerifiedCopyRetryState::AwaitingReview)return phase_;
    if(phase_==VerifiedCopyRetryState::Copying) {
        const auto state=copy_->advance(stop);
        if(state==OperationExecutionState::Complete)phase_=VerifiedCopyRetryState::Complete;
        else if(state==OperationExecutionState::Cancelled)phase_=VerifiedCopyRetryState::Cancelled;
        else if(state==OperationExecutionState::Failed||state==OperationExecutionState::NeedsReconciliation||state==OperationExecutionState::RetainedSource) {
            phase_=VerifiedCopyRetryState::ReviewRequired;failure_=copy_->result().failure;
        }
        return phase_;
    }
    auto result=phase_==VerifiedCopyRetryState::LoadingJournal?load_original_step():source_step(stop);
    if(!result.value())return reject(*result.unavailable_detail());
    if(!*result.value())return phase_;
    if(phase_==VerifiedCopyRetryState::LoadingJournal)phase_=VerifiedCopyRetryState::ReviewingSource;
    else if(phase_==VerifiedCopyRetryState::ReviewingSource)phase_=VerifiedCopyRetryState::AwaitingReview;
    else {
        result=begin_copy(stop);if(!result.value())return reject(*result.unavailable_detail());
        if(!*result.value())return reject(*denied("copy_retry.creation_failed").unavailable_detail());
        phase_=VerifiedCopyRetryState::Copying;
    }
    return phase_;
}
Observation<bool> VerifiedCopyRetryJob::finish_io() {
    if(finished_)return finish_failure_?forwarded(*finish_failure_):Observation<bool>::available(true);
    // Finish both owners even when the first reports a delayed error.
    const auto record=[this](ObservationState state,ErrorDomain domain,int64_t code,std::string_view operation) {
        if(!finish_failure_) {
            const auto count=std::min(operation.size(),finish_operation_.size()-1);
            std::copy_n(operation.data(),count,finish_operation_.data());
            finish_failure_=UnavailableObservation{state,{domain,code,{}}};
        }
    };
    if(attempt_stage_) {
        try {
            auto result=attempt_stage_->finish_content_writes();
            if(!result.value()) {const auto& e=*result.unavailable_detail();record(e.state,e.error.domain,e.error.code,e.error.operation);}
            else if(!*result.value())record(ObservationState::Failed,ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidNativeResult),"copy_retry.finish_stage_result");
        } catch(...) {record(ObservationState::Failed,ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidNativeResult),"copy_retry.finish_stage_exception");}
    }
    for(auto* file:{original_file_.get(),attempt_file_.get()})if(file) {
        try {
            auto result=file->finish_io();
            if(!result.value()) {const auto& e=*result.unavailable_detail();record(e.state,e.error.domain,e.error.code,e.error.operation);}
            else if(!*result.value())record(ObservationState::Failed,ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidNativeResult),"copy_retry.finish_journal_result");
        } catch(...) {record(ObservationState::Failed,ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidNativeResult),"copy_retry.finish_journal_exception");}
    }
    finished_=true;
    if(finish_failure_) {phase_=VerifiedCopyRetryState::ReviewRequired;failure_=finish_failure_;return forwarded(*finish_failure_);}
    return Observation<bool>::available(true);
}
OperationProgress VerifiedCopyRetryJob::progress() const noexcept {
    return copy_?copy_->progress():OperationProgress{OperationExecutionState::Copying,0,source_size_};
}
} // namespace ck::files
