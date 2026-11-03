// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_regular_metadata_job.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "sha256.hpp"
#include "attributes.hpp"
#include <algorithm>
#include <cstring>

namespace ck::files {
namespace {
using Step=OperationMetadataStep;
using State=OperationMetadataState;
template<class T>Observation<T> reject(const char* op,ObservationState state=ObservationState::Changed,
    AdapterError code=AdapterError::MetadataChanged) {
    return Observation<T>::unavailable(state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),op});
}
template<class T,class U>Observation<T> propagate(const Observation<U>& result) {
    const auto& e=*result.unavailable_detail();return Observation<T>::unavailable(e.state,e.error);
}
Observation<Step> pending(){return Observation<Step>::available(Step::Pending);}
Observation<Step> complete(){return Observation<Step>::available(Step::Complete);}
bool same(const ObjectIdentity& a,const Observation<ObjectIdentity>& b) {
    return b.value()&&compare_identity(a,*b.value())==IdentityComparison::Same;
}
bool privileged(const AttributeValue& value) {
    if(attribute_role(value.identifier,value.native_flags.value()?*value.native_flags.value():0)==AttributeRole::Security)return true;
    const auto* name=value.identifier.posix_bytes();
    return name&&(name->starts_with("security.")||name->starts_with("trusted.")||*name=="com.apple.macl"||*name=="com.apple.rootless");
}
void remember(detail::PreparedJournalConsumerFailure& first,bool& present,const UnavailableObservation& e)noexcept {
    if(present)return;present=true;first.state=e.state;first.domain=e.error.domain;first.code=e.error.code;
    const auto n=std::min(e.error.operation.size(),first.operation.size()-1);
    if(n)std::memcpy(first.operation.data(),e.error.operation.data(),n);first.operation[n]=0;
}
Observation<bool> failure_result(const detail::PreparedJournalConsumerFailure& e) {
    try{return Observation<bool>::unavailable(e.state,{e.domain,e.code,e.operation.data()});}
    catch(const std::bad_alloc&){return Observation<bool>::unavailable(e.state,{e.domain,e.code,{}});}
}
enum class Phase { SourceBefore,Preflight,OpenStream,ReadStream,WriteStream,CloseStream,OpenReader,
    AttributeCatalog,RemoveAttributes,OrdinaryAttributes,Ownership,InitialBasic,Security,PrivilegedAttributes,
    FinalTimes,ValuesBefore,VerifyStreams,ValuesAfter,SourceAfter,Flush,FinalValues,Complete };
class StreamLatch final:public MetadataCaptureFailureLatch {
public:
    explicit StreamLatch(PreparedJournalRoot::Pointer root):root_(std::move(root)){}
    void record_first(MetadataCaptureCleanupError e)const noexcept override {
        detail::record_prepared_journal_consumer_failure(*root_,e.state,e.domain,e.code,e.operation);
    }
private:PreparedJournalRoot::Pointer root_;
};
}
struct NativeRegularMetadataJob::Impl final:MetadataCaptureFailureLatch {
    explicit Impl(NativeRegularMetadataRequest value):request(std::move(value)),stream_latch(std::make_shared<StreamLatch>(request.journal_root)){}
    NativeRegularMetadataRequest request;
    std::shared_ptr<const MetadataCaptureFailureLatch> stream_latch;
    NativeRegularMetadataProgress progress;
    Phase phase=Phase::SourceBefore;
    BasicMetadata target_before,applied;
    std::unique_ptr<detail::NativeMetadataStreamWriter> writer;
    std::vector<std::unique_ptr<detail::NativeMetadataStreamReader>> readers;
    std::vector<std::byte> pending_bytes;
    std::optional<AttributeCatalog> attributes;
    std::size_t index=0,written=0;
    std::uint64_t offset=0;
    Sha256 hash;
    bool source_started=false,failed=false,has_failure=false,has_close_failure=false;
    detail::PreparedJournalConsumerFailure failure,close_failure;
    void record_first(MetadataCaptureCleanupError e)const noexcept override {
        auto& self=*const_cast<Impl*>(this);
        if(!self.has_close_failure){self.has_close_failure=true;self.close_failure.state=e.state;
            self.close_failure.domain=e.domain;self.close_failure.code=e.code;
            const auto n=std::min(std::strlen(e.operation),self.close_failure.operation.size()-1);
            std::memcpy(self.close_failure.operation.data(),e.operation,n);self.close_failure.operation[n]=0;}
        if(request.journal_root)detail::record_prepared_journal_consumer_failure(*request.journal_root,e.state,e.domain,e.code,e.operation);
    }
    void root_failure()noexcept {
        detail::PreparedJournalConsumerFailure first;
        if(request.journal_root&&detail::read_prepared_journal_consumer_failure(*request.journal_root,first)) {
            close_failure=first;has_close_failure=true;
        }
    }
    Observation<bool> clean() {
        root_failure();return has_close_failure?failure_result(close_failure):Observation<bool>::available(true);
    }
    Observation<bool> membership(std::stop_token stop) {
        auto result=clean();if(!result.value()||!*result.value())return result;
        if(!request.source||request.source->io_finished())return reject<bool>("regular_metadata_job.closed_source",ObservationState::Changed,AdapterError::InvalidAccess);
        result=request.journal_root->revalidate();if(!result.value()||!*result.value())return result;
        return request.verify_membership(stop);
    }
    void record_close(const Observation<bool>& result)noexcept {
        if(const auto* e=result.unavailable_detail()) {
            remember(close_failure,has_close_failure,*e);
            if(request.journal_root)detail::record_prepared_journal_consumer_failure(*request.journal_root,e->state,e->error.domain,e->error.code,e->error.operation);
        }else if(!*result.value())record_first({ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"regular_metadata_job.finish_false"});
    }
    template<class F>void close(F&& callback)noexcept {
        try{record_close(callback());}
        catch(...){root_failure();if(!has_close_failure)record_first({ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"regular_metadata_job.finish_exception"});}
    }
    const MetadataReplaySnapshot& snapshot()const{return request.source->snapshot();}
    State expected_state()const noexcept {
        if(phase==Phase::SourceBefore)return State::ApplyingTraversal;
        if(phase<Phase::FinalTimes)return State::ApplyingSecurity;
        if(phase<Phase::VerifyStreams)return State::ApplyingTimes;
        return State::Flushing;
    }
    Observation<Step> revalidate(Phase next,std::stop_token stop) {
        auto result=request.revalidate_source(!source_started,stop);source_started=true;
        if(!result.value())return result;
        if(*result.value()==Step::Pending)return pending();
        if(*result.value()!=Step::Complete)return reject<Step>("regular_metadata_job.source_step",ObservationState::Failed,AdapterError::InvalidNativeResult);
        source_started=false;phase=next;return pending();
    }
    Observation<bool> source_channel(const MetadataReplayChannelSnapshot& expected)const {
        if(!expected.source)return reject<bool>("regular_metadata_job.source_reader",ObservationState::Failed,AdapterError::InvalidNativeResult);
        auto state=expected.source->inspect();if(!state.value())return propagate<bool>(state);
        return state.value()->identifier==expected.identifier&&state.value()->logical_size==expected.logical_size&&
            same(state.value()->owner,snapshot().basic.identity)?Observation<bool>::available(true):reject<bool>("regular_metadata_job.source_channel_changed");
    }
    Observation<Step> step(State state,std::stop_token stop,std::shared_ptr<const MetadataCaptureFailureLatch> latch) {
        if(state!=expected_state())return reject<Step>("regular_metadata_job.phase_order",ObservationState::Failed,AdapterError::InvalidNativeResult);
        auto checked=membership(stop);if(!checked.value())return propagate<Step>(checked);
        if(!*checked.value())return reject<Step>("regular_metadata_job.membership_false");
        const auto& s=snapshot();auto& target=*request.target;
        auto result=Observation<bool>::available(true);
        switch(phase) {
        case Phase::SourceBefore:{auto r=revalidate(Phase::Preflight,stop);return r.value()&&phase==Phase::Preflight?complete():r;}
        case Phase::Preflight:
            result=detail::qualify_native_metadata_target(target,*request.source);
            if(result.value()&&*result.value()&&s.policy.scope==RegularMetadataScope::CompleteMetadataV1)
                result=target.preflight_metadata_security_coverage(s);
            if(result.value()&&*result.value()){auto now=target.inspect_basic();if(!now.value())return propagate<Step>(now);target_before=*now.value();phase=Phase::OpenStream;}
            break;
        case Phase::OpenStream:
            if(index==s.channels.size()){index=0;phase=Phase::AttributeCatalog;break;}
            result=source_channel(s.channels[index]);if(!result.value()||!*result.value())break;
            {progress.metadata_effects=true;
             auto opened=detail::open_native_metadata_stream_writer(target,request.source,s.channels[index].identifier,std::move(latch));
             if(!opened.value())return propagate<Step>(opened);
             writer=std::move(opened).take_value();offset=0;written=0;hash=Sha256{};phase=Phase::ReadStream;}
            break;
        case Phase::ReadStream:{const auto& channel=s.channels[index];
            if(offset==channel.logical_size){
                if(hash.digest()!=channel.digest)return reject<Step>("regular_metadata_job.source_digest");
                result=source_channel(channel);if(result.value()&&*result.value())phase=Phase::CloseStream;break;
            }
            auto limits=request.read_limits;limits.max_bytes=static_cast<std::size_t>(std::min<std::uint64_t>(limits.max_bytes,channel.logical_size-offset));
            ++progress.source_read_calls;auto data=channel.source->read_content(limits,offset,stop);
            if(!data.value())return propagate<Step>(data);
            if(data.value()->bytes.empty()||data.value()->bytes.size()>limits.max_bytes||
               data.value()->complete!=(data.value()->bytes.size()==channel.logical_size-offset))return reject<Step>("regular_metadata_job.source_read_shape");
            progress.source_read_bytes+=data.value()->bytes.size();pending_bytes=std::move(data).take_value().bytes;
            hash.update(pending_bytes);written=0;phase=Phase::WriteStream;break;}
        case Phase::WriteStream:{++progress.target_write_calls;
            auto count=writer->write(offset+written,std::span(pending_bytes).subspan(written));if(!count.value())return propagate<Step>(count);
            if(!*count.value()||*count.value()>pending_bytes.size()-written)return reject<Step>("regular_metadata_job.write_progress",ObservationState::Unknown,AdapterError::InvalidNativeResult);
            written+=*count.value();progress.target_write_bytes+=*count.value();
            if(written==pending_bytes.size()){offset+=written;pending_bytes.clear();phase=Phase::ReadStream;}break;}
        case Phase::CloseStream:
            close([&]{return writer->finish_io();});writer.reset();
            if(has_close_failure)return propagate<Step>(failure_result(close_failure));phase=Phase::OpenReader;break;
        case Phase::OpenReader:{auto reader=detail::open_native_metadata_stream_reader(target,request.source,s.channels[index].identifier,std::move(latch));
            if(!reader.value())return propagate<Step>(reader);readers.push_back(std::move(reader).take_value());++index;phase=Phase::OpenStream;break;}
        case Phase::AttributeCatalog:{auto catalog=target.inspect_attributes(s.policy.limits);if(!catalog.value())return propagate<Step>(catalog);
            if(!target_before.identity.value()||!same(*target_before.identity.value(),catalog.value()->owner))return reject<Step>("regular_metadata_job.target_attribute_owner");
            attributes=std::move(catalog).take_value();index=0;phase=Phase::RemoveAttributes;break;}
        case Phase::RemoveAttributes:
            if(index==attributes->attributes.size()){index=0;phase=Phase::OrdinaryAttributes;break;}
            if(std::none_of(s.attributes.begin(),s.attributes.end(),[&](const auto& a){return a.identifier==attributes->attributes[index].identifier;})) {
                progress.metadata_effects=true;result=target.remove_replay_attribute(attributes->attributes[index].identifier,s.policy);
            }
            if(result.value()&&*result.value())++index;break;
        case Phase::OrdinaryAttributes:case Phase::PrivilegedAttributes:{const bool privileged_phase=phase==Phase::PrivilegedAttributes;
            if(index==s.attributes.size()){index=0;if(privileged_phase){phase=Phase::FinalTimes;return complete();}phase=Phase::Ownership;break;}
            if(privileged(s.attributes[index])==privileged_phase){progress.metadata_effects=true;result=target.apply_replay_attribute(s.attributes[index],s.policy);}
            if(result.value()&&*result.value())++index;break;}
        case Phase::Ownership:progress.metadata_effects=true;result=target.apply_replay_ownership(s.basic,s.policy);
            if(result.value()&&*result.value())phase=Phase::InitialBasic;break;
        case Phase::InitialBasic:progress.metadata_effects=true;result=target.apply_replay_basic(s.basic,s.policy);
            if(result.value()&&*result.value()){index=0;phase=Phase::Security;}break;
        case Phase::Security:
            if(index==s.security.size()){index=0;phase=Phase::PrivilegedAttributes;break;}
            progress.metadata_effects=true;result=target.apply_replay_security(s.security[index],s.policy);
            if(result.value()&&*result.value())++index;break;
        case Phase::FinalTimes:
            progress.metadata_effects=true;result=target.apply_replay_basic(s.basic,s.policy);
            if(result.value()&&*result.value()){auto now=target.inspect_basic();if(!now.value())return propagate<Step>(now);applied=*now.value();phase=Phase::ValuesBefore;}break;
        case Phase::ValuesBefore:
            result=verify_metadata_replay_values(target,s,applied,stop);
            if(result.value()&&*result.value()){index=0;offset=0;hash=Sha256{};phase=Phase::VerifyStreams;return complete();}break;
        case Phase::VerifyStreams:{
            if(index==s.channels.size()){phase=Phase::ValuesAfter;break;}
            const auto& expected=s.channels[index];auto native=readers[index]->inspect();if(!native.value())return propagate<Step>(native);
            if(!target_before.identity.value()||!same(native.value()->owner,target_before.identity)||native.value()->identifier!=expected.identifier||native.value()->logical_size!=expected.logical_size)
                return reject<Step>("regular_metadata_job.target_stream_binding");
            if(offset==expected.logical_size){if(hash.digest()!=expected.digest)return reject<Step>("regular_metadata_job.target_stream_digest");
                ++index;offset=0;hash=Sha256{};break;}
            auto limits=request.read_limits;limits.max_bytes=static_cast<std::size_t>(std::min<std::uint64_t>(limits.max_bytes,expected.logical_size-offset));
            ++progress.verification_read_calls;auto data=readers[index]->read_content(limits,offset,stop);
            if(!data.value())return propagate<Step>(data);
            if(data.value()->bytes.empty()||data.value()->bytes.size()>limits.max_bytes||
               data.value()->complete!=(data.value()->bytes.size()==expected.logical_size-offset))return reject<Step>("regular_metadata_job.target_read_shape");
            hash.update(data.value()->bytes);offset+=data.value()->bytes.size();progress.verification_read_bytes+=data.value()->bytes.size();break;}
        case Phase::ValuesAfter:result=verify_metadata_replay_values(target,s,applied,stop);
            if(result.value()&&*result.value())phase=Phase::SourceAfter;break;
        case Phase::SourceAfter:return revalidate(Phase::Flush,stop);
        case Phase::Flush:result=target.flush_content();if(result.value()&&*result.value())phase=Phase::FinalValues;break;
        case Phase::FinalValues:result=verify_metadata_replay_values(target,s,applied,stop);
            if(result.value()&&*result.value()){phase=Phase::Complete;progress.complete=true;return complete();}break;
        case Phase::Complete:return complete();
        }
        if(!result.value())return propagate<Step>(result);
        if(!*result.value())return reject<Step>("regular_metadata_job.native_false",ObservationState::Unknown,AdapterError::InvalidNativeResult);
        return pending();
    }
};

NativeRegularMetadataJob::NativeRegularMetadataJob(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
NativeRegularMetadataJob::~NativeRegularMetadataJob(){try{(void)finish_io();}catch(...){}}
Observation<bool> NativeRegularMetadataJob::qualify_source(const NativeMetadataProof& proof) {
    if(auto e=proof.cleanup_error())return Observation<bool>::unavailable(e->state,{e->domain,e->code,e->operation});
    const auto& s=proof.snapshot();
    if(proof.io_finished()||!s.policy.valid()||!s.basic.identity.value()||!s.basic.kind.value()||*s.basic.kind.value()!=ObjectKind::RegularFile)
        return reject<bool>("regular_metadata_job.source_proof",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    if(s.basic.posix_permissions.value()&&(*s.basic.posix_permissions.value()&07000U)&&!s.policy.allow_privilege_metadata)
        return reject<bool>("regular_metadata_job.privileged_mode",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    for(std::size_t i=0;i<s.attributes.size();++i) {
        const auto& a=s.attributes[i];
        if(!same(*s.basic.identity.value(),a.owner))return reject<bool>("regular_metadata_job.attribute_owner");
        if((privileged(a)&&!s.policy.allow_privilege_metadata)||
           attribute_role(a.identifier,a.native_flags.value()?*a.native_flags.value():0)==AttributeRole::InterpretationRequired)
            return reject<bool>("regular_metadata_job.attribute_interpretation",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
        for(std::size_t j=0;j<i;++j)if(s.attributes[j].identifier==a.identifier)
            return reject<bool>("regular_metadata_job.duplicate_attribute",ObservationState::Failed,AdapterError::InvalidNativeResult);
        if(const auto* name=a.identifier.windows_ea_bytes()) {
            auto key=*name;for(auto& unit:key)if(unit>='a'&&unit<='z')unit=static_cast<char>(unit-'a'+'A');
            if(key.starts_with("$KERNEL.")||!a.native_flags.value()||*a.native_flags.value()!=0)
                return reject<bool>("regular_metadata_job.protected_ea",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
        }
    }
    for(const auto& security:s.security)if(!same(*s.basic.identity.value(),security.owner))return reject<bool>("regular_metadata_job.security_owner");
    if(s.channel_coverage==DataChannelCoverage::WindowsFileStreamInfo)return verify_native_metadata_replay_channels(s);
    if(!s.channels.empty())return reject<bool>("regular_metadata_job.channel_coverage",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    return Observation<bool>::available(true);
}
Observation<NativeRegularMetadataJob::Pointer> NativeRegularMetadataJob::create(NativeRegularMetadataRequest request) {
    if(!request.target||!request.source||!request.journal_root||!request.verify_membership||!request.revalidate_source||!request.finish_source||
       !request.read_limits.valid()||request.read_limits.max_bytes>64*1024||!request.max_target_stream_handles||request.max_target_stream_handles>16384)
        return reject<Pointer>("regular_metadata_job.request",ObservationState::Failed,AdapterError::InvalidLimit);
    const auto& proof=*request.source;const auto& snapshot=proof.snapshot();
    if(proof.io_finished()||!snapshot.basic.kind.value()||*snapshot.basic.kind.value()!=ObjectKind::RegularFile||
       !snapshot.basic.identity.value()||snapshot.channels.size()>request.max_target_stream_handles)
        return reject<Pointer>("regular_metadata_job.open_regular_proof",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    if(auto e=proof.cleanup_error())return Observation<Pointer>::unavailable(e->state,{e->domain,e->code,e->operation});
    auto qualified=qualify_source(proof);if(!qualified.value())return propagate<Pointer>(qualified);
    if(!*qualified.value())return reject<Pointer>("regular_metadata_job.source_false",ObservationState::Failed,AdapterError::InvalidNativeResult);
    auto impl=std::make_unique<Impl>(std::move(request));impl->readers.reserve(snapshot.channels.size());
    impl->pending_bytes.reserve(impl->request.read_limits.max_bytes);
    return Observation<Pointer>::available(Pointer(new NativeRegularMetadataJob(std::move(impl))));
}
const NativeRegularMetadataProgress& NativeRegularMetadataJob::progress()const noexcept{return impl_->progress;}
Observation<Step> NativeRegularMetadataJob::advance(State state,std::stop_token stop) {
    auto& p=*impl_;
    if(p.progress.cancelled&&!p.has_close_failure)return Observation<Step>::available(Step::Cancelled);
    if(p.failed){auto failure=p.has_close_failure?failure_result(p.close_failure):failure_result(p.failure);return propagate<Step>(failure);}
    if(p.progress.complete)return complete();
    if(p.progress.worker_drained)return reject<Step>("regular_metadata_job.finished",ObservationState::Changed,AdapterError::InvalidAccess);
    try {
        detail::MetadataCaptureCleanupScope scope(&p);
        if(stop.stop_requested()){auto stopped=reject<Step>("regular_metadata_job.cancelled",ObservationState::Unknown,AdapterError::InterruptedRead);
            remember(p.failure,p.has_failure,*stopped.unavailable_detail());}
        else {auto result=p.step(state,stop,p.stream_latch);
            p.root_failure();if(result.value()&&!p.has_close_failure&&!stop.stop_requested())return result;
            if(!result.value())remember(p.failure,p.has_failure,*result.unavailable_detail());}
    }catch(...){p.root_failure();if(!p.has_failure){p.failure.state=ObservationState::Unknown;p.failure.domain=ErrorDomain::Adapter;
        p.failure.code=static_cast<std::int64_t>(AdapterError::InvalidNativeResult);std::strcpy(p.failure.operation.data(),"regular_metadata_job.exception");p.has_failure=true;}}
    const bool clean_cancel=stop.stop_requested()&&!p.has_close_failure&&(!p.has_failure||
        (p.failure.domain==ErrorDomain::Adapter&&p.failure.code==static_cast<std::int64_t>(AdapterError::InterruptedRead)));
    p.failed=true;try{(void)finish_io();}catch(...){}
    if(clean_cancel&&!p.has_close_failure){p.progress.cancelled=true;p.progress.complete=false;p.failed=false;return Observation<Step>::available(Step::Cancelled);}
    p.progress.complete=false;
    return propagate<Step>(failure_result(p.has_close_failure?p.close_failure:p.failure));
}
Observation<bool> NativeRegularMetadataJob::verify(OpenedEntry& target,std::stop_token stop)const {
    auto& p=*impl_;
    if(!p.progress.complete||p.failed||p.progress.worker_drained||&target!=p.request.target)
        return reject<bool>("regular_metadata_job.verification_not_ready",ObservationState::Changed,AdapterError::InvalidAccess);
    auto checked=p.membership(stop);if(!checked.value()||!*checked.value())return checked;
    return verify_metadata_replay_values(target,p.snapshot(),p.applied,stop);
}
Observation<bool> NativeRegularMetadataJob::finish_io() {
    auto& p=*impl_;
    if(!p.progress.worker_drained) {
        detail::MetadataCaptureCleanupScope scope(&p);
        if(p.writer){p.close([&]{return p.writer->finish_io();});p.writer.reset();}
        for(auto& reader:p.readers)if(reader)p.close([&]{return reader->finish_io();});
        p.readers.clear();
        if(p.request.finish_source)p.close([&]{return p.request.finish_source();});
        if(p.request.source)p.close([&]{return p.request.source->finish_io();});
        p.request.source.reset();p.pending_bytes.clear();p.attributes.reset();
        p.request.verify_membership={};p.request.revalidate_source={};p.request.finish_source={};
        p.root_failure();p.request.target=nullptr;p.stream_latch.reset();p.request.journal_root.reset();p.progress.worker_drained=true;
        if(p.has_close_failure){p.progress.complete=false;p.progress.cancelled=false;p.failed=true;}
        else if(!p.progress.complete&&!p.failed){p.failed=true;p.has_failure=true;p.failure.state=ObservationState::Changed;
            p.failure.domain=ErrorDomain::Adapter;p.failure.code=static_cast<std::int64_t>(AdapterError::InvalidAccess);
            std::strcpy(p.failure.operation.data(),"regular_metadata_job.finished");}
    }
    return p.has_close_failure?failure_result(p.close_failure):Observation<bool>::available(true);
}
} // namespace ck::files
