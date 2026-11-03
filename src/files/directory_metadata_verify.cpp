// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "directory_metadata_verify.hpp"
#include "metadata_semantic_digest.hpp"
#include <algorithm>
namespace ck::files {
namespace {
Observation<bool> reject(const char* operation,ObservationState state=ObservationState::Changed,
    AdapterError code=AdapterError::MetadataChanged) {
    return Observation<bool>::unavailable(state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),operation});
}
template<class T>Observation<bool> propagate(const Observation<T>& value){const auto&e=*value.unavailable_detail();return Observation<bool>::unavailable(e.state,e.error);}
template<class T>bool equal(const Observation<T>&a,const Observation<T>&b){return a.value()&&b.value()?*a.value()==*b.value():
    !a.value()&&!b.value()&&a.state()==b.state()&&a.unavailable_detail()->error==b.unavailable_detail()->error;}
// Carries only a canonical family tag for value hashing. Native adapters
// validate their private evidence classes; this marker always refuses replay.
class ValueCoverage final:public MetadataSecurityCoverageEvidence {
public:
    explicit ValueCoverage(MetadataSecurityCoverage family):family_(family){}
    MetadataSecurityCoverage family()const noexcept override{return family_;}
    Observation<bool> recheck(const MetadataReplaySnapshot&)const override {
        return reject("directory_target.values_are_not_replay_evidence",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    }
private: MetadataSecurityCoverage family_;
};
bool same(const Observation<ObjectIdentity>&a,const Observation<ObjectIdentity>&b){return a.value()&&b.value()&&compare_identity(*a.value(),*b.value())==IdentityComparison::Same;}
}
Observation<std::array<std::byte,32>> directory_metadata_payload_digest(const NativeMetadataProof& proof) {
    using R=Observation<std::array<std::byte,32>>;
    if(proof.io_finished()||!proof.snapshot().basic.kind.value()||*proof.snapshot().basic.kind.value()!=ObjectKind::Directory)
        return R::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"directory_payload.open_directory_proof_required"});
    // This explicit component schema never replaces the full reviewed digest.
    // It compares fresh native proofs after known namespace effects; no caller
    // identity, scope, attribute, owner, security or ADS value is rewritten.
    return directory_metadata_payload_digest_values(proof.snapshot());
}
Observation<std::array<std::byte,32>> directory_metadata_payload_digest_values(const MetadataReplaySnapshot& values) {
    using R=Observation<std::array<std::byte,32>>;
    if(!values.basic.kind.value()||*values.basic.kind.value()!=ObjectKind::Directory)
        return R::unavailable(ObservationState::Unsupported,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"directory_payload.directory_values_required"});
    auto payload=values;payload.basic.modified=Observation<FileTimestamp>::available(*FileTimestamp::from_unix(0,0));
    auto digest=detail::metadata_snapshot_semantic_digest(payload);if(!digest.value())return digest;
    Sha256 hash;constexpr char domain[]="ck-core-fs-lib/directory-namespace-independent-metadata/v1";
    hash.update(std::as_bytes(std::span(domain,sizeof(domain)-1)));hash.update(*digest.value());return R::available(hash.digest());
}
DirectoryMetadataVerifyJob::DirectoryMetadataVerifyJob(const OpenedEntry& target,std::shared_ptr<const NativeMetadataProof> source,
    BasicMetadata applied,ContentReadLimits limits,std::function<Observation<bool>(std::stop_token)> membership)
    :target_(&target),source_(std::move(source)),applied_(std::move(applied)),limits_(limits),membership_(std::move(membership)){
    observed_.policy=source_->snapshot().policy;
}
Observation<DirectoryMetadataVerifyJob::Pointer> DirectoryMetadataVerifyJob::create(const OpenedEntry& target,
    std::shared_ptr<const NativeMetadataProof> source,BasicMetadata applied,ContentReadLimits limits,
    std::function<Observation<bool>(std::stop_token)> membership) {
    if(!source||source->io_finished()||!limits.valid()||!membership||!applied.identity.value()||
       !source->snapshot().basic.kind.value()||*source->snapshot().basic.kind.value()!=ObjectKind::Directory||
       source->snapshot().policy.ownership!=MetadataOwnership::Original)
        return Observation<Pointer>::unavailable(ObservationState::Unsupported,{ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"directory_target.request_or_ownership"});
    return Observation<Pointer>::available(Pointer(new DirectoryMetadataVerifyJob(target,std::move(source),std::move(applied),limits,std::move(membership))));
}
void DirectoryMetadataVerifyJob::fail(const UnavailableObservation& error)noexcept {
    fail(error.state,error.error.domain,error.error.code,error.error.operation);
}
void DirectoryMetadataVerifyJob::fail(ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view operation)noexcept {
    auto& first=progress_.failure;if(!first.present){first.present=true;first.state=state;first.domain=domain;first.code=code;
        std::copy_n(operation.data(),std::min(operation.size(),first.operation.size()-1),first.operation.data());}
    progress_.phase=DirectoryVerifyPhase::Failed;release_readers();
}
void DirectoryMetadataVerifyJob::release_readers()noexcept {reader_.reset();source_.reset();target_=nullptr;membership_={};}
Observation<bool> DirectoryMetadataVerifyJob::native_evidence()const {
    const auto& snapshot=source_->snapshot();
    if(source_->io_finished())return reject("directory_target.closed_source_proof");
    if(snapshot.channel_coverage==DataChannelCoverage::WindowsFileStreamInfo){auto valid=verify_native_metadata_replay_channels(snapshot);if(!valid.value()||!*valid.value())return valid;}
    else if(!snapshot.channels.empty())return reject("directory_target.channel_coverage",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    if(snapshot.policy.scope==RegularMetadataScope::CompleteMetadataV1){
        if(!snapshot.security_coverage)return reject("directory_target.security_coverage",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
        auto valid=target_->verify_metadata_security_coverage(snapshot);if(!valid.value()||!*valid.value())return valid;
    }
    return Observation<bool>::available(true);
}
Observation<bool> DirectoryMetadataVerifyJob::basic(bool final)const {
    auto metadata=target_->inspect_basic();if(!metadata.value())return propagate(metadata);
    const auto& now=*metadata.value();const auto& snapshot=source_->snapshot();const auto& expected=snapshot.basic;
    if(!same(now.identity,applied_.identity)||!equal(now.kind,expected.kind)||!equal(now.accessed,expected.accessed)||
       !equal(now.modified,expected.modified)||!equal(now.posix_permissions,expected.posix_permissions)||
       !equal(now.posix_uid,expected.posix_uid)||!equal(now.posix_gid,expected.posix_gid)||
       !equal(now.windows_attributes,expected.windows_attributes)||!equal(now.bsd_flags,expected.bsd_flags)||
       !equal(now.changed,applied_.changed)||
       (snapshot.policy.scope==RegularMetadataScope::CompleteMetadataV1&&!equal(now.created,expected.created)))
        return reject(final?"directory_target.final_metadata":"directory_target.basic_metadata");
    if(final&&(!same(now.identity,before_.identity)||!equal(now.accessed,before_.accessed)||!equal(now.modified,before_.modified)||
       !equal(now.changed,before_.changed)))return reject("directory_target.changed_during_verification");
    return Observation<bool>::available(true);
}
DirectoryVerifyProgress DirectoryMetadataVerifyJob::advance(std::stop_token stop) {
    if(progress_.phase==DirectoryVerifyPhase::Complete||progress_.phase==DirectoryVerifyPhase::Failed||progress_.phase==DirectoryVerifyPhase::Cancelled)return progress_;
    if(stop.stop_requested()){progress_.phase=DirectoryVerifyPhase::Cancelled;release_readers();return progress_;}
    try{
        auto result=membership_(stop);if(!result.value()||!*result.value()){if(!result.value())fail(*result.unavailable_detail());
            else fail(*reject("directory_target.membership_false").unavailable_detail());return progress_;}
        const auto& snapshot=source_->snapshot();
        switch(progress_.phase){
        case DirectoryVerifyPhase::Preflight:
            result=target_->qualify_metadata_replay(snapshot.policy);if(result.value()&&*result.value())result=native_evidence();
            if(result.value()&&*result.value())progress_.phase=DirectoryVerifyPhase::Basic;break;
        case DirectoryVerifyPhase::Basic:{
            result=basic(false);if(!result.value()||!*result.value())break;
            auto current=target_->inspect_basic();if(!current.value()){result=propagate(current);break;}
            before_=*current.value();observed_.basic=before_;progress_.phase=DirectoryVerifyPhase::AttributeCatalog;break;}
        case DirectoryVerifyPhase::AttributeCatalog:{
            auto catalog=target_->inspect_attributes(snapshot.policy.limits);if(!catalog.value()){result=propagate(catalog);break;}
            if(!same(catalog.value()->owner,applied_.identity)||catalog.value()->coverage!=snapshot.attribute_coverage||
               catalog.value()->attributes.size()!=snapshot.attributes.size()){result=reject("directory_target.attribute_set");break;}
            for(const auto& source:snapshot.attributes)if(std::none_of(catalog.value()->attributes.begin(),catalog.value()->attributes.end(),
                [&](const auto& entry){return entry.identifier==source.identifier;})){result=reject("directory_target.attribute_name");break;}
            if(result.value()&&*result.value()){observed_.attribute_coverage=catalog.value()->coverage;index_=0;progress_.phase=DirectoryVerifyPhase::Attributes;}break;}
        case DirectoryVerifyPhase::Attributes:{
            if(index_==snapshot.attributes.size()){index_=0;progress_.phase=DirectoryVerifyPhase::Security;break;}
            const auto& expected=snapshot.attributes[index_];auto value=target_->read_attribute(expected.identifier,snapshot.policy.limits);
            if(!value.value()){result=propagate(value);break;}
            if(!same(value.value()->owner,applied_.identity)||value.value()->bytes!=expected.bytes||!equal(value.value()->native_flags,expected.native_flags))
                result=reject("directory_target.attribute_bytes");else {observed_.attributes.push_back(std::move(value).take_value());++index_;}break;}
        case DirectoryVerifyPhase::Security:
            if(index_==snapshot.security.size()){index_=0;progress_.phase=DirectoryVerifyPhase::ChannelCatalog;break;}
            result=target_->verify_replay_security(snapshot.security[index_],snapshot.policy);
            if(result.value()&&*result.value()){
                auto value=target_->read_security(snapshot.security[index_].part,snapshot.policy.limits);
                if(!value.value()){result=propagate(value);break;}
                if(!same(value.value()->owner,applied_.identity)||value.value()->part!=snapshot.security[index_].part){
                    result=reject("directory_target.security_binding");break;}
                observed_.security.push_back(std::move(value).take_value());++index_;
            }break;
        case DirectoryVerifyPhase::ChannelCatalog:{
            if(snapshot.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo){observed_.channel_coverage=snapshot.channel_coverage;progress_.phase=DirectoryVerifyPhase::Postflight;break;}
            auto catalog=target_->inspect_data_channels(snapshot.policy.limits);if(!catalog.value()){result=propagate(catalog);break;}
            if(catalog.value()->coverage!=snapshot.channel_coverage||!same(catalog.value()->owner,applied_.identity)||
               catalog.value()->channels.size()!=snapshot.channels.size()){result=reject("directory_target.channel_set");break;}
            for(const auto& source:snapshot.channels){const auto match=std::find_if(catalog.value()->channels.begin(),catalog.value()->channels.end(),
                [&](const auto& entry){return entry.identifier==source.identifier&&entry.kind==DataChannelKind::NamedData;});
                if(match==catalog.value()->channels.end()||!match->logical_size.value()||*match->logical_size.value()!=source.logical_size){result=reject("directory_target.channel_size");break;}}
            if(result.value()&&*result.value()){observed_.channel_coverage=catalog.value()->coverage;index_=0;progress_.phase=DirectoryVerifyPhase::OpenChannel;}break;}
        case DirectoryVerifyPhase::OpenChannel:{
            if(index_==snapshot.channels.size()){progress_.phase=DirectoryVerifyPhase::Postflight;break;}
            auto reader=target_->open_metadata_replay_channel_read(snapshot.channels[index_].identifier);
            if(!reader.value()){result=propagate(reader);break;}
            if(!*reader.value()){result=reject("directory_target.missing_reader",ObservationState::Failed,AdapterError::InvalidNativeResult);break;}
            reader_=*reader.value();offset_=0;hash_=Sha256{};progress_.phase=DirectoryVerifyPhase::ReadChannel;break;}
        case DirectoryVerifyPhase::ReadChannel:{
            const auto& expected=snapshot.channels[index_];auto state=reader_->inspect();if(!state.value()){result=propagate(state);break;}
            if(!applied_.identity.value()||compare_identity(state.value()->owner,*applied_.identity.value())!=IdentityComparison::Same||
               state.value()->identifier!=expected.identifier||state.value()->logical_size!=expected.logical_size){result=reject("directory_target.channel_binding");break;}
            if(offset_==expected.logical_size){if(hash_.digest()!=expected.digest){result=reject("directory_target.channel_digest");break;}
                observed_.channels.push_back({expected.identifier,state.value()->logical_size,hash_.digest(),{}});
                reader_.reset();++index_;progress_.phase=DirectoryVerifyPhase::OpenChannel;break;}
            auto limit=limits_;limit.max_bytes=static_cast<std::size_t>(std::min<std::uint64_t>(limit.max_bytes,expected.logical_size-offset_));
            ++progress_.read_calls;auto read=reader_->read_content(limit,offset_,stop);if(!read.value()){result=propagate(read);break;}
            if(read.value()->bytes.empty()||read.value()->bytes.size()>limit.max_bytes){result=reject("directory_target.channel_read_count",ObservationState::Changed,AdapterError::InvalidNativeResult);break;}
            progress_.read_bytes+=read.value()->bytes.size();hash_.update(read.value()->bytes);offset_+=read.value()->bytes.size();break;}
        case DirectoryVerifyPhase::Postflight:
            result=native_evidence();if(result.value()&&*result.value())result=target_->qualify_metadata_replay(snapshot.policy);
            if(result.value()&&*result.value())result=basic(true);
            if(result.value()&&*result.value()){
                auto actual=target_->inspect_basic();if(!actual.value()){result=propagate(actual);break;}
                observed_.basic=*actual.value();
                if(snapshot.security_coverage)observed_.security_coverage=std::make_shared<ValueCoverage>(snapshot.security_coverage->family());
                progress_.phase=DirectoryVerifyPhase::Complete;release_readers();
            }break;
        default:break;
        }
        if(!result.value())fail(*result.unavailable_detail());else if(!*result.value())fail(*reject("directory_target.unexpected_false",ObservationState::Unknown,AdapterError::InvalidNativeResult).unavailable_detail());
    }catch(...){fail(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"directory_target.worker_exception");}
    return progress_;
}
} // namespace ck::files
