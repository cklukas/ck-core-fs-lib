// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_capture_job.hpp"
#include "held_child.hpp"
#include "sha256.hpp"
#include <algorithm>
#include <set>
namespace ck::files {
namespace {
struct Failure{UnavailableObservation detail;};
[[noreturn]]void fail(const char* op,ObservationState s=ObservationState::Changed,AdapterError code=AdapterError::MetadataChanged){throw Failure{{s,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),op}}};}
template<class T>T value(Observation<T> o){if(!o.value())throw Failure{*o.unavailable_detail()};return std::move(o).take_value();}
void require(Observation<bool> o){if(!value(std::move(o)))fail("metadata_capture.false_result",ObservationState::Failed,AdapterError::InvalidNativeResult);}
void stop_now(std::stop_token stop){if(stop.stop_requested())fail("metadata_capture.cancelled",ObservationState::Unknown,AdapterError::InterruptedRead);}
template<class T>bool eq(const Observation<T>&a,const Observation<T>&b){return a.value()&&b.value()?*a.value()==*b.value():!a.value()&&!b.value()&&a.state()==b.state();}
bool owner(const Observation<ObjectIdentity>&a,const Observation<ObjectIdentity>&b){return a.value()&&b.value()&&compare_identity(*a.value(),*b.value())==IdentityComparison::Same;}
bool stable(const BasicMetadata&a,const BasicMetadata&b){return owner(a.identity,b.identity)&&eq(a.kind,b.kind)&&eq(a.logical_size,b.logical_size)&&eq(a.link_count,b.link_count)&&eq(a.modified,b.modified)&&eq(a.changed,b.changed)&&eq(a.created,b.created)&&eq(a.posix_uid,b.posix_uid)&&eq(a.posix_gid,b.posix_gid)&&eq(a.posix_permissions,b.posix_permissions)&&eq(a.bsd_flags,b.bsd_flags)&&eq(a.windows_attributes,b.windows_attributes)&&eq(a.mount_id,b.mount_id);}
std::size_t name_bytes(const NativeFeatureIdentifier&n){if(auto*p=n.posix_bytes())return p->size();if(auto*p=n.windows_units())return p->size()*2;if(auto*p=n.windows_ea_bytes())return p->size();fail("metadata_capture.identifier",ObservationState::Unsupported,AdapterError::InvalidIdentifier);}
bool attribute_same(const AttributeValue&a,const AttributeValue&b){return a.identifier==b.identifier&&a.bytes==b.bytes&&eq(a.native_flags,b.native_flags)&&owner(a.owner,b.owner);}
bool security_same(const NativeSecurityValue&a,const NativeSecurityValue&b){return a.part==b.part&&a.presence==b.presence&&a.encoding==b.encoding&&a.native_query_mask==b.native_query_mask&&a.bytes==b.bytes&&owner(a.owner,b.owner);}
void add(std::uint64_t&n,std::uint64_t v){if(v>std::numeric_limits<std::uint64_t>::max()-n)fail("metadata_capture.size_overflow",ObservationState::Unknown,AdapterError::InventoryLimit);n+=v;}
}
namespace detail {
namespace { thread_local const MetadataCaptureFailureLatch* active_cleanup=nullptr; }
MetadataCaptureCleanupScope::MetadataCaptureCleanupScope(const MetadataCaptureFailureLatch* p)noexcept:previous_(active_cleanup){active_cleanup=p;}
MetadataCaptureCleanupScope::~MetadataCaptureCleanupScope(){active_cleanup=previous_;}
void record_metadata_capture_close(MetadataCaptureCleanupError e)noexcept{if(active_cleanup)active_cleanup->record_first(e);}
struct MetadataCaptureCleanupState final:MetadataCaptureFailureLatch {
    std::shared_ptr<MetadataCaptureBudget> budget;
    std::shared_ptr<const MetadataCaptureFailureLatch> outer;
    mutable std::optional<MetadataCaptureCleanupError> first;
    MetadataCaptureCleanupState(std::shared_ptr<MetadataCaptureBudget>b,std::shared_ptr<const MetadataCaptureFailureLatch>o):budget(std::move(b)),outer(std::move(o)){}
    void record_first(MetadataCaptureCleanupError e)const noexcept override{
        if(first)return;first=e;if(!budget->cleanup_error_)budget->cleanup_error_=e;if(outer)outer->record_first(e);
    }
    std::optional<MetadataCaptureCleanupError> error()const noexcept{return first?first:budget->cleanup_error_;}
};
struct MetadataCaptureLease final {
    std::shared_ptr<MetadataCaptureBudget> budget;
    std::shared_ptr<MetadataCaptureCleanupState> cleanup;
    std::size_t handles=0,metadata=0;
    explicit MetadataCaptureLease(std::shared_ptr<MetadataCaptureBudget>b):budget(std::move(b)){}
    ~MetadataCaptureLease(){budget->handles_-=handles;budget->metadata_-=metadata;}
    void release_handles()noexcept{budget->handles_-=handles;handles=0;}
    void reserve_handles(std::size_t n){if(n>budget->limits_.max_retained_handles-budget->handles_)fail("metadata_capture.handle_budget",ObservationState::Unknown,AdapterError::InventoryLimit);budget->handles_+=n;handles+=n;}
    void reserve_metadata(std::size_t n){if(n>budget->limits_.max_metadata_bytes-budget->metadata_)fail("metadata_capture.metadata_budget",ObservationState::Unknown,AdapterError::InventoryLimit);budget->metadata_+=n;metadata+=n;}
    void admit(std::uint64_t n,std::uint64_t per_object){if(n>per_object||n>budget->limits_.max_logical_bytes-budget->logical_)fail("metadata_capture.logical_budget",ObservationState::Unknown,AdapterError::InventoryLimit);budget->logical_+=n;}
};
}
namespace {
Observation<bool> cleanup_result(std::optional<MetadataCaptureCleanupError> e){if(e)return Observation<bool>::unavailable(e->state,{e->domain,e->code,e->operation});return Observation<bool>::available(true);}
[[noreturn]]void cleanup_fail(MetadataCaptureCleanupError e){throw Failure{{e.state,{e.domain,e.code,e.operation}}};}
}
bool MetadataCaptureLimits::valid()const noexcept{return read.valid()&&max_retained_handles>=8&&max_metadata_bytes>0;}
NativeMetadataProof::NativeMetadataProof(MetadataReplaySnapshot s,std::optional<std::array<std::byte,32>>h,std::shared_ptr<const OpenedEntry>source,std::shared_ptr<detail::MetadataCaptureLease>lease,MetadataCaptureProgress p):snapshot_(std::move(s)),main_(h),source_(std::move(source)),lease_(std::move(lease)),progress_(p){}
NativeMetadataProof::~NativeMetadataProof(){try{(void)finish_io();}catch(...){}}
std::optional<MetadataCaptureCleanupError> NativeMetadataProof::cleanup_error()const noexcept{return lease_->cleanup->error();}
bool NativeMetadataProof::io_finished()const noexcept{return cleanup_done_;}
Observation<bool> NativeMetadataProof::finish_io()const{
    if(!cleanup_done_){cleanup_done_=true;detail::MetadataCaptureCleanupScope scope(lease_->cleanup.get());detail::finish_native_metadata_capture(source_.get(),snapshot_);lease_->release_handles();}
    return cleanup_result(cleanup_error());
}
struct MetadataCaptureJob::Impl {
    std::shared_ptr<const OpenedEntry> source;
    MetadataCaptureLimits limits;
    std::shared_ptr<detail::MetadataCaptureLease> lease;
    std::shared_ptr<const NativeMetadataProof> expected,proof;
    MetadataReplaySnapshot snapshot;
    MetadataCaptureProgress progress;
    StorageInfo storage;
    DataChannelCatalog catalog;
    AttributeCatalog attributes;
    std::vector<SecurityPart> parts;
    std::optional<UnavailableObservation> failure;
    std::optional<std::array<std::byte,32>> main;
    std::size_t index=0,metadata_bytes=0;
    std::uint64_t offset=0;
    Sha256 hash;
    bool directory=false,windows=false,verified=false,cleanup_done=false;
    ~Impl(){if(!proof&&lease){detail::MetadataCaptureCleanupScope scope(lease->cleanup.get());detail::finish_native_metadata_capture(source.get(),snapshot);lease->release_handles();}}
    void metadata(std::size_t n){if(n>snapshot.policy.limits.max_native_bytes-metadata_bytes)fail("metadata_capture.aggregate_metadata",ObservationState::Unknown,AdapterError::InventoryLimit);metadata_bytes+=n;lease->reserve_metadata(n*4);}
    void basic(){auto b=value(source->inspect_basic());if(!stable(snapshot.basic,b))fail("metadata_capture.version_changed");}
    void check_attributes(const AttributeCatalog&c){if(c.coverage!=attributes.coverage||!owner(c.owner,snapshot.basic.identity)||c.attributes.size()!=attributes.attributes.size())fail("metadata_capture.attribute_catalog_changed");for(const auto&a:attributes.attributes){auto i=std::find_if(c.attributes.begin(),c.attributes.end(),[&](const auto&v){return v.identifier==a.identifier;});if(i==c.attributes.end()||!eq(a.value_size,i->value_size)||!eq(a.native_flags,i->native_flags)||a.role!=i->role)fail("metadata_capture.attribute_name_size_changed");}}
    void check_catalog(const DataChannelCatalog&c){if(c.coverage!=catalog.coverage||!owner(c.owner,snapshot.basic.identity)||c.channels.size()!=catalog.channels.size())fail("metadata_capture.channel_catalog_changed");for(const auto&a:catalog.channels){auto i=std::find_if(c.channels.begin(),c.channels.end(),[&](const auto&v){return v.identifier==a.identifier;});if(i==c.channels.end()||a.kind!=i->kind||!eq(a.logical_size,i->logical_size))fail("metadata_capture.channel_set_changed");}}
    void compare_expected(){if(!expected)return;const auto&e=expected->snapshot();if(!stable(e.basic,snapshot.basic)||e.attribute_coverage!=snapshot.attribute_coverage||e.attributes.size()!=snapshot.attributes.size()||e.security.size()!=snapshot.security.size()||e.channel_coverage!=snapshot.channel_coverage||e.channels.size()!=snapshot.channels.size()||main!=expected->main_digest())fail("metadata_capture.previous_proof_changed");for(const auto&a:e.attributes){auto i=std::find_if(snapshot.attributes.begin(),snapshot.attributes.end(),[&](const auto&v){return v.identifier==a.identifier;});if(i==snapshot.attributes.end()||!attribute_same(a,*i))fail("metadata_capture.previous_attribute_changed");}for(std::size_t i=0;i<e.security.size();++i)if(!security_same(e.security[i],snapshot.security[i]))fail("metadata_capture.previous_security_changed");for(const auto&a:e.channels){auto i=std::find_if(snapshot.channels.begin(),snapshot.channels.end(),[&](const auto&v){return v.identifier==a.identifier;});if(i==snapshot.channels.end()||i->logical_size!=a.logical_size||i->digest!=a.digest)fail("metadata_capture.previous_channel_changed");}}
};
MetadataCaptureJob::MetadataCaptureJob(std::unique_ptr<Impl>p):impl_(std::move(p)){}
MetadataCaptureJob::~MetadataCaptureJob()=default;
std::optional<MetadataCaptureCleanupError> MetadataCaptureJob::cleanup_error()const noexcept{return impl_->lease->cleanup->error();}
Observation<bool> MetadataCaptureJob::finish_io(){
 auto&p=*impl_;if(p.proof)return p.proof->finish_io();
 if(!p.cleanup_done){p.cleanup_done=true;detail::MetadataCaptureCleanupScope scope(p.lease->cleanup.get());detail::finish_native_metadata_capture(p.source.get(),p.snapshot);p.lease->release_handles();}
 return cleanup_result(cleanup_error());
}
const MetadataCaptureProgress& MetadataCaptureJob::progress()const noexcept{return impl_->progress;}
bool MetadataCaptureJob::ready_to_seal()const noexcept{return impl_->progress.phase==MetadataCapturePhase::Seal&&impl_->verified;}
MetadataReplaySnapshot&MetadataCaptureJob::sealing_snapshot(){return impl_->snapshot;}
const std::shared_ptr<const OpenedEntry>&MetadataCaptureJob::sealing_source()const{return impl_->source;}
std::shared_ptr<const void>MetadataCaptureJob::sealing_lease()const{return impl_->lease;}
Observation<std::unique_ptr<MetadataCaptureJob>> MetadataCaptureJob::begin(std::shared_ptr<const OpenedEntry>source,MetadataReplayPolicy policy,MetadataCaptureLimits limits,std::shared_ptr<MetadataCaptureBudget>budget,std::shared_ptr<const MetadataCaptureFailureLatch>cleanup_latch){
    using R=Observation<std::unique_ptr<MetadataCaptureJob>>;try{if(!source||!policy.valid()||!limits.valid()||(budget&&!budget->limits().valid()))fail("metadata_capture.input",ObservationState::Failed,AdapterError::InvalidLimit);if(!budget)budget=std::make_shared<MetadataCaptureBudget>(limits);auto p=std::make_unique<Impl>();p->limits=limits;p->lease=std::make_shared<detail::MetadataCaptureLease>(std::move(budget));p->lease->cleanup=std::make_shared<detail::MetadataCaptureCleanupState>(p->lease->budget,std::move(cleanup_latch));detail::MetadataCaptureCleanupScope cleanup_scope(p->lease->cleanup.get());if(auto e=p->lease->cleanup->error())cleanup_fail(*e);p->lease->reserve_handles(8);p->lease->reserve_metadata(2*policy.limits.max_native_bytes+sizeof(Impl));p->source=value(detail::open_native_metadata_capture_source(std::move(source),policy));if(auto e=p->lease->cleanup->error())cleanup_fail(*e);if(!p->source)fail("metadata_capture.null_native_source",ObservationState::Failed,AdapterError::InvalidNativeResult);p->snapshot.policy=policy;return R::available(std::unique_ptr<MetadataCaptureJob>(new MetadataCaptureJob(std::move(p))));}catch(const Failure&e){return R::unavailable(e.detail.state,e.detail.error);}}
Observation<std::unique_ptr<MetadataCaptureJob>> MetadataCaptureJob::begin_held(std::shared_ptr<const HeldChild>held,MetadataReplayPolicy policy,MetadataCaptureLimits limits,std::shared_ptr<MetadataCaptureBudget>budget,std::shared_ptr<const MetadataCaptureFailureLatch>latch){
 using R=Observation<std::unique_ptr<MetadataCaptureJob>>;
 if(!held)return R::unavailable(ObservationState::Failed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidIdentifier),"metadata_capture.null_held"});
 return begin(held->child_,policy,limits,std::move(budget),std::move(latch));
}
Observation<std::unique_ptr<MetadataCaptureJob>> MetadataCaptureJob::begin_directory(std::shared_ptr<const DirectoryCursor>source,MetadataReplayPolicy policy,MetadataCaptureLimits limits,std::shared_ptr<MetadataCaptureBudget>budget,std::shared_ptr<const MetadataCaptureFailureLatch>cleanup_latch){
    using R=Observation<std::unique_ptr<MetadataCaptureJob>>;try{if(!source||!policy.valid()||!limits.valid()||(budget&&!budget->limits().valid()))fail("metadata_capture.input",ObservationState::Failed,AdapterError::InvalidLimit);if(!budget)budget=std::make_shared<MetadataCaptureBudget>(limits);auto p=std::make_unique<Impl>();p->limits=limits;p->lease=std::make_shared<detail::MetadataCaptureLease>(std::move(budget));p->lease->cleanup=std::make_shared<detail::MetadataCaptureCleanupState>(p->lease->budget,std::move(cleanup_latch));detail::MetadataCaptureCleanupScope cleanup_scope(p->lease->cleanup.get());if(auto e=p->lease->cleanup->error())cleanup_fail(*e);p->lease->reserve_handles(8);p->lease->reserve_metadata(2*policy.limits.max_native_bytes+sizeof(Impl));p->source=value(detail::open_native_directory_capture_source(std::move(source),policy));if(auto e=p->lease->cleanup->error())cleanup_fail(*e);if(!p->source)fail("metadata_capture.null_native_source",ObservationState::Failed,AdapterError::InvalidNativeResult);p->snapshot.policy=policy;return R::available(std::unique_ptr<MetadataCaptureJob>(new MetadataCaptureJob(std::move(p))));}catch(const Failure&e){return R::unavailable(e.detail.state,e.detail.error);}}
Observation<std::unique_ptr<MetadataCaptureJob>> MetadataCaptureJob::verify(std::shared_ptr<const NativeMetadataProof>proof,MetadataCaptureLimits limits,std::shared_ptr<MetadataCaptureBudget>budget,std::shared_ptr<const MetadataCaptureFailureLatch>latch){
 using R=Observation<std::unique_ptr<MetadataCaptureJob>>;
 if(!proof||proof->io_finished())return R::unavailable(ObservationState::Failed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"metadata_capture.open_source_required"});
 auto source=proof->source_;return verify(std::move(source),std::move(proof),limits,std::move(budget),std::move(latch));
}
Observation<std::unique_ptr<MetadataCaptureJob>> MetadataCaptureJob::verify(std::shared_ptr<const OpenedEntry>source,std::shared_ptr<const NativeMetadataProof>proof,MetadataCaptureLimits limits,std::shared_ptr<MetadataCaptureBudget>budget,std::shared_ptr<const MetadataCaptureFailureLatch>latch){
 using R=Observation<std::unique_ptr<MetadataCaptureJob>>;
 if(!proof)return R::unavailable(ObservationState::Failed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidIdentifier),"metadata_capture.null_proof"});
 if(auto e=proof->cleanup_error())return R::unavailable(e->state,{e->domain,e->code,e->operation});
 auto made=begin(std::move(source),proof->snapshot_.policy,limits,std::move(budget),std::move(latch));
 if(made.value())(*made.value())->impl_->expected=std::move(proof);return made;
}
Observation<std::shared_ptr<const NativeMetadataProof>>MetadataCaptureJob::result()const{using R=Observation<std::shared_ptr<const NativeMetadataProof>>;if(auto e=cleanup_error())return R::unavailable(e->state,{e->domain,e->code,e->operation});if(impl_->failure)return R::unavailable(impl_->failure->state,impl_->failure->error);if(impl_->proof)return R::available(impl_->proof);return R::unavailable(ObservationState::Unknown,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_capture.not_complete"});}
Observation<MetadataCaptureAdvance> MetadataCaptureJob::advance(std::stop_token stop){
 using R=Observation<MetadataCaptureAdvance>;auto&p=*impl_;auto&phase=p.progress.phase;MetadataCaptureAdvance out{phase};
 detail::MetadataCaptureCleanupScope cleanup_scope(p.lease->cleanup.get());
 try{if(p.failure)return R::unavailable(p.failure->state,p.failure->error);if(auto e=cleanup_error())cleanup_fail(*e);if(p.cleanup_done)fail("metadata_capture.closed_job",ObservationState::Failed,AdapterError::InvalidAccess);if(phase==MetadataCapturePhase::Complete)return R::available(out);stop_now(stop);const auto&policy=p.snapshot.policy;
 switch(phase){
 case MetadataCapturePhase::Basic:{p.snapshot.basic=value(p.source->inspect_basic());const auto&b=p.snapshot.basic;p.directory=b.kind.value()&&*b.kind.value()==ObjectKind::Directory;if(!owner(b.identity,b.identity)||!b.kind.value()||(!p.directory&&*b.kind.value()!=ObjectKind::RegularFile)||(!p.directory&&!b.logical_size.value())||!b.link_count.value()||*b.link_count.value()<1||!b.accessed.value()||!b.modified.value()||!b.changed.value())fail("metadata_capture.basic",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);if(b.posix_permissions.value()&&(*b.posix_permissions.value()&07000U)&&!policy.allow_privilege_metadata)fail("metadata_capture.privilege_optin",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);if(p.expected&&!stable(p.expected->snapshot().basic,b))fail("metadata_capture.previous_version_changed");if(!p.directory)p.progress.main_logical_bytes=*b.logical_size.value();phase=MetadataCapturePhase::Qualify;break;}
 case MetadataCapturePhase::Qualify:require(p.source->qualify_metadata_replay(policy));phase=MetadataCapturePhase::Storage;break;
 case MetadataCapturePhase::Storage:p.storage=value(p.source->inspect_storage());if(!owner(p.storage.owner,p.snapshot.basic.identity))fail("metadata_capture.storage_owner");p.windows=p.storage.model==StorageModel::WindowsHandleAttributes;if(p.windows&&p.snapshot.basic.identity.value()->scheme!=IdentityScheme::WindowsFileId128)fail("metadata_capture.strong_windows_identity",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);switch(p.storage.model){case StorageModel::WindowsHandleAttributes:p.parts=policy.scope==RegularMetadataScope::CompleteMetadataV1?std::vector{SecurityPart::WindowsFullDescriptor}:std::vector{SecurityPart::WindowsAccess,SecurityPart::WindowsIntegrity};break;case StorageModel::DarwinStatFlags:p.parts={SecurityPart::DarwinExtendedAcl};break;case StorageModel::LinuxStatx:p.parts=p.directory?std::vector{SecurityPart::LinuxAccessAcl,SecurityPart::LinuxDefaultAcl}:std::vector{SecurityPart::LinuxAccessAcl};break;default:fail("metadata_capture.storage_model",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);}phase=MetadataCapturePhase::Channels;break;
 case MetadataCapturePhase::Channels:if(p.storage.model==StorageModel::LinuxStatx){p.catalog.coverage=DataChannelCoverage::Unknown;p.catalog.owner=p.snapshot.basic.identity;}else p.catalog=value(p.source->inspect_data_channels(policy.limits));if(!owner(p.catalog.owner,p.snapshot.basic.identity))fail("metadata_capture.catalog_owner");phase=MetadataCapturePhase::Admission;break;
 case MetadataCapturePhase::Admission:{std::uint64_t bytes=p.progress.main_logical_bytes.value_or(0);std::size_t named=0;unsigned main=0;std::set<std::u16string> names;if(p.windows){if(p.catalog.coverage!=DataChannelCoverage::WindowsFileStreamInfo)fail("metadata_capture.stream_coverage",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);bytes=0;for(const auto&c:p.catalog.channels){stop_now(stop);auto*n=c.identifier.windows_units();if(!n||!names.insert(*n).second||!c.logical_size.value())fail("metadata_capture.channel_name_size");if(c.kind==DataChannelKind::MainData){++main;if(p.directory||*n!=u"::$DATA"||!p.progress.main_logical_bytes||*c.logical_size.value()!=*p.progress.main_logical_bytes)fail("metadata_capture.main_size");}else if(c.kind==DataChannelKind::NamedData&&n->size()>7&&n->front()==u':'&&n->ends_with(u":$DATA")&&n->substr(1,n->size()-7).find_first_of(u":/\\\0",0,4)==std::u16string::npos)++named;else fail("metadata_capture.unknown_channel",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);add(bytes,*c.logical_size.value());p.lease->reserve_metadata(4*(sizeof(MetadataReplayChannelSnapshot)+name_bytes(c.identifier)));}if(main!=(p.directory?0U:1U))fail("metadata_capture.main_count");p.snapshot.channel_coverage=p.catalog.coverage;p.progress.all_stream_logical_bytes=bytes;}else if(!p.catalog.channels.empty())fail("metadata_capture.nonwindows_channel_not_integrated",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);p.lease->admit(bytes,p.limits.max_logical_bytes);p.lease->reserve_handles(named);p.progress.named_stream_count=named;phase=MetadataCapturePhase::AttributeCatalog;break;}
 case MetadataCapturePhase::AttributeCatalog:p.attributes=value(p.source->inspect_attributes(policy.limits));if(p.attributes.coverage==AttributeCoverage::Unknown||!owner(p.attributes.owner,p.snapshot.basic.identity))fail("metadata_capture.attribute_coverage",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);p.snapshot.attribute_coverage=p.attributes.coverage;for(const auto&a:p.attributes.attributes){stop_now(stop);if(!a.value_size.value()||*a.value_size.value()>policy.limits.max_native_bytes)fail("metadata_capture.attribute_value_size",ObservationState::Unknown,AdapterError::InventoryLimit);p.lease->reserve_metadata(4*(sizeof(AttributeDescriptor)+name_bytes(a.identifier)));}p.index=0;phase=MetadataCapturePhase::Attributes;break;
 case MetadataCapturePhase::Attributes:if(p.index==p.attributes.attributes.size()){p.index=0;phase=MetadataCapturePhase::Security;break;}else{const auto&a=p.attributes.attributes[p.index++];const auto*n=a.identifier.posix_bytes();if(n&&(n->starts_with("security.")||*n=="com.apple.macl"||*n=="com.apple.rootless"||n->starts_with("trusted."))&&!policy.allow_privilege_metadata)fail("metadata_capture.security_attribute_optin",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);if((n&&(n->starts_with("com.apple.fileprovider.")||*n=="security.ima"||*n=="security.evm"))||a.role==AttributeRole::StorageRepresentation||a.role==AttributeRole::InterpretationRequired)fail("metadata_capture.attribute_provider",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);auto v=value(p.source->read_attribute(a.identifier,policy.limits));if(v.identifier!=a.identifier||!owner(v.owner,p.snapshot.basic.identity)||v.bytes.size()!=*a.value_size.value())fail("metadata_capture.attribute_changed");p.metadata(v.bytes.size());p.snapshot.attributes.push_back(std::move(v));break;}
 case MetadataCapturePhase::Security:if(p.index==p.parts.size()){p.index=0;phase=MetadataCapturePhase::OpenChannels;break;}else{const auto part=p.parts[p.index++];auto v=value(p.source->read_security(part,policy.limits));if(v.part!=part||v.presence==SecurityPresence::Unknown||v.encoding==SecurityEncoding::Unknown||!owner(v.owner,p.snapshot.basic.identity))fail("metadata_capture.security_changed");p.metadata(v.bytes.size());p.snapshot.security.push_back(std::move(v));break;}
 case MetadataCapturePhase::OpenChannels:{while(p.index<p.catalog.channels.size()&&p.catalog.channels[p.index].kind==DataChannelKind::MainData)++p.index;if(p.index==p.catalog.channels.size()){p.index=0;p.offset=0;p.hash.reset();p.progress.data_pass=1;phase=MetadataCapturePhase::ReadData;break;}const auto&c=p.catalog.channels[p.index++];auto reader=value(p.source->open_metadata_replay_channel_read(c.identifier));if(!reader)fail("metadata_capture.null_reader",ObservationState::Failed,AdapterError::InvalidNativeResult);const auto state=value(reader->inspect());if(state.identifier!=c.identifier||state.logical_size!=*c.logical_size.value()||compare_identity(state.owner,*p.snapshot.basic.identity.value())!=IdentityComparison::Same)fail("metadata_capture.channel_reader_changed");p.snapshot.channels.push_back({c.identifier,*c.logical_size.value(),{},std::move(reader)});break;}
 case MetadataCapturePhase::ReadData:{const auto main_count=p.directory?0U:1U;if(p.index==main_count+p.snapshot.channels.size()){phase=MetadataCapturePhase::DataBoundary;break;}const bool is_main=p.index<main_count;const auto n=is_main?0:p.index-main_count;const auto size=is_main?*p.progress.main_logical_bytes:p.snapshot.channels[n].logical_size;if(p.offset<size){out.content_reads=1;++p.progress.read_calls;auto data=value(is_main?p.source->read_content(p.limits.read,p.offset,stop):p.snapshot.channels[n].source->read_content(p.limits.read,p.offset,stop));out.content_bytes=data.bytes.size();add(p.progress.read_bytes,data.bytes.size());add(p.progress.pass_bytes,data.bytes.size());if(data.bytes.empty()||data.bytes.size()>p.limits.read.max_bytes||data.bytes.size()>size-p.offset||(data.complete&&data.bytes.size()!=size-p.offset))fail("metadata_capture.read_shape");p.hash.update(data.bytes);p.offset+=data.bytes.size();if(p.offset==size&&!data.complete)fail("metadata_capture.stream_grew");}if(p.offset==size){const auto digest=p.hash.digest();if(p.progress.data_pass==1){if(is_main)p.main=digest;else p.snapshot.channels[n].digest=digest;}else if(digest!=(is_main?*p.main:p.snapshot.channels[n].digest))fail("metadata_capture.stream_changed");++p.index;p.offset=0;p.hash.reset();}break;}
 case MetadataCapturePhase::DataBoundary:p.basic();if(p.progress.data_pass==1){p.progress.data_pass=2;p.progress.pass_bytes=0;p.index=0;phase=MetadataCapturePhase::ReadData;}else phase=MetadataCapturePhase::VerifyAttributeCatalog;break;
 case MetadataCapturePhase::VerifyAttributeCatalog:p.check_attributes(value(p.source->inspect_attributes(policy.limits)));p.index=0;phase=MetadataCapturePhase::VerifyAttributes;break;
 case MetadataCapturePhase::VerifyAttributes:if(p.index==p.snapshot.attributes.size()){p.index=0;phase=MetadataCapturePhase::VerifySecurity;}else{const auto&a=p.snapshot.attributes[p.index++];if(!attribute_same(a,value(p.source->read_attribute(a.identifier,policy.limits))))fail("metadata_capture.attribute_changed");}break;
 case MetadataCapturePhase::VerifySecurity:if(p.index==p.parts.size())phase=MetadataCapturePhase::VerifyChannels;else{const auto i=p.index++;if(!security_same(p.snapshot.security[i],value(p.source->read_security(p.parts[i],policy.limits))))fail("metadata_capture.security_changed");}break;
 case MetadataCapturePhase::VerifyChannels:if(p.storage.model==StorageModel::LinuxStatx){DataChannelCatalog current;current.owner=value(p.source->inspect_basic()).identity;p.check_catalog(current);}else p.check_catalog(value(p.source->inspect_data_channels(policy.limits)));phase=MetadataCapturePhase::FinalBasic;break;
 case MetadataCapturePhase::FinalBasic:p.basic();p.compare_expected();p.verified=true;phase=MetadataCapturePhase::Seal;break;
 case MetadataCapturePhase::Seal:{require(detail::seal_native_metadata_capture(*this));stop_now(stop);auto done=p.progress;done.phase=MetadataCapturePhase::Complete;p.proof=std::shared_ptr<const NativeMetadataProof>(new NativeMetadataProof(std::move(p.snapshot),p.main,p.source,p.lease,done));phase=MetadataCapturePhase::Complete;break;}
 default:fail("metadata_capture.invalid_phase",ObservationState::Failed,AdapterError::InvalidNativeResult);
 }
 if(auto e=cleanup_error())cleanup_fail(*e);stop_now(stop);out.phase=phase;return R::available(out);
 }catch(const Failure&e){p.proof.reset();p.failure=e.detail;phase=stop.stop_requested()?MetadataCapturePhase::Cancelled:MetadataCapturePhase::Failed;return R::unavailable(e.detail.state,e.detail.error);}
}
} // namespace ck::files
