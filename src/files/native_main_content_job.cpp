// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_main_content_job.hpp"
#include "sha256.hpp"
#include <algorithm>

namespace ck::files {
namespace detail {
// Implemented only by the native adapters. No caller-created OpenedEntry can
// issue a main-content proof; no metadata policy is consulted by this clone.
Observation<std::shared_ptr<const OpenedEntry>> open_native_main_content_source(std::shared_ptr<const OpenedEntry>);
}
namespace {
struct Failure{UnavailableObservation detail;};
[[noreturn]]void fail(const char* op,ObservationState state=ObservationState::Changed,AdapterError code=AdapterError::MetadataChanged){
    throw Failure{{state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),op}}};
}
template<class T>T value(Observation<T> o){if(!o.value())throw Failure{*o.unavailable_detail()};return std::move(o).take_value();}
void require(Observation<bool> o){if(!value(std::move(o)))fail("main_content.false_result",ObservationState::Failed,AdapterError::InvalidNativeResult);}
void cancelled(std::stop_token stop){if(stop.stop_requested())fail("main_content.cancelled",ObservationState::Unknown,AdapterError::InterruptedRead);}
template<class T>bool eq(const Observation<T>&a,const Observation<T>&b){
    if(a.value()&&b.value())return *a.value()==*b.value();
    return !a.value()&&!b.value()&&a.state()==b.state()&&a.unavailable_detail()->error==b.unavailable_detail()->error;
}
bool stable(const BasicMetadata&a,const BasicMetadata&b){
    return a.identity.value()&&b.identity.value()&&compare_identity(*a.identity.value(),*b.identity.value())==IdentityComparison::Same&&
        eq(a.kind,b.kind)&&eq(a.logical_size,b.logical_size)&&eq(a.allocated_size,b.allocated_size)&&eq(a.link_count,b.link_count)&&
        eq(a.modified,b.modified)&&eq(a.changed,b.changed)&&eq(a.created,b.created)&&eq(a.posix_uid,b.posix_uid)&&
        eq(a.posix_gid,b.posix_gid)&&eq(a.posix_permissions,b.posix_permissions)&&eq(a.bsd_flags,b.bsd_flags)&&
        eq(a.windows_attributes,b.windows_attributes)&&eq(a.mount_id,b.mount_id);
}
struct Cleanup final:MetadataCaptureFailureLatch {
    std::shared_ptr<const MetadataCaptureFailureLatch> outer;
    mutable std::optional<MetadataCaptureCleanupError> first;
    void record_first(MetadataCaptureCleanupError e)const noexcept override{if(!first){first=e;if(outer)outer->record_first(e);}}
};
}
struct NativeMainContentJob::Impl {
    // Empty cleanup snapshot constructed before acquiring native owners. No
    // noexcept close path constructs strings (including MSVC proxy storage).
    const MetadataReplaySnapshot empty_snapshot;
    Cleanup cleanup;
    HeldChild::Pointer held;
    JournalScopeGuard::Pointer scope;
    std::shared_ptr<const OpenedEntry> source;
    NativeMainContentLimits limits;
    NativeMainContentProgress progress;
    BasicMetadata before;
    std::optional<UnavailableObservation> failure;
    std::shared_ptr<const NativeMainContentProof> proof;
    Sha256 hash;
    std::array<std::byte,32> first_hash{};
    std::uint64_t offset=0;
    bool closed=false;
    ~Impl(){drain();}
    void drain()noexcept{
        if(closed)return;closed=true;
        detail::MetadataCaptureCleanupScope observer(&cleanup);
        detail::finish_native_metadata_capture(source.get(),empty_snapshot);
        source.reset();held.reset();scope.reset();cleanup.outer.reset();
        if(cleanup.first)proof.reset();
        if(progress.phase==NativeMainContentPhase::DataReady&&!cleanup.first)progress.phase=NativeMainContentPhase::Closed;
    }
    void check_cleanup()const {if(cleanup.first){auto&e=*cleanup.first;throw Failure{{e.state,{e.domain,e.code,e.operation}}};}}
    void scope_check(std::stop_token stop){if(scope){require(scope->check_root(stop));require(scope->check_entry(*held,stop));}}
    void membership(std::stop_token stop){
        cancelled(stop);scope_check(stop);
        const auto actual=value(source->inspect_basic());
        const auto current=value(held->inspect_basic());
        const auto refreshed=value(held->refresh(stop));
        if(!refreshed->continues(*held)||!stable(before,actual)||!stable(before,current)||!stable(before,refreshed->metadata()))
            fail("main_content.source_version_or_membership");
        scope_check(stop);cancelled(stop);check_cleanup();
    }
};
NativeMainContentJob::NativeMainContentJob(std::unique_ptr<Impl> p):impl_(std::move(p)){}
NativeMainContentJob::~NativeMainContentJob()=default;
const NativeMainContentProgress& NativeMainContentJob::progress()const noexcept{return impl_->progress;}
std::optional<MetadataCaptureCleanupError> NativeMainContentJob::cleanup_error()const noexcept{return impl_->cleanup.first;}
Observation<bool> NativeMainContentJob::finish_read(){
    auto&p=*impl_;p.drain();
    if(auto e=p.cleanup.first)return Observation<bool>::unavailable(e->state,{e->domain,e->code,e->operation});
    return Observation<bool>::available(true);
}
Observation<std::shared_ptr<const NativeMainContentProof>> NativeMainContentJob::result()const{
    using R=Observation<std::shared_ptr<const NativeMainContentProof>>;const auto&p=*impl_;
    if(auto e=p.cleanup.first)return R::unavailable(e->state,{e->domain,e->code,e->operation});
    if(p.failure)return R::unavailable(p.failure->state,p.failure->error);
    if(p.closed&&p.progress.phase==NativeMainContentPhase::Closed&&p.proof)return R::available(p.proof);
    return R::unavailable(ObservationState::Unknown,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"main_content.closed_proof_required"});
}
Observation<std::unique_ptr<NativeMainContentJob>> NativeMainContentJob::begin_held(
    HeldChild::Pointer held,NativeMainContentLimits limits,JournalScopeGuard::Pointer scope,
    std::shared_ptr<const MetadataCaptureFailureLatch> latch,std::stop_token stop){
    using R=Observation<std::unique_ptr<NativeMainContentJob>>;
    // Stack sink also covers allocation failure before Impl exists and the
    // final release of rvalue input owners on invalid/cancelled factories.
    Cleanup startup;startup.outer=std::move(latch);
    detail::MetadataCaptureCleanupScope startup_observer(&startup);
    std::unique_ptr<Impl> p;
    try{
        p=std::make_unique<Impl>();p->cleanup.outer=startup.outer;
        detail::MetadataCaptureCleanupScope observer(&p->cleanup);
        p->held=std::move(held);p->scope=std::move(scope);p->limits=limits;
        if(!p->held||!limits.valid()||!requests_content_read(p->held->access()))
            fail("main_content.input",ObservationState::Failed,AdapterError::InvalidAccess);
        cancelled(stop);p->scope_check(stop);
        p->source=value(detail::open_native_main_content_source(p->held->child_));p->check_cleanup();
        p->before=value(p->source->inspect_basic());
        const auto&b=p->before;
        if(!b.kind.value()||*b.kind.value()!=ObjectKind::RegularFile||!b.identity.value()||
           compare_identity(*b.identity.value(),*b.identity.value())!=IdentityComparison::Same||!b.logical_size.value()||
           !b.modified.value()||!b.changed.value()||!b.link_count.value()||*b.link_count.value()==0)
            fail("main_content.basic_qualification",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
        if(*b.logical_size.value()>limits.max_main_bytes)
            fail("main_content.logical_budget",ObservationState::Unknown,AdapterError::InventoryLimit);
        p->progress.main_bytes=*b.logical_size.value();p->membership(stop);p->check_cleanup();
        auto job=R::available(std::unique_ptr<NativeMainContentJob>(new NativeMainContentJob(std::move(p))));
        startup.outer.reset();return job;
    }catch(const Failure&e){
        if(p)p->drain();held.reset();scope.reset();startup.outer.reset();
        const auto close=p&&p->cleanup.first?p->cleanup.first:startup.first;
        if(close)return R::unavailable(close->state,{close->domain,close->code,close->operation});
        return R::unavailable(e.detail.state,e.detail.error);
    }catch(...){if(p)p->drain();held.reset();scope.reset();startup.outer.reset();throw;}
}

Observation<NativeMainContentAdvance> NativeMainContentJob::advance(std::stop_token stop){
    using R=Observation<NativeMainContentAdvance>;auto&p=*impl_;
    if(p.cleanup.first){p.drain();const auto&e=*p.cleanup.first;return R::unavailable(e.state,{e.domain,e.code,e.operation});}
    if(p.failure)return R::unavailable(p.failure->state,p.failure->error);
    if(p.closed)return R::unavailable(ObservationState::Unknown,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"main_content.already_closed"});
    detail::MetadataCaptureCleanupScope observer(&p.cleanup);
    try{
        p.membership(stop);NativeMainContentAdvance out{p.progress.phase};
        switch(p.progress.phase){
        case NativeMainContentPhase::Basic:
            p.progress.pass=1;p.progress.phase=NativeMainContentPhase::ReadData;break;
        case NativeMainContentPhase::ReadData:{
            const auto size=*p.progress.main_bytes;
            if(p.offset==size){p.progress.phase=p.progress.pass==1?NativeMainContentPhase::Boundary:NativeMainContentPhase::FinalBasic;break;}
            const auto count=static_cast<std::size_t>(std::min<std::uint64_t>(p.limits.read.max_bytes,size-p.offset));
            ++p.progress.read_calls;out.content_reads=1;
            auto read=value(p.source->read_content({count},p.offset,stop));
            if(read.bytes.empty()||read.bytes.size()>count||read.complete!=(read.bytes.size()==size-p.offset))
                fail("main_content.read_shape",ObservationState::Changed,AdapterError::InvalidNativeResult);
            out.content_bytes=read.bytes.size();p.hash.update(read.bytes);p.offset+=read.bytes.size();
            p.progress.pass_bytes=p.offset;p.progress.read_bytes+=read.bytes.size();break;}
        case NativeMainContentPhase::Boundary:
            p.first_hash=p.hash.digest();p.hash.reset();p.offset=0;p.progress.pass_bytes=0;p.progress.pass=2;
            p.progress.phase=NativeMainContentPhase::ReadData;break;
        case NativeMainContentPhase::FinalBasic:{
            const auto after=value(p.source->inspect_basic());
            if(!stable(p.before,after)||p.first_hash!=p.hash.digest())fail("main_content.two_pass_changed");
            p.proof=std::shared_ptr<const NativeMainContentProof>(new NativeMainContentProof(p.before,after,p.first_hash,*p.progress.main_bytes));
            p.progress.phase=NativeMainContentPhase::DataReady;break;}
        case NativeMainContentPhase::DataReady:break;
        default:fail("main_content.invalid_phase",ObservationState::Failed,AdapterError::InvalidNativeResult);
        }
        p.membership(stop);out.phase=p.progress.phase;return R::available(out);
    }catch(const Failure&e){
        // Close actual native owners before any error copy/format allocation.
        p.proof.reset();p.progress.phase=stop.stop_requested()&&e.detail.error.domain==ErrorDomain::Adapter&&
            e.detail.error.code==static_cast<std::int64_t>(AdapterError::InterruptedRead)?NativeMainContentPhase::Cancelled:NativeMainContentPhase::Failed;
        p.drain();
        if(auto close=p.cleanup.first)return R::unavailable(close->state,{close->domain,close->code,close->operation});
        p.failure=e.detail;return R::unavailable(e.detail.state,e.detail.error);
    }catch(...){p.proof.reset();p.progress.phase=NativeMainContentPhase::Failed;p.drain();throw;}
}
} // namespace ck::files
