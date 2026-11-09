// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_retry.h"
#include "native_handles.hpp"
#include "verified_copy_retry.hpp"
#include "journal_root_handles.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <new>
#include <stdexcept>
#include <thread>

using namespace ck::files;
namespace {
std::atomic<uint32_t> live_jobs{0};
std::atomic<uint64_t> next_job{1};
struct RetryState final {
    std::mutex mutex;
    std::condition_variable cv;
    std::stop_source stop;
    ckfer_snapshot_v1 cache{};
    bool execute=false,slot=false;
    ~RetryState(){if(slot)--live_jobs;}
};
void require(bool valid){if(!valid)throw std::invalid_argument("invalid retry ABI input");}
template<class F> ckfe_api_status boundary(F&& f) noexcept {
    try{return f();}catch(const std::bad_alloc&){return CKFE_API_OUT_OF_MEMORY;}
    catch(const std::invalid_argument&){return CKFE_API_INVALID_ARGUMENT;}
    catch(...){return CKFE_API_EXCEPTION;}
}
template<class T> void init(T& value) noexcept {value={};value.version=CKFER_VERSION;value.struct_size=sizeof(T);}
template<class T> bool header(const T* value) noexcept {return value&&value->version==CKFER_VERSION&&value->struct_size==sizeof(T);}
void native_header(const ckfer_native_v1& n) {
    require(header(&n)&&!n.reserved&&n.encoding<=CKFER_UTF16&&n.data&&n.byte_count&&n.byte_count<=CKFER_MAX_NATIVE_BYTES&&
        (n.encoding!=CKFER_UTF16||!(n.byte_count&1)));
}
std::u16string units(const ckfer_native_v1& n) {
    std::u16string result(static_cast<size_t>(n.byte_count/2),u'\0');
    std::memcpy(result.data(),n.data,static_cast<size_t>(n.byte_count));return result;
}
NativeName name(const ckfer_native_v1& n) {
    native_header(n);auto value=n.encoding==CKFER_POSIX_BYTES?NativeName::from_posix(
        std::string(static_cast<const char*>(n.data),static_cast<size_t>(n.byte_count))):NativeName::from_windows(units(n));
    require(bool(value));return std::move(*value);
}
NativeAbsolutePath address(const ckfer_native_v1& n) {
    native_header(n);auto value=n.encoding==CKFER_POSIX_BYTES?NativeAbsolutePath::from_posix(
        std::string_view(static_cast<const char*>(n.data),static_cast<size_t>(n.byte_count))):NativeAbsolutePath::from_windows(units(n));
    require(value.value()!=nullptr);return std::move(value).take_value();
}
VerifiedCopyRetryRequest convert(const ckfer_options_v1& in,PreparedJournalRoot::Pointer original={},PreparedJournalRoot::Pointer attempt={}) {
    require(header(&in)&&!in.reserved&&in.source&&in.source->child&&in.destination&&in.destination->cursor&&
        (!in.candidate||in.candidate->child)&&bool(in.candidate)==bool(in.prefix_bytes)&&
        in.max_content_bytes&&in.max_content_bytes<=UINT64_C(4)*1024*1024*1024&&
        in.max_journal_bytes&&in.max_journal_bytes<=4*1024*1024&&in.prefix_bytes<=in.max_content_bytes&&
        in.original_item<256&&in.metadata_scope<=CKFER_ORDINARY_METADATA_V1&&
        in.metadata_ownership<=CKFER_CURRENT_CALLER_OWNERSHIP&&in.allow_privilege_metadata<=1);
    for(auto r:in.reserved_words)require(!r);
    require(bool(original)==bool(attempt));
    if(original)for(const auto* text:{&in.original_journal_root,&in.attempt_journal_root})
        require(header(text)&&!text->reserved&&text->encoding<=CKFER_UTF16&&!text->data&&!text->byte_count);
    VerifiedCopyRetryRequest out=original?
        VerifiedCopyRetryRequest(std::move(original),name(in.original_journal_name),std::move(attempt),
            name(in.attempt_journal_name),name(in.staging_hint),name(in.destination_name)):
        VerifiedCopyRetryRequest(address(in.original_journal_root),name(in.original_journal_name),
            address(in.attempt_journal_root),name(in.attempt_journal_name),name(in.staging_hint),name(in.destination_name));
    out.source=in.source->child;out.candidate=in.candidate?in.candidate->child:nullptr;
    out.candidate_prefix_bytes=in.prefix_bytes;out.destination=in.destination->cursor;
    out.destination_address=in.destination->address;out.original_item=static_cast<size_t>(in.original_item);
    out.max_content_bytes=in.max_content_bytes;out.max_journal_bytes=static_cast<size_t>(in.max_journal_bytes);
    out.metadata_policy.scope=static_cast<RegularMetadataScope>(in.metadata_scope);
    out.metadata_policy.ownership=static_cast<MetadataOwnership>(in.metadata_ownership);
    out.metadata_policy.allow_privilege_metadata=in.allow_privilege_metadata!=0;
    bool nonzero=false;for(size_t i=0;i<16;++i){out.attempt_id.bytes[i]=std::byte(in.attempt_id[i]);nonzero|=in.attempt_id[i]!=0;}require(nonzero);
    require(out.source->name().encoding()==out.destination_name.encoding()&&
        out.staging_hint.encoding()==out.destination_name.encoding());
    return out;
}
ckfer_identity_v1 identity(const ObjectIdentity* value) noexcept {
    ckfer_identity_v1 result{};if(!value)return result;
    result.scheme=static_cast<uint32_t>(value->scheme);result.has_generation=value->generation.has_value();
    result.generation=value->generation.value_or(0);std::memcpy(result.volume,value->volume.bytes.data(),16);
    std::memcpy(result.object,value->object.bytes.data(),16);return result;
}
void error(ckfer_snapshot_v1& cache,ObservationState observation,ErrorDomain domain,int64_t code,const char* operation,size_t count) noexcept {
    cache.failure_state=static_cast<uint32_t>(observation);cache.failure_domain=static_cast<uint32_t>(domain);cache.failure_code=code;
    const auto bytes=std::min(count,sizeof(cache.failure_operation)-1);std::memset(cache.failure_operation,0,sizeof(cache.failure_operation));
    if(bytes)std::memcpy(cache.failure_operation,operation,bytes);
}
void error(ckfer_snapshot_v1& cache,const UnavailableObservation& failure) noexcept {
    error(cache,failure.state,failure.error.domain,failure.error.code,failure.error.operation.data(),failure.error.operation.size());
}
bool finish_error(ckfer_snapshot_v1& cache,const VerifiedCopyRetryJob& core)noexcept {
    const auto& e=core.native_finish_failure();if(!e.present)return false;
    error(cache,e.state,e.domain,e.code,e.operation.data(),std::char_traits<char>::length(e.operation.data()));
    cache.state=CKFER_REVIEW_REQUIRED;cache.recovery_required=1;return true;
}
void emergency(ckfer_snapshot_v1& cache) noexcept {
    error(cache,ObservationState::Failed,ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidNativeResult),"copy_retry.worker_exception",27);
    cache.state=CKFER_FAILED;cache.recovery_required=1;
}
uint32_t phase(VerifiedCopyRetryState state) noexcept {
    switch(state) {
    case VerifiedCopyRetryState::LoadingJournal:return CKFER_LOADING_JOURNAL;
    case VerifiedCopyRetryState::ReviewingSource:return CKFER_REVIEWING;
    case VerifiedCopyRetryState::AwaitingReview:return CKFER_AWAITING_REVIEW;
    case VerifiedCopyRetryState::RevalidatingSource:return CKFER_REVALIDATING;
    case VerifiedCopyRetryState::Copying:return CKFER_COPYING;
    case VerifiedCopyRetryState::Complete:return CKFER_COMPLETE;
    case VerifiedCopyRetryState::ReviewRequired:return CKFER_REVIEW_REQUIRED;
    case VerifiedCopyRetryState::Cancelled:return CKFER_CANCELLED;
    }return CKFER_FAILED;
}
bool terminal(uint32_t state) noexcept {return state>=CKFER_COMPLETE;}
void cache_core(RetryState& state,const VerifiedCopyRetryJob& core,bool final) {
    auto& out=state.cache;
    const auto next=phase(core.state());out.state=(!final&&terminal(next))?out.state:next;
    out.source_bytes=core.source_bytes();out.reviewed_bytes=core.reviewed_bytes();out.copied_bytes=core.progress().observed_bytes;
    out.prefix_bytes=core.prefix_bytes();out.copied_prefix_bytes=core.copied_prefix_bytes();
    if(const auto digest=core.reviewed_digest()){out.has_source_digest=1;std::memcpy(out.source_digest,digest->data(),32);}
    if(const auto digest=core.origin_digest()){out.has_origin_digest=1;std::memcpy(out.origin_journal_digest,digest->data(),32);}
    if(core.failure())error(out,*core.failure());
    if(!core.finish_operation().empty())
        error(out,static_cast<ObservationState>(out.failure_state),static_cast<ErrorDomain>(out.failure_domain),
            out.failure_code,core.finish_operation().data(),core.finish_operation().size());
    if(final&&finish_error(out,core)){++out.sequence;state.cv.notify_all();return;}
    out.recovery_required=core.has_attempt()&&next!=CKFER_COMPLETE;
    if(next==CKFER_REVIEW_REQUIRED)out.recovery_required=1;
    if(next==CKFER_AWAITING_REVIEW&&!state.execute)out.review_id=out.job_id;
    ++out.sequence;state.cv.notify_all();
}
void run(std::shared_ptr<RetryState> state,VerifiedCopyRetryRequest request) noexcept {
    VerifiedCopyRetryJob::Pointer core;
    bool exceptional=false;
    try {
        auto made=VerifiedCopyRetryJob::create(std::move(request));
        if(!made.value()) {std::lock_guard lock(state->mutex);error(state->cache,*made.unavailable_detail());state->cache.state=CKFER_REVIEW_REQUIRED;}
        else {
            core=std::move(made).take_value();
            for(;;) {
                const auto current=core->advance(state->stop.get_token());
                {std::lock_guard lock(state->mutex);cache_core(*state,*core,false);}
                if(terminal(phase(current)))break;
                if(current==VerifiedCopyRetryState::AwaitingReview) {
                    std::unique_lock lock(state->mutex);
                    state->cv.wait(lock,[&]{return state->execute||state->stop.stop_requested();});
                    const bool execute=state->execute&&!state->stop.stop_requested();lock.unlock();
                    if(execute) {
                        auto approved=core->approve();
                        if(!approved.value()||!*approved.value()) {
                            std::lock_guard guard(state->mutex);
                            if(!approved.value())error(state->cache,*approved.unavailable_detail());else emergency(state->cache);
                            state->cache.state=CKFER_REVIEW_REQUIRED;exceptional=true;break;
                        }
                    }
                }
            }
        }
    } catch(...) {exceptional=true;std::lock_guard lock(state->mutex);emergency(state->cache);}
    // Finalization and destruction stay on the worker. This path allocates no
    // cached error strings and cannot turn an exception into public Complete.
    if(core) {
        try {
            auto finished=core->finish_io();
            std::lock_guard lock(state->mutex);
            if(!exceptional)cache_core(*state,*core,true);
            if(!finished.value()||!*finished.value()) {
                if(!finished.value()) {
                    const auto& e=*finished.unavailable_detail();error(state->cache,e);
                    if(!core->finish_operation().empty())error(state->cache,e.state,e.error.domain,e.error.code,core->finish_operation().data(),core->finish_operation().size());
                } else if(!finish_error(state->cache,*core))emergency(state->cache);
                state->cache.state=CKFER_REVIEW_REQUIRED;state->cache.recovery_required=1;
            }
        } catch(...) {std::lock_guard lock(state->mutex);if(!finish_error(state->cache,*core))emergency(state->cache);}
    }
    core.reset();
    // A failed core factory may leave request holding native inputs. Release
    // every caller-owned reference on this worker before publishing drained.
    request.source.reset();request.candidate.reset();request.destination.reset();
    request.original_prepared_root.reset();request.attempt_prepared_root.reset();
    {std::lock_guard lock(state->mutex);state->cache.worker_drained=1;state->cache.review_id=0;++state->cache.sequence;state->cv.notify_all();}
}
}
struct ckfer_job {std::shared_ptr<RetryState> state;};
namespace {
ckfe_api_status start(VerifiedCopyRetryRequest request,ckfer_job** output) {
    auto state=std::make_shared<RetryState>();
    auto count=live_jobs.load();do{if(count>=CKFER_MAX_JOBS)return CKFE_API_BUSY;}while(!live_jobs.compare_exchange_weak(count,count+1));
    state->slot=true;
    auto id=next_job.load();do{if(id==UINT64_MAX)return CKFE_API_BUSY;}while(!next_job.compare_exchange_weak(id,id+1));
    init(state->cache);state->cache.job_id=id;state->cache.sequence=1;
    state->cache.source_identity=identity(request.source->metadata().identity.value());
    state->cache.candidate_identity=identity(request.candidate?request.candidate->metadata().identity.value():nullptr);
    auto result=std::make_unique<ckfer_job>();result->state=state;
    std::thread worker([state,request=std::move(request)]() mutable {run(std::move(state),std::move(request));});
    try {worker.detach();}
    catch(...) {
        {std::lock_guard lock(state->mutex);state->stop.request_stop();state->cv.notify_all();}
        if(worker.joinable())worker.join();
        throw;
    }
    *output=result.release();return CKFE_API_OK;
}
}
extern "C" {
void ckfer_native_init_v1(ckfer_native_v1* out) noexcept {if(out)init(*out);}
void ckfer_options_init_v1(ckfer_options_v1* out) noexcept {
    if(!out)return;
    init(*out);
    for(auto* native:{&out->original_journal_root,&out->original_journal_name,&out->attempt_journal_root,&out->attempt_journal_name,&out->staging_hint,&out->destination_name})init(*native);
    out->max_content_bytes=UINT64_C(4)*1024*1024*1024;out->max_journal_bytes=4*1024*1024;
}
void ckfer_snapshot_init_v1(ckfer_snapshot_v1* out) noexcept {if(out)init(*out);}
ckfe_api_status ckfer_start_v1(const ckfer_options_v1* input,ckfer_job** output) noexcept {
    if(output)*output=nullptr;
    return boundary([&]()->ckfe_api_status {
        require(input&&output);return start(convert(*input),output);
    });
}
ckfe_api_status ckfer_start_with_journal_roots_v1(const ckfer_options_v1* input,
    const ckfjr_root* original,const ckfjr_root* attempt,ckfer_job** output) noexcept {
    if(output)*output=nullptr;
    return boundary([&]()->ckfe_api_status {
        require(input&&output&&original&&attempt);
        auto source_root=retain_prepared_journal_root(original);
        if(!source_root.value())return CKFE_API_OPERATION_UNAVAILABLE;
        auto attempt_root=retain_prepared_journal_root(attempt);
        if(!attempt_root.value())return CKFE_API_OPERATION_UNAVAILABLE;
        return start(convert(*input,std::move(source_root).take_value(),std::move(attempt_root).take_value()),output);
    });
}
ckfe_api_status ckfer_poll_v1(const ckfer_job* job,ckfer_snapshot_v1* output) noexcept {
    if(!header(output)||output->reserved)return CKFE_API_INVALID_ARGUMENT;
    for(auto r:output->reserved_words)if(r)return CKFE_API_INVALID_ARGUMENT;
    init(*output);
    return boundary([&]()->ckfe_api_status{require(job&&job->state);std::lock_guard lock(job->state->mutex);*output=job->state->cache;return CKFE_API_OK;});
}
ckfe_api_status ckfer_execute_v1(ckfer_job* job,uint64_t review) noexcept {
    return boundary([&]()->ckfe_api_status {
        require(job&&job->state&&review);auto& state=*job->state;std::lock_guard lock(state.mutex);
        if(review!=state.cache.review_id)return CKFE_API_STALE_PLAN;
        if(state.cache.state!=CKFER_AWAITING_REVIEW||state.execute||state.stop.stop_requested())return CKFE_API_NOT_READY;
        state.execute=true;state.cache.review_id=0;state.cache.state=CKFER_REVALIDATING;++state.cache.sequence;state.cv.notify_all();return CKFE_API_OK;
    });
}
ckfe_api_status ckfer_cancel_v1(ckfer_job* job) noexcept {
    return boundary([&]()->ckfe_api_status {
        require(job&&job->state);std::lock_guard lock(job->state->mutex);
        job->state->stop.request_stop();job->state->cv.notify_all();return CKFE_API_OK;
    });
}
ckfe_api_status ckfer_worker_drained_v1(const ckfer_job* job,uint32_t* output) noexcept {
    if(output)*output=0;
    return boundary([&]()->ckfe_api_status{require(job&&job->state&&output);std::lock_guard lock(job->state->mutex);*output=job->state->cache.worker_drained;return CKFE_API_OK;});
}
ckfe_api_status ckfer_wait_v1(ckfer_job* job,uint32_t milliseconds) noexcept {
    return boundary([&]()->ckfe_api_status {
        require(job&&job->state&&milliseconds<=1000);auto& state=*job->state;std::unique_lock lock(state.mutex);
        return state.cv.wait_for(lock,std::chrono::milliseconds(milliseconds),[&]{
            return (state.cache.state==CKFER_AWAITING_REVIEW&&!state.stop.stop_requested())||state.cache.worker_drained;
        })?CKFE_API_OK:CKFE_API_NOT_READY;
    });
}
void ckfer_release(ckfer_job* job) noexcept {if(job){(void)ckfer_cancel_v1(job);delete job;}}
}
