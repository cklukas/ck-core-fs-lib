// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "journal_root_handles.hpp"
#include "native_handles.hpp"
#include "../files/platform/journal_root_test_faults.hpp"
#include "../files/platform/prepared_journal_root_bridge.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace ck::files;
namespace {
std::atomic<std::uint32_t> live_roots{0};
struct RootState final {
    std::mutex mutex;
    std::condition_variable cv;
    std::stop_source stop;
    ckfjr_snapshot_v1 cache{};
    PreparedJournalRoot::Pointer root;
    std::atomic<std::uint32_t> handles{1};
    bool finish=false,slot=false,failure_pending=false;
    ~RootState(){if(slot)--live_roots;}
};
template<class T> void init(T& x) noexcept {x={};x.version=CKFJR_VERSION;x.struct_size=sizeof(T);}
template<class T> bool header(const T* x) noexcept {return x && x->version==CKFJR_VERSION && x->struct_size==sizeof(T);}
void require(bool ok){if(!ok)throw std::invalid_argument("invalid prepared journal root input");}
template<class F> ckfe_api_status boundary(F&& f) noexcept {
    try{return f();}catch(const std::bad_alloc&){return CKFE_API_OUT_OF_MEMORY;}
    catch(const std::invalid_argument&){return CKFE_API_INVALID_ARGUMENT;}
    catch(...){return CKFE_API_EXCEPTION;}
}
void set_error(ckfjr_snapshot_v1& cache,const UnavailableObservation& failure) noexcept {
    cache.failure_state=static_cast<uint32_t>(failure.state);
    cache.failure_domain=static_cast<uint32_t>(failure.error.domain);cache.failure_code=failure.error.code;
    std::memset(cache.failure_operation,0,sizeof(cache.failure_operation));
    std::memcpy(cache.failure_operation,failure.error.operation.data(),
        std::min(failure.error.operation.size(),sizeof(cache.failure_operation)-1));
}
void update_progress(RootState& state,const JournalRootPreparationProgress& p) {
    std::lock_guard lock(state.mutex);state.cache.phase=static_cast<uint32_t>(p.phase);
    state.cache.acquired_directories=p.acquired_directories;state.cache.flushed_directories=p.flushed_directories;
    state.cache.directory_creates=p.directory_creates;++state.cache.sequence;state.cv.notify_all();
}
PreparedJournalRootRequest convert(const ckfjr_options_v1& options) {
    require(header(&options)&&options.parent&&options.parent->cursor&&options.disposition<=CKFJR_PROVISION_CHILD&&
        options.max_ancestors>=1&&options.max_ancestors<=4096&&header(&options.child)&&!options.child.reserved&&
        options.child.encoding<=CKFJR_UTF16);
    for(const auto r:options.reserved_words)require(!r);
    PreparedJournalRootRequest result;result.parent=options.parent->cursor;
    result.disposition=static_cast<JournalRootDisposition>(options.disposition);result.max_ancestors=options.max_ancestors;
    result.navigation_hint=options.parent->address;
    const auto& n=options.child;
    if(options.disposition==CKFJR_ADOPT_HELD)require(!n.byte_count&&!n.data);
    else {
        require(n.data&&n.byte_count&&n.byte_count<=65536&&(n.encoding!=CKFJR_UTF16||!(n.byte_count&1)));
        if(n.encoding==CKFJR_POSIX_BYTES)result.child=NativeName::from_posix(std::string(static_cast<const char*>(n.data),static_cast<size_t>(n.byte_count)));
        else {
            std::u16string units(static_cast<size_t>(n.byte_count/2),u'\0');std::memcpy(units.data(),n.data,static_cast<size_t>(n.byte_count));
            result.child=NativeName::from_windows(std::move(units));
        }
        require(result.child.has_value());
        if(result.navigation_hint) {
            auto hint=result.navigation_hint->child_address(*result.child);
            if(hint.value())result.navigation_hint=std::move(hint).take_value();else result.navigation_hint.reset();
        }
    }
    return result;
}
void emergency(RootState& state) noexcept {
    if(state.cache.failure_domain==static_cast<uint32_t>(ErrorDomain::None)) {
        state.cache.failure_state=static_cast<uint32_t>(ObservationState::Failed);
        state.cache.failure_domain=static_cast<uint32_t>(ErrorDomain::Adapter);
        state.cache.failure_code=static_cast<int64_t>(AdapterError::InvalidNativeResult);
        constexpr char operation[]="journal_root.worker_exception";
        std::memset(state.cache.failure_operation,0,sizeof(state.cache.failure_operation));
        std::memcpy(state.cache.failure_operation,operation,sizeof(operation)-1);
    }
    state.cache.state=CKFJR_FAILED;state.cache.recovery_required=1;
}
bool collect_consumer_failure(RootState& state,const PreparedJournalRoot& root) noexcept {
    detail::PreparedJournalConsumerFailure failure;
    if(!detail::read_prepared_journal_consumer_failure(root,failure))return false;
    bool changed=state.cache.state!=CKFJR_FAILED||!state.cache.recovery_required;
    if(state.cache.failure_domain==static_cast<uint32_t>(ErrorDomain::None)||
        (state.failure_pending&&!failure.pending)) {
        state.cache.failure_state=static_cast<uint32_t>(failure.state);
        state.cache.failure_domain=static_cast<uint32_t>(failure.domain);state.cache.failure_code=failure.code;
        static_assert(sizeof(state.cache.failure_operation)==sizeof(failure.operation));
        std::memcpy(state.cache.failure_operation,failure.operation.data(),sizeof(state.cache.failure_operation));
        state.failure_pending=failure.pending;changed=true;
    }
    state.cache.state=CKFJR_FAILED;state.cache.recovery_required=1;
    if(changed){++state.cache.sequence;state.cv.notify_all();}
    return true;
}
void run(std::shared_ptr<RootState> state,PreparedJournalRootRequest request) noexcept {
    JournalRootPreparationProgress progress;
    try {
        auto prepared=prepare_native_journal_root(std::move(request),progress,state->stop.get_token(),
            [state](const auto& p){update_progress(*state,p);});
        std::lock_guard lock(state->mutex);
        state->cache.directory_creates=progress.directory_creates;
        if(!prepared.value()) {
            const auto& failure=*prepared.unavailable_detail();set_error(state->cache,failure);
            const bool cancelled=state->stop.stop_requested()&&failure.state==ObservationState::Changed&&
                failure.error.domain==ErrorDomain::Adapter&&
                failure.error.code==static_cast<int64_t>(AdapterError::InterruptedRead);
            state->cache.state=cancelled?CKFJR_CANCELLED:CKFJR_FAILED;
            state->cache.recovery_required=progress.directory_creates!=0;
        } else {
            state->root=std::move(prepared).take_value();const auto& id=state->root->identity();
            state->cache.identity_scheme=static_cast<uint32_t>(id.scheme);
            std::memcpy(state->cache.volume,id.volume.bytes.data(),16);std::memcpy(state->cache.object,id.object.bytes.data(),16);
            state->cache.state=state->finish?CKFJR_FINISHING:CKFJR_READY;
        }
        ++state->cache.sequence;state->cv.notify_all();
    } catch(...) {
        std::lock_guard lock(state->mutex);emergency(*state);state->finish=true;state->stop.request_stop();
        ++state->cache.sequence;state->cv.notify_all();
    }
    // One owner remains on this worker even after any exception. No root is
    // destroyed until consumers have released their shared native authority.
    for(;;) {
        PreparedJournalRoot::Pointer owned;
        {
            std::unique_lock lock(state->mutex);
            if(!state->root)break;
            state->cv.wait(lock,[&]{return state->finish;});
            collect_consumer_failure(*state,*state->root);
            try {
                if(detail::take_journal_root_worker_test_exception())throw std::bad_alloc();
            } catch(...) {emergency(*state);++state->cache.sequence;state->cv.notify_all();}
            if(state->cache.state==CKFJR_READY)state->cache.state=CKFJR_FINISHING;
            if(state->root.use_count()!=1) {state->cv.wait_for(lock,std::chrono::milliseconds(20));continue;}
            owned=std::move(state->root);
        }
        bool busy=false;
        try {
            bool consumer_failed;
            {std::lock_guard lock(state->mutex);consumer_failed=collect_consumer_failure(*state,*owned);}
            auto finished=owned->finish_io();
            busy=!consumer_failed&&!finished.value()&&finished.state()==ObservationState::Changed&&
                finished.unavailable_detail()->error.domain==ErrorDomain::Adapter&&
                finished.unavailable_detail()->error.code==static_cast<int64_t>(AdapterError::InvalidAccess)&&
                finished.unavailable_detail()->error.operation=="journal_root.consumers_active";
            if(!busy) {
                std::lock_guard lock(state->mutex);
                if(!finished.value()) {
                    if(state->cache.failure_domain==static_cast<uint32_t>(ErrorDomain::None))set_error(state->cache,*finished.unavailable_detail());
                    state->cache.state=CKFJR_FAILED;state->cache.recovery_required=1;
                } else if(!*finished.value()) {emergency(*state);}
                else if(state->cache.failure_domain==static_cast<uint32_t>(ErrorDomain::None))state->cache.state=CKFJR_COMPLETE;
            }
        } catch(...) {
            std::lock_guard lock(state->mutex);collect_consumer_failure(*state,*owned);emergency(*state);
        }
        if(busy) {
            std::unique_lock lock(state->mutex);state->root=std::move(owned);
            state->cv.wait_for(lock,std::chrono::milliseconds(20));continue;
        }
        // Native fallback destruction after a fallible finalizer also occurs
        // here, outside the cache lock, with no other shared consumers left.
        owned.reset();break;
    }
    std::lock_guard lock(state->mutex);state->cache.worker_drained=1;++state->cache.sequence;state->cv.notify_all();
}

}
struct ckfjr_root final {std::shared_ptr<RootState> state;};

namespace ck::files {
Observation<PreparedJournalRoot::Pointer> retain_prepared_journal_root(const ckfjr_root* root) {
    if(root && root->state) {
        std::lock_guard lock(root->state->mutex);
        if(root->state->root)collect_consumer_failure(*root->state,*root->state->root);
        if(root->state->cache.state==CKFJR_READY&&!root->state->finish&&root->state->root)
            return Observation<PreparedJournalRoot::Pointer>::available(root->state->root);
        if(root->state->failure_pending)return Observation<PreparedJournalRoot::Pointer>::unavailable(
            ObservationState::Changed,{ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidAccess),{}});
    }
    return Observation<PreparedJournalRoot::Pointer>::unavailable(ObservationState::Changed,
        {ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidAccess),"journal_root.not_ready"});
}
}
extern "C" {
void ckfjr_native_init_v1(ckfjr_native_v1* x) noexcept {if(x)init(*x);}
void ckfjr_options_init_v1(ckfjr_options_v1* x) noexcept {if(x){init(*x);init(x->child);x->max_ancestors=256;}}
void ckfjr_snapshot_init_v1(ckfjr_snapshot_v1* x) noexcept {if(x)init(*x);}
ckfe_api_status ckfjr_start_v1(const ckfjr_options_v1* options,ckfjr_root** out) noexcept {
    if(out)*out=nullptr;
    return boundary([&]{require(out&&options);auto request=convert(*options);
        auto count=live_roots.load();do {if(count>=CKFJR_MAX_ROOTS)return CKFE_API_BUSY;}
        while(!live_roots.compare_exchange_weak(count,count+1));
        std::shared_ptr<RootState> state;
        try {state=std::make_shared<RootState>();}catch(...){--live_roots;throw;}
        state->slot=true;init(state->cache);state->cache.state=CKFJR_PREPARING;
        auto result=std::make_unique<ckfjr_root>();result->state=state;
        std::thread worker(run,state,std::move(request));
        try {worker.detach();}catch(...) {
            {std::lock_guard lock(state->mutex);state->finish=true;state->stop.request_stop();state->cv.notify_all();}
            if(worker.joinable())worker.join();
            throw;
        }
        *out=result.release();return CKFE_API_OK;});
}
ckfe_api_status ckfjr_poll_v1(const ckfjr_root* root,ckfjr_snapshot_v1* out) noexcept {
    return boundary([&]{require(root&&root->state&&header(out));std::lock_guard lock(root->state->mutex);
        if(root->state->root)collect_consumer_failure(*root->state,*root->state->root);
        *out=root->state->cache;return CKFE_API_OK;});
}
ckfe_api_status ckfjr_retain_v1(const ckfjr_root* root,ckfjr_root** out) noexcept {
    if(out)*out=nullptr;
    return boundary([&]{require(root&&root->state&&out);
        std::lock_guard lock(root->state->mutex);
        if(root->state->root)collect_consumer_failure(*root->state,*root->state->root);
        if(root->state->finish||(root->state->cache.state!=CKFJR_PREPARING&&root->state->cache.state!=CKFJR_READY))
            return CKFE_API_INVALID_ARGUMENT;
        auto result=std::make_unique<ckfjr_root>();
        result->state=root->state;++root->state->handles;*out=result.release();return CKFE_API_OK;});
}
ckfe_api_status ckfjr_finish_v1(ckfjr_root* root) noexcept {
    return boundary([&]{require(root&&root->state);std::lock_guard lock(root->state->mutex);root->state->finish=true;
        root->state->stop.request_stop();if(root->state->cache.state==CKFJR_READY)root->state->cache.state=CKFJR_FINISHING;
        ++root->state->cache.sequence;root->state->cv.notify_all();return CKFE_API_OK;});
}
ckfe_api_status ckfjr_cancel_v1(ckfjr_root* root) noexcept {return ckfjr_finish_v1(root);}
ckfe_api_status ckfjr_worker_drained_v1(const ckfjr_root* root,uint32_t* out) noexcept {
    if(out)*out=0;
    return boundary([&]{require(root&&root->state&&out);std::lock_guard lock(root->state->mutex);*out=root->state->cache.worker_drained;return CKFE_API_OK;});
}
ckfe_api_status ckfjr_wait_v1(ckfjr_root* root,uint32_t milliseconds) noexcept {
    return boundary([&]{require(root&&root->state&&milliseconds<=1000);std::unique_lock lock(root->state->mutex);
        const auto before=root->state->cache.sequence;root->state->cv.wait_for(lock,std::chrono::milliseconds(milliseconds),
            [&]{return root->state->cache.sequence!=before||root->state->cache.worker_drained;});return CKFE_API_OK;});
}
void ckfjr_release(ckfjr_root* root) noexcept {
    if(!root)return;
    if(root->state&&root->state->handles.fetch_sub(1)==1) {
        std::lock_guard lock(root->state->mutex);root->state->finish=true;root->state->stop.request_stop();root->state->cv.notify_all();
    }
    delete root;
}
}
