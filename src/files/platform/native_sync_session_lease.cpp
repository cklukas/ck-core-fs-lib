// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_session_lease.hpp"
#include <algorithm>
#include <atomic>
namespace ck::files::detail {
namespace {
template<class T>Observation<T> rejected(const char* tag,ObservationState state=ObservationState::Changed) {
    return Observation<T>::unavailable(state,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),tag});
}
template<class T,class U>Observation<T> propagate(const Observation<U>& result) {
    const auto& e=*result.unavailable_detail();
    return Observation<T>::unavailable(e.state,e.error);
}
}
NativeSessionLease::NativeSessionLease(std::shared_ptr<SessionReaderEpoch> epoch,PreparedJournalRoot::Pointer root,std::uint64_t generation):epoch_(std::move(epoch)),root_(std::move(root)),generation_(generation){}
Observation<std::shared_ptr<NativeSessionLease>> NativeSessionLease::borrow(SyncSession& session,const std::shared_ptr<SessionReadConsumer>& consumer) {
    using R=Observation<std::shared_ptr<NativeSessionLease>>;
    if(!consumer||session.finished_||!certify_native_sync_backend(*session.backend_))return rejected<std::shared_ptr<NativeSessionLease>>("session_lease.native_backend_required",ObservationState::Unsupported);
    auto valid=session.revalidate();if(!valid.value())return propagate<std::shared_ptr<NativeSessionLease>>(valid);if(!*valid.value())return rejected<std::shared_ptr<NativeSessionLease>>("session_lease.revalidate_false",ObservationState::Unsupported);
    auto root=session.storage_root();if(!root)return rejected<std::shared_ptr<NativeSessionLease>>("session_lease.root_missing",ObservationState::Unsupported);
    if(!session.reader_epoch_||!session.reader_epoch_->active_){
        static std::atomic<std::uint64_t> next{1};auto id=next.load(std::memory_order_relaxed);
        while(id&&id!=UINT64_MAX&&!next.compare_exchange_weak(id,id+1,std::memory_order_relaxed)){}
        if(!id||id==UINT64_MAX)return rejected<std::shared_ptr<NativeSessionLease>>("session_lease.epoch_exhausted",ObservationState::Unsupported);
        if(session_epoch_before_construct_test)session_epoch_before_construct_test();
        session.reader_epoch_=std::shared_ptr<SessionReaderEpoch>(new SessionReaderEpoch(&session,id));
    }
    auto epoch=session.reader_epoch_;
    epoch->readers_.erase(std::remove_if(epoch->readers_.begin(),epoch->readers_.end(),[](const auto& p){return p.expired();}),epoch->readers_.end());
    auto lease=std::shared_ptr<NativeSessionLease>(new NativeSessionLease(epoch,std::move(root),session.snapshot_.generation));
    epoch->readers_.push_back(consumer);
    return R::available(std::move(lease));
}
std::uint64_t NativeSessionLease::epoch_id()const noexcept{return epoch_->id_;}
Observation<bool> NativeSessionLease::revalidate()const {
    if(!epoch_->active_||!epoch_->session_)return rejected<bool>("session_lease.revoked");
    if(epoch_->session_->snapshot_.generation!=generation_)return rejected<bool>("session_lease.generation_changed");
    return epoch_->session_->revalidate();
}
Observation<std::intptr_t> NativeSessionLease::handle(bool right)const {
    auto valid=revalidate();if(!valid.value())return propagate<std::intptr_t>(valid);if(!*valid.value())return rejected<std::intptr_t>("session_lease.revalidate_false",ObservationState::Unsupported);
    const auto handle=epoch_->session_->root_handle(right);
    if(handle<0)return rejected<std::intptr_t>("session_lease.root_closed");
    return Observation<std::intptr_t>::available(handle);
}
Observation<std::unique_ptr<DirectoryCursor>> NativeSessionLease::open_root(bool right)const {
    auto valid=revalidate();if(!valid.value())return propagate<std::unique_ptr<DirectoryCursor>>(valid);if(!*valid.value())return rejected<std::unique_ptr<DirectoryCursor>>("session_lease.revalidate_false",ObservationState::Unsupported);
    auto opened=open_native_session_root(*this,right);if(!opened.value())return opened;
    valid=revalidate();if(!valid.value())return propagate<std::unique_ptr<DirectoryCursor>>(valid);if(!*valid.value())return rejected<std::unique_ptr<DirectoryCursor>>("session_lease.revalidate_false",ObservationState::Unsupported);
    return opened;
}
} // namespace ck::files::detail
