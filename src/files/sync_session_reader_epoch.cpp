// SPDX-License-Identifier: LGPL-2.0-or-later
#include "sync_session_reader_epoch.hpp"
namespace ck::files::detail {
Observation<bool> SessionReaderFailure::result()const {
    if(!failed)return Observation<bool>::available(true);
    // Allocating diagnostic, deliberately allowed to propagate after POD drain.
    return Observation<bool>::unavailable(state,{domain,code,operation.data()});
}
SessionReaderEpoch::SessionReaderEpoch(SyncSession* session,std::uint64_t id):session_(session),id_(id),readers_(std::initializer_list<std::weak_ptr<SessionReadConsumer>>{}){}
SessionReaderEpoch::~SessionReaderEpoch(){revoke();}
SessionReaderFailure SessionReaderEpoch::revoke()noexcept {
    if(!active_)return first_;
    // Serialized worker: revoke pointer BEFORE any consumer callback, native
    // close, lock release or destruction. A surviving lease cannot dereference it.
    active_=false;session_=nullptr;
    for(auto& weak:readers_){if(auto consumer=weak.lock()){
        const auto failure=consumer->revoke_readers();
        if(failure.failed&&!first_.failed)first_=failure;
    }}
    readers_.clear();return first_;
}
} // namespace ck::files::detail
