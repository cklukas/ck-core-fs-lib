// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_replay.hpp"
#include "sha256.hpp"

namespace ck::files {
namespace {
template<class T> Observation<T> fail(const char* op, ObservationState state = ObservationState::Unsupported,
                                      AdapterError code = AdapterError::ProviderReviewRequired) {
    return Observation<T>::unavailable(state, {ErrorDomain::Adapter, static_cast<std::int64_t>(code), op});
}
template<class T> Observation<T> propagate(const UnavailableObservation& e) {
    return Observation<T>::unavailable(e.state, e.error);
}
Observation<bool> interrupted() { return fail<bool>("metadata_replay.cancelled",ObservationState::Unknown,AdapterError::InterruptedRead); }
}
bool MetadataReplayPolicy::valid() const noexcept {
    return version==1 && limits.valid() && (scope==RegularMetadataScope::CompleteMetadataV1 ||
        scope==RegularMetadataScope::OrdinaryCallerVisibleV1) &&
        (ownership==MetadataOwnership::Original || ownership==MetadataOwnership::CurrentCaller);
}
Observation<std::array<std::byte,32>> digest_metadata_replay_channel(const MetadataReplayChannelSource& stream,
    const NativeFeatureIdentifier& identifier,const ObjectIdentity& owner,std::uint64_t size,std::stop_token stop) {
    using Result=Observation<std::array<std::byte,32>>;
    const auto check=[&]()->Observation<bool> {
        const auto state=stream.inspect();
        if(!state.value()) return propagate<bool>(*state.unavailable_detail());
        if(state.value()->identifier!=identifier || state.value()->logical_size!=size ||
            compare_identity(state.value()->owner,owner)!=IdentityComparison::Same)
            return fail<bool>("metadata_replay.channel_identity_size",ObservationState::Changed,AdapterError::MetadataChanged);
        return Observation<bool>::available(true);
    };
    auto stable=check();if(!stable.value())return propagate<std::array<std::byte,32>>(*stable.unavailable_detail());
    Sha256 hash;std::uint64_t offset=0;
    while(offset<size) {
        if(stop.stop_requested())return propagate<std::array<std::byte,32>>(*interrupted().unavailable_detail());
        const auto data=stream.read_content({64*1024},offset,stop);
        if(!data.value())return propagate<std::array<std::byte,32>>(*data.unavailable_detail());
        if(data.value()->bytes.empty() || data.value()->bytes.size()>size-offset ||
            (data.value()->complete && data.value()->bytes.size()!=size-offset))
            return fail<std::array<std::byte,32>>("metadata_replay.channel_read_shape",ObservationState::Changed,AdapterError::MetadataChanged);
        hash.update(data.value()->bytes);offset+=data.value()->bytes.size();
        if(offset==size&&!data.value()->complete)
            return fail<std::array<std::byte,32>>("metadata_replay.channel_grew",ObservationState::Changed,AdapterError::MetadataChanged);
    }
    stable=check();if(!stable.value())return propagate<std::array<std::byte,32>>(*stable.unavailable_detail());
    return Result::available(hash.digest());
}
} // namespace ck::files
