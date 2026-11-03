// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_ownership_digest.hpp"
#include "sha256.hpp"
#include <array>
#include <optional>
#include <string_view>
namespace ck::files {
namespace {
Observation<SyncDigest> unknown(const char* tag) {
    return Observation<SyncDigest>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),tag});
}
void number(Sha256& hash,std::uint64_t value) noexcept {
    std::array<std::byte,8> bytes{};
    for(unsigned i=0;i<bytes.size();++i)bytes[i]=std::byte((value>>(8*i))&255);
    hash.update(bytes);
}
void text(Sha256& hash,std::string_view value) noexcept {
    hash.update(std::as_bytes(std::span(value.data(),value.size())));
}
std::uint32_t offset(std::span<const std::byte> bytes,std::size_t at) noexcept {
    std::uint32_t value=0;
    for(unsigned i=0;i<4;++i)value|=std::uint32_t(std::to_integer<unsigned>(bytes[at+i]))<<(8*i);
    return value;
}
void sid(Sha256& hash,std::span<const std::byte> bytes,std::size_t field) noexcept {
    const auto at=offset(bytes,field);
    if(!at){number(hash,0);return;}
    // validate_windows_descriptor has already bounded the revision/count and
    // the entire exact SID, including its six-byte identifier authority.
    const auto size=8+4*std::to_integer<std::size_t>(bytes[at+1]);
    number(hash,size);hash.update(bytes.subspan(at,size));
}
}
Observation<SyncDigest> metadata_ownership_digest(const MetadataReplaySnapshot& snapshot) {
    const auto* id=snapshot.basic.identity.value();
    const bool windows=snapshot.basic.windows_attributes.value()||
        (id&&(id->scheme==IdentityScheme::WindowsFileId128||id->scheme==IdentityScheme::WindowsFileIndex64));
    if(!windows) {
        if(!snapshot.basic.posix_uid.value()||!snapshot.basic.posix_gid.value())
            return unknown("metadata_owner.posix_owner_unknown");
        Sha256 hash;text(hash,"ck.metadata.owner.posix.v1");
        number(hash,*snapshot.basic.posix_uid.value());number(hash,*snapshot.basic.posix_gid.value());
        return Observation<SyncDigest>::available(hash.digest());
    }
    std::optional<SyncDigest> result;
    for(const auto& record:snapshot.security) {
        if(record.part!=SecurityPart::WindowsAccess&&record.part!=SecurityPart::WindowsFullDescriptor)continue;
        // OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION. A null
        // requested SID is distinct from a SID that was never requested.
        if(record.encoding!=SecurityEncoding::WindowsRelativeDescriptor||record.presence!=SecurityPresence::Present||
            (record.native_query_mask&3U)!=3U)return unknown("metadata_owner.windows_owner_unrequested");
        auto checked=detail::validate_windows_descriptor(record.bytes,snapshot.policy.limits);
        if(!checked.value())return Observation<SyncDigest>::unavailable(checked.state(),checked.unavailable_detail()->error);
        Sha256 hash;text(hash,"ck.metadata.owner.sid.v1");sid(hash,record.bytes,4);sid(hash,record.bytes,8);
        const auto current=hash.digest();
        if(result&&*result!=current)return Observation<SyncDigest>::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_owner.inconsistent_descriptors"});
        result=current;
    }
    return result?Observation<SyncDigest>::available(*result):unknown("metadata_owner.windows_owner_unknown");
}
}
