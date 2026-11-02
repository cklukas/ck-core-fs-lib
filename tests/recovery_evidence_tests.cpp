// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_operation_recovery_evidence.hpp"
#include <cassert>
#include <cstdio>

using namespace ck::files;
namespace {
NativeOperationRecoveryEvidence evidence() {
    const NativeDurableIdentity id{IdentityScheme::PosixDeviceInode,
        NativeIdentifier::from_u64(7),NativeIdentifier::from_u64(19),{}};
    return {*NativeName::from_posix("hint-\xff"),*NativeName::from_posix("published"),id,id,id,{},{},{},{}};
}
void same(const NativeOperationRecoveryEvidence& a,const NativeOperationRecoveryEvidence& b) {
    assert(a.staging_name==b.staging_name && a.destination_name==b.destination_name);
    assert(a.source_parent_identity==b.source_parent_identity && a.source_identity==b.source_identity);
    assert(a.destination_identity==b.destination_identity && a.staging_identity==b.staging_identity);
    assert(a.content_digest==b.content_digest && a.published_identity==b.published_identity);
    assert(a.staging_namespace==b.staging_namespace);
    assert(a.destination_address.has_value()==b.destination_address.has_value());
    if(a.destination_address) assert(a.destination_address->posix_bytes() &&
        *a.destination_address->posix_bytes()==*b.destination_address->posix_bytes());
}
}
int main() {
    for(unsigned flags=0;flags<8;++flags) {
        auto value=evidence(); value.staging_namespace=StagingNamespace::Anonymous;
        value.staging_identity=value.source_identity;
        if(flags&1)value.destination_address=*NativeAbsolutePath::from_posix("/encoded-destination").value();
        if(flags&2)value.content_digest=std::array<std::byte,32>{std::byte{91}};
        if(flags&4)value.published_identity=value.source_identity;
        auto bytes=encode_native_operation_recovery_evidence(value);
        if((flags&4)&&!(flags&2)) { assert(!bytes.value());continue; }
        assert(bytes.value() && std::to_integer<unsigned>((*bytes.value())[4])==6);
        auto decoded=decode_native_operation_recovery_evidence(*bytes.value());assert(decoded.value());same(value,*decoded.value());
        for(std::size_t n=0;n<bytes.value()->size();++n)
            assert(!decode_native_operation_recovery_evidence(std::span(*bytes.value()).first(n)).value());
        auto damaged=*bytes.value(); damaged[6]=std::byte{0};assert(!decode_native_operation_recovery_evidence(damaged).value());
        damaged=*bytes.value();damaged[6]=std::byte{1};assert(!decode_native_operation_recovery_evidence(damaged).value());
        damaged=*bytes.value();damaged.push_back(std::byte{0});assert(!decode_native_operation_recovery_evidence(damaged).value());
    }
    // Old journals remain Named; their serialized bytes do not acquire a new
    // namespace flag or silently become anonymous cleanup authority.
    for(unsigned version=2;version<=5;++version) {
        auto value=evidence();
        if(version>=3)value.destination_address=*NativeAbsolutePath::from_posix("/encoded-destination").value();
        if(version>=4)value.content_digest=std::array<std::byte,32>{};
        if(version>=5)value.published_identity=value.source_identity;
        auto bytes=encode_native_operation_recovery_evidence(value);assert(bytes.value());
        assert(std::to_integer<unsigned>((*bytes.value())[4])==version);
        auto decoded=decode_native_operation_recovery_evidence(*bytes.value());assert(decoded.value());same(value,*decoded.value());
        if(version==2) {
            auto legacy=*bytes.value();legacy[4]=std::byte{1};
            const auto flag=6+5+value.staging_name.posix_bytes()->size()+5+value.destination_name.posix_bytes()->size();
            legacy.erase(legacy.begin()+static_cast<std::ptrdiff_t>(flag));
            auto old=decode_native_operation_recovery_evidence(legacy);assert(old.value());same(value,*old.value());
        }
    }
    auto invalid=evidence(); invalid.staging_namespace=StagingNamespace::Unknown;
    assert(!encode_native_operation_recovery_evidence(invalid).value());
    invalid.staging_namespace=StagingNamespace::Anonymous;invalid.staging_name=*NativeName::from_windows(u"hint");
    assert(!encode_native_operation_recovery_evidence(invalid).value());
    std::puts("recovery_evidence: v1-v6 compatibility, anonymous hints, bounds and truncated tails passed");
}
