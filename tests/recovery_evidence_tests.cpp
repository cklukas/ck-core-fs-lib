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
    assert(a.source_name==b.source_name);
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
    for (const auto ns : {StagingNamespace::Named, StagingNamespace::Anonymous}) {
        auto move = evidence();
        move.staging_namespace = ns;
        move.source_name = NativeName::from_posix("source-\xff");
        move.destination_address = *NativeAbsolutePath::from_posix("/move-target").value();
        move.content_digest = std::array<std::byte, 32>{std::byte{91}};
        move.published_identity = move.destination_identity;
        const auto bytes = encode_native_operation_recovery_evidence(move);
        assert(bytes.value() && (*bytes.value())[4] == std::byte{7});
        const auto decoded = decode_native_operation_recovery_evidence(*bytes.value());
        assert(decoded.value());
        same(move, *decoded.value());
        for (std::size_t n = 0; n < bytes.value()->size(); ++n)
            assert(!decode_native_operation_recovery_evidence(std::span(*bytes.value()).first(n)).value());
        auto malformed = *bytes.value();
        malformed.back() = std::byte{0};
        assert(!decode_native_operation_recovery_evidence(malformed).value());
        move.source_name = NativeName::from_windows(u"wrong-namespace");
        assert(!encode_native_operation_recovery_evidence(move).value());
    }
    auto windows_move = evidence();
    const NativeDurableIdentity windows_id{IdentityScheme::WindowsFileId128,
        NativeIdentifier::from_u64(7), NativeIdentifier::from_u64(19), {}};
    windows_move.staging_name = *NativeName::from_windows(u"stage");
    windows_move.destination_name = *NativeName::from_windows(u"target");
    windows_move.source_identity = windows_id;
    windows_move.source_parent_identity = windows_id;
    windows_move.destination_identity = windows_id;
    windows_move.source_name = NativeName::from_windows(std::u16string{u'a', char16_t{0xd800}});
    const auto windows_bytes = encode_native_operation_recovery_evidence(windows_move);
    assert(windows_bytes.value());
    const auto windows_decoded = decode_native_operation_recovery_evidence(*windows_bytes.value());
    assert(windows_decoded.value());
    same(windows_move, *windows_decoded.value());
    std::puts("recovery_evidence: v1-v7 compatibility, exact move names, bounds and truncated tails passed");
}
