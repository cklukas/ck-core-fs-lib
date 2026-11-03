// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_ownership_digest.hpp"
#include <algorithm>
#include <cassert>
using namespace ck::files;
namespace {
SyncDigest take(Observation<SyncDigest> value){assert(value.value());return *value.value();}
void set32(NativeBytes& bytes,std::size_t at,unsigned value){
    for(unsigned i=0;i<4;++i)bytes[at+i]=std::byte((value>>(8*i))&255);
}
NativeSecurityValue descriptor(unsigned owner,unsigned group) {
    NativeSecurityValue result;result.part=SecurityPart::WindowsAccess;
    result.encoding=SecurityEncoding::WindowsRelativeDescriptor;result.presence=SecurityPresence::Present;
    result.native_query_mask=7;result.bytes.resize(44);
    result.bytes[0]=std::byte(1);result.bytes[2]=std::byte(4);result.bytes[3]=std::byte(0x80);
    set32(result.bytes,4,20);set32(result.bytes,8,32);
    for(const unsigned at:{20,32}){result.bytes[at]=std::byte(1);result.bytes[at+1]=std::byte(1);result.bytes[at+7]=std::byte(5);}
    set32(result.bytes,28,owner);set32(result.bytes,40,group);return result;
}
}
int main(){
    MetadataReplaySnapshot posix;
    assert(!metadata_ownership_digest(posix).value());
    posix.basic.posix_uid=Observation<std::uint64_t>::available(1000);
    assert(!metadata_ownership_digest(posix).value());
    posix.basic.posix_gid=Observation<std::uint64_t>::available(100);
    const auto original=take(metadata_ownership_digest(posix));
    auto changed=posix;changed.basic.posix_uid=Observation<std::uint64_t>::available(1001);
    assert(take(metadata_ownership_digest(changed))!=original);
    changed=posix;changed.basic.posix_gid=Observation<std::uint64_t>::available(101);
    assert(take(metadata_ownership_digest(changed))!=original);
    MetadataReplaySnapshot windows;windows.basic.windows_attributes=Observation<std::uint32_t>::available(0);
    assert(!metadata_ownership_digest(windows).value());
    windows.security.push_back(descriptor(21,32));const auto owner=take(metadata_ownership_digest(windows));
    assert(owner!=original);
    changed=windows;changed.security[0].part=SecurityPart::WindowsFullDescriptor;changed.security[0].native_query_mask|=0x1f8;
    assert(take(metadata_ownership_digest(changed))==owner);
    changed.security.push_back(windows.security[0]);assert(take(metadata_ownership_digest(changed))==owner);
    changed.security[1]=descriptor(22,32);assert(!metadata_ownership_digest(changed).value());
    changed=windows;changed.security[0].native_query_mask&=~1U;assert(!metadata_ownership_digest(changed).value());
    changed=windows;changed.security[0].native_query_mask&=~2U;assert(!metadata_ownership_digest(changed).value());
    changed=windows;set32(changed.security[0].bytes,28,22);assert(take(metadata_ownership_digest(changed))!=owner);
    changed=windows;set32(changed.security[0].bytes,40,33);assert(take(metadata_ownership_digest(changed))!=owner);
    // Self-relative packing is not an ownership semantic. Move the exact SIDs.
    changed=windows;changed.security[0].bytes.resize(48);
    std::copy_backward(changed.security[0].bytes.begin()+20,changed.security[0].bytes.begin()+44,changed.security[0].bytes.end());
    set32(changed.security[0].bytes,4,24);set32(changed.security[0].bytes,8,36);
    assert(take(metadata_ownership_digest(changed))==owner);
    changed=windows;set32(changed.security[0].bytes,4,43);assert(!metadata_ownership_digest(changed).value());
    changed=windows;changed.security[0].bytes[21]=std::byte(15);assert(!metadata_ownership_digest(changed).value());
    changed=windows;set32(changed.security[0].bytes,4,0);set32(changed.security[0].bytes,8,0);
    assert(take(metadata_ownership_digest(changed))!=owner);
}
