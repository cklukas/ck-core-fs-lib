// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "security.hpp"
#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

namespace ck::files::detail {
// Canonical persistent ACE values, not an access-check evaluator. The caller
// must authenticate the actual native descriptor/issuer and call IsValidAcl.
// SD/claim offsets, ACL capacity, reserved fields and documented padding are
// not values. ACE order/revision, type/flags/masks, GUIDs, SIDs, every claim
// value and all callback application bytes are values. Opaque callbacks have
// no defined internal padding, so their complete native payload is retained.
namespace windows_acl_wire {
using Bytes=std::vector<std::byte>;
struct Failure {const char* operation;ObservationState state=ObservationState::Failed;};
inline void need(bool condition,const char* op){if(!condition)throw Failure{op};}
inline std::span<const std::byte> part(std::span<const std::byte> b,std::size_t at,std::size_t n){
    need(at<=b.size()&&n<=b.size()-at,"windows_acl.bounds");return b.subspan(at,n);
}
inline std::uint64_t value(std::span<const std::byte> b,std::size_t at,std::size_t n){
    need(n<=8,"windows_acl.integer_width");auto p=part(b,at,n);std::uint64_t v=0;for(std::size_t i=0;i<n;++i)v|=std::uint64_t(std::to_integer<unsigned>(p[i]))<<(8*i);return v;
}
inline void room(const Bytes& out,std::size_t n){if(out.size()>InventoryLimits::hard_native_bytes||n>InventoryLimits::hard_native_bytes-out.size())throw Failure{"windows_acl.output_limit",ObservationState::Unknown};}
inline void number(Bytes& out,std::uint64_t v){room(out,8);for(unsigned i=0;i<8;++i)out.push_back(std::byte((v>>(i*8))&255));}
inline void blob(Bytes& out,std::span<const std::byte> p){number(out,p.size());room(out,p.size());out.insert(out.end(),p.begin(),p.end());}
inline std::size_t sid_size(std::span<const std::byte> b,std::size_t at){
    need(value(b,at,1)==1&&value(b,at+1,1)<=15,"windows_acl.sid");
    const auto n=std::size_t(8+4*value(b,at+1,1));(void)part(b,at,n);return n;
}
inline std::size_t sid(Bytes& out,std::span<const std::byte> b,std::size_t at){const auto n=sid_size(b,at);blob(out,part(b,at,n));return at+n;}
inline void string(Bytes& out,std::span<const std::byte> b,std::size_t at){
    need((at&1)==0,"windows_acl.claim_string_alignment");const auto start=at;
    while(value(b,at,2)!=0)at+=2;blob(out,part(b,start,at-start));
}
inline void claim(Bytes& out,std::span<const std::byte> b){
    const auto type=value(b,4,2),count=value(b,12,4);(void)part(b,0,16);
    need(count<=(b.size()-16)/4,"windows_acl.claim_count");const auto header=std::size_t(16+4*count);
    const auto offset=[&](std::size_t at){const auto n=std::size_t(value(b,at,4));need(n>=header&&n<b.size(),"windows_acl.claim_offset");return n;};
    if(type!=1&&type!=2&&type!=3&&type!=5&&type!=6&&type!=16)throw Failure{"windows_acl.claim_type",ObservationState::Unsupported};
    number(out,type);number(out,value(b,8,4));string(out,b,offset(0));number(out,count);
    for(std::size_t i=0;i<count;++i){const auto at=offset(16+4*i);
        switch(type){
        case 1:case 2:case 6:
            if(type==6)need(value(b,at,8)<=1,"windows_acl.claim_boolean");blob(out,part(b,at,8));break;
        case 3:string(out,b,at);break;
        case 5:case 16:{const auto n=std::size_t(value(b,at,4));auto bytes=part(b,at+4,n);blob(out,bytes);break;}
        default:throw Failure{"windows_acl.claim_type",ObservationState::Unsupported};
        }
    }
}
// Locate every token before dropping the explicitly defined 0..3 zero bytes at
// the end of an artx condition. A zero inside a length-framed literal is data.
inline void tokens(std::span<const std::byte> b,bool composite,unsigned depth){
    need(depth<=32,"windows_acl.condition_depth");std::size_t at=0;
    while(at<b.size()){
        const auto token=value(b,at++,1);
        if(token>=1&&token<=4){(void)part(b,at,10);at+=10;continue;}
        if(token==0x10||token==0x18||token==0x50||token==0x51||token==0xf8||token==0xf9||token==0xfa||token==0xfb){
            const auto n=std::size_t(value(b,at,4));at+=4;const auto p=part(b,at,n);
            if(token==0x50)tokens(p,true,depth+1);
            if(token==0x51)need(sid_size(p,0)==p.size(),"windows_acl.condition_sid");
            if(token==0x10||token>=0xf8)need((n&1)==0,"windows_acl.condition_string");at+=n;continue;
        }
        if(!composite&&((token>=0x80&&token<=0x93)||token==0xa0||token==0xa1||token==0xa2))continue;
        throw Failure{"windows_acl.condition_token",ObservationState::Unsupported};
    }
}
inline void application(Bytes& out,std::span<const std::byte> b){
    if(b.size()<4||value(b,0,4)!=0x78747261){number(out,0);blob(out,b);return;}
    // Parse to a token boundary; do not blindly strip zero bytes from literals.
    std::size_t at=4,end=4;
    while(at<b.size()){
        const auto token=value(b,at,1);
        if(token==0){need(b.size()-at<=3&&std::all_of(b.begin()+at,b.end(),[](auto x){return x==std::byte{};}),"windows_acl.condition_padding");break;}
        std::size_t n=1;
        if(token>=1&&token<=4)n=11;
        else if(token==0x10||token==0x18||token==0x50||token==0x51||(token>=0xf8&&token<=0xfb))n=5+std::size_t(value(b,at+1,4));
        auto one=part(b,at,n);tokens(one,false,0);at+=n;end=at;
    }
    number(out,1);blob(out,part(b,0,end));
}
inline Bytes ace(std::span<const std::byte> b){
    need(b.size()>=8&&(b.size()&3)==0&&value(b,2,2)==b.size(),"windows_acl.ace_size");
    const auto type=value(b,0,1);Bytes out;number(out,type);number(out,value(b,1,1));number(out,value(b,4,4));std::size_t at=8;
    const bool object=(type>=5&&type<=8)||type==11||type==12||type==15||type==16;
    const bool callback=(type>=9&&type<=16)||type==21;
    need(type<=21,"windows_acl.ace_type");
    if(object){const auto flags=value(b,at,4);at+=4;need((flags&~3ULL)==0,"windows_acl.object_flags");number(out,flags);
        for(unsigned i=0;i<2;++i)if(flags&(std::uint64_t{1}<<i)){blob(out,part(b,at,16));at+=16;}}
    if(type==4){const auto compound=value(b,at,2);if(compound!=1)throw Failure{"windows_acl.compound_type",ObservationState::Unsupported};number(out,compound);at+=4;at=sid(out,b,at);}
    at=sid(out,b,at);
    if(type==18)claim(out,b.subspan(at));else if(callback)application(out,b.subspan(at));
    // Fixed-layout ACEs may carry ignored trailing bytes (MS-DTYP 2.4.4.1).
    return out;
}
}
inline Observation<std::vector<std::byte>> canonical_windows_acl(std::span<const std::byte> bytes,InventoryLimits limits={}){
    using namespace windows_acl_wire;using Result=Observation<Bytes>;
    try{
        need(limits.valid(),"windows_acl.limits");
        if(bytes.size()>limits.max_native_bytes)throw Failure{"windows_acl.bytes",ObservationState::Unknown};
        need(bytes.size()>=8&&value(bytes,2,2)==bytes.size(),"windows_acl.header");
        const auto revision=value(bytes,0,1),count=value(bytes,4,2);need(revision==2||revision==3||revision==4,"windows_acl.revision");
        if(count>limits.max_records)throw Failure{"windows_acl.records",ObservationState::Unknown};
        Bytes out;number(out,1);number(out,revision);number(out,count);std::size_t at=8;
        for(std::size_t i=0;i<count;++i){const auto size=std::size_t(value(bytes,at+2,2));auto a=ace(part(bytes,at,size));blob(out,a);at+=size;}
        return Result::available(std::move(out));
    }catch(const Failure& e){return Result::unavailable(e.state,{ErrorDomain::Adapter,static_cast<std::int64_t>(e.state==ObservationState::Unknown?AdapterError::InventoryLimit:AdapterError::InvalidNativeResult),e.operation});}
}
} // namespace ck::files::detail
