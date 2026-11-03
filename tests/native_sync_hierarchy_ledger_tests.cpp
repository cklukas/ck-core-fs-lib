// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_ledger.hpp"
#include "native_sync_observation.hpp"
#include "sha256.hpp"
#include <cstdio>
#include <stdexcept>
#include <algorithm>
using namespace ck::files;
namespace {
unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x))throw std::runtime_error(std::string("line ")+std::to_string(__LINE__)+": "+#x);}while(false)
template<class T>T get(Observation<T> o){if(const auto* e=o.unavailable_detail())throw std::runtime_error(e->error.operation);return std::move(o).take_value();}
SyncDigest digest(unsigned b){SyncDigest d{};d[0]=std::byte(b);return d;}
NativeDurableIdentity identity(unsigned object){return {IdentityScheme::PosixDeviceInode,NativeIdentifier::from_u64(7),NativeIdentifier::from_u64(object),{}};}
SyncEntryStatus present(SyncKind kind,unsigned content=6,unsigned metadata=7){return {SyncPresence::Present,kind,digest(content),digest(metadata)};}
SyncEntryStatus absent(){return {SyncPresence::Absent,SyncKind::Unknown,{},{}};}
NativeSyncLedgerEvidence base(){NativeSyncLedgerEvidence e;e.session={digest(1),digest(2),digest(3),digest(4)};e.reviewed_plan=digest(5);return e;}
NativeName posix(const char* value){return *NativeName::from_posix(value);}
NativeSyncPathRecord row(std::vector<NativeName> names,SyncKind kind,unsigned left,unsigned right){
    NativeSyncPathRecord p;p.opaque_key=native_sync_key(names);p.components=std::move(names);p.left=left?present(kind):absent();p.right=right?present(kind):absent();
    if(left)p.left_object=identity(left);if(right)p.right_object=identity(right);return p;
}
template<class T>void rejected(const Observation<T>& o,const char* tag){CHECK(!o.value());CHECK(o.unavailable_detail());CHECK(o.unavailable_detail()->error.domain==ErrorDomain::Adapter);CHECK(o.unavailable_detail()->error.operation==tag);}
NativeSyncLedgerEvidence nested(bool windows){auto e=base();auto d=windows?*NativeName::from_windows(u"d"):posix("d");auto sub=windows?*NativeName::from_windows(u"sub"):posix("sub");
    auto raw=windows?*NativeName::from_windows(std::u16string{u'x',char16_t(0xd800),u'.',u' '}):*NativeName::from_posix(std::string("x")+char(0xff)+". ");
    e.paths.push_back(row({d},SyncKind::Directory,10,11));e.paths.push_back(row({d,sub},SyncKind::Directory,20,21));e.paths.push_back(row({d,sub,raw},SyncKind::File,30,31));
    auto retained=windows?*NativeName::from_windows(u"retained. "):posix("retained. ");e.artifacts.push_back({true,{d,sub,retained},identity(21),identity(41),present(SyncKind::File)});return e;}
void roundtrip(bool windows){auto e=nested(windows);auto bytes=get(encode_native_sync_hierarchy_ledger(e));auto decoded=get(decode_native_sync_ledger(bytes));CHECK(decoded.paths.size()==3&&decoded.paths[1].left.kind==SyncKind::Directory);
    CHECK(decoded.paths[2].components==e.paths[2].components&&decoded.paths[2].left_object==e.paths[2].left_object);CHECK(decoded.artifacts[0].components==e.artifacts[0].components&&decoded.artifacts[0].parent==identity(21));
    CHECK(get(encode_native_sync_hierarchy_ledger(decoded))==bytes);auto directory_only=e;directory_only.paths.resize(1);directory_only.artifacts.clear();rejected(encode_native_sync_ledger(directory_only),"native_sync.ledger_side_status");rejected(encode_native_sync_ledger(e),"native_sync.ledger_component_count");
    for(std::size_t n=0;n<bytes.size();++n)CHECK(!decode_native_sync_ledger(std::span(bytes).first(n)).value());auto extra=bytes;extra.push_back(std::byte{});rejected(decode_native_sync_ledger(extra),"native_sync.ledger_noncanonical");
    auto bad=e;bad.paths.erase(bad.paths.begin());rejected(encode_native_sync_hierarchy_ledger(bad),"native_sync.hierarchy_ledger_parent_missing");
    bad=e;bad.paths[0].left.kind=SyncKind::File;rejected(encode_native_sync_hierarchy_ledger(bad),"native_sync.hierarchy_ledger_parent_binding");
    bad=e;bad.paths[2].left_object=bad.paths[1].left_object;rejected(encode_native_sync_hierarchy_ledger(bad),"native_sync.hierarchy_ledger_parent_binding");
    for(unsigned variant=0;variant<3;++variant){bad=e;bad.paths[2].left_object=bad.paths[1].left_object;
        if(variant==0)bad.paths[2].left_object->generation=123;
        if(variant==1)bad.paths[1].left_object->generation=123;
        if(variant==2){bad.paths[1].left_object->generation=123;bad.paths[2].left_object->generation=456;}
        rejected(encode_native_sync_hierarchy_ledger(bad),"native_sync.hierarchy_ledger_parent_binding");}
    bad=e;bad.artifacts[0].parent=identity(99);rejected(encode_native_sync_hierarchy_ledger(bad),"native_sync.hierarchy_ledger_artifact_parent_binding");
    bad=e;bad.paths[2].opaque_key="p00";rejected(encode_native_sync_hierarchy_ledger(bad),"native_sync.hierarchy_ledger_native_key");
    NativeSyncLedgerLimits limited;limited.max_total_wire_bytes=bytes.size()-1;rejected(encode_native_sync_hierarchy_ledger(e,limited),"native_sync.ledger_wire_limit");
}
void flat_wire(){auto e=base();auto p=row({posix("a")},SyncKind::File,41,0);p.action=SyncAction::CopyLeftToRight;e.paths.push_back(p);auto bytes=get(encode_native_sync_ledger(e));
    Sha256 h;h.update(bytes);const auto hash=h.digest();std::string text;constexpr char hex[]="0123456789abcdef";for(auto b:hash){const auto x=std::to_integer<unsigned>(b);text+=hex[x>>4];text+=hex[x&15];}
    std::printf("FLAT_WIRE bytes=%zu sha256=%s\n",bytes.size(),text.c_str());CHECK(bytes.size()==444&&text=="f7ad55d2f5ebb97126a667c6d4d008a39a1b17309d241625a5152e8f090ae1cd");CHECK(get(encode_native_sync_ledger(get(decode_native_sync_ledger(bytes))))==bytes);
    auto nested_path=e;nested_path.paths[0].components.insert(nested_path.paths[0].components.begin(),posix("d"));rejected(encode_native_sync_ledger(nested_path),"native_sync.ledger_component_count");
}
}
int main(){try{flat_wire();roundtrip(false);roundtrip(true);std::printf("NATIVE_HIERARCHY_LEDGER checks=%u PASS\n",checks);return 0;}catch(const std::exception& e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
