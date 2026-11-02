// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_trash.hpp"
#include <cstring>

namespace ck::files {
namespace {
template<class T> Observation<T> unsupported(const char* op) {
    return Observation<T>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::UnsupportedQuery),op});
}
void put(std::vector<std::byte>& out,uint64_t v,unsigned n) {
    for(unsigned i=0;i<n;++i) out.push_back(std::byte(static_cast<unsigned char>(v>>(i*8))));
}
bool append_name(std::vector<std::byte>& out,const NativeName& n) {
    if(!n.is_valid()) return false;
    const auto* p=n.posix_bytes(); const auto* w=n.windows_units();
    const size_t count=p?p->size():w->size(); if(count>32767) return false;
    put(out,p?0:1,1); put(out,count,4);
    if(p) for(unsigned char c:*p) put(out,c,1);
    else for(char16_t c:*w) put(out,c,2);
    return true;
}
bool append_id(std::vector<std::byte>& out,const NativeDurableIdentity& id) {
    if(id.scheme==IdentityScheme::Unknown || id.object==NativeIdentifier{}) return false;
    put(out,static_cast<uint64_t>(id.scheme),1);
    out.insert(out.end(),id.volume.bytes.begin(),id.volume.bytes.end());
    out.insert(out.end(),id.object.bytes.begin(),id.object.bytes.end());
    put(out,id.generation.has_value(),1); put(out,id.generation.value_or(0),8); return true;
}
}
Observation<std::vector<std::byte>> windows_trash_metadata(std::u16string_view path,uint64_t size,uint64_t time) {
    using R=Observation<std::vector<std::byte>>;
    if(path.empty() || path.size()>32767 || path.find(u'\0')!=path.npos)
        return R::unavailable(ObservationState::Failed,{ErrorDomain::Adapter,
            static_cast<int64_t>(AdapterError::InvalidPath),"trash.metadata_path"});
    std::vector<std::byte> out; out.reserve(30+path.size()*2);
    // Primary format research: libyal/dtformats, Windows Recycle.Bin file formats.
    put(out,2,8); put(out,size,8); put(out,time,8); put(out,path.size()+1,4);
    for(char16_t c:path) put(out,c,2); put(out,0,2);
    return R::available(std::move(out));
}
Observation<std::vector<std::byte>> encode_native_trash_receipt(const NativeTrashReceipt& r) {
    using R=Observation<std::vector<std::byte>>;
    if(r.metadata_bytes.size()>65564 || (r.object_kind!=ObjectKind::RegularFile && r.object_kind!=ObjectKind::Directory))
        return unsupported<std::vector<std::byte>>("trash.evidence_limit_or_kind");
    std::vector<std::byte> out; out.reserve(r.metadata_bytes.size()+512);
    for(unsigned char c:std::string_view("CKTR\2",5)) put(out,c,1);
    put(out,r.object_kind==ObjectKind::Directory?1:0,1);
    put(out,r.metadata_retired?1:0,1);
    if(!append_name(out,r.original_name)||!append_name(out,r.data_name)||!append_name(out,r.metadata_name)||!append_name(out,r.user_sid)||
        !append_id(out,r.original_parent)||!append_id(out,r.object)||!append_id(out,r.recycle_parent))
        return R::unavailable(ObservationState::Failed,{ErrorDomain::Adapter,
            static_cast<int64_t>(AdapterError::UnqualifiedIdentity),"trash.evidence"});
    put(out,r.metadata_identity.has_value(),1);
    if(r.metadata_identity&&!append_id(out,*r.metadata_identity)) return unsupported<std::vector<std::byte>>("trash.metadata_identity");
    put(out,r.metadata_bytes.size(),4); out.insert(out.end(),r.metadata_bytes.begin(),r.metadata_bytes.end());
    if(out.size()>256*1024) return unsupported<std::vector<std::byte>>("trash.evidence_limit");
    return R::available(std::move(out));
}
#ifndef _WIN32
namespace {
class UnsupportedBackend final : public NativeTrashBackend {
public:
    Observation<std::unique_ptr<NativeTrashTransaction>> prepare_trash(HeldChild::Pointer,std::stop_token) const override {
        return unsupported<std::unique_ptr<NativeTrashTransaction>>("trash.posix_source_not_bound");
    }
    Observation<std::unique_ptr<NativeTrashTransaction>> prepare_restore(const NativeTrashReceipt&,
        std::shared_ptr<const DirectoryCursor>,std::stop_token) const override {
        return unsupported<std::unique_ptr<NativeTrashTransaction>>("restore.posix_source_not_bound");
    }
};
}
std::shared_ptr<const NativeTrashBackend> native_trash_backend() { return std::make_shared<UnsupportedBackend>(); }
#endif
} // namespace ck::files
