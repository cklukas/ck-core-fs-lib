// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_observation.hpp"
#ifdef _WIN32
#include "platform/native_windows_journal_volume.hpp"
#endif
#include "sha256.hpp"
#include "windows_acl_semantics.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <set>
#include <bit>
#include "platform/native_journal_directory_bridge.hpp"
#include "windows_stream_records.hpp"
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#endif
namespace ck::files {
namespace {
struct NativeFailure { UnavailableObservation detail; };
[[noreturn]] void native_fail(const char* op,ObservationState state=ObservationState::Changed,
    AdapterError code=AdapterError::MetadataChanged) {
    throw NativeFailure{{state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),op}}};
}
template<class T> T native_value(Observation<T> o) {
    if(!o.value()) throw NativeFailure{*o.unavailable_detail()};return std::move(o).take_value();
}
template<class T,class F> Observation<T> observed(F&& f) {
    try { return Observation<T>::available(f()); } catch(const NativeFailure& e) {
        return Observation<T>::unavailable(e.detail.state,e.detail.error);
    }
}
template<class T> bool equal(const Observation<T>& a,const Observation<T>& b) {
    return a.value() && b.value()?*a.value()==*b.value():!a.value()&&!b.value()&&a.state()==b.state();
}
using Wire=std::vector<std::byte>;
void number(Wire& b,std::uint64_t n) {for(unsigned i=0;i<8;++i)b.push_back(std::byte((n>>(i*8))&255));}
void blob(Wire& b,std::span<const std::byte> v) {number(b,v.size());b.insert(b.end(),v.begin(),v.end());}
SyncDigest hashed(std::span<const std::byte> b) {Sha256 h;h.update(b);return h.digest();}
void check_stop(std::stop_token stop) {if(stop.stop_requested())native_fail("native_sync.cancelled",ObservationState::Changed,AdapterError::InterruptedRead);}
void charge(std::uint64_t& used,std::uint64_t n,std::uint64_t max,const char* op) {
    if(used>max||n>max-used)native_fail(op,ObservationState::Unknown,AdapterError::InventoryLimit);used+=n;
}
Wire identifier(const NativeFeatureIdentifier& id) {
    Wire b; number(b,static_cast<unsigned>(id.encoding()));
    if(auto* p=id.posix_bytes()) blob(b,std::as_bytes(std::span(*p)));
    else if(auto* w=id.windows_units()) { number(b,w->size()); for(auto u:*w) { b.push_back(std::byte(u&255));b.push_back(std::byte(u>>8)); } }
    else if(auto* e=id.windows_ea_bytes()) blob(b,std::as_bytes(std::span(*e)));
    else native_fail("sync_session.metadata_identifier",ObservationState::Unsupported);
    return b;
}
#ifdef _WIN32
void sid_semantics(Wire& b,PSID sid) {
    if(!sid) { number(b,0); return; }
    if(!IsValidSid(sid)) native_fail("sync_session.metadata_sid",ObservationState::Unsupported);
    blob(b,std::as_bytes(std::span(static_cast<const std::byte*>(sid),GetLengthSid(sid))));
}
#endif
void require_true(Observation<bool> o) {
    if(!native_value(std::move(o)))native_fail("native_sync.false_proof",ObservationState::Unknown,AdapterError::InvalidNativeResult);
}
bool windows_object(const BasicMetadata& b) {
    return b.windows_attributes.value()||(b.identity.value()&&b.identity.value()->scheme==IdentityScheme::WindowsFileId128);
}
Wire channel_manifest(const MetadataReplaySnapshot& s) {
    Wire out;number(out,1);number(out,static_cast<unsigned>(s.channel_coverage));
    std::vector<Wire> records;records.reserve(s.channels.size());
    for(const auto& c:s.channels) {
        if(c.identifier.encoding()!=NameEncoding::WindowsUtf16)
            native_fail("native_sync.channel_identifier",ObservationState::Unsupported,AdapterError::InvalidIdentifier);
        Wire record=identifier(c.identifier);number(record,c.logical_size);blob(record,c.digest);records.push_back(std::move(record));
    }
    std::sort(records.begin(),records.end());
    if(std::adjacent_find(records.begin(),records.end())!=records.end())native_fail("native_sync.duplicate_channel");
    number(out,records.size());for(const auto& record:records)blob(out,record);return out;
}
std::uint64_t validate_catalog(const DataChannelCatalog& catalog,const BasicMetadata& b,InventoryLimits limits) {
    if(!limits.valid()||!b.identity.value()||!b.kind.value()||
       catalog.coverage!=DataChannelCoverage::WindowsFileStreamInfo||!catalog.owner.value()||
       compare_identity(*catalog.owner.value(),*b.identity.value())!=IdentityComparison::Same)
        native_fail("native_sync.channel_catalog_unqualified",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    if(catalog.channels.size()>limits.max_records)native_fail("native_sync.channel_record_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
    const bool directory=*b.kind.value()==ObjectKind::Directory;
    if(!directory&&*b.kind.value()!=ObjectKind::RegularFile)native_fail("native_sync.channel_object_kind",ObservationState::Unsupported);
    std::uint64_t bytes=0,native_bytes=0;unsigned mains=0;std::set<std::u16string> names;
    for(const auto& channel:catalog.channels) {
        const auto* name=channel.identifier.windows_units();
        if(!name||!names.insert(*name).second||!channel.logical_size.value())native_fail("native_sync.channel_name_size",ObservationState::Unsupported);
        charge(native_bytes,24,limits.max_native_bytes,"native_sync.channel_name_limit");
        if(name->size()>(limits.max_native_bytes-native_bytes)/2)native_fail("native_sync.channel_name_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        charge(native_bytes,name->size()*2,limits.max_native_bytes,"native_sync.channel_name_limit");
        if(channel.kind==DataChannelKind::MainData) {
            ++mains;
            if(*name!=u"::$DATA"||directory||!b.logical_size.value()||*channel.logical_size.value()!=*b.logical_size.value())
                native_fail("native_sync.main_channel_size");
        } else {
            if(channel.kind!=DataChannelKind::NamedData||name->size()<=7||name->front()!=u':'||!name->ends_with(u":$DATA")||
               name->substr(1,name->size()-7).find_first_of(u":/\\\0",0,4)!=std::u16string::npos)
                native_fail("native_sync.opaque_channel",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
        }
        charge(bytes,*channel.logical_size.value(),std::numeric_limits<std::uint64_t>::max(),"native_sync.channel_size_overflow");
    }
    if(mains!=(directory?0U:1U))native_fail("native_sync.unnamed_main_count",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    return bytes;
}
void match_catalog(const DataChannelCatalog& before,const MetadataReplaySnapshot& snapshot) {
    if(snapshot.channel_coverage!=before.coverage||before.channels.size()!=snapshot.channels.size()+1)
        native_fail("native_sync.channel_capture_set_changed");
    for(const auto& channel:before.channels)if(channel.kind!=DataChannelKind::MainData) {
        const auto it=std::find_if(snapshot.channels.begin(),snapshot.channels.end(),[&](const auto& c){return c.identifier==channel.identifier;});
        if(it==snapshot.channels.end()||!channel.logical_size.value()||it->logical_size!=*channel.logical_size.value())
            native_fail("native_sync.channel_capture_changed");
    }
}
#ifdef _WIN32
ObservationState windows_state(DWORD code) {
    if(code==ERROR_ACCESS_DENIED||code==ERROR_SHARING_VIOLATION||code==ERROR_PRIVILEGE_NOT_HELD)return ObservationState::Denied;
    if(code==ERROR_INVALID_FUNCTION||code==ERROR_NOT_SUPPORTED||code==ERROR_INVALID_PARAMETER)return ObservationState::Unsupported;
    return ObservationState::Failed;
}
[[noreturn]]void windows_fail(DWORD code,const char* op) {throw NativeFailure{{windows_state(code),{ErrorDomain::Win32,code,op}}};}
struct QueryHandle {
    HANDLE value=nullptr;
    ~QueryHandle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
    void finish(){const HANDLE h=value;value=nullptr;if(!CloseHandle(h))windows_fail(GetLastError(),"native_sync.root_channel_close");}
};
void root_provider(HANDLE h,const BasicMetadata& b) {
    DWORD flags=0;WCHAR fs[32]{};
    if(!GetVolumeInformationByHandleW(h,nullptr,0,nullptr,nullptr,&flags,fs,32))windows_fail(GetLastError(),"native_sync.root_volume");
    if((std::wstring_view(fs)!=L"NTFS"&&std::wstring_view(fs)!=L"ReFS")||!(flags&FILE_PERSISTENT_ACLS))
        native_fail("native_sync.root_stream_provider",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    // Use the I/O manager's actual FSD-path proof. A filesystem's reported
    // name/device flags cannot certify a native NTFS/ReFS implementation.
    const auto driver=detail::prove_windows_journal_volume(h);
    if(!driver.qualified)throw NativeFailure{{driver.state,{driver.domain,driver.code,driver.operation}}};
    FILE_ID_INFO id{};if(!GetFileInformationByHandleEx(h,FileIdInfo,&id,sizeof(id)))windows_fail(GetLastError(),"native_sync.root_channel_id");
    NativeIdentifier object;std::memcpy(object.bytes.data(),id.FileId.Identifier,16);
    if(!b.identity.value()||b.identity.value()->scheme!=IdentityScheme::WindowsFileId128||
       b.identity.value()->volume!=NativeIdentifier::from_u64(id.VolumeSerialNumber)||b.identity.value()->object!=object)
        native_fail("native_sync.root_channel_identity");
    constexpr DWORD supported=FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|
        FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    if(!b.windows_attributes.value()||(*b.windows_attributes.value()&~supported))native_fail("native_sync.root_stream_storage",ObservationState::Unsupported);
}
DataChannelCatalog root_catalog(HANDLE handle,InventoryLimits limits) {
    if(!limits.valid()||limits.max_native_bytes<sizeof(FILE_STREAM_INFO))native_fail("native_sync.root_channel_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
    std::size_t capacity=std::min<std::size_t>(4096,limits.max_native_bytes);
    for(;;) {
        std::vector<std::uint64_t> bytes((capacity+7)/8);SetLastError(ERROR_SUCCESS);
        const bool ok=GetFileInformationByHandleEx(handle,FileStreamInfo,bytes.data(),static_cast<DWORD>(capacity))!=0;
        const DWORD code=GetLastError();
        if(code==ERROR_HANDLE_EOF) {DataChannelCatalog empty;empty.coverage=DataChannelCoverage::WindowsFileStreamInfo;return empty;}
        if(ok)return native_value(detail::decode_windows_stream_records(std::as_bytes(std::span(bytes)).first(capacity),limits));
        if(code!=ERROR_MORE_DATA&&code!=ERROR_INSUFFICIENT_BUFFER&&code!=ERROR_BAD_LENGTH)windows_fail(code,"native_sync.root_FileStreamInfo");
        if(capacity==limits.max_native_bytes)native_fail("native_sync.root_channel_buffer_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        capacity=capacity>limits.max_native_bytes/2?limits.max_native_bytes:capacity*2;
    }
}
#endif

SyncDigest metadata_digest(const MetadataReplaySnapshot& s) {
    return native_value(detail::metadata_snapshot_semantic_digest(s));
}

}
bool native_sync_same_ownership(const MetadataReplaySnapshot& a,const MetadataReplaySnapshot& b) {
    if(!equal(a.basic.posix_uid,b.basic.posix_uid)||!equal(a.basic.posix_gid,b.basic.posix_gid))return false;
#ifdef _WIN32
    for(const auto& x:a.security)for(const auto& y:b.security)if(x.part==y.part) {
        Wire left,right;
        for(const auto* v:{&x,&y}) {
            if(v->presence!=SecurityPresence::Present)continue;
            auto* sd=reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(v->bytes.data()));
            PSID owner=nullptr,group=nullptr;BOOL def=FALSE;
            if(!GetSecurityDescriptorOwner(sd,&owner,&def)||!GetSecurityDescriptorGroup(sd,&group,&def))return false;
            auto& wire=v==&x?left:right;sid_semantics(wire,owner);sid_semantics(wire,group);
        }
        if(left!=right)return false;
    }
#endif
    return true;
}
bool native_sync_same_version(const BasicMetadata& a,const BasicMetadata& b) noexcept {
    return a.identity.value()&&b.identity.value()&&compare_identity(*a.identity.value(),*b.identity.value())==IdentityComparison::Same&&
        a.kind.value()&&b.kind.value()&&equal(a.kind,b.kind)&&a.modified.value()&&b.modified.value()&&
        a.changed.value()&&b.changed.value()&&equal(a.modified,b.modified)&&equal(a.changed,b.changed)&&
        equal(a.logical_size,b.logical_size)&&equal(a.link_count,b.link_count)&&equal(a.created,b.created)&&
        equal(a.mount_id,b.mount_id)&&equal(a.posix_uid,b.posix_uid)&&equal(a.posix_gid,b.posix_gid)&&
        equal(a.posix_permissions,b.posix_permissions)&&equal(a.bsd_flags,b.bsd_flags)&&equal(a.windows_attributes,b.windows_attributes);
}
Observation<SyncDigest> native_sync_metadata_digest(const OpenedEntry& source,const MetadataReplaySnapshot& s,std::stop_token stop) {
    return observed<SyncDigest>([&]{
        check_stop(stop);if(!s.policy.valid())native_fail("native_sync.metadata_policy",ObservationState::Failed,AdapterError::InvalidIdentifier);
        if(s.policy.scope==RegularMetadataScope::OrdinaryCallerVisibleV1&&s.security_coverage)
            native_fail("native_sync.ordinary_security_evidence",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
        const auto before=native_value(source.inspect_basic());
        if(!native_sync_same_version(before,s.basic))native_fail("native_sync.metadata_source_version");
        if(windows_object(before)) {
            if(s.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo)native_fail("native_sync.metadata_channel_coverage",ObservationState::Unsupported);
            require_true(verify_native_metadata_replay_channels(s));
            // Also authenticate the supplied source's concrete native adapter,
            // inventory and bytes. The issuer does not sign caller hashes.
            (void)native_value(issue_native_metadata_replay_channels(source,s,stop));
        } else if(s.channel_coverage!=DataChannelCoverage::Unknown||!s.channels.empty()||s.channel_evidence)
            native_fail("native_sync.foreign_channel_scope",ObservationState::Unsupported);
        if(s.policy.scope==RegularMetadataScope::CompleteMetadataV1)
            require_true(source.verify_metadata_security_coverage(s));
        require_true(verify_metadata_replay_source(source,s,stop));
        const auto after=native_value(source.inspect_basic());
        if(!native_sync_same_version(before,after))native_fail("native_sync.metadata_source_changed");
        check_stop(stop);return metadata_digest(s);
    });
}
Observation<bool> qualify_native_sync_root_channels(const DirectoryCursor& root,InventoryLimits limits) {
    return observed<bool>([&]{
        const auto before=native_value(root.inspect_basic());
        if(!before.kind.value()||*before.kind.value()!=ObjectKind::Directory)native_fail("native_sync.root_channels_kind",ObservationState::Unsupported);
#ifdef _WIN32
        QueryHandle handle{native_value(detail::duplicate_windows_journal_directory(root))};
        root_provider(handle.value,before);auto catalog=root_catalog(handle.value,limits);catalog.owner=before.identity;
        (void)validate_catalog(catalog,before,limits);
        // The root-flat executor does not replay or baseline directory ADS.
        if(!catalog.channels.empty())native_fail("native_sync.directory_channels_unimplemented",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
        handle.finish();
#else
        (void)limits;
        if(windows_object(before))native_fail("native_sync.foreign_root",ObservationState::Unsupported);
#endif
        if(!native_sync_same_version(before,native_value(root.inspect_basic())))native_fail("native_sync.root_channel_version");
        return true;
    });
}
std::string native_sync_key(std::span<const NativeName> components) {
    constexpr char hex[]="0123456789abcdef";std::string out;
    const auto byte=[&](unsigned n){out+=hex[n>>4];out+=hex[n&15];};
    for(const auto& n:components){if(!out.empty())out+='/';
        if(auto* p=n.posix_bytes()){out+='p';for(unsigned char c:*p)byte(c);}
        else if(auto* w=n.windows_units()){out+='w';for(auto c:*w){byte(c&255);byte(c>>8);}}
        else throw std::invalid_argument("native sync component encoding");
    }return out;
}
SyncDigest native_sync_policy_binding(const SyncDigest& application,const MetadataReplayPolicy& metadata) noexcept {
    Sha256 hash;
    const auto number=[&](std::uint64_t value) {
        std::array<std::byte,8> bytes{};
        for(unsigned i=0;i<bytes.size();++i)bytes[i]=std::byte((value>>(i*8))&255);
        hash.update(bytes);
    };
    number(0x32534d4553534643ULL);number(native_sync_metadata_digest_version);
    number(application.size());hash.update(application);
    number(static_cast<unsigned>(metadata.scope));number(static_cast<unsigned>(metadata.ownership));
    number(metadata.allow_privilege_metadata);
    return hash.digest();
}
Observation<NativeSyncFileProof> observe_native_sync_file(std::shared_ptr<const DirectoryCursor> parent,NativeName name,
    MetadataReplayPolicy policy,const NativeSyncProofLimits& limits,NativeSyncProofBudget& budget,std::stop_token stop) {
    return observed<NativeSyncFileProof>([&]{
        check_stop(stop);if(budget.entries>=limits.max_entries)native_fail("native_sync.entry_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        ++budget.entries;charge(budget.metadata,sizeof(NativeSyncFileProof),limits.max_metadata_bytes,"native_sync.proof_limit");
        auto access=EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity;
        if(policy.scope==RegularMetadataScope::CompleteMetadataV1)access=access|EntryAccess::MetadataAndFullSecurity;
        auto held=native_value(HeldChild::observe_with_access(parent,name,access,stop));
        if(!held->metadata().kind.value()||*held->metadata().kind.value()!=ObjectKind::RegularFile)
            native_fail("native_sync.regular_files_only",ObservationState::Unsupported,AdapterError::UnsupportedQuery);
        auto query=native_value(parent->open_child(name,access));
        if(!query)native_fail("native_sync.native_query_missing",ObservationState::Unknown,AdapterError::InvalidNativeResult);
        const auto before=native_value(query->inspect_basic());
        if(!native_sync_same_version(held->metadata(),before))native_fail("native_sync.native_query_changed");
        require_true(query->qualify_metadata_replay(policy));
        if(!before.logical_size.value())native_fail("native_sync.file_size",ObservationState::Unsupported);
        const auto size=*before.logical_size.value();std::uint64_t logical=size;
        std::optional<DataChannelCatalog> channels;
        if(windows_object(before)) {
            channels=native_value(query->inspect_data_channels(policy.limits));logical=validate_catalog(*channels,before,policy.limits);
            for(const auto& c:channels->channels)if(c.kind==DataChannelKind::NamedData)
                charge(budget.metadata,sizeof(MetadataReplayChannelSnapshot)+identifier(c.identifier).size(),limits.max_metadata_bytes,"native_sync.channel_metadata_limit");
        }
        if(logical>limits.max_file_bytes)native_fail("native_sync.all_stream_file_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        // Charge main + ALL named logical data before capture performs any ADS hashing.
        charge(budget.bytes,logical,limits.max_total_bytes,"native_sync.all_stream_content_limit");
        auto metadata=native_value(capture_metadata_replay(*query,policy,stop));
        if(!native_sync_same_version(before,metadata.basic))native_fail("native_sync.capture_changed");
        if(channels)match_catalog(*channels,metadata);
        else if(metadata.channel_coverage!=DataChannelCoverage::Unknown||!metadata.channels.empty())
            native_fail("native_sync.foreign_channel_capture",ObservationState::Unsupported);
        for(const auto& a:metadata.attributes)charge(budget.metadata,sizeof(AttributeValue)+a.bytes.size()+identifier(a.identifier).size(),limits.max_metadata_bytes,"native_sync.attribute_limit");
        for(const auto& a:metadata.security)charge(budget.metadata,sizeof(NativeSecurityValue)+a.bytes.size(),limits.max_metadata_bytes,"native_sync.security_limit");
        Sha256 hash;std::uint64_t offset=0;
        for(;;){check_stop(stop);auto read=native_value(held->read_content({limits.chunk_bytes},offset,stop));
            if(offset>size||read.bytes.size()>size-offset||(read.bytes.empty()&&!read.complete))native_fail("native_sync.hash_progress");
            hash.update(read.bytes);offset+=read.bytes.size();if(read.complete)break;}
        if(offset!=size)native_fail("native_sync.hash_length");
        native_value(held->verify_metadata_source(metadata,stop));
        auto digest=native_value(native_sync_metadata_digest(*query,metadata,stop));
        // The retained query is an object proof, not proof that its old name
        // still selects it. Check membership AFTER the final potentially long
        // stream digest, with the original held family still alive.
        auto member=native_value(held->refresh(stop));
        if(!member->continues(*held)||!native_sync_same_version(metadata.basic,member->metadata())||
           !native_sync_same_version(metadata.basic,native_value(query->inspect_basic())))native_fail("native_sync.member_changed");
        NativeSyncChannelFacts facts;facts.coverage=metadata.channel_coverage;facts.named_stream_count=metadata.channels.size();
        if(channels)facts.all_stream_logical_bytes=logical;facts.semantic_digest=hashed(channel_manifest(metadata));
        NativeSyncFileProof result{{name},std::move(held),std::move(metadata),{SyncPresence::Present,SyncKind::File,hash.digest(),digest},
            std::shared_ptr<const OpenedEntry>(std::move(query)),std::move(facts)};
        check_stop(stop);return result;
    });
}
Observation<std::unique_ptr<NativeSyncInventory>> observe_native_sync_root(std::shared_ptr<const DirectoryCursor> root,MetadataReplayPolicy policy,
    const NativeSyncProofLimits& limits,NativeSyncProofBudget& budget,std::stop_token stop) {
    return observed<std::unique_ptr<NativeSyncInventory>>([&]{
        check_stop(stop);auto owned=std::make_unique<NativeSyncInventory>();auto& out=*owned;out.root=root;out.root_metadata=native_value(root->inspect_basic());
        if(!out.root_metadata.identity.value()||!out.root_metadata.kind.value()||*out.root_metadata.kind.value()!=ObjectKind::Directory||
            !out.root_metadata.changed.value()||!out.root_metadata.modified.value())native_fail("native_sync.root_version",ObservationState::Unsupported);
        require_true(qualify_native_sync_root_channels(*root,policy.limits));
        std::size_t total=0;
        for(;;){check_stop(stop);auto batch=const_cast<DirectoryCursor&>(*root).read(128,stop);
            if(batch.state==DirectoryReadState::Error)throw NativeFailure{*batch.error};
            if(batch.state==DirectoryReadState::Cancelled)check_stop(stop);
            for(auto& name:batch.names){std::array names{name};const auto key=native_sync_key(names);
                if(key.size()>limits.baseline.max_path_bytes||key.size()>limits.baseline.max_total_path_bytes-total)
                    native_fail("native_sync.path_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
                total+=key.size();auto proof=native_value(observe_native_sync_file(root,name,policy,limits,budget,stop));
                if(!out.files.emplace(key,std::move(proof)).second)native_fail("native_sync.duplicate_name");}
            if(batch.state==DirectoryReadState::End)break;}
        require_true(qualify_native_sync_root_channels(*root,policy.limits));
        auto after=native_value(root->inspect_basic());if(!native_sync_same_version(out.root_metadata,after))native_fail("native_sync.inventory_changed");
        return owned;
    });
}
Observation<bool> compare_native_sync_inventories(const NativeSyncInventory& a,const NativeSyncInventory& b) {
    return observed<bool>([&]{if(!native_sync_same_version(a.root_metadata,b.root_metadata)||a.files.size()!=b.files.size())native_fail("native_sync.inventory_version_changed");
        for(const auto& [key,p]:a.files){auto it=b.files.find(key);if(it==b.files.end()||p.status!=it->second.status||
            !native_sync_same_version(p.metadata.basic,it->second.metadata.basic))native_fail("native_sync.file_version_changed");}
        return true;});
}
} // namespace ck::files
