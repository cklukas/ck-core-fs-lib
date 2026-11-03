// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_directory_replay_verifier.hpp"
#include "private_journal_scope.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "native_trash.hpp"
#include <windows.h>
#include <winternl.h>
#endif
namespace ck::files {
namespace {
template<class T> Observation<T> unsupported(const char* operation) {
    return Observation<T>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),operation});
}
template<class T,class U> Observation<T> propagate(const Observation<U>& value) {
    const auto& e=*value.unavailable_detail();return Observation<T>::unavailable(e.state,e.error);
}
#ifdef _WIN32
template<class T> Observation<T> failure(DWORD code,const char* operation) {
    return Observation<T>::unavailable(code==ERROR_ACCESS_DENIED?ObservationState::Denied:ObservationState::Unknown,
        {ErrorDomain::Win32,code,operation});
}
class ReadOwner final {
public:
    ReadOwner(HANDLE handle,PreparedJournalRoot::Pointer root):handle_(handle),root_(std::move(root)){}
    ReadOwner(ReadOwner&& other)noexcept:handle_(std::exchange(other.handle_,nullptr)),root_(std::move(other.root_)),code_(other.code_){}
    ReadOwner(const ReadOwner&)=delete;
    ReadOwner& operator=(const ReadOwner&)=delete;
    ~ReadOwner(){close();}
    HANDLE get()const noexcept{return handle_;}
    void close()noexcept {
        const auto raw=std::exchange(handle_,nullptr);if(!raw||raw==INVALID_HANDLE_VALUE)return;
        if(!CloseHandle(raw)) {code_=GetLastError();detail::record_prepared_journal_consumer_failure(*root_,
            ObservationState::Unknown,ErrorDomain::Win32,code_,"directory_verifier.CloseHandle");}
        root_.reset();
    }
    DWORD close_code()const noexcept{return code_;}
private:
    HANDLE handle_;PreparedJournalRoot::Pointer root_;DWORD code_=0;
};
bool matches(HANDLE handle,const ObjectIdentity& expected) {
    FILE_ID_INFO id{};if(!GetFileInformationByHandleEx(handle,FileIdInfo,&id,sizeof(id)))return false;
    NativeIdentifier object;std::memcpy(object.bytes.data(),id.FileId.Identifier,16);
    return expected.scheme==IdentityScheme::WindowsFileId128&&expected.volume==NativeIdentifier::from_u64(id.VolumeSerialNumber)&&expected.object==object;
}
class Reader final:public MetadataReplayChannelSource {
public:
    Reader(ReadOwner handle,NativeFeatureIdentifier name,ObjectIdentity owner)
        :handle_(std::move(handle)),name_(std::move(name)),owner_(std::move(owner)){}
    Observation<MetadataReplayChannelState> inspect()const override {
        if(!handle_.get()||!matches(handle_.get(),owner_))return Observation<MetadataReplayChannelState>::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"directory_verifier.stream_owner"});
        FILE_STANDARD_INFO standard{};if(!GetFileInformationByHandleEx(handle_.get(),FileStandardInfo,&standard,sizeof(standard)))
            return failure<MetadataReplayChannelState>(GetLastError(),"directory_verifier.stream_standard");
        if(standard.DeletePending||standard.EndOfFile.QuadPart<0)return Observation<MetadataReplayChannelState>::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"directory_verifier.stream_pending_or_size"});
        return Observation<MetadataReplayChannelState>::available({name_,owner_,static_cast<std::uint64_t>(standard.EndOfFile.QuadPart)});
    }
    Observation<ContentRead> read_content(ContentReadLimits limits,std::uint64_t offset,std::stop_token stop)const override {
        if(!limits.valid()||offset>static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max()))return unsupported<ContentRead>("directory_verifier.read_limits");
        if(stop.stop_requested())return Observation<ContentRead>::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,6,"directory_verifier.cancelled"});
        auto before=inspect();if(!before.value())return propagate<ContentRead>(before);
        if(offset>before.value()->logical_size)return Observation<ContentRead>::unavailable(ObservationState::Changed);
        LARGE_INTEGER position{};position.QuadPart=static_cast<LONGLONG>(offset);
        if(!SetFilePointerEx(handle_.get(),position,nullptr,FILE_BEGIN))return failure<ContentRead>(GetLastError(),"directory_verifier.stream_seek");
        const auto count=static_cast<DWORD>(std::min<std::uint64_t>(limits.max_bytes,before.value()->logical_size-offset));
        std::vector<std::byte> bytes(count);DWORD read=0;
        if(count&&!ReadFile(handle_.get(),bytes.data(),count,&read,nullptr))return failure<ContentRead>(GetLastError(),"directory_verifier.stream_read");
        bytes.resize(read);auto after=inspect();if(!after.value())return propagate<ContentRead>(after);
        if(after.value()->logical_size!=before.value()->logical_size)return Observation<ContentRead>::unavailable(ObservationState::Changed);
        return Observation<ContentRead>::available({std::move(bytes),offset+read==before.value()->logical_size});
    }
    DWORD finish()noexcept {handle_.close();return handle_.close_code();}
    const NativeFeatureIdentifier& identifier()const noexcept{return name_;}
private:
    ReadOwner handle_;NativeFeatureIdentifier name_;ObjectIdentity owner_;
};
class VerifiedEntry final:public OpenedEntry {
public:
    VerifiedEntry(std::unique_ptr<OpenedEntry> entry,std::vector<std::shared_ptr<Reader>> readers)
        :entry_(std::move(entry)),readers_(std::move(readers)){}
    Observation<BasicMetadata> inspect_basic()const override{return entry_?entry_->inspect_basic():closed<BasicMetadata>();}
    Observation<AttributeCatalog> inspect_attributes(InventoryLimits limits)const override{return entry_?entry_->inspect_attributes(limits):closed<AttributeCatalog>();}
    Observation<AttributeValue> read_attribute(const NativeFeatureIdentifier& id,InventoryLimits limits)const override{return entry_?entry_->read_attribute(id,limits):closed<AttributeValue>();}
    Observation<NativeSecurityValue> read_security(SecurityPart part,InventoryLimits limits)const override{return entry_?entry_->read_security(part,limits):closed<NativeSecurityValue>();}
    Observation<DataChannelCatalog> inspect_data_channels(InventoryLimits limits)const override{return entry_?entry_->inspect_data_channels(limits):closed<DataChannelCatalog>();}
    Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy& policy)const override{return entry_?entry_->qualify_metadata_replay(policy):closed<bool>();}
    Observation<bool> verify_replay_security(const NativeSecurityValue& value,const MetadataReplayPolicy& policy)const override{return entry_?entry_->verify_replay_security(value,policy):closed<bool>();}
    Observation<bool> verify_metadata_security_coverage(const MetadataReplaySnapshot& snapshot)const override{return entry_?entry_->verify_metadata_security_coverage(snapshot):closed<bool>();}
    Observation<std::shared_ptr<const MetadataReplayChannelSource>> open_metadata_replay_channel_read(const NativeFeatureIdentifier& id)const override {
        for(const auto& reader:readers_)if(reader->identifier()==id)return Observation<std::shared_ptr<const MetadataReplayChannelSource>>::available(reader);
        return unsupported<std::shared_ptr<const MetadataReplayChannelSource>>("directory_verifier.unprepared_stream");
    }
    DWORD finish()noexcept {
        DWORD first=0;for(const auto& reader:readers_) {const auto code=reader->finish();if(!first)first=code;}
        readers_.clear();entry_.reset();return first;
    }
private:
    template<class T>static Observation<T> closed() {
        return Observation<T>::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidAccess),"directory_verifier.finished"});
    }
    std::unique_ptr<OpenedEntry> entry_;std::vector<std::shared_ptr<Reader>> readers_;
};
class Verifier final:public DirectoryReplayVerifier {
public:
    Verifier(std::unique_ptr<VerifiedEntry> entry,JournalScopeGuard::Pointer scope):entry_(std::move(entry)),scope_(std::move(scope)){}
    ~Verifier()override{if(!finished_)try{(void)finish_io();}catch(...){}}
    OpenedEntry& entry()override{return *entry_;}
    Observation<bool> finish_io()override {
        if(!finished_){code_=entry_->finish();scope_.reset();finished_=true;}
        return code_?failure<bool>(code_,"directory_verifier.CloseHandle"):Observation<bool>::available(true);
    }
private:
    std::unique_ptr<VerifiedEntry> entry_;JournalScopeGuard::Pointer scope_;bool finished_=false;DWORD code_=0;
};
#endif
}
Observation<std::unique_ptr<DirectoryReplayVerifier>> create_directory_replay_verifier(HeldChild::Pointer held,
    std::shared_ptr<const DirectoryCursor> cursor,std::unique_ptr<OpenedEntry> metadata,const MetadataReplaySnapshot& snapshot,
    PreparedJournalRoot::Pointer root,std::stop_token stop) {
#ifdef _WIN32
    using R=Observation<std::unique_ptr<DirectoryReplayVerifier>>;
    if(!held||!cursor||!metadata||!root||snapshot.policy.ownership!=MetadataOwnership::Original)
        return unsupported<std::unique_ptr<DirectoryReplayVerifier>>("directory_verifier.native_inputs_or_ownership");
    auto scope=JournalScopeGuard::create_for_entry(root,*held,stop);if(!scope.value())return propagate<std::unique_ptr<DirectoryReplayVerifier>>(scope);
    auto basic=metadata->inspect_basic();if(!basic.value())return propagate<std::unique_ptr<DirectoryReplayVerifier>>(basic);
    if(!basic.value()->identity.value()||!held->metadata().identity.value()||compare_identity(*basic.value()->identity.value(),*held->metadata().identity.value())!=IdentityComparison::Same)
        return unsupported<std::unique_ptr<DirectoryReplayVerifier>>("directory_verifier.metadata_binding");
    auto duplicate=duplicate_windows_trash_parent(*cursor);if(!duplicate.value())return propagate<std::unique_ptr<DirectoryReplayVerifier>>(duplicate);
    auto held_directory=std::move(duplicate).take_value();
    ReadOwner directory(held_directory.release(),root);const auto owner=*basic.value()->identity.value();
    if(!matches(directory.get(),owner))return unsupported<std::unique_ptr<DirectoryReplayVerifier>>("directory_verifier.cursor_binding");
    std::vector<std::shared_ptr<Reader>> readers;readers.reserve(snapshot.channels.size());
    for(const auto& stream:snapshot.channels) {
        if(stop.stop_requested())return R::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,6,"directory_verifier.cancelled"});
        const auto* units=stream.identifier.windows_units();
        if(!units||units->size()<=7||units->front()!=u':'||!units->ends_with(u":$DATA")||units->size()>32767||
            units->substr(1,units->size()-7).find_first_of(u":/\\\0",0,4)!=std::u16string::npos)
            return unsupported<std::unique_ptr<DirectoryReplayVerifier>>("directory_verifier.stream_name");
        std::wstring native(units->begin(),units->end());UNICODE_STRING name{};name.Buffer=native.data();
        name.Length=static_cast<USHORT>(native.size()*sizeof(wchar_t));name.MaximumLength=name.Length;
        OBJECT_ATTRIBUTES attributes{};InitializeObjectAttributes(&attributes,&name,0,directory.get(),nullptr);
        IO_STATUS_BLOCK io{};HANDLE raw=nullptr;
        const auto status=NtCreateFile(&raw,FILE_READ_DATA|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE,
            &attributes,&io,nullptr,0,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,FILE_OPEN,
            FILE_OPEN_REPARSE_POINT|FILE_OPEN_NO_RECALL|FILE_SYNCHRONOUS_IO_NONALERT,nullptr,0);
        ReadOwner temporary(raw,root);
        if(status!=0)return R::unavailable(ObservationState::Unknown,{ErrorDomain::NtStatus,static_cast<std::uint32_t>(status),"directory_verifier.NtCreateFile"});
        if(io.Information!=FILE_OPENED||!matches(temporary.get(),owner))return unsupported<std::unique_ptr<DirectoryReplayVerifier>>("directory_verifier.stream_binding");
        const FILETIME suppressed{MAXDWORD,MAXDWORD};if(!SetFileTime(temporary.get(),nullptr,&suppressed,&suppressed))
            return failure<std::unique_ptr<DirectoryReplayVerifier>>(GetLastError(),"directory_verifier.suppress_times");
        HANDLE reduced=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),temporary.get(),GetCurrentProcess(),&reduced,
            FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE,FALSE,0))return failure<std::unique_ptr<DirectoryReplayVerifier>>(GetLastError(),"directory_verifier.reduce_rights");
        ReadOwner reduced_owner(reduced,root);auto identifier=stream.identifier;
        auto reader=std::make_shared<Reader>(std::move(reduced_owner),std::move(identifier),owner);
        temporary.close();if(temporary.close_code())return failure<std::unique_ptr<DirectoryReplayVerifier>>(temporary.close_code(),"directory_verifier.prepare_close");
        auto inspected=reader->inspect();if(!inspected.value())return propagate<std::unique_ptr<DirectoryReplayVerifier>>(inspected);
        if(inspected.value()->logical_size!=stream.logical_size)return R::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,15,"directory_verifier.stream_size"});
        readers.push_back(std::move(reader));
    }
    directory.close();if(directory.close_code())return failure<std::unique_ptr<DirectoryReplayVerifier>>(directory.close_code(),"directory_verifier.directory_close");
    auto entry=std::make_unique<VerifiedEntry>(std::move(metadata),std::move(readers));
    return R::available(std::make_unique<Verifier>(std::move(entry),std::move(scope).take_value()));
#else
    (void)held;(void)cursor;(void)metadata;(void)snapshot;(void)root;(void)stop;
    return unsupported<std::unique_ptr<DirectoryReplayVerifier>>("directory_verifier.windows_streams_only");
#endif
}
} // namespace ck::files
