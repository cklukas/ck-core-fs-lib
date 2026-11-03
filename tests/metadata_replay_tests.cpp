// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_replay.hpp"
#include "regular_metadata_preservation.hpp"
#include "native_filesystem.hpp"
#include "retained_target.hpp"
#include "windows_name.hpp"
#include <cstdlib>
#include <algorithm>
#include <iostream>
#include <bit>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <atomic>
#include <thread>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#ifdef __APPLE__
#include <sys/acl.h>
#include <membership.h>
#include <sys/mount.h>
#endif
#endif
#ifdef _WIN32
// Test-only import interception requests cancellation after a real native
// target-stream write; the snapshot retains its genuine bound native readers.
namespace {
std::atomic<std::stop_source*> ads_cancel_on_write{nullptr};
FILE_ID_INFO ads_cancel_target{};
BOOL WINAPI metadata_test_write_file(HANDLE h,LPCVOID bytes,DWORD size,LPDWORD written,LPOVERLAPPED io) {
    using NativeWrite=BOOL(WINAPI*)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
    static const auto native=std::bit_cast<NativeWrite>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"WriteFile"));
    const BOOL result=native(h,bytes,size,written,io);const DWORD saved=GetLastError();
    if(result&&ads_cancel_on_write.load(std::memory_order_acquire)) {
        FILE_ID_INFO current{};
        if(GetFileInformationByHandleEx(h,FileIdInfo,&current,sizeof(current))&&
           current.VolumeSerialNumber==ads_cancel_target.VolumeSerialNumber&&
           std::memcmp(current.FileId.Identifier,ads_cancel_target.FileId.Identifier,16)==0) {
            if(auto* stop=ads_cancel_on_write.exchange(nullptr,std::memory_order_acq_rel))stop->request_stop();
        }
    }
    SetLastError(saved);return result;
}
}
extern "C" { decltype(&WriteFile) __imp_WriteFile=&metadata_test_write_file; }
#ifdef CK_FS_METADATA_TEST_CLOSE_FAULT
// Test executable import replacement only. Production adapters still call the
// native API. Consume the real handle before reporting a deterministic delayed
// close error, then ensure cached finalization never retries that consumed ID.
namespace {
std::atomic<bool> close_fault_armed{false};
std::atomic<unsigned> close_fault_hits{0};
FILE_ID_INFO close_fault_target{};
BOOL WINAPI metadata_test_close_handle(HANDLE handle) {
    using NativeClose=BOOL(WINAPI*)(HANDLE);
    static const auto native=std::bit_cast<NativeClose>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CloseHandle"));
    const DWORD saved=GetLastError();bool selected=false;
    if(close_fault_armed.load(std::memory_order_acquire)) {
        FILE_ID_INFO current{};
        selected=GetFileInformationByHandleEx(handle,FileIdInfo,&current,sizeof(current))!=0&&
            current.VolumeSerialNumber==close_fault_target.VolumeSerialNumber&&
            std::memcmp(current.FileId.Identifier,close_fault_target.FileId.Identifier,16)==0;
    }
    SetLastError(saved);const auto result=native(handle);
    if(selected&&result&&close_fault_armed.exchange(false,std::memory_order_acq_rel)) {
        close_fault_hits.fetch_add(1,std::memory_order_relaxed);SetLastError(ERROR_WRITE_FAULT);return FALSE;
    }
    return result;
}
}
extern "C" { decltype(&CloseHandle) __imp_CloseHandle=&metadata_test_close_handle; }
#endif
#endif
using namespace ck::files;
namespace {
void require(bool value,const char* message) {if(!value) throw std::runtime_error(message);}
template<class T> const T& need(const Observation<T>& value,const char* message) {
    if(!value.value()) {
        std::cerr<<message<<": "<<value.unavailable_detail()->error.operation<<" state="<<static_cast<int>(value.state())
                 <<" code="<<value.unavailable_detail()->error.code<<'\n';
        throw std::runtime_error(message);
    }
    return *value.value();
}
void success(const Observation<bool>& value,const char* message) {require(need(value,message),message);}
NativeName name(const char* raw) {
#ifdef _WIN32
    std::u16string units;for(;*raw;++raw)units.push_back(static_cast<unsigned char>(*raw));
    return *NativeName::from_windows(std::move(units));
#else
    return *NativeName::from_posix(raw);
#endif
}
class UnsupportedEntry final:public OpenedEntry {
public:Observation<BasicMetadata> inspect_basic() const override {return {};}
};
struct Fixture {
    NativeFileSystem filesystem;
    std::shared_ptr<const DirectoryCursor> directory;
    std::unique_ptr<OpenedEntry> source;
    std::unique_ptr<OpenedEntry> target;
#ifdef _WIN32
    std::wstring root;
    std::vector<std::wstring> directories;
#else
    std::string root;
#endif
    explicit Fixture(const char* fixture_root=nullptr) {
#ifdef _WIN32
        (void)fixture_root;
        const auto* temp=_wgetenv(L"TEMP");const auto* tmp=_wgetenv(L"TMP");
        require(temp&&*temp&&tmp&&*tmp,"Windows tests require explicit TEMP/TMP");
        const auto native_temp=windows_extended_path(temp);const auto native_tmp=windows_extended_path(tmp);
        require(native_temp&&native_tmp,"Windows tests require absolute TEMP/TMP");
        const auto* require_v=_wgetenv(L"CK_FS_REQUIRE_V_DEV_DRIVE");
        if (require_v&&std::wstring_view(require_v)==L"1")
            require(native_temp->starts_with(L"\\\\?\\V:\\tmp\\")&&native_tmp->starts_with(L"\\\\?\\V:\\tmp\\"),"workstation tests require V:\\tmp TEMP/TMP");
        static std::atomic<std::uint64_t> sequence{0};
        root=*native_temp+L"\\metadata-replay-"+std::to_wstring(GetCurrentProcessId())+L"-"+
            std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(sequence.fetch_add(1,std::memory_order_relaxed));
        require(CreateDirectoryW(root.c_str(),nullptr)!=0,"create root");directories.push_back(root);
        // Exact wide/native calls exercise an extended path longer than MAX_PATH.
        for(int i=0;i<4;++i) {root+=L"\\"+std::wstring(72,static_cast<wchar_t>(L'a'+i));require(CreateDirectoryW(root.c_str(),nullptr)!=0,"create long root");directories.push_back(root);}
#else
        const auto* temp=fixture_root?fixture_root:std::getenv("TMPDIR");require(temp&&*temp,"explicit TMPDIR required");
#ifdef __APPLE__
        require(std::string(temp).starts_with("/Volumes/S8T/tmp/")||std::string(temp).starts_with("/Volumes/PRO-BLADE/tmp/"),"approved Mac temporary volume required");
#endif
        root=std::string(temp)+"/metadata-replay-tests.XXXXXX";require(mkdtemp(root.data())!=nullptr,"mkdtemp");
#endif
        auto opened=filesystem.open_directory(root);need(opened,"open directory");
        directory=std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
        auto from=directory->create_child_file(name("source"));need(from,"create source");source=std::move(from).take_value();
        auto to=directory->create_child_file(name("target"));need(to,"create target");target=std::move(to).take_value();
        const std::byte data[]{std::byte{'t'},std::byte{'e'},std::byte{'s'},std::byte{'t'}};
        require(need(source->write_content(0,data),"write source")==4,"source write count");
        require(need(target->write_content(0,data),"write target")==4,"target write count");
        success(source->flush_content(),"flush source");success(target->flush_content(),"flush target");
    }
    ~Fixture() {
        source.reset();target.reset();directory.reset();
#ifdef _WIN32
        for(const auto* n:{L"source",L"target",L"renamed",L"moved",L"held-renamed",L"retained",L"staging",L"published",L"exact_\u00e9. "}) DeleteFileW((root+L"\\"+n).c_str());
        for(auto it=directories.rbegin();it!=directories.rend();++it) RemoveDirectoryW(it->c_str());
#else
        for(const auto* n:{"source","target","renamed"}) unlink((root+"/"+n).c_str());
        rmdir(root.c_str());
#endif
    }
    MetadataReplayPolicy policy(RegularMetadataScope scope=RegularMetadataScope::OrdinaryCallerVisibleV1) {
        MetadataReplayPolicy result;result.scope=scope;result.ownership=MetadataOwnership::CurrentCaller;return result;
    }
    AttributeValue attribute(const char* key,std::vector<std::byte> bytes) {
#ifdef _WIN32
        auto id=*NativeFeatureIdentifier::from_windows_ea(key);
        auto flags=Observation<std::uint32_t>::available(0);
#else
        auto id=*NativeFeatureIdentifier::from_posix(key);Observation<std::uint32_t> flags;
#endif
        return {std::move(id),std::move(bytes),need(source->inspect_basic(),"source identity").identity,std::move(flags)};
    }
    void add_attribute(const char* key,std::vector<std::byte> value) {success(source->apply_nonsecurity_attribute(attribute(key,std::move(value))),"set source attribute");}
    MetadataReplaySnapshot capture(MetadataReplayPolicy p) {return need(capture_metadata_replay(*source,p),"capture");}
    BasicMetadata replay(const MetadataReplaySnapshot& snapshot) {
        success(apply_metadata_replay(*target,snapshot),"apply replay");
        const auto applied=need(target->inspect_basic(),"applied identity");
        success(verify_metadata_replay(*target,snapshot,applied),"verify replay");return applied;
    }
};
class DeniedInventory final : public OpenedEntry {
public:
    DeniedInventory(const OpenedEntry& entry,bool attributes):entry_(entry),attributes_(attributes) {}
    Observation<BasicMetadata> inspect_basic() const override {return entry_.inspect_basic();}
    Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy& p) const override {return entry_.qualify_metadata_replay(p);}
    Observation<AttributeCatalog> inspect_attributes(InventoryLimits limits) const override {
        return attributes_ ? Observation<AttributeCatalog>::unavailable(ObservationState::Denied,{ErrorDomain::Posix,13,"fixture.attribute_denied"}) : entry_.inspect_attributes(limits);
    }
    Observation<AttributeValue> read_attribute(const NativeFeatureIdentifier& id,InventoryLimits limits) const override {return entry_.read_attribute(id,limits);}
    Observation<StorageInfo> inspect_storage() const override {return entry_.inspect_storage();}
    Observation<NativeSecurityValue> read_security(SecurityPart,InventoryLimits) const override {
        return Observation<NativeSecurityValue>::unavailable(ObservationState::Denied,{ErrorDomain::Posix,13,"fixture.security_denied"});
    }
private:const OpenedEntry& entry_;bool attributes_;
};
class DeniedOwnership final : public OpenedEntry {
public:
    explicit DeniedOwnership(OpenedEntry& entry):entry_(entry) {}
    Observation<BasicMetadata> inspect_basic() const override {return entry_.inspect_basic();}
    Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy& p) const override {return entry_.qualify_metadata_replay(p);}
    Observation<bool> apply_replay_channels(const MetadataReplaySnapshot& snapshot,std::stop_token stop) override {
        return entry_.apply_replay_channels(snapshot,stop);
    }
    Observation<bool> apply_replay_ownership(const BasicMetadata&,const MetadataReplayPolicy&) override {
        return Observation<bool>::unavailable(ObservationState::Denied,{ErrorDomain::Posix,1,"fixture.ownership_denied"});
    }
private:OpenedEntry& entry_;
};
void directory_metadata_tests(bool complete=false);
#ifdef _WIN32
void windows_ads_tests(bool complete=false) {
    Fixture f;auto policy=f.policy();
    if(complete){policy.scope=RegularMetadataScope::CompleteMetadataV1;policy.ownership=MetadataOwnership::Original;policy.allow_privilege_metadata=true;}
    const std::vector<std::u16string> names{u":Zone.Identifier:$DATA",u":empty:$DATA",
        std::u16string(u":exact_\u00e9. ")+static_cast<char16_t>(0xd800)+u":$DATA",u":large:$DATA",std::u16string(u":")+std::u16string(220,u'q')+u":$DATA"};
    const auto path=[&](const wchar_t* base,const std::u16string& stream){return f.root+L"\\"+base+std::wstring(stream.begin(),stream.end());};
    const auto write_fixture=[&](const std::wstring& native_path,std::uint64_t size) {
        HANDLE handle=CreateFileW(native_path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        require(handle!=INVALID_HANDLE_VALUE,"native ADS fixture creation");
        std::vector<std::byte> chunk(64*1024);std::uint64_t offset=0;
        while(offset<size) {
            const auto count=static_cast<DWORD>(std::min<std::uint64_t>(chunk.size(),size-offset));
            for(DWORD i=0;i<count;++i)chunk[i]=static_cast<std::byte>((offset+i)*131U+17U);
            DWORD copied=0;require(WriteFile(handle,chunk.data(),count,&copied,nullptr)!=0&&copied==count,"native ADS fixture write");offset+=copied;
        }
        require(FlushFileBuffers(handle)!=0,"native ADS fixture flush");require(CloseHandle(handle)!=0,"native ADS fixture close");
    };
    write_fixture(path(L"source",names[0]),71);write_fixture(path(L"source",names[1]),0);
    write_fixture(path(L"source",names[2]),65559);write_fixture(path(L"source",names[3]),9*1024*1024+37);write_fixture(path(L"source",names[4]),2301);
    f.add_attribute("ADS_SECURITY_EA",{std::byte{'e'},std::byte{0},std::byte{'a'}});
    auto snapshot=f.capture(policy);require(snapshot.channel_coverage==DataChannelCoverage::WindowsFileStreamInfo&&snapshot.channels.size()==names.size(),
        "ADS manifest missing source stream");
    for(const auto& expected:names)require(std::any_of(snapshot.channels.begin(),snapshot.channels.end(),
        [&](const auto& item){return item.identifier.windows_units()&&*item.identifier.windows_units()==expected;}),"exact UTF16 ADS name changed");
    const auto applied=f.replay(snapshot);
    for(const auto& stream:names) {
        HANDLE outsider=CreateFileW(path(L"target",stream).c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        const DWORD code=GetLastError();if(outsider!=INVALID_HANDLE_VALUE)CloseHandle(outsider);
        require(outsider==INVALID_HANDLE_VALUE&&code==ERROR_SHARING_VIOLATION,"target ADS writer lacks matching WRITE exclusion");
    }
    success(f.target->publish_noreplace(*f.directory,name("published")),"publish base with all guarded streams");
    success(f.target->finish_content_writes(),"finalize ALL ADS and main writers");
    success(f.target->finish_content_writes(),"cached ALL-stream finalization");
    auto final=f.directory->open_child(name("published"),EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity|EntryAccess::ContentRead);
    need(final,"independent published ADS base");
    const auto after=need((*final.value())->inspect_basic(),"published ADS base identity");
    require(compare_identity(*after.identity.value(),*applied.identity.value())==IdentityComparison::Same,"ADS publication changed base identity");
    require(after.accessed.value()&&after.modified.value()&&*after.accessed.value()==*snapshot.basic.accessed.value()&&
        *after.modified.value()==*snapshot.basic.modified.value(),"ADS writer close changed preserved times");
    const auto final_snapshot=need(capture_metadata_replay(**final.value(),policy),"post-close native ADS inventory/digests");
    require(final_snapshot.channels.size()==snapshot.channels.size(),"final close lost ADS");
    for(const auto& expected:snapshot.channels) {
        const auto found=std::find_if(final_snapshot.channels.begin(),final_snapshot.channels.end(),[&](const auto& item){return item.identifier==expected.identifier;});
        require(found!=final_snapshot.channels.end()&&found->logical_size==expected.logical_size&&found->digest==expected.digest,
            "post-close ADS data/name/digest mismatch");
    }
    // Native source handles remain bound through rename; neither capture's
    // retained stream readers nor replay resolve the old source pathname.
    success(f.source->finish_content_writes(),"close fixture source writer before held rename");
    success(f.directory->rename_child_noreplace(name("source"),*snapshot.basic.identity.value(),*f.directory,name("renamed")),"rename held ADS source");
    for(const auto& stream:snapshot.channels) {
        const auto digest=digest_metadata_replay_channel(*stream.source,stream.identifier,*snapshot.basic.identity.value(),stream.logical_size);
        require(need(digest,"retained ADS read after base rename")==stream.digest,"ADS reader reopened old pathname");
    }
    std::cout<<"native ADS exact UTF16/long-path, empty and multi-buffer data, security/EA, guarded publish, final close and source rename passed\n";
}
void windows_ads_proof_tests(bool complete=false) {
    Fixture f;auto policy=f.policy(complete?RegularMetadataScope::CompleteMetadataV1:RegularMetadataScope::OrdinaryCallerVisibleV1);
    policy.allow_privilege_metadata=complete;
    for(const auto* stream:{L":proof-a:$DATA",L":proof-b:$DATA"}) {
        HANDLE h=CreateFileW((f.root+L"\\source"+stream).c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);require(h!=INVALID_HANDLE_VALUE,"proof source ADS fixture");
        DWORD count=0;require(WriteFile(h,"actual",6,&count,nullptr)&&count==6,"proof source ADS bytes");require(CloseHandle(h)!=0,"proof source ADS close");
    }
    f.source.reset();auto source=f.directory->open_child(name("source"),EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity);
    need(source,"proof read-only source");f.source=std::move(source).take_value();auto snapshot=f.capture(policy);
    require(snapshot.channels.size()==2&&snapshot.channel_evidence,"native channel proof missing");
    const auto before=need(f.target->inspect_basic(),"proof target before");
    const auto rejects=[&](const MetadataReplaySnapshot& forged,const char* message) {
        require(!apply_metadata_replay(*f.target,forged).value(),message);
        require(!f.target->apply_replay_channels(forged).value(),"direct native channel apply bypassed manifest proof");
        const auto actual=need(f.target->inspect_basic(),"proof rejected target after");
        require(*actual.changed.value()==*before.changed.value(),"forged manifest changed target before rejection");
        const auto catalog=need(f.target->inspect_data_channels(),"proof rejected target stream set");
        require(catalog.channels.size()==1&&catalog.channels.front().kind==DataChannelKind::MainData,"forged manifest created ADS before rejection");
    };
    auto forged=snapshot;forged.channel_evidence.reset();rejects(forged,"missing native stream proof accepted");
    class FakeProof final:public MetadataReplayChannelEvidence {};
    forged=snapshot;forged.channel_evidence=std::make_shared<FakeProof>();rejects(forged,"caller-created stream proof accepted");
    forged=snapshot;forged.channels.pop_back();rejects(forged,"omitted source stream accepted");
    require(!issue_native_metadata_replay_channels(*f.source,forged).value(),"issuer signed omitted source stream");
    forged=snapshot;forged.channels[0].digest[0]^=std::byte{1};rejects(forged,"forged stream digest accepted");
    require(!issue_native_metadata_replay_channels(*f.source,forged).value(),"native issuer signed caller digest without actual hash");
    forged=snapshot;forged.channels[0].logical_size++;rejects(forged,"forged stream size accepted");
    forged=snapshot;forged.channels[0].identifier=*NativeFeatureIdentifier::from_windows(u":forged:$DATA");rejects(forged,"forged stream name accepted");
    forged=snapshot;forged.channels[1]=forged.channels[0];rejects(forged,"duplicate stream alias accepted");
    require(!issue_native_metadata_replay_channels(*f.source,forged).value(),"issuer signed duplicate stream aliases");
    forged=snapshot;forged.policy.limits.max_records=1;rejects(forged,"forged stream inventory bounds accepted");
    require(!issue_native_metadata_replay_channels(*f.source,forged).value(),"issuer ignored stream inventory bounds");
    class FakeReader final:public MetadataReplayChannelSource {
    public:explicit FakeReader(std::shared_ptr<const MetadataReplayChannelSource> native):native_(std::move(native)){}
        Observation<MetadataReplayChannelState> inspect()const override{return native_->inspect();}
        Observation<ContentRead> read_content(ContentReadLimits limits,std::uint64_t offset,std::stop_token stop)const override{return native_->read_content(limits,offset,stop);}
    private:std::shared_ptr<const MetadataReplayChannelSource> native_;
    };
    forged=snapshot;forged.channels[0].source=std::make_shared<FakeReader>(snapshot.channels[0].source);rejects(forged,"caller reader accepted as native bound stream");
    require(!issue_native_metadata_replay_channels(*f.source,forged).value(),"issuer accepted caller-created reader");
    forged=snapshot;auto owner=*forged.basic.identity.value();owner.object=NativeIdentifier::from_u64(1);
    forged.basic.identity=Observation<ObjectIdentity>::available(owner);rejects(forged,"forged stream owner accepted");
    require(!issue_native_metadata_replay_channels(*f.source,forged).value(),"issuer signed unrelated stream owner");
    std::stop_source stop;stop.request_stop();require(!issue_native_metadata_replay_channels(*f.source,snapshot,stop.get_token()).value(),"issuer ignored cancellation");
    success(verify_native_metadata_replay_channels(snapshot),"valid native stream manifest proof");f.replay(snapshot);
    std::cout<<"native ADS issuer bounds/owner/actual digest and forged manifest/proof/reader negatives passed before target mutation\n";
}

void windows_ads_change_cancel_tests() {
    Fixture f;auto policy=f.policy();
    const std::u16string stream=u":mutable:$DATA";
    const auto native_path=f.root+L"\\source"+std::wstring(stream.begin(),stream.end());
    HANDLE handle=CreateFileW(native_path.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);require(handle!=INVALID_HANDLE_VALUE,"mutable ADS fixture");
    std::vector<std::byte> data(3*64*1024,std::byte{'a'});DWORD written=0;
    require(WriteFile(handle,data.data(),static_cast<DWORD>(data.size()),&written,nullptr)!=0&&written==data.size(),"mutable ADS write");
    require(CloseHandle(handle)!=0,"mutable ADS fixture close");
    auto snapshot=f.capture(policy);
    HANDLE witness=CreateFileW((f.root+L"\\target").c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(witness!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(witness,FileIdInfo,&ads_cancel_target,sizeof(ads_cancel_target)),"ADS cancellation target ID");
    require(CloseHandle(witness)!=0,"ADS cancellation witness close");
    std::stop_source stop;ads_cancel_on_write.store(&stop,std::memory_order_release);
    const auto result=apply_metadata_replay(*f.target,snapshot,stop.get_token());
    ads_cancel_on_write.store(nullptr,std::memory_order_release);
    require(!result.value()&&result.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::InterruptedRead),"ADS chunk cancellation ignored");
    auto partial=f.target->open_metadata_replay_channel_read(snapshot.channels.front().identifier);need(partial,"owned partial native ADS reader");
    const auto partial_state=need((*partial.value())->inspect(),"actual partial ADS size through retained stream handle");
    require(partial_state.logical_size>0&&partial_state.logical_size<data.size(),"ADS cancellation did not interrupt actual partial native copy");
    success(apply_metadata_replay(*f.target,snapshot),"replay owned partial ADS after cancellation");
    const auto applied=need(f.target->inspect_basic(),"ADS applied metadata after retry");
    success(verify_metadata_replay(*f.target,snapshot,applied),"verify ADS retry");
    const auto extra=f.root+L"\\target:unexpected:$DATA";
    HANDLE extra_handle=CreateFileW(extra.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,CREATE_NEW,
        FILE_FLAG_OPEN_REPARSE_POINT,nullptr);require(extra_handle!=INVALID_HANDLE_VALUE,"extra ADS tamper fixture");CloseHandle(extra_handle);
    require(verify_metadata_replay(*f.target,snapshot,applied).state()==ObservationState::Changed,"extra target stream silently dropped");
    success(f.target->finish_content_writes(),"cancel/retry ADS writer close");
    std::cout<<"native ADS cancellation/retry and unexpected stream-set refusal passed\n";
}
void windows_ads_source_change_and_unknown_tests() {
    Fixture f;auto policy=f.policy();
    const auto stream_path=f.root+L"\\source:change:$DATA";
    HANDLE writer=CreateFileW(stream_path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);require(writer!=INVALID_HANDLE_VALUE,"ADS source change fixture");
    const char data[]="source-stream";DWORD count=0;
    require(WriteFile(writer,data,sizeof(data),&count,nullptr)!=0&&count==sizeof(data),"ADS source change bytes");CloseHandle(writer);
    success(f.source->finish_content_writes(),"close original base writer for stream-delete test");
    auto held=f.directory->open_child(name("source"),EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity);
    need(held,"held ADS change source");
    const auto snapshot=need(capture_metadata_replay(**held.value(),policy),"ADS source change snapshot");
    HANDLE basic=CreateFileW((f.root+L"\\source").c_str(),FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(basic!=INVALID_HANDLE_VALUE,"source timestamp witness handle");FILE_BASIC_INFO saved{};
    require(GetFileInformationByHandleEx(basic,FileBasicInfo,&saved,sizeof(saved))!=0,"source timestamp witness");
    const auto added_path=f.root+L"\\source:added:$DATA";
    HANDLE added=CreateFileW(added_path.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);require(added!=INVALID_HANDLE_VALUE,"add source ADS after capture");
    require(WriteFile(added,data,sizeof(data),&count,nullptr)!=0&&count==sizeof(data),"write source added ADS");
    require(CloseHandle(added)!=0,"close source added ADS");
    require(SetFileInformationByHandle(basic,FileBasicInfo,&saved,sizeof(saved))!=0,"restore source basic timestamps after ADS mutation");CloseHandle(basic);
    require(verify_metadata_replay_source(**held.value(),snapshot).state()==ObservationState::Changed,
        "source ADS addition hidden by restored basic metadata");
    class OpaqueProvider final:public OpenedEntry {
    public:
        explicit OpaqueProvider(const OpenedEntry& entry):entry_(entry){}
        Observation<BasicMetadata> inspect_basic()const override{return entry_.inspect_basic();}
        Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy& p)const override{return entry_.qualify_metadata_replay(p);}
        Observation<AttributeCatalog> inspect_attributes(InventoryLimits l)const override{return entry_.inspect_attributes(l);}
        Observation<AttributeValue> read_attribute(const NativeFeatureIdentifier& n,InventoryLimits l)const override{return entry_.read_attribute(n,l);}
        Observation<NativeSecurityValue> read_security(SecurityPart p,InventoryLimits l)const override{return entry_.read_security(p,l);}
        Observation<StorageInfo> inspect_storage()const override{return entry_.inspect_storage();}
        Observation<DataChannelCatalog> inspect_data_channels(InventoryLimits)const override {
            DataChannelCatalog result;result.coverage=DataChannelCoverage::WindowsFileStreamInfo;result.owner=entry_.inspect_basic().value()->identity;
            result.channels.push_back({*NativeFeatureIdentifier::from_windows(u":unknown:$UNKNOWN"),DataChannelKind::Opaque,
                Observation<std::uint64_t>::available(7),{}});return Observation<DataChannelCatalog>::available(std::move(result));
        }
    private:const OpenedEntry& entry_;
    } opaque(**held.value());
    require(capture_metadata_replay(opaque,policy).state()==ObservationState::Unsupported,"unknown native stream kind silently dropped");
    std::cout<<"ADS source manifest mutation with restored timestamps and unknown stream-type refusal passed\n";
}
#ifdef CK_FS_METADATA_TEST_CLOSE_FAULT
void windows_ads_close_failure_test() {
    Fixture f;auto policy=f.policy();
    const auto path=f.root+L"\\source:fault:$DATA";
    HANDLE native=CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);require(native!=INVALID_HANDLE_VALUE,"close-fault ADS fixture");
    const char byte='f';DWORD count=0;require(WriteFile(native,&byte,1,&count,nullptr)!=0&&count==1,"close-fault ADS bytes");CloseHandle(native);
    const auto snapshot=f.capture(policy);f.replay(snapshot);
    HANDLE witness=CreateFileW((f.root+L"\\target").c_str(),FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(witness!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(witness,FileIdInfo,&close_fault_target,sizeof(close_fault_target))!=0,
        "capture actual target file ID for close-only fault");CloseHandle(witness);
    close_fault_armed.store(true,std::memory_order_release);
    const auto result=f.target->finish_content_writes();
    require(close_fault_hits.load()==1&&!result.value()&&result.unavailable_detail()->error.code==ERROR_WRITE_FAULT&&
        result.unavailable_detail()->error.operation=="metadata_channels.finish_CloseHandle","ADS delayed close error hidden");
    const auto repeated=f.target->finish_content_writes();
    require(!repeated.value()&&repeated.unavailable_detail()->error==result.unavailable_detail()->error&&close_fault_hits.load()==1,
        "ADS close error retried/forgotten");
    require(!f.target->inspect_basic().value(),"ADS close failure left main writer live");
    std::cout<<"native consumed ADS close failure propagated and cached; all writers closed\n";
}
#endif
void windows_complete_coverage_tests() {
    Fixture f;auto policy=f.policy(RegularMetadataScope::CompleteMetadataV1);
    policy.ownership=MetadataOwnership::Original;policy.allow_privilege_metadata=true;
    HANDLE token=nullptr;
    require(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token)!=0,"open coverage test token");
    struct Privilege {HANDLE token;TOKEN_PRIVILEGES previous{};~Privilege(){AdjustTokenPrivileges(token,FALSE,&previous,0,nullptr,nullptr);CloseHandle(token);}} privilege{token};
    TOKEN_PRIVILEGES enable{};enable.PrivilegeCount=1;enable.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    require(LookupPrivilegeValueW(nullptr,L"SeSecurityPrivilege",&enable.Privileges[0].Luid)!=0,"lookup test-only SeSecurityPrivilege");
    DWORD previous_size=sizeof(privilege.previous);
    require(AdjustTokenPrivileges(token,FALSE,&enable,sizeof(privilege.previous),&privilege.previous,&previous_size)!=0,
        "adjust test-only security privilege");
    if(GetLastError()==ERROR_NOT_ALL_ASSIGNED) {
        require(capture_metadata_replay(*f.source,policy).state()==ObservationState::Denied,
            "missing source security privilege did not retain native Denied");
        require(!std::getenv("CK_METADATA_REPLAY_REQUIRE_NATIVE_SUCCESS"),"native Complete qualification needs actual security privilege");
        std::cout<<"Complete positive unavailable: actual source SACL access denied; ordinary metadata still tested\n";return;
    }
    PSECURITY_DESCRIPTOR descriptor=nullptr;ULONG descriptor_size=0;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(AU;SAFA;FW;;;WD)(ML;;NW;;;LW)",SDDL_REVISION_1,
        &descriptor,&descriptor_size)!=0,"construct audit and mandatory SACL");
    HANDLE native=CreateFileW((f.root+L"\\source").c_str(),ACCESS_SYSTEM_SECURITY|WRITE_OWNER,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(native!=INVALID_HANDLE_VALUE,"open native SACL writer");
    const BOOL installed=SetKernelObjectSecurity(native,SACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION,descriptor);
    const DWORD installed_error=GetLastError();CloseHandle(native);LocalFree(descriptor);
    if(!installed)std::cerr<<"SACL install error "<<installed_error<<'\n';
    require(installed!=0,"install real audit and mandatory SACL");
    f.add_attribute("COMPLETE_SECURITY_EA",{std::byte{'p'},std::byte{0},std::byte{'s'}});
    auto snapshot=f.capture(policy);
    require(snapshot.security_coverage&&snapshot.security_coverage->family()==MetadataSecurityCoverage::WindowsPersistentSecurityV1,
        "Complete lacked typed actual provider evidence");
    constexpr SECURITY_INFORMATION modern=OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|
        SACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION|ATTRIBUTE_SECURITY_INFORMATION|SCOPE_SECURITY_INFORMATION|
        PROCESS_TRUST_LABEL_SECURITY_INFORMATION|ACCESS_FILTER_SECURITY_INFORMATION;
    require(snapshot.security.size()==1&&snapshot.security.front().native_query_mask==modern,"Complete modern mask weakened");
    PACL captured_sacl=nullptr;BOOL captured_present=FALSE,captured_defaulted=FALSE;
    require(GetSecurityDescriptorSacl(snapshot.security.front().bytes.data(),&captured_present,&captured_sacl,&captured_defaulted)!=0&&
        captured_present&&captured_sacl,"actual Complete source SACL missing");
    bool actual_audit=false,actual_label=false;
    for(DWORD index=0;index<captured_sacl->AceCount;++index) {
        void* raw=nullptr;require(GetAce(captured_sacl,index,&raw)!=0,"read actual captured SACL ACE");
        actual_audit|=static_cast<const ACE_HEADER*>(raw)->AceType==SYSTEM_AUDIT_ACE_TYPE;
        actual_label|=static_cast<const ACE_HEADER*>(raw)->AceType==SYSTEM_MANDATORY_LABEL_ACE_TYPE;
    }
    require(actual_audit&&actual_label,"Complete fixture did not store real audit AND mandatory ACEs");
    // The proof keeps its query handle; a new target still must acquire actual
    // mutation rights before effects. Disabled privilege must remain Denied.
    TOKEN_PRIVILEGES disabled=enable;disabled.Privileges[0].Attributes=0;
    require(AdjustTokenPrivileges(token,FALSE,&disabled,0,nullptr,nullptr)!=0,"disable test security privilege");
    const auto denied_before=need(f.target->inspect_basic(),"Complete denied target before");
    const auto denied=apply_metadata_replay(*f.target,snapshot);
    require(denied.state()==ObservationState::Denied,"missing target SACL rights silently weakened");
    std::cout<<"Complete denied at "<<denied.unavailable_detail()->error.operation<<" code="<<denied.unavailable_detail()->error.code<<'\n';
    const auto denied_after=need(f.target->inspect_basic(),"Complete denied target after");
    std::cout<<"denied target changed before="<<denied_before.changed.value()->seconds()<<":"<<denied_before.changed.value()->nanoseconds()
        <<" after="<<denied_after.changed.value()->seconds()<<":"<<denied_after.changed.value()->nanoseconds()<<'\n';
    require(*denied_before.changed.value()==*denied_after.changed.value(),"Complete denial mutated target");
    require(AdjustTokenPrivileges(token,FALSE,&enable,0,nullptr,nullptr)!=0,"restore test security privilege");
    f.replay(snapshot);
    auto forged=snapshot;forged.security_coverage.reset();
    require(apply_metadata_replay(*f.target,forged).state()==ObservationState::Unsupported,"Complete missing proof accepted");
    class PretendProof final:public MetadataSecurityCoverageEvidence {
    public:MetadataSecurityCoverage family() const noexcept override{return MetadataSecurityCoverage::WindowsPersistentSecurityV1;}
        Observation<bool> recheck(const MetadataReplaySnapshot&)const override{return Observation<bool>::available(true);}
    };
    forged.security_coverage=std::make_shared<PretendProof>();
    require(apply_metadata_replay(*f.target,forged).state()==ObservationState::Unsupported,"caller-created coverage flag/proof accepted by native target");
    auto altered=snapshot;altered.security.front().bytes.back()^=std::byte{1};
    require(apply_metadata_replay(*f.target,altered).state()==ObservationState::Changed,"altered descriptor bypassed native proof binding");
    f.add_attribute("COMPLETE_SECURITY_EA",{std::byte{'x'}});
    require(snapshot.security_coverage->recheck(snapshot).state()==ObservationState::Changed,"held Complete EA mutation not detected");
    const auto target_before=need(f.target->inspect_basic(),"coverage target before stale proof");
    require(apply_metadata_replay(*f.target,snapshot).state()==ObservationState::Changed,"stale native Complete proof accepted");
    const auto target_after=need(f.target->inspect_basic(),"coverage target after stale proof");
    require(*target_before.changed.value()==*target_after.changed.value(),"stale coverage mutated target before refusal");
    auto caller=policy;caller.ownership=MetadataOwnership::CurrentCaller;
    f.replay(f.capture(caller));
    directory_metadata_tests(true);windows_ads_tests(true);windows_ads_proof_tests(true);
    std::cout<<"Complete actual modern SD + complete EA evidence and stale-proof refusal passed\n";
}
#endif
void directory_metadata_tests(bool complete) {
    Fixture f;auto policy=f.policy();
    if(complete){policy.scope=RegularMetadataScope::CompleteMetadataV1;policy.ownership=MetadataOwnership::Original;policy.allow_privilege_metadata=true;}
    auto source_cursor=f.directory->create_child_directory(name("dir-source"));need(source_cursor,"create directory source");
    auto target_cursor=f.directory->create_child_directory(name("dir-target"));need(target_cursor,"create directory target");
    // Different descendants must not impose regular-file logical-size equality.
    auto child=(*source_cursor.value())->create_child_file(name("nested"));need(child,"create directory descendant");
    success((*child.value())->finish_content_writes(),"finish directory descendant");
    auto source=HeldChild::observe_with_access(f.directory,name("dir-source"),EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity);
    auto target=HeldChild::observe_with_access(f.directory,name("dir-target"),EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity);
    need(source,"hold directory source");need(target,"hold directory target");
    auto source_writer=(*source.value())->open_directory_metadata_target(policy);need(source_writer,"source directory metadata writer");
#ifdef _WIN32
    const auto id=*NativeFeatureIdentifier::from_windows_ea("DIR_METADATA_EA");
    auto flags=Observation<std::uint32_t>::available(0);
#else
    const auto id=*NativeFeatureIdentifier::from_posix(
#ifdef __APPLE__
        "org.ckcore.directory-metadata"
#else
        "user.ckcore.directory-metadata"
#endif
    );Observation<std::uint32_t> flags;
#endif
    const auto before=need((*source_writer.value())->inspect_basic(),"directory source writer identity");
    success((*source_writer.value())->apply_replay_attribute({id,{std::byte{'d'},std::byte{0},std::byte{'r'}},before.identity,flags},policy),
        "set directory native attribute");
#ifndef _WIN32
    auto basic=before;basic.posix_permissions=Observation<std::uint32_t>::available(0750);
    success((*source_writer.value())->apply_replay_basic(basic,policy),"set directory mode and times");
#endif
#ifdef __linux__
    const unsigned char acl_bytes[]={2,0,0,0,1,0,7,0,255,255,255,255,2,0,4,0,210,4,0,0,
        4,0,5,0,255,255,255,255,16,0,5,0,255,255,255,255,32,0,0,0,255,255,255,255};
    const auto* acl_first=reinterpret_cast<const std::byte*>(acl_bytes);
    for(const auto part:{SecurityPart::LinuxAccessAcl,SecurityPart::LinuxDefaultAcl})
        success((*source_writer.value())->apply_replay_security({part,SecurityEncoding::LinuxPosixAclXattrV2,
            SecurityPresence::Present,NativeBytes(acl_first,acl_first+sizeof(acl_bytes)),before.identity,0},policy),
            "install directory access/default ACL");
#endif
#ifdef __APPLE__
    acl_t acl=acl_init(1);require(acl!=nullptr,"directory acl_init");acl_entry_t entry{};uuid_t uuid{};
    require(acl_create_entry(&acl,&entry)==0&&acl_set_tag_type(entry,ACL_EXTENDED_ALLOW)==0&&
        mbr_uid_to_uuid(geteuid(),uuid)==0&&acl_set_qualifier(entry,uuid)==0,"directory ACL identity");
    acl_permset_t permissions{};
    require(acl_get_permset(entry,&permissions)==0&&acl_add_perm(permissions,ACL_LIST_DIRECTORY)==0&&
        acl_set_permset(entry,permissions)==0,"directory ACL permission");
    const int acl_fd=open((f.root+"/dir-source").c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    require(acl_fd>=0&&acl_set_fd_np(acl_fd,acl,ACL_TYPE_EXTENDED)==0,"install actual directory ACL");close(acl_fd);acl_free(acl);
#endif
#ifdef _WIN32
    PSECURITY_DESCRIPTOR directory_acl=nullptr;ULONG directory_acl_size=0;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:PAI(A;OICI;FA;;;OW)(A;;FR;;;WD)",SDDL_REVISION_1,
        &directory_acl,&directory_acl_size)!=0,"construct directory inherited/protected ACL");
    HANDLE acl_native=CreateFileW((f.root+L"\\dir-source").c_str(),WRITE_DAC,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(acl_native!=INVALID_HANDLE_VALUE,"open actual directory DACL writer");
    const BOOL set_acl=SetKernelObjectSecurity(acl_native,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,directory_acl);
    CloseHandle(acl_native);LocalFree(directory_acl);require(set_acl!=0,"install actual directory DACL");
#endif
#ifdef _WIN32
    HANDLE directory_stream=CreateFileW((f.root+L"\\dir-source:directory-data:$DATA").c_str(),GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,CREATE_NEW,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(directory_stream!=INVALID_HANDLE_VALUE,"create native directory ADS");
    const char directory_bytes[]="directory-stream-data";DWORD directory_count=0;
    require(WriteFile(directory_stream,directory_bytes,sizeof(directory_bytes),&directory_count,nullptr)!=0&&
        directory_count==sizeof(directory_bytes)&&FlushFileBuffers(directory_stream)!=0,"write native directory ADS");
    require(CloseHandle(directory_stream)!=0,"close directory ADS fixture writer");
#endif
    success((*source_writer.value())->finish_content_writes(),"finish source directory metadata writer");
    require(!(*source_writer.value())->inspect_basic().value(),"finalized directory writer still inspectable");
    const auto snapshot=need((*source.value())->capture_metadata(policy),"capture directory metadata");
    require(snapshot.basic.kind.value()&&*snapshot.basic.kind.value()==ObjectKind::Directory,"directory snapshot kind lost");
#ifdef __linux__
    require(snapshot.security.size()==2&&snapshot.security[0].presence==SecurityPresence::Present&&
        snapshot.security[1].presence==SecurityPresence::Present,"directory access/default ACL fixture was not captured");
#endif
    auto writer=(*target.value())->open_directory_metadata_target(policy);need(writer,"target directory metadata writer");
    const std::byte data[]{std::byte{'x'}};
    require(!(*writer.value())->write_content(0,data).value(),"directory metadata writer authorized data writes");
    success(apply_metadata_replay(**writer.value(),snapshot),"replay directory ACL and native attributes");
    auto applied=need((*writer.value())->inspect_basic(),"directory applied identity");
    success(verify_metadata_replay(**writer.value(),snapshot,applied),"verify directory metadata");
    success((*writer.value())->finish_content_writes(),"finish directory metadata writer");
    success((*writer.value())->finish_content_writes(),"finish directory writer cached result");
    const auto held=need((*target.value())->inspect_basic(),"original held directory survived writer finalization");
    require(held.identity.value()&&compare_identity(*held.identity.value(),*applied.identity.value())==IdentityComparison::Same,
        "directory writer changed held identity");
    // Query through a separate held view after native writer close.
    const auto final_snapshot=need((*target.value())->capture_metadata(policy),"capture finalized directory metadata");
    require(final_snapshot.attributes.size()==snapshot.attributes.size(),"directory final attribute set differs");
    require(final_snapshot.channels.size()==snapshot.channels.size(),"directory close lost named data stream");
    for(const auto& channel:snapshot.channels) {
        const auto actual=std::find_if(final_snapshot.channels.begin(),final_snapshot.channels.end(),[&](const auto& item){return item.identifier==channel.identifier;});
        require(actual!=final_snapshot.channels.end()&&actual->logical_size==channel.logical_size&&actual->digest==channel.digest,
            "directory ADS post-close manifest/hash changed");
    }
    for(const auto& attribute:snapshot.attributes) {
        const auto actual=std::find_if(final_snapshot.attributes.begin(),final_snapshot.attributes.end(),
            [&](const auto& item){return item.identifier==attribute.identifier;});
        require(actual!=final_snapshot.attributes.end()&&actual->bytes==attribute.bytes,"directory final attribute bytes differ");
    }
    const auto same=[](const auto& a,const auto& b){return a.value()&&b.value()?*a.value()==*b.value():!a.value()&&!b.value()&&a.state()==b.state();};
    const auto& final_basic=final_snapshot.basic;const auto& initial=snapshot.basic;
    const auto& expected_owner=policy.ownership==MetadataOwnership::Original?initial:applied;
    if(!(same(initial.accessed,final_basic.accessed)&&same(initial.modified,final_basic.modified)&&
        same(initial.posix_permissions,final_basic.posix_permissions)&&same(expected_owner.posix_uid,final_basic.posix_uid)&&
        same(expected_owner.posix_gid,final_basic.posix_gid)&&same(initial.windows_attributes,final_basic.windows_attributes)))
        std::cerr<<"post-close basic matches: atime="<<same(initial.accessed,final_basic.accessed)<<" mtime="<<same(initial.modified,final_basic.modified)
            <<" mode="<<same(initial.posix_permissions,final_basic.posix_permissions)<<" uid="<<same(expected_owner.posix_uid,final_basic.posix_uid)
            <<" gid="<<same(expected_owner.posix_gid,final_basic.posix_gid)<<" winattrs="<<same(initial.windows_attributes,final_basic.windows_attributes)<<'\n';
    require(same(initial.accessed,final_basic.accessed)&&same(initial.modified,final_basic.modified)&&
        same(initial.posix_permissions,final_basic.posix_permissions)&&same(expected_owner.posix_uid,final_basic.posix_uid)&&
        same(expected_owner.posix_gid,final_basic.posix_gid)&&same(initial.windows_attributes,final_basic.windows_attributes),
        "directory writer close changed preserved basic metadata");
    if(complete)require(same(initial.created,final_basic.created),"directory writer close changed preserved birth time");
    auto observer=f.directory->open_child(name("dir-target"),EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity);
    need(observer,"independent post-close directory observer");
    auto view=(*observer.value())->open_metadata_replay_view(policy);need(view,"post-close directory policy query rights");
    const auto& query=*view.value()?**view.value():**observer.value();
    auto expected=policy;expected.ownership=MetadataOwnership::Original; // fixture source and caller own the same SIDs/UIDs
    for(const auto& security:snapshot.security)success(query.verify_replay_security(security,expected),"independent post-close directory ACL verification");
    std::move(view).take_value().reset();std::move(observer).take_value().reset();
    std::cout<<"native directory metadata independent writer replay/verify/finalization passed\n";
#ifdef _WIN32
    std::move(child).take_value().reset();std::move(source_writer).take_value().reset();std::move(writer).take_value().reset();std::move(source).take_value().reset();std::move(target).take_value().reset();
    std::move(source_cursor).take_value().reset();std::move(target_cursor).take_value().reset();
    DeleteFileW((f.root+L"\\dir-source\\nested").c_str());
    require(RemoveDirectoryW((f.root+L"\\dir-source").c_str())!=0,"remove directory source fixture");
    require(RemoveDirectoryW((f.root+L"\\dir-target").c_str())!=0,"remove directory target fixture");
#else
    std::move(child).take_value().reset();std::move(source_writer).take_value().reset();std::move(writer).take_value().reset();std::move(source).take_value().reset();std::move(target).take_value().reset();
    std::move(source_cursor).take_value().reset();std::move(target_cursor).take_value().reset();
    unlink((f.root+"/dir-source/nested").c_str());
    require(rmdir((f.root+"/dir-source").c_str())==0,"remove directory source fixture");
    require(rmdir((f.root+"/dir-target").c_str())==0,"remove directory target fixture");
#endif
}
void policy_tests() {
    MetadataReplayPolicy p;require(p.valid(),"default policy invalid");p.version=2;require(!p.valid(),"unknown version accepted");
    UnsupportedEntry unsupported;
    require(unsupported.qualify_stable_content().state()==ObservationState::Unsupported,"unqualified content freeze accepted");
    require(capture_metadata_replay(unsupported,p).state()==ObservationState::Failed,"invalid policy not typed Failed");
    require(!valid_entry_access(EntryAccess::RenameSource|EntryAccess::MoveSource),"contradictory guards accepted");
    require(valid_entry_access(EntryAccess::RenameSource|EntryAccess::ContentRead),"rename read guard rejected");
}
void writer_finalization_tests() {
    Fixture f;
    // Capture live qualified evidence before fully closing the writer. The
    // receipt can retain this value, never a post-close reinspection claim.
    const auto before=need(f.target->inspect_basic(),"writer identity before finish");
    success(f.target->finish_content_writes(),"native writer finish");
    success(f.target->finish_content_writes(),"native writer finish idempotent");
    require(!f.target->inspect_basic().value(),"closed writer remained inspectable");
    require(!f.target->read_content().value(),"closed writer remained readable");
    const std::byte bytes[]{std::byte{'x'}};
    require(!f.target->write_content(0,bytes).value(),"closed writer remained writable");
    require(!f.target->flush_content().value(),"closed writer flush accepted");
    auto opened=f.directory->open_child(name("target"),EntryAccess::ContentRead);
    need(opened,"independent final destination read");
    const auto after=need((*opened.value())->inspect_basic(),"independent final identity");
    require(before.identity.value()&&after.identity.value()&&
        compare_identity(*before.identity.value(),*after.identity.value())==IdentityComparison::Same,
        "finalized writer identity changed");
    const auto data=need((*opened.value())->read_content(),"finalized data");
    require(data.bytes==std::vector<std::byte>{std::byte{'t'},std::byte{'e'},std::byte{'s'},std::byte{'t'}},
        "finalized bytes changed");
#ifdef _WIN32
    HANDLE writer=CreateFileW((f.root+L"\\target").c_str(),GENERIC_WRITE|DELETE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(writer!=INVALID_HANDLE_VALUE,"finalization retained WRITE/DELETE share exclusion");
    require(CloseHandle(writer)!=0,"independent writer close");
#endif
    std::cout<<"native writer finalization closes handle, disables live access and caches success\n";
}
#ifdef _WIN32
struct RhTestHandle {
    HANDLE value=INVALID_HANDLE_VALUE;
    explicit RhTestHandle(HANDLE raw=INVALID_HANDLE_VALUE):value(raw){}
    RhTestHandle(const RhTestHandle&)=delete;
    ~RhTestHandle(){close();}
    void close(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);value=INVALID_HANDLE_VALUE;}
};
void windows_acl_control_tests() {
    for(const bool protected_acl:{false,true}) {
        Fixture f;auto policy=f.policy();
        auto original=need(f.source->read_security(SecurityPart::WindowsAccess),"source control fixture descriptor");
        SECURITY_DESCRIPTOR_CONTROL mask=SE_DACL_AUTO_INHERIT_REQ|SE_DACL_AUTO_INHERITED|SE_DACL_PROTECTED;
        const SECURITY_DESCRIPTOR_CONTROL wanted=SE_DACL_AUTO_INHERIT_REQ|SE_DACL_AUTO_INHERITED|
            (protected_acl?SE_DACL_PROTECTED:0);
        require(SetSecurityDescriptorControl(original.bytes.data(),mask,wanted)!=0,"configure source auto-inheritance request");
        // Establish a real stored AI descriptor independently of the replay
        // implementation, then query it again before taking the snapshot.
        RhTestHandle source(CreateFileW((f.root+L"\\source").c_str(),READ_CONTROL|WRITE_DAC,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        require(source.value!=INVALID_HANDLE_VALUE,"source ACL setup handle");
        require(SetKernelObjectSecurity(source.value,DACL_SECURITY_INFORMATION|
            (protected_acl?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION),original.bytes.data())!=0,
            "persist source auto-inherited descriptor");source.close();
        auto seed=need(f.target->read_security(SecurityPart::WindowsAccess),"target control fixture descriptor");
        PACL acl=nullptr;BOOL present=FALSE,defaulted=FALSE;
        require(GetSecurityDescriptorDacl(seed.bytes.data(),&present,&acl,&defaulted)&&present&&acl&&acl->AceCount,
            "target fixture ACL");
        void* first=nullptr;require(GetAce(acl,0,&first)!=0,"target seed ACE");
        static_cast<ACE_HEADER*>(first)->AceFlags|=INHERITED_ACE;
        RhTestHandle target(CreateFileW((f.root+L"\\target").c_str(),READ_CONTROL|WRITE_DAC,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        require(target.value!=INVALID_HANDLE_VALUE&&SetKernelObjectSecurity(target.value,DACL_SECURITY_INFORMATION,seed.bytes.data())!=0,
            "seed different target inherited ACE");target.close();
        const auto snapshot=f.capture(policy);
        SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;
        require(GetSecurityDescriptorControl(const_cast<std::byte*>(snapshot.security.front().bytes.data()),&control,&revision)!=0&&
            (control&SE_DACL_AUTO_INHERITED)&&!(control&SE_DACL_AUTO_INHERIT_REQ)&&
            bool(control&SE_DACL_PROTECTED)==protected_acl,"source AI fixture not actually stored");
        f.replay(snapshot);
        const auto copied=need(f.target->read_security(SecurityPart::WindowsAccess),"target stored control descriptor");
        require(GetSecurityDescriptorControl(const_cast<std::byte*>(copied.bytes.data()),&control,&revision)!=0&&
            (control&SE_DACL_AUTO_INHERITED)&&!(control&SE_DACL_AUTO_INHERIT_REQ)&&
            bool(control&SE_DACL_PROTECTED)==protected_acl,"persisted AI/protection control bits lost");
    }
    std::cout<<"protected/unprotected auto-inherited DACL control and exact ACL replay passed\n";
}
void rh_content_guard_tests() {
    // Include never-mapped and previously-unmapped sections. A section handle
    // alone permits a later writable view without another user file open.
    for (int scenario=0;scenario<4;++scenario) {
        Fixture f;success(f.source->finish_content_writes(),"section source writer finish");f.source.reset();
        RhTestHandle writer(CreateFileW((f.root+L"\\source").c_str(),GENERIC_READ|GENERIC_WRITE,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        require(writer.value!=INVALID_HANDLE_VALUE,"section source open");
        RhTestHandle section(CreateFileMappingW(writer.value,nullptr,PAGE_READWRITE,0,0,nullptr));
        require(section.value!=nullptr,"writable section admission fixture");
        struct View {void* value=nullptr;~View(){if(value)UnmapViewOfFile(value);}} view;
        if(scenario){view.value=MapViewOfFile(section.value,FILE_MAP_WRITE,0,0,0);require(view.value,"initial mapped view");}
        if(scenario==1){require(UnmapViewOfFile(view.value)!=0,"unmap before admission");view.value=nullptr;}
        writer.close();if(scenario==3)section.close();
        auto guard=HeldChild::observe_with_access(f.directory,name("source"),EntryAccess::RenameSource|EntryAccess::ContentRead);
        if(guard.value()) {
            const auto proof=(*guard.value())->qualify_stable_content();
            require(!proof.value()&&(proof.state()==ObservationState::Unsupported||proof.state()==ObservationState::Denied||proof.state()==ObservationState::Changed),
                "live writable section admitted as immutable content");
        } else require(guard.state()==ObservationState::Denied||guard.state()==ObservationState::Changed,
            "writable-section guard open failed unexpectedly");
        guard={};
        if(!view.value){view.value=MapViewOfFile(section.value,FILE_MAP_WRITE,0,0,0);require(view.value,"later map without file reopen");}
        static_cast<volatile char*>(view.value)[0]='M';require(FlushViewOfFile(view.value,1)!=0,"mapped section write proof");
        require(UnmapViewOfFile(view.value)!=0,"unmap section proof");view.value=nullptr;section.close();
        auto after=HeldChild::observe_with_access(f.directory,name("source"),EntryAccess::RenameSource|EntryAccess::ContentRead);
        need(after,"guard after section close");success((*after.value())->qualify_stable_content(),"RH admitted after last section reference closed");
        require(need((*after.value())->read_content(),"guarded explicit-offset read").bytes.front()==std::byte{'M'},"guarded read lost mapped fixture change");
    }
    {
        Fixture f;success(f.source->finish_content_writes(),"break source finish");f.source.reset();
        auto held=HeldChild::observe_with_access(f.directory,name("source"),EntryAccess::RenameSource|EntryAccess::ContentRead);need(held,"break guard");
        auto guard=*held.value();success(guard->qualify_stable_content(),"break lease admission");
        RhTestHandle done(CreateEventW(nullptr,TRUE,FALSE,nullptr));require(done.value!=nullptr,"break actor event");
        std::atomic<DWORD> result=ERROR_IO_PENDING;
        std::thread actor([&]{
            RhTestHandle writer(CreateFileW((f.root+L"\\source").c_str(),GENERIC_WRITE,
                FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
            DWORD code=writer.value==INVALID_HANDLE_VALUE?GetLastError():ERROR_SUCCESS;
            if(!code){DWORD count=0;if(!WriteFile(writer.value,"x",1,&count,nullptr)||count!=1)code=GetLastError();}
            result=code;SetEvent(done.value);
        });
        bool broken=false;
        for(unsigned n=0;n<200;++n){if(guard->qualify_stable_content().state()==ObservationState::Changed){broken=true;break;}Sleep(10);}
        guard.reset();held={};
        if(WaitForSingleObject(done.value,5000)!=WAIT_OBJECT_0)CancelSynchronousIo(static_cast<HANDLE>(actor.native_handle()));
        actor.join();require(broken&&result==ERROR_SUCCESS,"RH break detection or pending-I/O teardown failed");
    }
    std::cout<<"RH section-only, unmapped/remapped and live-view admission, guarded reads and break teardown passed\n";
}
void rh_native_retention_test() {
    Fixture f;success(f.source->finish_content_writes(),"retention source writer finish");f.source.reset();
    const auto journal_path=f.root+L"\\rh-journal";
    require(CreateDirectoryW(journal_path.c_str(),nullptr)!=0,"native retention journal fixture directory");
    struct Cleanup {
        std::wstring root;
        ~Cleanup(){
            WIN32_FIND_DATAW data{};HANDLE found=FindFirstFileW((root+L"\\*").c_str(),&data);
            if(found!=INVALID_HANDLE_VALUE){do{if(!(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))DeleteFileW((root+L"\\"+data.cFileName).c_str());}while(FindNextFileW(found,&data));FindClose(found);}
            RemoveDirectoryW(root.c_str());
        }
    } cleanup{journal_path};
    const auto parent=NativeAbsolutePath::from_windows(std::u16string(f.root.begin(),f.root.end()));need(parent,"retention parent address");
    const auto root=NativeAbsolutePath::from_windows(std::u16string(journal_path.begin(),journal_path.end()));need(root,"retention journal address");
    auto old=HeldChild::observe(f.directory,name("source"));need(old,"reviewed native old target");
    const std::byte bytes[]{std::byte{'t'},std::byte{'e'},std::byte{'s'},std::byte{'t'}};
    Sha256 hash;hash.update(bytes);OperationJournalId id{};id.bytes[0]=std::byte{0x52};
    // This fixed task-owned fixture supplies an explicit ancestor decision;
    // all guard admission, hashing, rename and journal operations are native.
    RetainedTargetRequest request{*old.value(),name("retained"),hash.digest(),*root.value(),id,*parent.value(),
        []{return Observation<bool>::available(true);}};
    request.chunk_bytes=1;
    auto created=RetainedTarget::create(std::move(request));need(created,"native RH retention create");
    auto retained=*created.value();
    for(unsigned n=0;n<32&&retained->state()==RetainedTargetState::Verifying;++n)retained->advance();
    if(retained->state()!=RetainedTargetState::Ready&&retained->failure())
        std::cerr<<"native retention: "<<retained->failure()->error.operation<<'\n';
    require(retained->state()==RetainedTargetState::Ready,"native retained digest not ready");
    success(retained->retain(),"native retained old-target publication");
    require(retained->state()==RetainedTargetState::Retained,"native retained journal finalization failed");
    retained.reset();created={};old={};
    const auto former=f.directory->lookup_child(name("source"),ChildLookupMode::NativeDefault);need(former,"retired old name lookup");
    require(former.value()->state()==ChildLookupState::Missing,"retention left old namespace binding");
    auto published=f.directory->open_child(name("retained"),EntryAccess::ContentRead);need(published,"retained native observer");
    require(need((*published.value())->read_content(),"retained native bytes").bytes==std::vector<std::byte>(std::begin(bytes),std::end(bytes)),
        "native retained bytes changed");
    std::cout<<"native RH RetainedTarget digest, same-object rename and journal finalization passed\n";
}
void rh_retention_review_break_test() {
    Fixture f;success(f.source->finish_content_writes(),"review-break source writer finish");f.source.reset();
    const auto journal_path=f.root+L"\\rh-break-journal";
    require(CreateDirectoryW(journal_path.c_str(),nullptr)!=0,"review-break journal fixture directory");
    struct Cleanup {std::wstring root;~Cleanup(){WIN32_FIND_DATAW data{};HANDLE h=FindFirstFileW((root+L"\\*").c_str(),&data);if(h!=INVALID_HANDLE_VALUE){do{if(!(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))DeleteFileW((root+L"\\"+data.cFileName).c_str());}while(FindNextFileW(h,&data));FindClose(h);}RemoveDirectoryW(root.c_str());}} cleanup{journal_path};
    const auto root=NativeAbsolutePath::from_windows(std::u16string(journal_path.begin(),journal_path.end()));need(root,"review-break journal address");
    auto old=HeldChild::observe(f.directory,name("source"));need(old,"reviewed break target");
    const std::byte bytes[]{std::byte{'t'},std::byte{'e'},std::byte{'s'},std::byte{'t'}};Sha256 hash;hash.update(bytes);
    RhTestHandle started(CreateEventW(nullptr,TRUE,FALSE,nullptr)),done(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    require(started.value&&done.value,"review-break events");std::atomic<DWORD> outcome=ERROR_IO_PENDING;std::thread actor;
    struct Join {std::thread& actor;~Join(){if(actor.joinable()){CancelSynchronousIo(static_cast<HANDLE>(actor.native_handle()));actor.join();}}} join{actor};
    OperationJournalId id{};id.bytes[0]=std::byte{0x53};
    RetainedTargetRequest request{*old.value(),name("retained"),hash.digest(),*root.value(),id,{},[&]{
        actor=std::thread([&]{SetEvent(started.value);RhTestHandle writer(CreateFileW((f.root+L"\\source").c_str(),GENERIC_WRITE,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
            DWORD code=writer.value==INVALID_HANDLE_VALUE?GetLastError():ERROR_SUCCESS;
            if(!code){DWORD n=0;if(!WriteFile(writer.value,"B",1,&n,nullptr)||n!=1)code=GetLastError();}outcome=code;SetEvent(done.value);
        });
        if(WaitForSingleObject(started.value,2000)!=WAIT_OBJECT_0)return Observation<bool>::available(false);
        // Yield to the competing open. A pass additionally requires the native
        // break error and a durable prefix without any commit intent below.
        Sleep(100);return Observation<bool>::available(true);
    }};
    auto created=RetainedTarget::create(std::move(request));need(created,"review-break native retention create");auto retained=*created.value();
    for(unsigned n=0;n<32&&retained->state()==RetainedTargetState::Verifying;++n)retained->advance();
    require(retained->state()==RetainedTargetState::Ready,"review-break digest not ready");
    const auto result=retained->retain();
    require(result.state()==ObservationState::Changed&&result.unavailable_detail()->error.operation=="stable_content.windows_rh_broken",
        "post-review oplock break did not refuse retention");
    require(retained->state()==RetainedTargetState::Failed,"post-review failure state");
    retained.reset();created={};old={};
    if(WaitForSingleObject(done.value,5000)!=WAIT_OBJECT_0)CancelSynchronousIo(static_cast<HANDLE>(actor.native_handle()));
    actor.join();require(outcome==ERROR_SUCCESS,"post-review writer not released after guard disposal");
    const auto destination=f.directory->lookup_child(name("retained"),ChildLookupMode::NativeDefault);need(destination,"post-review retained-name lookup");
    require(destination.value()->state()==ChildLookupState::Missing,"post-review break renamed old target");
    const std::string journal=".ck-retention-53"+std::string(30,'0')+".journal";
    auto file=open_native_operation_journal_file(*root.value(),name(journal.c_str()),false);need(file,"post-review native journal observer");
    const auto decoded=load_operation_journal(**file.value());need(decoded,"post-review durable journal prefix");
    require(!decoded.value()->tail&&decoded.value()->journal,"post-review journal prefix invalid");
    for(const auto& record:decoded.value()->journal->records())require(record.state!=OperationJournalState::CommitIntended&&
        record.state!=OperationJournalState::DestinationCommitted,"post-review break crossed durable rename intent");
    success((*file.value())->finish_io(),"post-review journal observer finish");
    std::cout<<"post-review RH break refused retention before intent/rename and released competing writer\n";
}
void strong_staging_tests() {
    Fixture f;
    auto created=f.directory->create_staging_file(name("staging"));need(created,"strong Windows staging");
    require(created.value()->staging_namespace==StagingNamespace::Named&&created.value()->name&&
        *created.value()->name==name("staging"),"Windows staging namespace evidence");
    auto staging=std::move(created).take_value().entry;
    const auto before=need(staging->inspect_basic(),"staging held identity");
    const std::byte bytes[]{std::byte{'x'}};
    require(need(staging->write_content(0,bytes),"staging content")==1,"staging write length");
    const auto excluded=[&](const wchar_t* leaf) {
        for(const DWORD rights:{DWORD(GENERIC_WRITE),DWORD(DELETE)}) {
            HANDLE outsider=CreateFileW((f.root+L"\\"+leaf).c_str(),rights,
                FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
            const DWORD code=GetLastError();if(outsider!=INVALID_HANDLE_VALUE) CloseHandle(outsider);
            require(outsider==INVALID_HANDLE_VALUE&&code==ERROR_SHARING_VIOLATION,"strong staging lost WRITE/DELETE exclusion");
        }
    };
    excluded(L"staging");
    success(staging->publish_noreplace(*f.directory,name("published")),"same held staging publication");
    excluded(L"published");
    const auto published=need(staging->inspect_basic(),"published held identity");
    require(before.identity.value()&&published.identity.value()&&
        compare_identity(*before.identity.value(),*published.identity.value())==IdentityComparison::Same,
        "publication changed held staging identity");
    success(staging->finish_content_writes(),"published writer finish");
    success(staging->finish_content_writes(),"published writer cached finish");
    auto reopened=f.directory->open_child(name("published"),EntryAccess::ContentRead);need(reopened,"published independent reader");
    const auto observed=need((*reopened.value())->inspect_basic(),"published independent identity");
    require(observed.identity.value()&&compare_identity(*published.identity.value(),*observed.identity.value())==IdentityComparison::Same,
        "finalized published identity mismatch");
    require(need((*reopened.value())->read_content(),"published bytes").bytes==std::vector<std::byte>{std::byte{'x'}},
        "published content mismatch");
    std::cout<<"strong Windows staging retains WRITE/DELETE exclusion through held-object publication, then finalizes\n";
}
#endif
#ifdef __APPLE__
void noowners_tests() {
    const auto* negative_root=std::getenv("CK_FS_NOOWNERS_TEST_ROOT");
    if (!negative_root) negative_root="/Volumes/S8T/tmp/";
    struct statfs filesystem{};
    if (statfs(negative_root,&filesystem)!=0 || !(filesystem.f_flags&MNT_IGNORE_OWNERSHIP)) {
        require(!std::getenv("CK_METADATA_REPLAY_REQUIRE_NOOWNERS"),"mandatory noowners fixture mount unavailable");
        std::cout<<"noowners negative mount unavailable\n";return;
    }
    Fixture ignored(negative_root),enforced;
    struct statfs positive{};
    require(statfs(enforced.root.c_str(),&positive)==0 && !(positive.f_flags&MNT_IGNORE_OWNERSHIP),
        "positive metadata fixtures require ownership enforcement");
    const auto refused=[](const auto& observed) {
        require(observed.state()==ObservationState::Unsupported,"noowners metadata was qualified");
        require(observed.unavailable_detail()->error.domain==ErrorDomain::Adapter &&
            observed.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::ProviderReviewRequired) &&
            observed.unavailable_detail()->error.operation=="metadata_replay.ignored_ownership_mount",
            "noowners refusal lost its mount-specific evidence");
    };
    refused(ignored.source->qualify_ordinary_regular_metadata());
    const auto ignored_directory=ignored.root+"/ignored-directory";
    require(mkdir(ignored_directory.c_str(),0700)==0,"create actual noowners directory fixture");
    auto directory=ignored.directory->open_child(name("ignored-directory"));need(directory,"hold noowners directory");
    refused((*directory.value())->open_directory_metadata_target(ignored.policy()));
    refused(capture_metadata_replay(**directory.value(),ignored.policy()));
    std::move(directory).take_value().reset();
    require(rmdir(ignored_directory.c_str())==0,"remove noowners directory fixture");
    for (const auto scope:{RegularMetadataScope::OrdinaryCallerVisibleV1,RegularMetadataScope::CompleteMetadataV1})
        for (const auto owner:{MetadataOwnership::CurrentCaller,MetadataOwnership::Original}) {
            auto policy=ignored.policy(scope);policy.ownership=owner;
            refused(ignored.source->qualify_metadata_replay(policy));
            refused(capture_metadata_replay(*ignored.source,policy));
        }
    const auto policy=enforced.policy();
    const auto snapshot=enforced.capture(policy);
    const auto before=need(ignored.target->inspect_basic(),"noowners target before");
    refused(apply_metadata_replay(*ignored.target,snapshot));
    const auto after=need(ignored.target->inspect_basic(),"noowners target after");
    require(before.changed.value() && after.changed.value() && *before.changed.value()==*after.changed.value(),
        "noowners target mutated before refusal");
    refused(ignored.target->apply_current_caller_ownership());
    refused(ignored.target->apply_replay_ownership(snapshot.basic,policy));
    refused(ignored.target->apply_replay_security(snapshot.security.front(),policy));
    refused(ignored.target->verify_replay_security(snapshot.security.front(),policy));
    auto held=HeldChild::observe(ignored.directory,name("source"));need(held,"held noowners source");
    refused(RegularMetadataPreservation::create_with_policy(*held.value(),false,policy));
    std::cout<<"mounted noowners source/target capture, ownership, ACL apply/verify refusal passed\n";
}
#endif
void native_tests() {
    Fixture f;
    auto p=f.policy();
    const auto qualified=f.source->qualify_metadata_replay(p);
    if(!qualified.value()) {
        std::cout<<"native provider unsupported: "<<qualified.unavailable_detail()->error.operation<<'\n';
        require(!std::getenv("CK_METADATA_REPLAY_REQUIRE_NATIVE_SUCCESS"),"mandatory native replay unavailable");return;
    }
#ifdef _WIN32
    const char* key="CK.REPLAY";
#else
    const char* key="user.ck_replay";
#endif
    f.add_attribute(key,{std::byte{0},std::byte{0xff},std::byte{7}});
#ifndef _WIN32
    f.add_attribute("user.ck_empty",{});
#endif
#ifdef _WIN32
    // Opting into label replay must not materialize a present null SACL for
    // an already-exact implicit label. This is the C v2 Original-owner path.
    {
        Fixture original;
        auto explicit_policy=original.policy();explicit_policy.ownership=MetadataOwnership::Original;
        explicit_policy.allow_privilege_metadata=true;
        const auto captured=original.capture(explicit_policy);
        original.replay(captured);
        success(original.target->finish_content_writes(),"security-bearing writer finish");
        require(!original.target->inspect_basic().value(),"security-bearing writer still live");
    }
    {
        Fixture labelled;
        auto explicit_policy=labelled.policy();explicit_policy.ownership=MetadataOwnership::Original;
        explicit_policy.allow_privilege_metadata=true;
        PSECURITY_DESCRIPTOR descriptor=nullptr;ULONG size=0;
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;LW)",SDDL_REVISION_1,&descriptor,&size)!=0,
            "construct explicit low integrity label");
        const auto* first=static_cast<const std::byte*>(descriptor);
        NativeSecurityValue label{SecurityPart::WindowsIntegrity,SecurityEncoding::WindowsRelativeDescriptor,
            SecurityPresence::Present,NativeBytes(first,first+size),
            need(labelled.source->inspect_basic(),"label source identity").identity,LABEL_SECURITY_INFORMATION};
        LocalFree(descriptor);
        success(labelled.source->apply_replay_security(label,explicit_policy),"install actual mandatory integrity label");
        const auto captured=labelled.capture(explicit_policy);
        auto no_optin=explicit_policy;no_optin.allow_privilege_metadata=false;
        const auto refused=labelled.target->apply_replay_security(captured.security.back(),no_optin);
        require(refused.state()==ObservationState::Changed,"different integrity label silently accepted without optin");
        labelled.replay(captured);
        std::cout<<"explicit mandatory integrity ACE replayed and exactly verified with optin\n";
    }
    // Match the C API/tree leaf access: data read without EA/READ_CONTROL.
    auto minimal=HeldChild::observe_with_access(f.directory,name("source"),EntryAccess::ContentRead);
    need(minimal,"minimal source handle");
    const auto through_identity=(*minimal.value())->capture_metadata(p);
    need(through_identity,"policy-specific held identity query rights");
    require(!through_identity.value()->attributes.empty(),"identity query lost source EAs");
    auto full_policy=p;full_policy.scope=RegularMetadataScope::CompleteMetadataV1;full_policy.allow_privilege_metadata=true;
    auto full=(*minimal.value())->capture_metadata(full_policy);
    if (full.value()) require(full.value()->security.size()==1&&full.value()->security.front().part==SecurityPart::WindowsFullDescriptor,
        "full security query silently weakened");
    else require(full.state()==ObservationState::Denied||full.state()==ObservationState::Unsupported,"full security denial not retained");
    for (const DWORD rights:{DWORD(GENERIC_WRITE),DWORD(DELETE)}) {
        HANDLE outsider=CreateFileW((f.root+L"\\source").c_str(),rights,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        const DWORD code=GetLastError();
        if (outsider!=INVALID_HANDLE_VALUE) CloseHandle(outsider);
        require(outsider==INVALID_HANDLE_VALUE&&code==ERROR_SHARING_VIOLATION,"staging permits external WRITE/DELETE handle");
    }
    require(!MoveFileExW((f.root+L"\\source").c_str(),(f.root+L"\\moved").c_str(),0)&&
        GetLastError()==ERROR_SHARING_VIOLATION,"staging basename can be renamed externally");
#endif
    auto snapshot=f.capture(p);
    require(!snapshot.attributes.empty(),"missing attribute inventory");
#ifdef __APPLE__
    const auto provenance=std::find_if(snapshot.attributes.begin(),snapshot.attributes.end(),[](const auto& a){return a.identifier.posix_bytes()&&*a.identifier.posix_bytes()=="com.apple.provenance";});
    require(provenance!=snapshot.attributes.end(),"provenance regression fixture unavailable");
#endif
    DeniedInventory denied_attributes(*f.source,true),denied_security(*f.source,false);
    require(capture_metadata_replay(denied_attributes,p).state()==ObservationState::Denied,"attribute denial weakened");
    require(capture_metadata_replay(denied_security,p).state()==ObservationState::Denied,"security denial weakened");
    DeniedOwnership denied_owner(*f.target);
    require(apply_metadata_replay(denied_owner,snapshot).state()==ObservationState::Denied,"ownership denial weakened");
    const auto applied=f.replay(snapshot);
    auto mutation=f.attribute(key,{std::byte{8}});mutation.owner=applied.identity;
    success(f.target->apply_nonsecurity_attribute(mutation),"tamper target attribute");
    require(verify_metadata_replay(*f.target,snapshot,applied).state()==ObservationState::Changed,"target tampering accepted");
    f.add_attribute(key,{std::byte{9}});
    require(verify_metadata_replay_source(*f.source,snapshot).state()==ObservationState::Changed,"source tampering accepted");
    std::stop_source cancelled;cancelled.request_stop();
    require(!capture_metadata_replay(*f.source,p,cancelled.get_token()).value(),"cancelled capture accepted");
    auto bounded=p;bounded.limits.max_native_bytes=1;
    require(!capture_metadata_replay(*f.source,bounded).value(),"inventory byte bound ignored");

    Fixture inherited;
    auto extra=inherited.attribute("user.ck_inherited",{std::byte{6}});
#ifdef _WIN32
    extra.identifier=*NativeFeatureIdentifier::from_windows_ea("CK.INHERITED");
    extra.native_flags=Observation<std::uint32_t>::available(0);
#endif
    extra.owner=need(inherited.target->inspect_basic(),"target owner").identity;
    success(inherited.target->apply_nonsecurity_attribute(extra),"install inherited attribute");
    auto clean=inherited.capture(p);inherited.replay(clean);
    require(!inherited.target->read_attribute(extra.identifier).value(),"inherited extra attribute retained");

    Fixture held;
    const auto access=EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity;
    auto source=HeldChild::observe_with_access(held.directory,name("source"),access);need(source,"held source");
    auto preserving=RegularMetadataPreservation::create_with_policy(*source.value(),false,p);need(preserving,"regular preserving capture");
    auto prepared=(*preserving.value())->prepare(*held.target);need(prepared,"regular metadata job");
    auto& job=**prepared.value();
    for(int i=0;i<12&&job.state()!=OperationMetadataState::Complete&&job.state()!=OperationMetadataState::Failed;++i)job.advance();
    if(job.failure())std::cerr<<"job failure: "<<job.failure()->error.operation<<'\n';
    require(job.state()==OperationMetadataState::Complete,"regular metadata job failed");
    success((*preserving.value())->verify(*held.target),"regular final verification");
    auto smaller=held.attribute(key,{std::byte{3}});success(held.source->apply_nonsecurity_attribute(smaller),"held mutate source");
    require(!(*preserving.value())->verify(*held.target).value(),"regular prepublish source mutation accepted");

#ifndef _WIN32
    Fixture mode;
    // Darwin can clear setgid when an inherited directory group is not one
    // of the caller's groups. Establish the fixture's intended group first.
    success(mode.source->apply_current_caller_ownership(),"special-bit source ownership");
    require(chmod((mode.root+"/source").c_str(),06754)==0,"install special bits");
    require(*need(mode.source->inspect_basic(),"special source mode").posix_permissions.value()==06754,"fixture special bits not installed");
    require(!capture_metadata_replay(*mode.source,p).value(),"special bits silently accepted");
    auto opted=p;opted.allow_privilege_metadata=true;
    auto special=mode.capture(opted);mode.replay(special);
    require(*need(mode.target->inspect_basic(),"special mode").posix_permissions.value()==06754,"explicit special bits not preserved");
    // Captured metadata belongs to the retained inode after a name replacement.
    Fixture renamed;
    const auto before=renamed.capture(p);
    require(rename((renamed.root+"/source").c_str(),(renamed.root+"/renamed").c_str())==0,"rename source");
    const int replacement=open((renamed.root+"/source").c_str(),O_CREAT|O_EXCL|O_WRONLY,0600);
    require(replacement>=0,"replace source name");close(replacement);
    // Rename changes ctime: a new capture is needed, but it must still name
    // the original held inode, not the replacement basename.
    const auto held_snapshot=renamed.capture(p);
    require(compare_identity(*before.basic.identity.value(),*held_snapshot.basic.identity.value())==IdentityComparison::Same,"capture reopened replacement name");
#endif
#ifdef __APPLE__
    Fixture acl;
    acl_t native=acl_init(1);require(native!=nullptr,"acl_init");acl_entry_t entry{};
    require(acl_create_entry(&native,&entry)==0&&acl_set_tag_type(entry,ACL_EXTENDED_ALLOW)==0,"create ACE");
    uuid_t uuid{};require(mbr_uid_to_uuid(geteuid(),uuid)==0&&acl_set_qualifier(entry,uuid)==0,"ACE qualifier");
    acl_permset_t perms{};require(acl_get_permset(entry,&perms)==0&&acl_add_perm(perms,ACL_READ_DATA)==0&&acl_set_permset(entry,perms)==0,"ACE permissions");
    const int fd=open((acl.root+"/source").c_str(),O_RDONLY);require(fd>=0&&acl_set_fd_np(fd,native,ACL_TYPE_EXTENDED)==0,"install ACL");close(fd);acl_free(native);
    auto with_acl=acl.capture(p);require(with_acl.security.front().presence==SecurityPresence::Present,"ACL not captured");acl.replay(with_acl);
    // An inherited ACL must also be removed when the source has none.
    auto malformed=with_acl.security.front();malformed.bytes.resize(8);
    require(!acl.target->apply_replay_security(malformed,p).value(),"truncated Darwin ACL accepted");
    auto empty=acl.capture(p);empty.security.front().presence=SecurityPresence::Absent;empty.security.front().bytes.clear();
    success(acl.target->apply_replay_security(empty.security.front(),p),"remove inherited Darwin ACL");
    require(need(acl.target->read_security(SecurityPart::DarwinExtendedAcl),"removed ACL query").presence==SecurityPresence::Absent,"inherited ACL not removed");
    Fixture complete;
    auto full=complete.policy(RegularMetadataScope::CompleteMetadataV1);full.ownership=MetadataOwnership::Original;
    const auto unproved=capture_metadata_replay(*complete.source,full);
    require(unproved.state()==ObservationState::Unsupported&&
        unproved.unavailable_detail()->error.operation=="metadata_replay.complete_security_coverage_unproved",
        "Darwin complete security coverage overclaimed");
    auto forged=complete.capture(p);forged.policy=full;
    const auto untouched=need(complete.target->inspect_basic(),"complete target before refusal");
    require(apply_metadata_replay(*complete.target,forged).state()==ObservationState::Unsupported,
        "caller-constructed complete snapshot bypassed coverage proof");
    const auto after_refusal=need(complete.target->inspect_basic(),"complete target after refusal");
    require(untouched.changed.value()&&after_refusal.changed.value()&&*untouched.changed.value()==*after_refusal.changed.value(),
        "complete target mutated before coverage refusal");
#endif
#ifdef __linux__
    Fixture acl;
    const unsigned char bytes[]={2,0,0,0,1,0,6,0,255,255,255,255,2,0,4,0,210,4,0,0,4,0,4,0,255,255,255,255,16,0,4,0,255,255,255,255,32,0,0,0,255,255,255,255};
    const int fd=open((acl.root+"/source").c_str(),O_RDONLY);require(fd>=0&&fsetxattr(fd,"system.posix_acl_access",bytes,sizeof(bytes),0)==0,"install Linux ACL");close(fd);
    auto with_acl=acl.capture(p);require(with_acl.security.front().presence==SecurityPresence::Present,"Linux ACL not captured");acl.replay(with_acl);
    auto malformed=with_acl.security.front();malformed.bytes.resize(5);
    require(!acl.target->apply_replay_security(malformed,p).value(),"truncated Linux ACL accepted");
    require(!capture_metadata_replay(*acl.source,acl.policy(RegularMetadataScope::CompleteMetadataV1)).value(),"Linux complete coverage overclaimed");
    if (geteuid()==0) {
        Fixture ownership;
        require(chown((ownership.root+"/source").c_str(),1234,2345)==0,"distinct source ownership fixture");
        auto original=p;original.ownership=MetadataOwnership::Original;
        ownership.replay(ownership.capture(original));
        struct stat owner{};require(stat((ownership.root+"/target").c_str(),&owner)==0&&owner.st_uid==1234&&owner.st_gid==2345,
            "explicit original ownership not replayed");
        ownership.replay(ownership.capture(p));
        require(stat((ownership.root+"/target").c_str(),&owner)==0&&owner.st_uid==geteuid()&&owner.st_gid==getegid(),
            "explicit caller ownership not replayed");
        Fixture capabilities;
        const unsigned char capability[]={1,0,0,2,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        const int cap_fd=open((capabilities.root+"/source").c_str(),O_RDONLY|O_CLOEXEC);
        require(cap_fd>=0&&fsetxattr(cap_fd,"security.capability",capability,sizeof(capability),0)==0,"install real capability fixture");close(cap_fd);
        require(!capture_metadata_replay(*capabilities.source,p).value(),"capability replay without optin accepted");
        auto explicit_policy=p;explicit_policy.allow_privilege_metadata=true;
        auto captured=capabilities.capture(explicit_policy);const auto applied=capabilities.replay(captured);
        // Exercise the regular final-times callback again after capabilities.
        success(capabilities.target->apply_replay_basic(captured.basic,explicit_policy),"final times after capabilities");
        success(verify_metadata_replay(*capabilities.target,captured,applied),"capabilities survive final metadata phase");
        unsigned char copied[sizeof(capability)]{};
        const int target_fd=open((capabilities.root+"/target").c_str(),O_RDONLY|O_CLOEXEC);
        require(target_fd>=0&&fgetxattr(target_fd,"security.capability",copied,sizeof(copied))==sizeof(capability)&&
            std::equal(std::begin(copied),std::end(copied),std::begin(capability)),"opted-in capability bytes changed");close(target_fd);
        std::cout<<"real privileged capability replay and final-phase verification passed\n";
    }

#endif
#ifdef _WIN32
    if (f.root.size()>6 && f.root[5]==L':') {
    const auto unc_root=std::wstring(L"\\\\?\\UNC\\localhost\\")+f.root[4]+L"$"+f.root.substr(6);
    auto unc_directory=f.filesystem.open_directory(unc_root);
    if (unc_directory.value()) {
        auto unc_source=(*unc_directory.value())->open_child(name("source"),EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity);
        if (unc_source.value()) require(capture_metadata_replay(**unc_source.value(),p).state()==ObservationState::Unsupported,"UNC provider metadata coverage overclaimed");
        else std::cout<<"UNC source query unavailable: "<<unc_source.unavailable_detail()->error.operation<<'\n';
    } else std::cout<<"UNC administrative share unavailable: "<<unc_directory.unavailable_detail()->error.operation<<'\n';
    }
    f.source.reset();
    auto held_guard=HeldChild::observe_with_access(f.directory,name("source"),EntryAccess::RenameSource|EntryAccess::ContentRead|EntryAccess::MetadataAndLayout);
    need(held_guard,"held rename guard");
    for (const DWORD rights:{DWORD(GENERIC_WRITE),DWORD(DELETE)}) {
        HANDLE outsider=CreateFileW((f.root+L"\\source").c_str(),rights,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        const DWORD code=GetLastError();
        if (outsider!=INVALID_HANDLE_VALUE) CloseHandle(outsider);
        require(outsider==INVALID_HANDLE_VALUE&&code==ERROR_SHARING_VIOLATION,"rename guard permits WRITE/DELETE opener");
    }
    require(!MoveFileExW((f.root+L"\\source").c_str(),(f.root+L"\\moved").c_str(),0)&&
        GetLastError()==ERROR_SHARING_VIOLATION,"rename guard permits external basename replacement");
    success((*held_guard.value())->qualify_stable_content(),"qualified RH main-stream content guard");
    need((*held_guard.value())->capture_metadata(p),"synchronous policy-specific metadata view under RH");
    success(f.directory->qualify_identity_bound_rename(),"qualified Windows rename");
    const auto original_id=need((*held_guard.value())->inspect_basic(),"held rename identity").identity;
    success((*held_guard.value())->rename_noreplace(*f.directory,name("held-renamed")),"same held DELETE handle rename");
    const auto published=f.directory->open_child(name("held-renamed"));need(published,"held published entry");
    require(compare_identity(*need((*published.value())->inspect_basic(),"held published identity").identity.value(),*original_id.value())==IdentityComparison::Same,
        "held rename changed object identity");
    Fixture mapped;
    mapped.source.reset();
    struct NativeHandle { HANDLE value=INVALID_HANDLE_VALUE;~NativeHandle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);} };
    NativeHandle writer{CreateFileW((mapped.root+L"\\source").c_str(),GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
    require(writer.value!=INVALID_HANDLE_VALUE,"open writable mapping fixture");
    NativeHandle section{CreateFileMappingW(writer.value,nullptr,PAGE_READWRITE,0,0,nullptr)};
    require(section.value!=nullptr,"create existing writable section");
    struct View {void* value=nullptr;~View(){if(value)UnmapViewOfFile(value);}} view{MapViewOfFile(section.value,FILE_MAP_WRITE,0,0,0)};
    require(view.value!=nullptr,"map existing writable section");
    CloseHandle(writer.value);writer.value=INVALID_HANDLE_VALUE;
    auto mapped_guard=HeldChild::observe_with_access(mapped.directory,name("source"),EntryAccess::RenameSource|EntryAccess::ContentRead);
    if (mapped_guard.value()) {
        require((*mapped_guard.value())->qualify_stable_content().state()==ObservationState::Unsupported,
            "existing writable mapping qualified for old-target retention");
        static_cast<char*>(view.value)[0]='M';require(FlushViewOfFile(view.value,1)!=0,"flush mapped write");
        const auto changed=(*mapped_guard.value())->read_content();need(changed,"read under share-only guard");
        require(changed.value()->bytes.front()==std::byte{'M'},"mapped write regression fixture did not change held data");
    } else require(mapped_guard.state()==ObservationState::Denied||mapped_guard.state()==ObservationState::Changed,
        "mapped section guard failure not typed");
    auto exact=f.directory->create_child_file(*NativeName::from_windows(u"exact_\u00e9. "));need(exact,"exact UTF16/trailing spelling");
    require(need((*exact.value())->inspect_basic(),"exact spelling identity").identity.value()!=nullptr,"wide identity");
#endif
    std::cout<<"native capture/apply/verify, ACL/xattr, identity, limits and mutation regressions passed\n";
}
}
int main() {try {policy_tests();writer_finalization_tests();directory_metadata_tests();
#ifdef _WIN32
#ifdef CK_FS_METADATA_TEST_CLOSE_FAULT
    windows_ads_close_failure_test();
#endif
    windows_ads_tests();windows_ads_proof_tests();windows_ads_change_cancel_tests();windows_ads_source_change_and_unknown_tests();windows_complete_coverage_tests();strong_staging_tests();windows_acl_control_tests();rh_content_guard_tests();rh_native_retention_test();rh_retention_review_break_test();
#endif
#ifdef __APPLE__
    noowners_tests();
#endif
    native_tests();return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
