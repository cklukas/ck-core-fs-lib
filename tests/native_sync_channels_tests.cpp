// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_coordinator.hpp"
#include "native_filesystem.hpp"
#include "windows_name.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <cstring>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif
using namespace ck::files;
namespace {
void check(bool b,const char* message){if(!b)throw std::runtime_error(message);}
template<class T>T take(Observation<T> o){if(!o.value()) {const auto& e=*o.unavailable_detail();std::cerr<<e.error.operation<<" state="<<unsigned(e.state)<<" code="<<e.error.code<<'\n';throw std::runtime_error("native observation unavailable");}return std::move(o).take_value();}
void success(Observation<bool> o){check(take(std::move(o)),"native false success");}
MetadataReplayPolicy policy(bool full=false){MetadataReplayPolicy p;p.scope=full?RegularMetadataScope::CompleteMetadataV1:RegularMetadataScope::OrdinaryCallerVisibleV1;p.ownership=MetadataOwnership::Original;p.allow_privilege_metadata=full;return p;}
NativeName component(const char* n){
#ifdef _WIN32
    std::u16string u;while(*n)u.push_back(static_cast<unsigned char>(*n++));return *NativeName::from_windows(std::move(u));
#else
    return *NativeName::from_posix(n);
#endif
}
#ifdef _WIN32
std::atomic<bool> read_armed{false};std::atomic<unsigned> read_calls{0};FILE_ID_INFO read_target{};
std::stop_source* cancel_reads=nullptr;std::function<void()> mutate_on_read;unsigned mutation_read_number=2;
BOOL WINAPI watched_read(HANDLE h,LPVOID data,DWORD n,LPDWORD count,LPOVERLAPPED io){
    using Native=BOOL(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
    static const auto native=std::bit_cast<Native>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ReadFile"));
    const BOOL result=native(h,data,n,count,io);const DWORD saved=GetLastError();
    if(result&&read_armed.load()) {FILE_ID_INFO id{};
        if(GetFileInformationByHandleEx(h,FileIdInfo,&id,sizeof(id))&&id.VolumeSerialNumber==read_target.VolumeSerialNumber&&
           !std::memcmp(id.FileId.Identifier,read_target.FileId.Identifier,16)){
            const auto hits=read_calls.fetch_add(1)+1;
            if(hits==2&&cancel_reads)cancel_reads->request_stop();
            if(hits==mutation_read_number&&mutate_on_read){auto callback=std::move(mutate_on_read);mutate_on_read={};callback();}
        }}SetLastError(saved);return result;
}
#endif
}
#ifdef _WIN32
// Test executable import interception only; production calls still perform the
// actual native read. It counts real source bytes and deterministic boundaries.
extern "C" {decltype(&ReadFile) __imp_ReadFile=&watched_read;}
#endif
namespace {
struct Fixture {
    NativeFileSystem fs;
#ifdef _WIN32
    std::wstring base;std::vector<std::wstring> parents;
    PSECURITY_DESCRIPTOR private_sd=nullptr;
    static std::wstring extend(std::wstring p){return *windows_extended_path(p);}
    void mkdir(const std::wstring& p){SECURITY_ATTRIBUTES sa{sizeof(sa),private_sd,FALSE};check(CreateDirectoryW(p.c_str(),&sa)!=0,"native fixture mkdir");}
    Fixture(){const auto* t=_wgetenv(L"TEMP");const auto* u=_wgetenv(L"TMP");check(t&&u&&*t&&*u,"explicit TEMP/TMP required");
        const auto tmp=extend(t);if(const auto* required=_wgetenv(L"CK_FS_REQUIRE_V_DEV_DRIVE");required&&std::wstring_view(required)==L"1")check(tmp.starts_with(L"\\\\?\\V:\\tmp\\")&&extend(u).starts_with(L"\\\\?\\V:\\tmp\\"),"V development drive required");
        HANDLE token=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)!=0,"fixture token");DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);std::vector<std::byte> raw(size);check(GetTokenInformation(token,TokenUser,raw.data(),size,&size)!=0,"fixture user");check(CloseHandle(token)!=0,"fixture token close");
        LPWSTR sid=nullptr;check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(raw.data())->User.Sid,&sid)!=0,"fixture SID");const std::wstring descriptor=L"O:"+std::wstring(sid)+L"D:P(A;;FA;;;"+sid+L")(A;;FA;;;SY)";LocalFree(sid);
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.c_str(),SDDL_REVISION_1,&private_sd,nullptr)!=0,"fixture private SD");
        static std::atomic<unsigned> sequence{0};base=tmp+L"\\native-sync-channels-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(sequence++);mkdir(base);parents.push_back(base);
        for(unsigned i=0;i<4;++i){base+=L"\\"+std::wstring(70,wchar_t(L'a'+i));mkdir(base);parents.push_back(base);}
        for(const auto* n:{L"left",L"right",L"store"})mkdir(base+L"\\"+n);
    }
    std::wstring path(const char* side,const std::u16string& name={})const {std::wstring out=base+L"\\";while(*side)out+=wchar_t(*side++);if(!name.empty())out+=L"\\"+std::wstring(name.begin(),name.end());return out;}
    NativeAbsolutePath address(const char* side)const{
        // Same task-owned V: fixture, addressed by its actual volume root so
        // the backend need not accept a mounted-folder/reparse ancestry hop.
        const auto p=path(side);HANDLE held=CreateFileW(p.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        check(held!=INVALID_HANDLE_VALUE,"fixture address handle");
        WCHAR filesystem[32]{};check(GetVolumeInformationByHandleW(held,nullptr,0,nullptr,nullptr,nullptr,filesystem,32),"fixture filesystem query");
        if(const auto* expected=_wgetenv(L"CK_NATIVE_SYNC_CHANNELS_EXPECT_FS"))check(std::wstring_view(filesystem)==expected,"native qualification filesystem mismatch");
        static bool printed=false;if(!printed){std::cout<<"native fixture filesystem=";for(const auto* c=filesystem;*c;++c)std::cout<<char(*c);std::cout<<'\n';printed=true;}
        FILE_ID_INFO original{};check(GetFileInformationByHandleEx(held,FileIdInfo,&original,sizeof(original)),"fixture address original ID");
        const auto n=GetFinalPathNameByHandleW(held,nullptr,0,FILE_NAME_OPENED|VOLUME_NAME_GUID);check(n!=0,"fixture volume GUID size");
        std::wstring resolved(n,L'\0');const auto count=GetFinalPathNameByHandleW(held,resolved.data(),n,FILE_NAME_OPENED|VOLUME_NAME_GUID);check(count&&count<n,"fixture volume GUID path");resolved.resize(count);
        HANDLE roundtrip=CreateFileW(resolved.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);FILE_ID_INFO actual{};
        check(roundtrip!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(roundtrip,FileIdInfo,&actual,sizeof(actual))&&
            original.VolumeSerialNumber==actual.VolumeSerialNumber&&!std::memcmp(original.FileId.Identifier,actual.FileId.Identifier,16),"fixture volume GUID alias changed object");
        check(CloseHandle(roundtrip)&&CloseHandle(held),"fixture address handle close");return take(NativeAbsolutePath::from_windows(std::u16string(resolved.begin(),resolved.end())));
    }
    static void cleanup(const std::wstring& p){WIN32_FIND_DATAW info{};HANDLE search=FindFirstFileW((p+L"\\*").c_str(),&info);if(search!=INVALID_HANDLE_VALUE){do{std::wstring n=info.cFileName;if(n==L"."||n==L"..")continue;auto child=p+L"\\"+n;if((info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&!(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))cleanup(child);else {SetFileAttributesW(child.c_str(),FILE_ATTRIBUTE_NORMAL);check(DeleteFileW(child.c_str())!=0,"cleanup file");}}while(FindNextFileW(search,&info));check(FindClose(search)!=0,"cleanup find close");}check(RemoveDirectoryW(p.c_str())!=0,"cleanup directory");}
    ~Fixture(){read_armed=false;cancel_reads=nullptr;mutate_on_read={};cleanup(base);for(auto i=parents.rbegin()+1;i!=parents.rend();++i)check(RemoveDirectoryW(i->c_str())!=0,"cleanup long parent");if(private_sd)LocalFree(private_sd);}
    void data(const char* side,const std::u16string& name,std::string_view bytes,const std::u16string& stream={}){
        const auto p=path(side,name)+std::wstring(stream.begin(),stream.end());HANDLE h=CreateFileW(p.c_str(),GENERIC_WRITE|FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,CREATE_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr);check(h!=INVALID_HANDLE_VALUE,"native fixture create/write");DWORD n=0;check(bytes.size()<=MAXDWORD&&WriteFile(h,bytes.data(),DWORD(bytes.size()),&n,nullptr)&&n==bytes.size(),"native fixture write");check(FlushFileBuffers(h)!=0,"native fixture flush");check(CloseHandle(h)!=0,"native fixture close");}
    FILE_BASIC_INFO times(const char* side,const std::u16string& name){HANDLE h=CreateFileW(path(side,name).c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE,"read native fixture times");FILE_BASIC_INFO out{};check(GetFileInformationByHandleEx(h,FileBasicInfo,&out,sizeof(out))!=0,"native basic times");check(CloseHandle(h)!=0,"native times close");return out;}
    void restore(const char* side,const std::u16string& name,FILE_BASIC_INFO b){HANDLE h=CreateFileW(path(side,name).c_str(),FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE,"restore native fixture times");check(SetFileInformationByHandle(h,FileBasicInfo,&b,sizeof(b))!=0,"restore exact basic times");check(CloseHandle(h)!=0,"restore times close");}
    void fixed(const char* side,const std::u16string& name){auto b=times(side,name);b.CreationTime.QuadPart=125911584000000000LL;b.LastAccessTime.QuadPart=b.CreationTime.QuadPart;b.LastWriteTime.QuadPart=b.CreationTime.QuadPart;b.FileAttributes=FILE_ATTRIBUTE_ARCHIVE;restore(side,name,b);}
    void arm(const char* side,const std::u16string& name){HANDLE h=CreateFileW(path(side,name).c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(h,FileIdInfo,&read_target,sizeof(read_target)),"read watch ID");check(CloseHandle(h)!=0,"read watch close");read_calls=0;read_armed=true;}
#else
    std::string base;
    Fixture(){const auto* t=std::getenv("TMPDIR");check(t&&*t,"explicit TMPDIR required");base=std::string(t)+"/native-sync-channels.XXXXXX";check(mkdtemp(base.data())!=nullptr,"native fixture temp");for(auto n:{"left","right","store"})check(!::mkdir((base+"/"+n).c_str(),0700),"native mkdir");}
    NativeAbsolutePath address(const char* side)const{return take(NativeAbsolutePath::from_posix(base+"/"+side));}
    ~Fixture(){for(auto side:{"left","right","store"}){unlink((base+"/"+side+"/a").c_str());rmdir((base+"/"+side).c_str());}rmdir(base.c_str());}
    void data(const char* side,const std::u16string&,std::string_view bytes){auto p=base+"/"+side+"/a";int fd=open(p.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);check(fd>=0,"native fixture open");check(::write(fd,bytes.data(),bytes.size())==static_cast<ssize_t>(bytes.size()),"native fixture write");timespec ts[2]{{1000000000,0},{1000000000,0}};check(!futimens(fd,ts)&&!fsync(fd)&&!close(fd),"native fixture finish");}
#endif
    std::shared_ptr<const DirectoryCursor> directory(const char* side){return std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(address(side))));}
    NativeSyncCoordinatorRequest request(bool full=false){return {address("store"),address("left"),address("right"),{},policy(full),{},{},{},{},{}};}
    NativeSyncFileProof proof(const char* side,bool full=false,NativeSyncProofLimits limits={}){NativeSyncProofBudget budget;return take(observe_native_sync_file(directory(side),component("a"),policy(full),limits,budget));}
};
#ifdef _WIN32
void canonical_tests(bool full){Fixture f;const std::u16string a=u"a";f.data("left",a,"base");f.data("right",a,"base");
    std::u16string raw=u":exact_\u00e9_";raw.push_back(char16_t(0xd800));raw+=u". :$DATA";
    const std::u16string long_name=u":"+std::u16string(220,u'x')+u":$DATA";
    for(const auto& side:{"left","right"}){f.data(side,a,"AAAA",u":one:$DATA");f.data(side,a,"",u":empty:$DATA");f.data(side,a,"native exact",raw);f.data(side,a,"long",long_name);f.fixed(side,a);}
    f.data("left",u"b","base");f.data("left",u"b","AAAA",u":ONE:$DATA");f.data("left",u"b","",u":empty:$DATA");f.data("left",u"b","native exact",raw);f.data("left",u"b","long",long_name);f.fixed("left",u"b");
    f.data("left",u"c","base");f.data("left",u"c","AAAAAA",u":one:$DATA");f.data("left",u"c","",u":empty:$DATA");f.data("left",u"c","native exact",raw);f.data("left",u"c","long",long_name);f.fixed("left",u"c");
    auto left=f.proof("left",full),right=f.proof("right",full);check(left.status.content_digest==right.status.content_digest,"equal main digest changed");check(left.status.required_metadata_digest==right.status.required_metadata_digest,"identity/owner observations leaked into semantic digest");
    NativeSyncProofBudget variant_budget;auto spelling=take(observe_native_sync_file(f.directory("left"),component("b"),policy(full),{},variant_budget));variant_budget={};auto length=take(observe_native_sync_file(f.directory("left"),component("c"),policy(full),{},variant_budget));
    check(left.status.content_digest==spelling.status.content_digest&&left.status.required_metadata_digest!=spelling.status.required_metadata_digest,"exact stream-name case folded out of metadata digest");
    check(left.status.content_digest==length.status.content_digest&&left.status.required_metadata_digest!=length.status.required_metadata_digest&&length.channel_facts.all_stream_logical_bytes==26,"native stream length/content variation absent from semantic facts");
    check(left.channel_facts.coverage==DataChannelCoverage::WindowsFileStreamInfo&&left.channel_facts.named_stream_count==4&&left.channel_facts.all_stream_logical_bytes==24,"all-stream logical size/count wrong");
    auto reordered=left.metadata;std::reverse(reordered.channels.begin(),reordered.channels.end());check(take(native_sync_metadata_digest(*left.native_source,reordered))==left.status.required_metadata_digest,"stream enumeration order leaked into digest");
    const auto rejects=[&](MetadataReplaySnapshot s){check(!native_sync_metadata_digest(*left.native_source,s).value(),"forged stream snapshot/evidence accepted");};
    auto bad=left.metadata;bad.channel_evidence.reset();rejects(bad);
    class FakeProof final:public MetadataReplayChannelEvidence{};bad=left.metadata;bad.channel_evidence=std::make_shared<FakeProof>();rejects(bad);
    bad=left.metadata;bad.channels.pop_back();rejects(bad);bad=left.metadata;bad.channels[0].digest[0]^=std::byte{1};rejects(bad);
    bad=left.metadata;bad.channels[0].logical_size++;rejects(bad);bad=left.metadata;bad.channels[0].identifier=*NativeFeatureIdentifier::from_windows(u":forged:$DATA");rejects(bad);
    bad=left.metadata;bad.channel_coverage=DataChannelCoverage::Unknown;rejects(bad);bad=left.metadata;bad.channels[1]=bad.channels[0];rejects(bad);
    check(!native_sync_metadata_digest(*right.native_source,left.metadata).value(),"foreign native source accepted");
    {class FakeSecurity final:public MetadataSecurityCoverageEvidence{public:MetadataSecurityCoverage family()const noexcept override{return MetadataSecurityCoverage::WindowsPersistentSecurityV1;}Observation<bool> recheck(const MetadataReplaySnapshot&)const override{return Observation<bool>::available(true);}};bad=left.metadata;bad.security_coverage=std::make_shared<FakeSecurity>();rejects(bad);}
    std::cout<<"native exact UTF16/long-path/empty stream canonical order and strict forged evidence/source rejection passed scope="<<full<<'\n';
}
class CatalogEntry final:public OpenedEntry {
public:
    enum class Fault {Unknown,Opaque,MissingMain,ExtraMain,UnknownType};
    CatalogEntry(std::unique_ptr<OpenedEntry> native,Fault f):native_(std::move(native)),fault_(f){}
    Observation<BasicMetadata> inspect_basic()const override{return native_->inspect_basic();}
    Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy& p)const override{return native_->qualify_metadata_replay(p);}
    Observation<DataChannelCatalog> inspect_data_channels(InventoryLimits limits)const override{auto o=native_->inspect_data_channels(limits);if(!o.value())return o;auto c=std::move(o).take_value();
        if(fault_==Fault::Unknown)c.coverage=DataChannelCoverage::Unknown;
        else if(fault_==Fault::MissingMain)c.channels.erase(std::remove_if(c.channels.begin(),c.channels.end(),[](const auto& x){return x.kind==DataChannelKind::MainData;}),c.channels.end());
        else if(fault_==Fault::ExtraMain)c.channels.push_back(c.channels.front());
        else c.channels.push_back({*NativeFeatureIdentifier::from_windows(u":unknown:$UNKNOWN"),fault_==Fault::Opaque?DataChannelKind::Opaque:DataChannelKind::NamedData,Observation<std::uint64_t>::available(1),{}});
        return Observation<DataChannelCatalog>::available(std::move(c));}
private:std::unique_ptr<OpenedEntry> native_;Fault fault_;
};
class CatalogCursor final:public DirectoryCursor {
public:CatalogCursor(std::shared_ptr<const DirectoryCursor> native,CatalogEntry::Fault fault):DirectoryCursor(native->identity()),native_(std::move(native)),fault_(fault){}
    Observation<BasicMetadata> inspect_basic()const override{return native_->inspect_basic();}
    Observation<std::unique_ptr<OpenedEntry>> open_child(const NativeName& n,EntryAccess a)const override{auto o=native_->open_child(n,a);if(!o.value())return o;return Observation<std::unique_ptr<OpenedEntry>>::available(std::make_unique<CatalogEntry>(std::move(o).take_value(),fault_));}
protected:Observation<DirectoryStep> next_step()override{return Observation<DirectoryStep>::available(DirectoryEnd{});}
private:std::shared_ptr<const DirectoryCursor> native_;CatalogEntry::Fault fault_;
};
void budgets_unknown_and_cancel(){Fixture f;f.data("left",u"a","base");f.data("left",u"a",std::string(192*1024,'x'),u":large:$DATA");f.fixed("left",u"a");f.arm("left",u"a");
    NativeSyncProofLimits limits;limits.max_file_bytes=128*1024;NativeSyncProofBudget budget;auto result=observe_native_sync_file(f.directory("left"),component("a"),policy(),limits,budget);check(!result.value()&&result.unavailable_detail()->error.code==std::int64_t(AdapterError::InventoryLimit)&&read_calls==0,"ADS exceeded budget but capture hashed bytes first");
    limits={};limits.max_total_bytes=128*1024;budget={};result=observe_native_sync_file(f.directory("left"),component("a"),policy(),limits,budget);check(!result.value()&&read_calls==0,"ADS total budget ignored before capture");
    for(auto fault:{CatalogEntry::Fault::Unknown,CatalogEntry::Fault::Opaque,CatalogEntry::Fault::MissingMain,CatalogEntry::Fault::ExtraMain,CatalogEntry::Fault::UnknownType}){budget={};auto fake=std::make_shared<CatalogCursor>(f.directory("left"),fault);result=observe_native_sync_file(fake,component("a"),policy(),{},budget);check(!result.value()&&result.unavailable_detail()->error.operation.starts_with("native_sync.")&&read_calls==0,"unknown/opaque/main-count catalog hashed or accepted");}
    budget={};limits={};std::stop_source stop;cancel_reads=&stop;result=observe_native_sync_file(f.directory("left"),component("a"),policy(),limits,budget,stop.get_token());cancel_reads=nullptr;check(!result.value()&&result.unavailable_detail()->error.code==std::int64_t(AdapterError::InterruptedRead)&&read_calls>=2,"native ADS capture cancellation ignored");read_armed=false;
    std::cout<<"native pre-hash main+ADS budgets, catalog refusal boundaries, and actual read cancellation passed\n";
}
void final_membership_test(){Fixture f;f.data("left",u"a","base");f.data("left",u"a",std::string(192*1024,'x'),u":large:$DATA");f.fixed("left",u"a");
    unsigned reads=0;f.arm("left",u"a");{auto probe=f.proof("left");reads=read_calls.load();}read_armed=false;
    check(reads>3,"native final-digest read trace missing");const auto stamp=f.times("left",u"a");
    f.arm("left",u"a");mutation_read_number=reads-1;bool changed=false;mutate_on_read=[&]{
        check(MoveFileExW(f.path("left",u"a").c_str(),f.path("left",u"moved").c_str(),0)!=0,"native attacker rename");
        f.restore("left",u"moved",stamp);f.data("left",u"a","base");f.fixed("left",u"a");changed=true;};
    NativeSyncProofBudget budget;auto result=observe_native_sync_file(f.directory("left"),component("a"),policy(),{},budget);
    read_armed=false;mutate_on_read={};mutation_read_number=2;
    if(!result.value())std::cout<<"final membership refusal: "<<result.unavailable_detail()->error.operation<<'\n';
    check(changed&&!result.value()&&result.unavailable_detail()->error.operation=="native_sync.member_changed","late final-digest name replacement published stale source facts");
    std::cout<<"native parent/name membership revalidated after final ADS digest passed\n";
}
void mutation_and_root(){Fixture f;f.data("left",u"a","base");f.data("left",u"a",std::string(192*1024,'x'),u":large:$DATA");f.fixed("left",u"a");auto proof=f.proof("left");auto original=f.times("left",u"a");
    f.data("left",u"a","late",u":late:$DATA");f.restore("left",u"a",original);check(native_sync_same_version(proof.metadata.basic,take(proof.native_source->inspect_basic())),"fixture failed to restore native source version");check(!native_sync_metadata_digest(*proof.native_source,proof.metadata).value(),"new stream hidden by restored source version");
    auto root=f.directory("right");success(qualify_native_sync_root_channels(*root));f.data("right",u"","directory ADS",u":root-data:$DATA");
    auto rejected=qualify_native_sync_root_channels(*root);check(!rejected.value()&&rejected.state()==ObservationState::Unsupported,"directory ADS silently omitted from baseline");NativeSyncProofBudget budget;check(!observe_native_sync_root(root,policy(),{},budget).value(),"directory ADS published complete empty inventory");
    const auto unc=L"\\\\?\\UNC\\localhost\\"+std::wstring(1,f.base[4])+L"$"+f.base.substr(6)+L"\\left";auto remote=f.fs.open_directory(unc);
    if(remote.value())check(!qualify_native_sync_root_channels(**remote.value()).value(),"UNC provider qualified as local complete streams");else std::cout<<"UNC share unavailable: "<<remote.unavailable_detail()->error.operation<<'\n';
    std::cout<<"native source stream mutation despite restored versions, directory-zero-main gate and UNC refusal passed\n";
}
std::vector<NativeSyncDecision> decisions(const NativeSyncCoordinator& c,NativeSyncChoice choice=NativeSyncChoice::Proposal){std::vector<NativeSyncDecision> out;for(const auto& row:c.rows())out.push_back({row.exact_key,choice});return out;}
void drain(NativeSyncCoordinator& c){for(unsigned i=0;i<128;++i){auto s=c.advance();if(s==NativeSyncCoordinatorState::Complete||s==NativeSyncCoordinatorState::Cancelled||s==NativeSyncCoordinatorState::NeedsReview)return;}check(false,"native coordinator did not drain");}
void coordinator_tests(){Fixture f;for(auto side:{"left","right"}){f.data(side,u"a","base");f.data(side,u"a",side==std::string_view("left")?"AAAA":"BBBB",u":one:$DATA");f.fixed(side,u"a");}
    {auto c=take(NativeSyncCoordinator::open(f.request()));check(c->rows().size()==1&&c->rows()[0].proposal==SyncAction::Conflict,"equal main/different ADS falsely unchanged");auto facts=take(c->facts(0));check(facts.relation==ComparisonRelation::MetadataDifferent&&facts.conflict_class==ConflictClass::ExistingRegular&&facts.left.size==4&&facts.left.all_stream_size==8&&facts.left.named_stream_count==1,"ADS differences absent from independent preserved-metadata facts");check(!c->approve(decisions(*c),true).value(),"different ADS approved as no-op convergence");success(c->approve(decisions(*c,NativeSyncChoice::Skip),true));drain(*c);check(c->result().state==NativeSyncCoordinatorState::Complete&&c->result().pending_keys.size()==1,"skipped ADS difference advanced as confirmed equal");success(c->finish_io());}
    {auto c=take(NativeSyncCoordinator::open(f.request()));check(c->rows()[0].proposal==SyncAction::Conflict,"restart falsely converged differing ADS");success(c->finish_io());}
    Fixture changed;for(auto side:{"left","right"}){changed.data(side,u"a","base");changed.data(side,u"a","AAAA",u":one:$DATA");changed.fixed(side,u"a");}
    auto c=take(NativeSyncCoordinator::open(changed.request()));check(c->rows()[0].proposal==SyncAction::Unchanged,"equal complete streams not unchanged");const auto old=changed.times("right",u"a");changed.data("right",u"a","late",u":late:$DATA");changed.restore("right",u"a",old);check(!c->approve(decisions(*c),true).value(),"stale ADS no-op receipt accepted");success(c->finish_io());c.reset();
    Fixture cas;for(auto side:{"left","right"}){cas.data(side,u"a","base");cas.data(side,u"a","AAAA",u":one:$DATA");cas.fixed(side,u"a");}
    bool mutated=false;auto request=cas.request();request.before_event=[&](auto event){if(event==NativeSyncCoordinatorEvent::BeforeBaselineCommit&&!mutated){mutated=true;auto b=cas.times("right",u"a");cas.data("right",u"a","late",u":late:$DATA");cas.restore("right",u"a",b);}return true;};c=take(NativeSyncCoordinator::open(std::move(request)));success(c->approve(decisions(*c),true));drain(*c);check(mutated&&c->result().state==NativeSyncCoordinatorState::NeedsReview&&c->result().generation==0,"known ADS edit passed baseline CAS boundary");success(c->finish_io());c.reset();
    std::cout<<"native ADS conflict/facts, skip/restart, stale no-op review and pre-CAS mutation gates passed\n";
}
struct SecurityPrivilege{HANDLE token=nullptr;TOKEN_PRIVILEGES old{};bool enabled=false;SecurityPrivilege(){if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&token))return;TOKEN_PRIVILEGES p{};p.PrivilegeCount=1;p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;if(!LookupPrivilegeValueW(nullptr,L"SeSecurityPrivilege",&p.Privileges[0].Luid))return;DWORD n=sizeof(old);SetLastError(ERROR_SUCCESS);enabled=AdjustTokenPrivileges(token,FALSE,&p,sizeof(old),&old,&n)&&GetLastError()==ERROR_SUCCESS;}~SecurityPrivilege(){if(token){if(enabled)AdjustTokenPrivileges(token,FALSE,&old,0,nullptr,nullptr);CloseHandle(token);}}};
#else
void ordinary_smoke(){Fixture f;success(qualify_native_sync_root_channels(*f.directory("left")));f.data("left",u"a","base");f.data("right",u"a","base");auto a=f.proof("left"),b=f.proof("right");check(a.status.content_digest==b.status.content_digest&&a.status.required_metadata_digest==b.status.required_metadata_digest,"POSIX native canonical regression");check(!a.channel_facts.all_stream_logical_bytes&&a.channel_facts.coverage==DataChannelCoverage::Unknown,"POSIX ordinary claimed hidden all-stream total");auto bad=a.metadata;bad.channels.push_back({*NativeFeatureIdentifier::from_windows(u":fake:$DATA"),0,{},{}});check(!native_sync_metadata_digest(*a.native_source,bad).value(),"foreign stream payload accepted on POSIX");std::cout<<"POSIX native ordinary digest/source and unknown all-stream scope regression passed\n";}
#endif
}
int main(){try{
#ifdef _WIN32
    canonical_tests(false);budgets_unknown_and_cancel();final_membership_test();mutation_and_root();coordinator_tests();SecurityPrivilege privilege;
    if(privilege.enabled)canonical_tests(true);else {check(!std::getenv("CK_NATIVE_SYNC_CHANNELS_REQUIRE_FULL"),"required Full privilege unavailable");std::cout<<"Full native coverage not qualified: SeSecurityPrivilege unavailable\n";}
#else
    ordinary_smoke();
#endif
    std::cout<<"native_sync_channels_tests passed\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
