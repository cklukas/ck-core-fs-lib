// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_directory_replay_job.hpp"
#include "native_filesystem.hpp"
#include "native_operation_copy_job.hpp"
#include "platform/journal_root_test_faults.hpp"
#include "native_trash.hpp"
#include <atomic>
#include <algorithm>
#include <bit>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <source_location>
#include <cstdlib>
#include <new>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winternl.h>
#include "windows_name.hpp"
#else
#include <cerrno>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
using namespace ck::files;
namespace {
unsigned checks=0,sequence=0;
thread_local bool fail_next_allocation=false;
std::atomic<unsigned> allocation_failures{0};
#define CHECK(x) do {++checks;if(!(x)){std::fprintf(stderr,"directory_executor:%u %s\n",unsigned(__LINE__),#x);std::abort();}}while(false)
template<class T>T take(Observation<T> value,const std::source_location location=std::source_location::current()) {
    if(!value.value()) {const auto& e=*value.unavailable_detail();std::fprintf(stderr,"line=%u op=%s state=%u domain=%u code=%lld\n",
        unsigned(location.line()),e.error.operation.c_str(),unsigned(e.state),unsigned(e.error.domain),static_cast<long long>(e.error.code));}
    CHECK(value.value());return std::move(value).take_value();
}
NativeName name(const char* ascii) {
#ifdef _WIN32
    return *NativeName::from_windows(std::u16string(ascii,ascii+std::char_traits<char>::length(ascii)));
#else
    return *NativeName::from_posix(ascii);
#endif
}
using Cursor=std::shared_ptr<const DirectoryCursor>;
Cursor mkdir(Cursor parent,const NativeName& leaf) {return Cursor(take(parent->create_child_directory(leaf)));}
#ifdef _WIN32
Cursor child(Cursor parent,const NativeName& leaf) {return Cursor(take(parent->open_directory_child(leaf)));}
#endif
const std::vector<std::byte> payload(3*65536+17,std::byte{0x6a});
#ifdef _WIN32
void protect_file(Cursor parent,const NativeName& leaf) {
    auto directory=take(duplicate_windows_trash_parent(*parent));const auto* units=leaf.windows_units();CHECK(units);
    std::wstring spelling(units->begin(),units->end());UNICODE_STRING native{};native.Buffer=spelling.data();
    native.Length=static_cast<USHORT>(spelling.size()*sizeof(wchar_t));native.MaximumLength=native.Length;
    OBJECT_ATTRIBUTES attributes{};InitializeObjectAttributes(&attributes,&native,0,directory.get(),nullptr);IO_STATUS_BLOCK io{};HANDLE file_handle=nullptr;
    CHECK(NtCreateFile(&file_handle,WRITE_DAC|READ_CONTROL|SYNCHRONIZE,&attributes,&io,nullptr,0,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,FILE_OPEN,FILE_NON_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT,nullptr,0)==0);
    HANDLE token=nullptr;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));DWORD count=0;
    GetTokenInformation(token,TokenUser,nullptr,0,&count);CHECK(count&&count<65536);std::vector<std::byte> data(count);
    CHECK(GetTokenInformation(token,TokenUser,data.data(),count,&count));CHECK(CloseHandle(token));
    wchar_t* sid=nullptr;CHECK(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid,&sid));
    const auto sddl=std::wstring(L"D:P(A;;FA;;;")+sid+L")(A;;FA;;;SY)";LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor=nullptr;CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr));
    BOOL present=FALSE,defaulted=FALSE;PACL dacl=nullptr;CHECK(GetSecurityDescriptorDacl(descriptor,&present,&dacl,&defaulted)&&present);
    CHECK(SetSecurityInfo(file_handle,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,dacl,nullptr)==ERROR_SUCCESS);
    LocalFree(descriptor);CHECK(CloseHandle(file_handle));
}
#endif
void file(Cursor parent,const NativeName& leaf) {
    auto writer=take(parent->create_child_file(leaf));std::size_t offset=0;
    while(offset<payload.size()) {const auto written=take(writer->write_content(offset,std::span(payload).subspan(offset)));CHECK(written);offset+=written;}
    CHECK(take(writer->finish_content_writes()));
#ifdef _WIN32
    protect_file(parent,leaf); // Parent DACL tightening must not erase this fixture's read grants.
#endif
}
void binary_attribute(Cursor parent,const NativeName& leaf) {
    auto held=take(HeldChild::observe_with_access(parent,leaf,EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));
    MetadataReplayPolicy policy;policy.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;
    auto writer=take(held->open_directory_metadata_target(policy));auto basic=take(writer->inspect_basic());
#ifdef _WIN32
    const auto identifier=*NativeFeatureIdentifier::from_windows_ea("CK_DIRECTORY_BINARY_EA");
#else
    const auto identifier=*NativeFeatureIdentifier::from_posix("user.ck_directory_binary");
#endif
    CHECK(take(writer->apply_replay_attribute({identifier,{std::byte{'a'},std::byte{0},std::byte{'z'}},basic.identity,
        Observation<std::uint32_t>::available(0)},policy)));
    CHECK(take(writer->finish_content_writes()));
}
Observation<bool> payload_matches(const HeldChild& held,std::stop_token stop) {
    std::size_t offset=0;
    while(offset<payload.size()) {
        auto read=held.read_content({65536},offset,stop);if(!read.value())return Observation<bool>::unavailable(read.state(),read.unavailable_detail()->error);
        if(read.value()->bytes.empty()||read.value()->bytes.size()>payload.size()-offset||
            !std::equal(read.value()->bytes.begin(),read.value()->bytes.end(),payload.begin()+offset))
            return Observation<bool>::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,15,"test.payload_changed"});
        offset+=read.value()->bytes.size();
    }
    return Observation<bool>::available(true);
}
std::optional<ObjectIdentity> flush_target;
std::atomic<bool> inject_writer_flush{false};
std::atomic<unsigned> injected_flushes{0};
#ifdef _WIN32
BOOL WINAPI observed_flush(HANDLE handle) {
    using Fn=BOOL(WINAPI*)(HANDLE);
    static const auto real=std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"FlushFileBuffers"));
    const BOOL result=real(handle);
    if(result&&inject_writer_flush.load()&&flush_target) {
        FILE_ID_INFO id{};CHECK(GetFileInformationByHandleEx(handle,FileIdInfo,&id,sizeof(id)));
        NativeIdentifier object;std::memcpy(object.bytes.data(),id.FileId.Identifier,16);
        if(flush_target->volume==NativeIdentifier::from_u64(id.VolumeSerialNumber)&&flush_target->object==object) {
            ++injected_flushes;SetLastError(ERROR_ACCESS_DENIED);return FALSE;
        }
    }
    return result;
}
#else
int observed_fsync(int fd) {
    using Fn=int(*)(int);static const auto real=reinterpret_cast<Fn>(dlsym(RTLD_NEXT,"fsync"));CHECK(real);
    const auto result=real(fd);
    if(!result&&inject_writer_flush.load()&&flush_target) {
        struct stat value{};CHECK(::fstat(fd,&value)==0);
        if(flush_target->volume==NativeIdentifier::from_u64(value.st_dev)&&flush_target->object==NativeIdentifier::from_u64(value.st_ino)) {
            ++injected_flushes;errno=EIO;return -1;
        }
    }
    return result;
}
#endif
#ifdef _WIN32
void ads(Cursor directory,const std::u16string& spelling) {
    auto parent=take(duplicate_windows_trash_parent(*directory));std::wstring text(spelling.begin(),spelling.end());
    UNICODE_STRING native{};native.Buffer=text.data();native.Length=static_cast<USHORT>(text.size()*sizeof(wchar_t));native.MaximumLength=native.Length;
    OBJECT_ATTRIBUTES attributes{};InitializeObjectAttributes(&attributes,&native,0,parent.get(),nullptr);IO_STATUS_BLOCK io{};HANDLE stream=nullptr;
    CHECK(NtCreateFile(&stream,FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE,
        &attributes,&io,nullptr,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,FILE_CREATE,
        FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT,nullptr,0)==0&&io.Information==FILE_CREATED);
    DWORD written=0;CHECK(WriteFile(stream,payload.data(),static_cast<DWORD>(payload.size()),&written,nullptr)&&written==payload.size());
    CHECK(FlushFileBuffers(stream));CHECK(CloseHandle(stream));
}
std::wstring extended_address(const NativeAbsolutePath& address) {
    const auto* units=address.windows_units();CHECK(units);
    std::wstring native(units->begin(),units->end());
    if(!native.starts_with(L"\\\\?\\"))native=native.starts_with(L"\\\\")?L"\\\\?\\UNC\\"+native.substr(2):L"\\\\?\\"+native;
    return native;
}
void old_times(const NativeAbsolutePath& address) {
    const auto native=extended_address(address);
    const auto handle=CreateFileW(native.c_str(),FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);CHECK(handle!=INVALID_HANDLE_VALUE);
    const std::uint64_t ticks=126227808000000000ULL;FILETIME accessed{DWORD(ticks&0xffffffffULL),DWORD(ticks>>32)};
    const auto modified_ticks=ticks+330000000ULL;FILETIME modified{DWORD(modified_ticks&0xffffffffULL),DWORD(modified_ticks>>32)};
    CHECK(SetFileTime(handle,nullptr,&accessed,&modified));CHECK(CloseHandle(handle));
}
class SecurityPrivilege final {
public:
    SecurityPrivilege() {
        CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&token_));TOKEN_PRIVILEGES wanted{};
        wanted.PrivilegeCount=1;wanted.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        CHECK(LookupPrivilegeValueW(nullptr,L"SeSecurityPrivilege",&wanted.Privileges[0].Luid));DWORD size=sizeof(previous_);
        SetLastError(ERROR_SUCCESS);CHECK(AdjustTokenPrivileges(token_,FALSE,&wanted,sizeof(previous_),&previous_,&size)&&GetLastError()==ERROR_SUCCESS);
    }
    ~SecurityPrivilege(){CHECK(AdjustTokenPrivileges(token_,FALSE,&previous_,0,nullptr,nullptr));CHECK(CloseHandle(token_));}
private:HANDLE token_=nullptr;TOKEN_PRIVILEGES previous_{};
};
void directory_permissions(const NativeAbsolutePath& address,bool readonly) {
    const auto native=extended_address(address);
    const auto handle=CreateFileW(native.c_str(),WRITE_DAC|READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);CHECK(handle!=INVALID_HANDLE_VALUE);
    HANDLE token=nullptr;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));DWORD count=0;
    GetTokenInformation(token,TokenUser,nullptr,0,&count);CHECK(count&&count<65536);std::vector<std::byte> data(count);
    CHECK(GetTokenInformation(token,TokenUser,data.data(),count,&count));CHECK(CloseHandle(token));
    wchar_t* sid=nullptr;CHECK(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid,&sid));
    const auto sddl=std::wstring(L"D:P(A;;")+(readonly?L"FRFX":L"FA")+L";;;"+sid+L")(A;;FA;;;SY)";LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor=nullptr;CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr));
    BOOL present=FALSE,defaulted=FALSE;PACL dacl=nullptr;CHECK(GetSecurityDescriptorDacl(descriptor,&present,&dacl,&defaulted)&&present);
    CHECK(SetSecurityInfo(handle,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,dacl,nullptr)==ERROR_SUCCESS);
    LocalFree(descriptor);CHECK(CloseHandle(handle));
}
#endif
// CLI navigation address only. Validate before converting ordinary DOS/UNC
// separators to the extended Win32 boundary; already extended UTF16 is exact.
NativeAbsolutePath fixture_native_address(const std::filesystem::path& work) {
    auto address=take(NativeAbsolutePath::from_host(work));
#ifdef _WIN32
    const auto* units=address.windows_units();CHECK(units);
    if(units->starts_with(u"\\\\?\\"))return address;
    const std::wstring spelling(units->begin(),units->end());
    const auto native=windows_extended_path(spelling);CHECK(native);
    return take(NativeAbsolutePath::from_host(std::filesystem::path(*native)));
#else
    return address;
#endif
}
struct Fixture {
    NativeFileSystem fs;NativeAbsolutePath address;Cursor base,source,parent,journals;
    PreparedJournalRoot::Pointer root;NativeName target;HeldChild::Pointer source_held;
    MetadataReplaySnapshot metadata;
    explicit Fixture(const std::filesystem::path& work,bool nested=false,bool with_ads=false,bool complete=false):address(fixture_native_address(work)),target(name(("destination-"+std::to_string(++sequence)).c_str())) {
        base=Cursor(take(fs.open_native_directory(address)));source=mkdir(base,name(("source-"+std::to_string(sequence)).c_str()));parent=base;
        const auto journal_name=name(("journal-"+std::to_string(sequence)).c_str());journals=mkdir(base,journal_name);
        const auto journal_address=take(address.child_address(journal_name));CHECK(take(prepare_native_operation_journal_root(journal_address)));
        root=take(acquire_native_journal_root(journal_address));
        if(nested) {auto folder=mkdir(source,name("nested"));file(folder,name("payload"));}
        else file(source,name("payload"));
        binary_attribute(base,name(("source-"+std::to_string(sequence)).c_str()));
        // Test setup only. No production creator authority is inferred from
        // these fixture directory creations or security changes.
#ifdef _WIN32
        if(with_ads)ads(source,std::u16string(u":metadata-猫-\xd800:$DATA"));
        auto source_address=take(address.child_address(name(("source-"+std::to_string(sequence)).c_str())));
        old_times(source_address);directory_permissions(source_address,true);
        if(nested)directory_permissions(take(take(address.child_address(name(("source-"+std::to_string(sequence)).c_str()))).child_address(name("nested"))),true);
#else
        (void)with_ads;(void)complete;
        auto source_address=take(address.child_address(name(("source-"+std::to_string(sequence)).c_str())));
        CHECK(::chmod(source_address.host_path().value()->c_str(),0550)==0);
#endif
        const auto access=complete?EntryAccess::MetadataAndFullSecurity|EntryAccess::MetadataAndAttributes:EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity;
        source_held=take(HeldChild::observe_with_access(base,name(("source-"+std::to_string(sequence)).c_str()),access));
        MetadataReplayPolicy policy;policy.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;
#ifdef _WIN32
        if(complete){policy.scope=RegularMetadataScope::CompleteMetadataV1;policy.allow_privilege_metadata=true;}
#endif
        metadata=take(source_held->capture_metadata(policy));
        CHECK(metadata.channels.size()==(with_ads?1u:0u));
    }
    NativeDirectoryReplayRequest request(bool existing,std::function<Observation<bool>(std::stop_token)> validator) {
        NativeDirectoryReplayRequest request;request.source=source_held;request.reviewed_metadata=metadata;
        request.destination_parent=parent;request.destination_name=target;
        if(existing) {mkdir(parent,target);request.existing_destination=take(HeldChild::observe(parent,target));}
        request.journal_root=root;request.journal_name=name(("directory-"+std::to_string(sequence)+".journal").c_str());
        request.journal_id.bytes[0]=std::byte(sequence);request.review_digest[0]=std::byte{1};request.verify_children=std::move(validator);
        // This fixture's reviewed plan selects distinct siblings under this
        // same retained parent. This hook is not native Root qualification.
        request.verify_plan=[source=source_held,parent=parent,target=target](std::stop_token) {
            return Observation<bool>::available(source->parent().get()==parent.get()&&source->name()!=target);
        };
        return request;
    }
};
bool terminal(DirectoryReplayPhase phase) {
    return phase==DirectoryReplayPhase::Complete||phase==DirectoryReplayPhase::Cancelled||
        phase==DirectoryReplayPhase::Unsupported||phase==DirectoryReplayPhase::ReviewRequired;
}
void await(NativeDirectoryReplayJob& job,DirectoryReplayPhase wanted) {
    auto previous=job.progress().phase;
    for(unsigned i=0;i<50&&!terminal(job.progress().phase)&&job.progress().phase!=wanted;++i){previous=job.progress().phase;job.advance();}
    if(job.progress().phase!=wanted)std::fprintf(stderr,"phase=%u error=%s code=%lld finish=%s code=%lld\n",unsigned(job.progress().phase),
        job.progress().failure.operation.data(),static_cast<long long>(job.progress().failure.code),job.progress().finish_failure.operation.data(),static_cast<long long>(job.progress().finish_failure.code));
    if(job.progress().phase!=wanted)std::fprintf(stderr,"case=%u previous_phase=%u\n",sequence,unsigned(previous));
    CHECK(job.progress().phase==wanted);
}
void copy_payload(Fixture& f,Cursor destination,Cursor source={}) {
#ifdef _WIN32
    NativeOperationCopyBatchRequest request;request.sources.push_back(take(HeldChild::observe_with_access(source?source:f.source,name("payload"),EntryAccess::ContentRead)));
    request.destination=destination;request.destination_names.push_back(name("payload"));
    request.journal_root=take(f.address.child_address(name(("journal-"+std::to_string(sequence)).c_str())));
    request.journal_id.bytes[0]=std::byte(sequence+100);request.policy.metadata_policy=f.metadata.policy;request.policy.metadata_scope=f.metadata.policy.scope;
    request.open_journal=[root=f.root](const NativeAbsolutePath&,const NativeName& leaf,bool create){return root->open_journal(leaf,create);};
    auto batch=take(create_native_operation_copy_batch(std::move(request)));
    for(unsigned i=0;i<5000&&(batch->state()==OperationBatchState::Ready||batch->state()==OperationBatchState::Running);++i)batch->advance();
    CHECK(batch->state()==OperationBatchState::Complete);
#else
    (void)f;(void)source;file(destination,name("payload"));
#endif
}
void positive(const std::filesystem::path& path,bool existing,bool exact_name=false,bool with_ads=false,bool complete=false) {
    Fixture f(path,false,with_ads,complete);HeldChild::Pointer copied;bool ready=false;
    std::fprintf(stderr,"directory case=%u existing=%u ads=%u complete=%u exact=%u\n",sequence,unsigned(existing),unsigned(with_ads),unsigned(complete),unsigned(exact_name));
#ifdef _WIN32
    if(exact_name)f.target=*NativeName::from_windows(std::u16string(u"directory-猫-")+char16_t(0xdc00)+u"-"+std::u16string(1,char16_t(u'a'+sequence)));
#else
    (void)exact_name;
#endif
    auto request=f.request(existing,[&](std::stop_token stop) {
        if(!ready)return Observation<bool>::available(false);
        auto fresh=copied->refresh(stop);if(!fresh.value())return Observation<bool>::unavailable(fresh.state(),fresh.unavailable_detail()->error);
        if(!(*fresh.value())->continues(*copied))return Observation<bool>::unavailable(ObservationState::Changed);
        return Observation<bool>::available(true);
    });
    auto job=take(NativeDirectoryReplayJob::create(std::move(request)));job->advance();
#ifndef _WIN32
    if(!existing) {CHECK(job->progress().phase==DirectoryReplayPhase::Unsupported&&!job->progress().creation_attempted);
        CHECK(take(f.parent->lookup_child(f.target,ChildLookupMode::NativeDefault)).state()==ChildLookupState::Missing);CHECK(take(f.root->finish_io()));return;}
#endif
    CHECK(job->progress().phase==DirectoryReplayPhase::AwaitingChildren&&!job->progress().metadata_attempted);
    auto pending=job->children_finished();CHECK(pending.value()&&!*pending.value());
    auto cursor=take(job->child_cursor());copy_payload(f,cursor);copied=take(HeldChild::observe_with_access(cursor,name("payload"),EntryAccess::ContentRead));ready=true;
    CHECK(take(job->children_finished()));await(*job,DirectoryReplayPhase::Complete);
    CHECK(job->progress().worker_drained&&!job->progress().recovery_required);
    auto target=take(HeldChild::observe(f.parent,f.target));auto captured=take(target->capture_metadata(f.metadata.policy));
    CHECK(captured.basic.modified.value()&&*captured.basic.modified.value()==*f.metadata.basic.modified.value());
    CHECK(captured.attributes.size()==f.metadata.attributes.size());
    for(const auto& expected:f.metadata.attributes) {
        const auto actual=std::find_if(captured.attributes.begin(),captured.attributes.end(),[&](const auto& value){return value.identifier==expected.identifier;});
        CHECK(actual!=captured.attributes.end()&&actual->bytes==expected.bytes);
    }
    CHECK(captured.channels.size()==f.metadata.channels.size());
    for(std::size_t i=0;i<captured.channels.size();++i)CHECK(captured.channels[i].identifier==f.metadata.channels[i].identifier&&captured.channels[i].digest==f.metadata.channels[i].digest);
    CHECK(take(payload_matches(*copied,{}))); // External consumer read after job completion.
#ifndef _WIN32
    CHECK(captured.basic.posix_permissions.value()&&*captured.basic.posix_permissions.value()==0550);
#endif
    CHECK(take(f.root->finish_io()));CHECK(job->advance().phase==DirectoryReplayPhase::Complete);
}
#ifdef _WIN32
void nested_tree(const std::filesystem::path& path) {
    Fixture f(path,true);HeldChild::Pointer nested_binding,payload_binding;bool child_complete=false,payload_complete=false;
    auto parent_request=f.request(false,[&](std::stop_token stop) {
        if(!child_complete)return Observation<bool>::available(false);
        auto refreshed=nested_binding->refresh(stop);if(!refreshed.value())return Observation<bool>::unavailable(refreshed.state(),refreshed.unavailable_detail()->error);
        return Observation<bool>::available((*refreshed.value())->continues(*nested_binding));
    });
    auto parent=take(NativeDirectoryReplayJob::create(std::move(parent_request)));parent->advance();
    CHECK(parent->progress().phase==DirectoryReplayPhase::AwaitingChildren);auto parent_cursor=take(parent->child_cursor());
    auto source_nested=child(f.source,name("nested"));
    NativeDirectoryReplayRequest request;request.source=take(HeldChild::observe_with_access(f.source,name("nested"),EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));
    request.reviewed_metadata=take(request.source->capture_metadata(f.metadata.policy));request.destination_parent=parent_cursor;request.destination_name=name("nested");
    request.journal_root=f.root;request.journal_name=name(("nested-"+std::to_string(sequence)+".journal").c_str());request.journal_id.bytes[0]=std::byte(sequence+50);
    request.verify_plan=[&](std::stop_token) {
        return Observation<bool>::available(parent->progress().created&&parent->progress().phase==DirectoryReplayPhase::AwaitingChildren);
    };
    request.verify_children=[&](std::stop_token stop) {
        if(!payload_complete)return Observation<bool>::available(false);
        auto refreshed=payload_binding->refresh(stop);if(!refreshed.value())return Observation<bool>::unavailable(refreshed.state(),refreshed.unavailable_detail()->error);
        return Observation<bool>::available((*refreshed.value())->continues(*payload_binding));
    };
    auto nested=take(NativeDirectoryReplayJob::create(std::move(request)));nested->advance();
    CHECK(nested->progress().phase==DirectoryReplayPhase::AwaitingChildren);auto nested_cursor=take(nested->child_cursor());
    nested_binding=take(HeldChild::observe(parent_cursor,name("nested")));
    copy_payload(f,nested_cursor,source_nested);payload_binding=take(HeldChild::observe_with_access(nested_cursor,name("payload"),EntryAccess::ContentRead));payload_complete=true;
    CHECK(take(nested->children_finished()));await(*nested,DirectoryReplayPhase::Complete);child_complete=true;
    CHECK(!parent->progress().metadata_attempted);CHECK(take(parent->children_finished()));await(*parent,DirectoryReplayPhase::Complete);
    CHECK(take(payload_matches(*payload_binding,{})));CHECK(take(f.root->finish_io()));
}
#endif
std::optional<std::int64_t> journal_close_fault(detail::JournalRootFaultPoint point) {
    return point==detail::JournalRootFaultPoint::JournalClose?std::optional<std::int64_t>{5}:std::nullopt;
}
std::optional<std::int64_t> journal_close_oom(detail::JournalRootFaultPoint point) {
    if(point!=detail::JournalRootFaultPoint::JournalClose)return std::nullopt;
    fail_next_allocation=true;return 5; // After actual native close; fail diagnostic allocation only.
}
void finish_failure(const std::filesystem::path& path,bool writer_failure,bool oom=false) {
    Fixture f(path);auto job=take(NativeDirectoryReplayJob::create(f.request(true,[](std::stop_token){return Observation<bool>::available(true);})));job->advance();
    CHECK(job->progress().phase==DirectoryReplayPhase::AwaitingChildren);CHECK(take(job->children_finished()));await(*job,DirectoryReplayPhase::ClosingWriter);
    if(writer_failure) {auto held=take(HeldChild::observe(f.parent,f.target));flush_target=*held->metadata().identity.value();injected_flushes=0;inject_writer_flush=true;}
    else {allocation_failures=0;detail::journal_root_test_fault=oom?journal_close_oom:journal_close_fault;}
    for(unsigned i=0;i<30&&!terminal(job->progress().phase);++i)job->advance();
    inject_writer_flush=false;detail::journal_root_test_fault=nullptr;
    CHECK(!fail_next_allocation);if(oom)CHECK(allocation_failures==1);
    CHECK(job->progress().phase==DirectoryReplayPhase::ReviewRequired&&job->progress().worker_drained&&job->progress().recovery_required);
    CHECK(job->progress().finish_failure.present&&job->progress().finish_failure.code==5);
    if(writer_failure)CHECK(injected_flushes==1);
    const auto root_result=f.root->finish_io();CHECK(!root_result.value()&&root_result.unavailable_detail()->error.code==5);
    const auto count=injected_flushes.load();job->advance();job.reset();CHECK(injected_flushes==count);
}
void cancelled(const std::filesystem::path& path,bool after_create) {
    Fixture f(path);auto job=take(NativeDirectoryReplayJob::create(f.request(!after_create,[](std::stop_token){return Observation<bool>::available(false);})));std::stop_source stop;
    if(after_create) {
        job->advance();
#ifndef _WIN32
        CHECK(job->progress().phase==DirectoryReplayPhase::Unsupported);CHECK(take(f.root->finish_io()));return;
#else
        CHECK(job->progress().created&&job->progress().phase==DirectoryReplayPhase::AwaitingChildren);
#endif
    }
    stop.request_stop();job->advance(stop.get_token());CHECK(job->progress().worker_drained);
    CHECK(job->progress().phase==(after_create?DirectoryReplayPhase::ReviewRequired:DirectoryReplayPhase::Cancelled));
    CHECK(job->progress().recovery_required==after_create);CHECK(take(f.root->finish_io()));
}
void changed_source(const std::filesystem::path& path) {
    Fixture f(path);auto request=f.request(false,[](std::stop_token){return Observation<bool>::available(true);});
#ifndef _WIN32
    auto source_address=take(f.address.child_address(f.source_held->name()));CHECK(::chmod(source_address.host_path().value()->c_str(),0750)==0);
#else
    directory_permissions(take(f.address.child_address(f.source_held->name())),false);
#endif
    auto job=take(NativeDirectoryReplayJob::create(std::move(request)));job->advance();
    CHECK(job->progress().phase==DirectoryReplayPhase::ReviewRequired&&!job->progress().creation_attempted&&!job->progress().metadata_attempted);
    CHECK(take(f.parent->lookup_child(f.target,ChildLookupMode::NativeDefault)).state()==ChildLookupState::Missing);CHECK(take(f.root->finish_io()));
}
void changed_source_after_prepare(const std::filesystem::path& path) {
    Fixture f(path);auto job=take(NativeDirectoryReplayJob::create(f.request(false,[](std::stop_token){return Observation<bool>::available(true);})));
    job->advance();
#ifndef _WIN32
    CHECK(job->progress().phase==DirectoryReplayPhase::Unsupported);CHECK(take(f.root->finish_io()));
#else
    CHECK(job->progress().phase==DirectoryReplayPhase::AwaitingChildren&&job->progress().created);
    directory_permissions(take(f.address.child_address(f.source_held->name())),false);
    const auto result=job->children_finished();CHECK(!result.value());
    CHECK(job->progress().phase==DirectoryReplayPhase::ReviewRequired&&job->progress().worker_drained&&job->progress().recovery_required);
    CHECK(!job->progress().metadata_attempted);CHECK(take(f.parent->lookup_child(f.target,ChildLookupMode::NativeDefault)).state()==ChildLookupState::Found);
    CHECK(take(f.root->finish_io()));
#endif
}
void run(const std::filesystem::path& path) {
    positive(path,true);positive(path,false);cancelled(path,false);cancelled(path,true);changed_source(path);
    finish_failure(path,true);finish_failure(path,false);finish_failure(path,false,true);changed_source_after_prepare(path);
#ifdef _WIN32
    CHECK(extended_address(take(NativeAbsolutePath::from_windows(u"V:\\exact-猫")))==L"\\\\?\\V:\\exact-猫");
    CHECK(extended_address(take(NativeAbsolutePath::from_windows(u"\\\\server\\share\\exact-猫")))==L"\\\\?\\UNC\\server\\share\\exact-猫");
    CHECK(extended_address(take(NativeAbsolutePath::from_windows(u"\\\\?\\V:\\exact-猫")))==L"\\\\?\\V:\\exact-猫");
    CHECK(extended_address(take(NativeAbsolutePath::from_windows(u"\\\\?\\UNC\\server\\share\\exact-猫")))==L"\\\\?\\UNC\\server\\share\\exact-猫");
    SecurityPrivilege privilege;
    nested_tree(path);
    positive(path,false,true);
    positive(path,true,true,true);positive(path,false,true,true);
    positive(path,false,true,true,true);positive(path,true,true,true,true);
    NativeFileSystem filesystem;auto address=take(NativeAbsolutePath::from_host(path));auto current=Cursor(take(filesystem.open_native_directory(address)));
    for(unsigned i=0;i<5;++i) {
        const auto leaf=*NativeName::from_windows(std::u16string(70,u'猫')+char16_t(u'a'+i));
        current=mkdir(current,leaf);address=take(address.child_address(leaf));
    }
    CHECK(address.windows_units()->size()>260);positive(take(address.host_path()),false,true);
#endif
    std::printf("directory_executor: %u checks passed\n",checks);
}
}
void* operator new(std::size_t size) {
    if(fail_next_allocation){fail_next_allocation=false;++allocation_failures;throw std::bad_alloc();}
    if(auto* pointer=std::malloc(size?size:1))return pointer;throw std::bad_alloc();
}
void* operator new[](std::size_t size){return ::operator new(size);}
void operator delete(void* pointer)noexcept{std::free(pointer);}
void operator delete[](void* pointer)noexcept{std::free(pointer);}
void operator delete(void* pointer,std::size_t)noexcept{std::free(pointer);}
void operator delete[](void* pointer,std::size_t)noexcept{std::free(pointer);}
#ifdef _WIN32
extern "C" BOOL (WINAPI* __imp_FlushFileBuffers)(HANDLE)=observed_flush;
int wmain(int argc,wchar_t** argv){CHECK(argc==2);run(std::filesystem::path(argv[1]));return 0;}
#else
extern "C" int fsync(int fd){return observed_fsync(fd);}
int main(int argc,char** argv){CHECK(argc==2);run(std::filesystem::path(argv[1]));return 0;}
#endif
