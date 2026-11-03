// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "private_journal_membership.hpp"
#include "native_filesystem.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "platform/native_journal_directory_bridge.hpp"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <string>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <winioctl.h>
#else
#include <cerrno>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {std::atomic<bool> fail_allocations{false};}
void* operator new(std::size_t size) {
    if(fail_allocations.load(std::memory_order_relaxed))throw std::bad_alloc();
    if(auto* value=std::malloc(size?size:1))return value;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size){return ::operator new(size);}
void operator delete(void* value) noexcept {std::free(value);}
void operator delete[](void* value) noexcept {std::free(value);}
void operator delete(void* value,std::size_t) noexcept {std::free(value);}
void operator delete[](void* value,std::size_t) noexcept {std::free(value);}

using namespace ck::files;
namespace {
unsigned checks=0;
void check(bool value,const char* expression,int line) {
    ++checks;if(!value)throw std::runtime_error(std::string("line ")+std::to_string(line)+": "+expression);
}
#define CHECK(x) check(bool(x),#x,__LINE__)
unsigned handles() {
#ifdef _WIN32
    DWORD value=0;CHECK(GetProcessHandleCount(GetCurrentProcess(),&value));return value;
#else
#ifdef __APPLE__
    DIR* dir=opendir("/dev/fd");
#else
    DIR* dir=opendir("/proc/self/fd");
#endif
    CHECK(dir);unsigned value=0;
    while(const auto* entry=readdir(dir))if(std::strcmp(entry->d_name,".")&&std::strcmp(entry->d_name,".."))++value;
    CHECK(closedir(dir)==0);return value;
#endif
}
template<class T> T take(Observation<T> value) {
    if(!value.value()) {
        const auto& error=*value.unavailable_detail();
        throw std::runtime_error(error.error.operation+" state="+std::to_string(int(error.state))+" code="+std::to_string(error.error.code));
    }
    return std::move(value).take_value();
}
NativeName name(std::string value) {
#ifdef _WIN32
    return *NativeName::from_windows(std::u16string(value.begin(),value.end()));
#else
    return *NativeName::from_posix(std::move(value));
#endif
}
using Cursor=std::shared_ptr<const DirectoryCursor>;
Cursor child(const Cursor& parent,const std::string& value) {return Cursor(take(parent->create_child_directory(name(value))));}
void file(const Cursor& parent,const std::string& value) {
    auto writer=take(parent->create_child_file(name(value)));
    const std::byte bytes[]{std::byte{0x42},std::byte{0x31}};
    CHECK(take(writer->write_content(0,bytes))==2);CHECK(take(writer->finish_content_writes()));
}
void link(const Cursor& source,const std::string& from,const Cursor& target,const std::string& to) {
    auto held=take(HeldChild::observe(source,name(from)));
    CHECK(take(source->create_hard_link(name(from),*held->metadata().identity.value(),*target,name(to))));
}
void unsafe(Observation<bool> value) {
    CHECK(!value.value()&&value.state()==ObservationState::Unsupported);
    CHECK(value.unavailable_detail()->error.domain==ErrorDomain::Adapter&&
        value.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe));
}
struct Fixture {
    NativeFileSystem fs;Cursor parent,source,state;PreparedJournalRoot::Pointer root;
    static unsigned sequence;
    explicit Fixture(const NativeAbsolutePath& scratch) {
        auto base=Cursor(take(fs.open_native_directory(scratch)));
        parent=child(base,"membership-"+std::to_string(++sequence));source=child(parent,"source");
        PreparedJournalRootRequest request;request.parent=parent;request.child=name("journals");
        request.disposition=JournalRootDisposition::ProvisionChild;JournalRootPreparationProgress progress;
        root=take(prepare_native_journal_root(std::move(request),progress));
        state=Cursor(take(parent->open_directory_child(name("journals"))));
        auto journal=take(root->open_journal(name("private-state"),true));
        const std::byte data[]{std::byte{9},std::byte{8},std::byte{7}};
        CHECK(take(journal->write_at(0,data))==3);CHECK(take(journal->finish_io()));
    }
    HeldChild::Pointer ordinary() {
        file(source,"ordinary");link(source,"ordinary",source,"ordinary-alias");
        // Link creation changes ctime/nlink: observe ONLY after the link exists.
        return take(HeldChild::observe(source,name("ordinary-alias")));
    }
    void finish(){CHECK(take(root->finish_io()));root.reset();}
};
unsigned Fixture::sequence=0;
Cursor mutation_directory;
bool mutate_namespace=false,mutate_source=false,close_fault=false,close_oom=false;
unsigned close_calls=0;
std::optional<std::int64_t> fault(detail::PrivateMembershipFaultPoint point) {
    if(point==detail::PrivateMembershipFaultPoint::BeforeFinalCheck) {
        if(mutate_namespace){mutate_namespace=false;file(mutation_directory,"added-during-proof");}
        if(mutate_source){mutate_source=false;link(mutation_directory,"ordinary",mutation_directory,"changed-link-count");}
    }
    if(point==detail::PrivateMembershipFaultPoint::Close) {
        ++close_calls;
        if(close_fault) {
            close_fault=false;if(close_oom)fail_allocations.store(true,std::memory_order_relaxed);
#ifdef _WIN32
            return ERROR_WRITE_FAULT;
#else
            return EIO;
#endif
        }
    }
    return {};
}
struct ResetFault {
    ~ResetFault(){fail_allocations.store(false);detail::private_membership_test_fault=nullptr;
        mutation_directory.reset();mutate_namespace=mutate_source=close_fault=close_oom=false;}
};
void positives_and_aliases(const NativeAbsolutePath& scratch) {
    Fixture f(scratch);auto ordinary=f.ordinary();CHECK(*ordinary->metadata().link_count.value()==2);
    CHECK(take(qualify_private_journal_disjointness(*f.root,*ordinary)));
    NativeFileSystem second; // A genuinely different engine/AdapterScope.
    auto other_parent=Cursor(take(second.open_native_directory(take(scratch.child_address(name("membership-"+std::to_string(Fixture::sequence)))))));
    auto other_source=Cursor(take(other_parent->open_directory_child(name("source"))));
    auto external=take(HeldChild::observe(other_source,name("ordinary-alias")));
    CHECK(compare_identity(*external->metadata().identity.value(),f.root->identity())==IdentityComparison::Unknown);
    CHECK(take(qualify_private_journal_disjointness(*f.root,*external)));
    link(f.state,"private-state",f.source,"private-alias");
    auto alias=take(HeldChild::observe(f.source,name("private-alias")));
    unsafe(qualify_private_journal_disjointness(*f.root,*alias));f.finish();
    Fixture nested(scratch);auto inside=child(nested.state,"nested");file(inside,"only-nested");
    link(inside,"only-nested",nested.source,"nested-alias");
    auto selected=take(HeldChild::observe(nested.source,name("nested-alias")));
    unsafe(qualify_private_journal_disjointness(*nested.root,*selected));nested.finish();
    Fixture exact(scratch);
#ifdef _WIN32
    std::u16string units=u"raw-";units.push_back(static_cast<char16_t>(0xd800));units+=u". ";
    const auto raw=*NativeName::from_windows(units);units.insert(0,u"alias-");
    const auto raw_alias=*NativeName::from_windows(units);
#elif defined(__APPLE__)
    // APFS accepts valid UTF-8 names, but rejects an invalid byte sequence.
    // NativeName preserves the original bytes; the provider must surface the
    // kernel error instead of re-encoding them into a different filename.
    auto invalid=exact.source->create_child_file(*NativeName::from_posix("invalid-\xff"));
    CHECK(!invalid.value()&&invalid.unavailable_detail()->error.domain==ErrorDomain::Posix&&
        invalid.unavailable_detail()->error.code==EILSEQ);
    auto empty=take(exact.parent->open_directory_child(name("source")));
    auto empty_page=empty->read(8);CHECK(empty_page.state==DirectoryReadState::End&&empty_page.names.empty());
    const auto raw=*NativeName::from_posix("raw-\xc3\xa9. ");
    const auto raw_alias=*NativeName::from_posix("alias-\xc3\xa9. ");
#else
    const auto raw=*NativeName::from_posix("raw-\xff. ");
    const auto raw_alias=*NativeName::from_posix("alias-\xff. ");
#endif
    {auto writer=take(exact.source->create_child_file(raw));CHECK(take(writer->finish_content_writes()));}
    auto original=take(HeldChild::observe(exact.source,raw));
    CHECK(take(exact.source->create_hard_link(raw,*original->metadata().identity.value(),*exact.source,raw_alias)));
    auto raw_selected=take(HeldChild::observe(exact.source,raw_alias));
    CHECK(take(qualify_private_journal_disjointness(*exact.root,*raw_selected)));
    CHECK(take(exact.source->create_hard_link(raw,*original->metadata().identity.value(),*exact.state,raw)));
    raw_selected=take(HeldChild::observe(exact.source,raw_alias));
    unsafe(qualify_private_journal_disjointness(*exact.root,*raw_selected));exact.finish();
}
void bounds_and_changes(const NativeAbsolutePath& scratch) {
    Fixture f(scratch);auto selected=f.ordinary();file(f.state,"extra");auto inside=child(f.state,"nested");child(inside,"deep");
    PrivateJournalMembershipLimits limits;limits.max_records=1;unsafe(qualify_private_journal_disjointness(*f.root,*selected,limits));
    limits={};limits.max_name_bytes=1;unsafe(qualify_private_journal_disjointness(*f.root,*selected,limits));
    limits={};limits.max_directories=1;unsafe(qualify_private_journal_disjointness(*f.root,*selected,limits));
    limits={};limits.max_depth=1;unsafe(qualify_private_journal_disjointness(*f.root,*selected,limits));
    std::stop_source stop;stop.request_stop();auto cancelled=qualify_private_journal_disjointness(*f.root,*selected,{},stop.get_token());
    CHECK(!cancelled.value()&&cancelled.state()==ObservationState::Changed);
    {ResetFault reset;mutation_directory=f.state;mutate_namespace=true;detail::private_membership_test_fault=fault;
        auto changed=qualify_private_journal_disjointness(*f.root,*selected);CHECK(!changed.value()&&changed.state()==ObservationState::Changed);}
    {ResetFault reset;mutation_directory=f.source;mutate_source=true;detail::private_membership_test_fault=fault;
        auto changed=qualify_private_journal_disjointness(*f.root,*selected);CHECK(!changed.value()&&changed.state()==ObservationState::Changed);}
    // A stale held snapshot must not become a new mutation authority.
    auto stale=qualify_private_journal_disjointness(*f.root,*selected);CHECK(!stale.value()&&stale.state()==ObservationState::Changed);
    f.finish();
}
void close_errors(const NativeAbsolutePath& scratch) {
    for(bool oom:{false,true}) {
        Fixture f(scratch);auto selected=f.ordinary();detail::PreparedJournalConsumerFailure stored;
        const auto before=handles();
        {ResetFault reset;close_calls=0;close_fault=true;close_oom=oom;detail::private_membership_test_fault=fault;
            bool refused=false;
            try {auto result=qualify_private_journal_disjointness(*f.root,*selected);refused=!result.value();}
            catch(const std::bad_alloc&){refused=true;}
            fail_allocations.store(false);CHECK(refused);CHECK(close_calls>=3);
            CHECK(detail::read_prepared_journal_consumer_failure(*f.root,stored));
#ifdef _WIN32
            CHECK(stored.domain==ErrorDomain::Win32&&stored.code==ERROR_WRITE_FAULT);
#else
            CHECK(stored.domain==ErrorDomain::Posix&&stored.code==EIO);
#endif
            const auto calls=close_calls;CHECK(detail::read_prepared_journal_consumer_failure(*f.root,stored));CHECK(close_calls==calls);
        }
        CHECK(handles()==before);
        auto finished=f.root->finish_io();CHECK(!finished.value());CHECK(finished.unavailable_detail()->error.domain==stored.domain&&finished.unavailable_detail()->error.code==stored.code);
        auto repeated=f.root->finish_io();CHECK(!repeated.value()&&repeated.unavailable_detail()->error.code==stored.code);
    }
}
#ifndef _WIN32
void denied_and_special(const NativeAbsolutePath& scratch) {
    CHECK(geteuid()!=0);Fixture f(scratch);auto selected=f.ordinary();child(f.state,"denied");
    auto fd=take(detail::duplicate_posix_journal_directory(*f.state));
    CHECK(fchmodat(fd,"denied",0000,0)==0);
    auto denied=qualify_private_journal_disjointness(*f.root,*selected);
    CHECK(fchmodat(fd,"denied",0700,0)==0);
    CHECK(!denied.value()&&denied.state()==ObservationState::Denied&&denied.unavailable_detail()->error.domain==ErrorDomain::Posix);
    CHECK(symlinkat("private-state",fd,"no-follow")==0);
    unsafe(qualify_private_journal_disjointness(*f.root,*selected));
    CHECK(unlinkat(fd,"no-follow",0)==0);CHECK(close(fd)==0);f.finish();
}
#else
void denied_and_special(const NativeAbsolutePath& scratch) {
    Fixture f(scratch);auto selected=f.ordinary();auto denied=child(f.state,"denied");
    const auto duplicate=take(detail::duplicate_windows_journal_directory(*denied));
    const auto hint=static_cast<HANDLE>(duplicate);FILE_ID_INFO id{};
    CHECK(GetFileInformationByHandleEx(hint,FileIdInfo,&id,sizeof(id)));
    FILE_ID_DESCRIPTOR descriptor{};descriptor.dwSize=sizeof(descriptor);descriptor.Type=ExtendedFileIdType;descriptor.ExtendedFileId=id.FileId;
    HANDLE writable=OpenFileById(hint,&descriptor,WRITE_DAC|READ_CONTROL|FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT);
    CHECK(writable!=INVALID_HANDLE_VALUE);CHECK(CloseHandle(hint));
    PSECURITY_DESCRIPTOR old=nullptr;PACL old_acl=nullptr,new_acl=nullptr;
    CHECK(GetSecurityInfo(writable,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&old_acl,nullptr,&old)==ERROR_SUCCESS);
    std::array<std::byte,SECURITY_MAX_SID_SIZE> sid{};DWORD sid_bytes=static_cast<DWORD>(sid.size());
    CHECK(CreateWellKnownSid(WinWorldSid,nullptr,sid.data(),&sid_bytes));
    EXPLICIT_ACCESS_W rule{};rule.grfAccessPermissions=FILE_LIST_DIRECTORY;rule.grfAccessMode=DENY_ACCESS;
    rule.Trustee.TrusteeForm=TRUSTEE_IS_SID;rule.Trustee.ptstrName=reinterpret_cast<LPWSTR>(sid.data());
    CHECK(SetEntriesInAclW(1,&rule,old_acl,&new_acl)==ERROR_SUCCESS);
    CHECK(SetSecurityInfo(writable,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,nullptr,new_acl,nullptr)==ERROR_SUCCESS);
    // The workstation account has backup/restore privileges enabled. Use a
    // restricted THREAD token for this actual access-denied observation; no
    // machine/account security settings are changed.
    HANDLE process_token=nullptr,restricted=nullptr;
    CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE|TOKEN_QUERY,&process_token));
    CHECK(CreateRestrictedToken(process_token,DISABLE_MAX_PRIVILEGE,0,nullptr,0,nullptr,0,nullptr,&restricted));
    CHECK(CloseHandle(process_token));CHECK(ImpersonateLoggedOnUser(restricted));
    struct Revert {bool active=true;~Revert(){if(active)RevertToSelf();}} revert;
    auto refused=qualify_private_journal_disjointness(*f.root,*selected);
    CHECK(RevertToSelf());revert.active=false;CHECK(CloseHandle(restricted));
    CHECK(SetSecurityInfo(writable,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,nullptr,old_acl,nullptr)==ERROR_SUCCESS);
    LocalFree(new_acl);LocalFree(old);CHECK(CloseHandle(writable));
    CHECK(!refused.value()&&refused.state()==ObservationState::Denied&&refused.unavailable_detail()->error.domain==ErrorDomain::Win32);
    auto junction=child(f.state,"no-follow");
    const auto raw=take(detail::duplicate_windows_journal_directory(*junction));const auto directory=static_cast<HANDLE>(raw);
    CHECK(GetFileInformationByHandleEx(directory,FileIdInfo,&id,sizeof(id)));descriptor.ExtendedFileId=id.FileId;
    writable=OpenFileById(directory,&descriptor,GENERIC_READ|GENERIC_WRITE|FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT);
    CHECK(writable!=INVALID_HANDLE_VALUE);CHECK(CloseHandle(directory));
    struct Reparse {DWORD tag;WORD bytes,reserved,sub_offset,sub_bytes,print_offset,print_bytes;WCHAR path[32];};
    Reparse reparse{};constexpr wchar_t target[]=L"\\??\\V:\\";
    reparse.tag=IO_REPARSE_TAG_MOUNT_POINT;reparse.sub_bytes=sizeof(target)-sizeof(WCHAR);
    reparse.print_offset=sizeof(target);reparse.bytes=8+sizeof(target)+sizeof(WCHAR);
    std::memcpy(reparse.path,target,sizeof(target));DWORD returned=0;
    CHECK(DeviceIoControl(writable,FSCTL_SET_REPARSE_POINT,&reparse,8+reparse.bytes,nullptr,0,&returned,nullptr));
    CHECK(CloseHandle(writable));unsafe(qualify_private_journal_disjointness(*f.root,*selected));f.finish();
}
#endif
int run(const NativeAbsolutePath& scratch) {
    positives_and_aliases(scratch);bounds_and_changes(scratch);close_errors(scratch);
    denied_and_special(scratch);
    std::printf("private journal membership: %u checks passed\n",checks);return 0;
}
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {
    try {CHECK(argc==2||argc==3);std::u16string units;for(auto p=argv[1];*p;++p)units.push_back(static_cast<char16_t>(*p));
        auto scratch=take(NativeAbsolutePath::from_windows(std::move(units)));
        if(argc==3) {
            CHECK(std::wstring_view(argv[2])==L"--long");NativeFileSystem fs;auto cursor=Cursor(take(fs.open_native_directory(scratch)));
            for(unsigned n=0;n<18;++n){const std::string component="long-component-0123456789-"+std::to_string(n);
                cursor=child(cursor,component);scratch=take(scratch.child_address(name(component)));}
        }
        return run(scratch);}
    catch(const std::exception& e){fail_allocations.store(false);std::fprintf(stderr,"membership: %s\n",e.what());return 1;}
}
#else
int main(int argc,char** argv) {
    try {CHECK(argc==2);return run(take(NativeAbsolutePath::from_posix(argv[1])));}
    catch(const std::exception& e){fail_allocations.store(false);std::fprintf(stderr,"membership: %s\n",e.what());return 1;}
}
#endif
