// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "prepared_journal_root.hpp"
#include "prepared_journal_directory.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "native_filesystem.hpp"
#include "platform/journal_root_test_faults.hpp"
#include "../src/c-api/journal_root_handles.hpp"
#include "../src/c-api/native_handles.hpp"
#include <atomic>
#include <array>
#include <algorithm>
#include <cwchar>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <thread>
#include <string>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#ifdef _MSC_VER
#include <crtdbg.h>
#endif
#include "windows_name.hpp"
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/acl.h>
#include <membership.h>
#endif
#endif
using namespace ck::files;
extern "C" int journal_root_c_smoke(void);
namespace {
std::atomic<bool> fail_worker_allocation{false},allocation_failed{false};
thread_local bool test_caller=false,deny_allocations=false;
}
void* operator new(std::size_t n) {
    if(deny_allocations)throw std::bad_alloc();
    if(!test_caller&&fail_worker_allocation.exchange(false)) {allocation_failed=true;throw std::bad_alloc();}
    if(void* p=std::malloc(n?n:1))return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
namespace {
template<class T> T take(Observation<T> value) {
    if(!value.value()) {std::fprintf(stderr,"journal root: state=%d code=%lld operation=%s\n",int(value.state()),
        static_cast<long long>(value.unavailable_detail()->error.code),value.unavailable_detail()->error.operation.c_str());std::abort();}
    return std::move(value).take_value();
}
NativeName name(const char* text) {
#ifdef _WIN32
    return *NativeName::from_windows(std::u16string(text,text+std::strlen(text)));
#else
    return *NativeName::from_posix(text);
#endif
}
NativeAbsolutePath child(const NativeAbsolutePath& p,const char* text) {return take(p.child_address(name(text)));}
#ifdef _WIN32
std::wstring wide(const NativeAbsolutePath& p) {return *windows_extended_path(take(p.host_path()).native());}
void mkdir(const NativeAbsolutePath& p) {assert(CreateDirectoryW(wide(p).c_str(),nullptr));}
bool move(const NativeAbsolutePath& a,const NativeAbsolutePath& b) {return MoveFileExW(wide(a).c_str(),wide(b).c_str(),MOVEFILE_WRITE_THROUGH)!=0;}
bool exists(const NativeAbsolutePath& p) {return GetFileAttributesW(wide(p).c_str())!=INVALID_FILE_ATTRIBUTES;}
#else
void mkdir(const NativeAbsolutePath& p) {assert(::mkdir(p.posix_bytes()->c_str(),0700)==0);}
bool move(const NativeAbsolutePath& a,const NativeAbsolutePath& b) {return ::rename(a.posix_bytes()->c_str(),b.posix_bytes()->c_str())==0;}
bool exists(const NativeAbsolutePath& p) {struct stat s{};return lstat(p.posix_bytes()->c_str(),&s)==0;}
#endif
std::shared_ptr<const DirectoryCursor> hold(const NativeAbsolutePath& p) {
    static NativeFileSystem fs;
    return std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(p)));
}
PreparedJournalRoot::Pointer prepare(std::shared_ptr<const DirectoryCursor> parent,const char* component,
    JournalRootDisposition mode=JournalRootDisposition::ProvisionChild) {
    PreparedJournalRootRequest request;request.parent=std::move(parent);request.disposition=mode;
    if(component)request.child=name(component);
    JournalRootPreparationProgress progress;auto root=take(prepare_native_journal_root(std::move(request),progress));
    assert(progress.phase==JournalRootPreparationPhase::Ready&&progress.acquired_directories&&
        progress.flushed_directories&&progress.flushed_directories<=progress.acquired_directories);
    return root;
}
void bytes(OperationJournalFile& file) {
    const std::array<std::byte,4> value{std::byte{1},std::byte{2},std::byte{3},std::byte{4}};
    assert(take(file.write_at(0,value))==value.size());assert(take(file.flush()));
    std::array<std::byte,4> read{};assert(take(file.read_at(0,read))==read.size()&&read==value);
}
class ForeignRoot final : public PreparedJournalRoot {
public:
    ObjectIdentity id;std::optional<NativeAbsolutePath> hint;
    Observation<std::unique_ptr<OperationJournalFile>> open_journal(const NativeName&,bool) override {return {};}
    Observation<bool> revalidate() const override {return Observation<bool>::available(true);}
    Observation<bool> sync() override {return Observation<bool>::available(true);}
    Observation<bool> finish_io() override {return Observation<bool>::available(true);}
    const ObjectIdentity& identity()const noexcept override{return id;}
    NameEncoding encoding()const noexcept override{return NameEncoding::PosixBytes;}
    const std::optional<NativeAbsolutePath>& navigation_address()const noexcept override{return hint;}
};
void enumeration(const std::shared_ptr<const DirectoryCursor>& parent) {
    auto foreign=std::make_shared<ForeignRoot>();
    assert(detail::duplicate_prepared_journal_directory(*foreign).state()==ObservationState::Unsupported);
    assert(open_prepared_journal_directory(foreign).state()==ObservationState::Unsupported);
    assert(detail::inspect_prepared_journal_ancestry(*foreign).state()==ObservationState::Unsupported);
    auto root=prepare(parent,"enumeration");
    auto ancestry=take(detail::inspect_prepared_journal_ancestry(*root));assert(ancestry.size()>=2);
    assert(compare_identity(ancestry.front(),root->identity())==IdentityComparison::Same);
    for(const auto& id:ancestry)assert(id.scope==root->identity().scope&&id.scheme==root->identity().scheme);
    const std::array<NativeName,3> expected{name("first"),name("second"),name("third")};
    for(const auto& n:expected) {auto file=take(root->open_journal(n,true));bytes(*file);assert(take(file->finish_io()));}
    auto native=take(detail::duplicate_prepared_journal_directory(*root));
#ifdef _WIN32
    FILE_ID_INFO native_id{};assert(GetFileInformationByHandleEx(native,FileIdInfo,&native_id,sizeof(native_id)));
    assert(root->identity().volume==NativeIdentifier::from_u64(native_id.VolumeSerialNumber));assert(CloseHandle(native));
#else
    struct stat st{};assert(!fstat(native,&st)&&S_ISDIR(st.st_mode));assert(!close(native));
#endif
    auto first=take(open_prepared_journal_directory(root)),second=take(open_prepared_journal_directory(root));
    assert(compare_identity(*first->identity().value(),root->identity())==IdentityComparison::Same);
    assert(first->source_scope().value()&&*first->source_scope().value()==root->identity().scope);
    std::stop_source stop;stop.request_stop();assert(first->read(1,stop.get_token()).state==DirectoryReadState::Cancelled);
    std::vector<NativeName> a,b;
    for(auto* view:{first.get(),second.get()}) {
        auto& found=view==first.get()?a:b;
        for(unsigned step=0;step<100;++step) {
            auto page=view->read(1);assert(page.names.size()<=1&&page.state!=DirectoryReadState::Error);
            for(auto& n:page.names)found.push_back(std::move(n));
            if(page.state==DirectoryReadState::End)break;
        }
        assert(found.size()==expected.size());
        for(const auto& n:expected)assert(std::find(found.begin(),found.end(),n)!=found.end());
    }
    assert(a==b);assert(root->finish_io().state()==ObservationState::Changed);
    assert(!first->open_child(expected.front()).value()); // enumeration confers no child authority
    assert(take(first->finish_io()));assert(take(first->finish_io()));first.reset();
    assert(root->finish_io().state()==ObservationState::Changed);
    assert(take(second->finish_io()));second.reset();assert(take(root->finish_io()));
}
void normal_and_held_adoption(const NativeAbsolutePath& address,const std::shared_ptr<const DirectoryCursor>& parent) {
    auto root=prepare(parent,"ordinary");auto id=root->identity();
#ifdef _WIN32
    std::u16string text=u"journal-";text.push_back(char16_t(0xd800));text+=u".bin";auto exact=*NativeName::from_windows(std::move(text));
#elif defined(__APPLE__)
    assert(!root->open_journal(*NativeName::from_posix(std::string("journal-\xff.bin")),true).value());
    auto exact=*NativeName::from_posix(std::string("journal-\xc3\xa9.bin"));
#else
    auto exact=*NativeName::from_posix(std::string("journal-\xff.bin"));
#endif
    auto file=take(root->open_journal(exact,true));bytes(*file);
    assert(!root->open_journal(exact,true).value());
    assert(root->finish_io().state()==ObservationState::Changed); // live file consumer
    assert(take(file->finish_io()));file.reset();assert(take(root->finish_io()));root.reset();
    auto held=hold(child(address,"ordinary"));root=prepare(held,nullptr,JournalRootDisposition::AdoptHeld);
    assert(compare_identity(id,root->identity())==IdentityComparison::Same);
#ifdef __APPLE__
    assert(id.generation.has_value()&&root->identity().generation.has_value());
    assert(held->identity().value()&&compare_identity(*held->identity().value(),root->identity())==IdentityComparison::Same);
#endif
    file=take(open_prepared_operation_journal_file(*root,exact,false));assert(take(file->size())==4);
    assert(take(file->finish_io()));file.reset();assert(take(root->finish_io()));
}
void root_substitution(const NativeAbsolutePath& address,const std::shared_ptr<const DirectoryCursor>& parent) {
    auto root=prepare(parent,"replace");const auto original=child(address,"replace"),moved=child(address,"replace-moved");
#ifdef _WIN32
    assert(!move(original,moved)); // held native root denies DELETE sharing
    assert(take(root->revalidate()));assert(take(root->finish_io()));
#else
    assert(move(original,moved));mkdir(original);
    assert(!root->revalidate().value());assert(!root->sync().value());
    assert(!root->open_journal(name("must-not-create"),true).value());
    assert(!exists(child(original,"must-not-create"))&&!exists(child(moved,"must-not-create")));
    assert(!root->finish_io().value());
#endif
    root.reset();
#ifndef _WIN32
    auto other=child(address,"other-parent");mkdir(other);
    root=prepare(parent,"cross-parent");assert(move(child(address,"cross-parent"),child(other,"cross-parent")));
    assert(!root->open_journal(name("no-write"),true).value());assert(!root->finish_io().value());
#endif
}
thread_local detail::JournalRootFaultPoint armed_point=detail::JournalRootFaultPoint::DirectoryFlush;
thread_local unsigned skip_fault=0,fault_calls=0;thread_local bool fault_armed=false;
std::optional<std::int64_t> fault(detail::JournalRootFaultPoint point) {
    if(point!=armed_point||!fault_armed)return {};
    ++fault_calls;if(skip_fault){--skip_fault;return {};}
    fault_armed=false;
#ifdef _WIN32
    return ERROR_WRITE_FAULT;
#else
    return EIO;
#endif
}
struct FaultScope {
    FaultScope(detail::JournalRootFaultPoint point,unsigned skip=0) {armed_point=point;skip_fault=skip;fault_calls=0;fault_armed=true;detail::journal_root_test_fault=fault;}
    ~FaultScope(){detail::journal_root_test_fault=nullptr;fault_armed=false;}
};
void durability_and_close_faults(const NativeAbsolutePath& address,const std::shared_ptr<const DirectoryCursor>& parent) {
    {
        FaultScope inject(detail::JournalRootFaultPoint::DirectoryFlush,1);
        PreparedJournalRootRequest request;request.parent=parent;request.child=name("barrier-failed");request.disposition=JournalRootDisposition::ProvisionChild;
        JournalRootPreparationProgress progress;auto failed=prepare_native_journal_root(request,progress);
        assert(!failed.value()&&progress.directory_creates==1&&progress.flushed_directories==1);
        assert(exists(child(address,"barrier-failed"))); // never unsafe pathname cleanup
    }
    auto root=prepare(parent,"close-failed");
    {
        FaultScope inject(detail::JournalRootFaultPoint::DirectoryClose);auto failed=root->finish_io();assert(!failed.value());
        const auto calls=fault_calls;auto again=root->finish_io();assert(!again.value()&&fault_calls==calls);
        assert(failed.unavailable_detail()->error==again.unavailable_detail()->error);
    }
    root.reset();root=prepare(parent,"journal-close-failed");auto file=take(root->open_journal(name("journal"),true));bytes(*file);
    {
        FaultScope inject(detail::JournalRootFaultPoint::JournalClose);auto failed=file->finish_io();assert(!failed.value());
        const auto calls=fault_calls;assert(!file->finish_io().value()&&fault_calls==calls);
    }
    file.reset();assert(!root->finish_io().value());
}
void sticky_consumer_close(const std::shared_ptr<const DirectoryCursor>& parent) {
    detail::PreparedJournalConsumerFailure slot;slot.domain=ErrorDomain::Posix;slot.code=123;
    ForeignRoot foreign;
    assert(!detail::record_prepared_journal_consumer_failure(foreign,ObservationState::Failed,ErrorDomain::Posix,5,"foreign"));
    assert(!detail::read_prepared_journal_consumer_failure(foreign,slot)&&slot.domain==ErrorDomain::None&&slot.code==0);
    auto root=prepare(parent,"consumer-latch-noalloc");
    deny_allocations=true;
    assert(detail::record_prepared_journal_consumer_failure(*root,ObservationState::Changed,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidAccess),"consumer.first_close_failed"));
    assert(detail::record_prepared_journal_consumer_failure(*root,ObservationState::Failed,ErrorDomain::Posix,999,"consumer.second"));
    assert(detail::read_prepared_journal_consumer_failure(*root,slot));
    deny_allocations=false;
    assert(slot.state==ObservationState::Changed&&slot.domain==ErrorDomain::Adapter&&
        slot.code==static_cast<std::int64_t>(AdapterError::InvalidAccess)&&!std::strcmp(slot.operation.data(),"consumer.first_close_failed"));
    assert(!root->revalidate().value()&&!root->open_journal(name("refused"),true).value());
    auto failed=root->finish_io();assert(!failed.value()&&failed.state()==slot.state&&failed.unavailable_detail()->error.operation==slot.operation.data());
    assert(!root->finish_io().value());
    for(bool fallback:{false,true}) {
        root=prepare(parent,fallback?"view-close-fallback":"view-close-explicit");
        auto view=take(open_prepared_journal_directory(root));
        {FaultScope inject(detail::JournalRootFaultPoint::DirectoryClose);
            if(fallback)view.reset();
            else {assert(!view->finish_io().value());const auto calls=fault_calls;assert(!view->finish_io().value()&&fault_calls==calls);view.reset();}}
        assert(detail::read_prepared_journal_consumer_failure(*root,slot));
        assert(!std::strcmp(slot.operation.data(),"journal_root.enumeration_close"));
        assert(!root->revalidate().value()&&!root->sync().value());
        failed=root->finish_io();assert(!failed.value()&&failed.unavailable_detail()->error.code==slot.code);
    }
    root=prepare(parent,"journal-close-fallback");auto file=take(root->open_journal(name("journal"),true));bytes(*file);
    {FaultScope inject(detail::JournalRootFaultPoint::JournalClose);file.reset();}
    assert(detail::read_prepared_journal_consumer_failure(*root,slot)&&!root->finish_io().value());
}
#ifdef _WIN32
void windows_boundaries(const NativeAbsolutePath& address,const std::shared_ptr<const DirectoryCursor>& parent) {
    const auto unsafe=child(address,"inherited-root");mkdir(unsafe);
    HANDLE handle=CreateFileW(wide(unsafe).c_str(),READ_CONTROL|WRITE_DAC,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    assert(handle!=INVALID_HANDLE_VALUE);PACL acl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    assert(GetSecurityInfo(handle,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&acl,nullptr,&descriptor)==ERROR_SUCCESS);
    assert(SetSecurityInfo(handle,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|UNPROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,nullptr,acl,nullptr)==ERROR_SUCCESS);LocalFree(descriptor);assert(CloseHandle(handle));
    PreparedJournalRootRequest request;request.parent=parent;request.child=name("inherited-root");request.disposition=JournalRootDisposition::AdoptChild;
    JournalRootPreparationProgress progress;assert(!prepare_native_journal_root(request,progress).value());
    assert(progress.directory_creates==0);
    auto deep=child(address,"long-parent");mkdir(deep);
    for(unsigned level=0;level<14;++level) {deep=child(deep,"component-012345678901234567890123");mkdir(deep);}
    assert(deep.windows_units()->size()>260);
    auto root=prepare(hold(deep),"private-root");auto file=take(root->open_journal(name("journal"),true));bytes(*file);
    assert(take(file->finish_io()));file.reset();assert(take(root->finish_io()));root.reset();
    // Explicit network-scope refusal against an existing loopback share, with
    // no share creation, root access changes, or path-based journal fallback.
    auto units=*address.windows_units();if(units.starts_with(u"\\\\?\\"))units.erase(0,4);
    bool unc_checked=false;
    if(units.size()>2&&units[1]==u':') {
        std::u16string unc=u"\\\\localhost\\";unc.push_back(units[0]);unc+=u"$";unc+=units.substr(2);
        auto path=NativeAbsolutePath::from_windows(unc);assert(path.value());NativeFileSystem fs;
        auto opened=fs.open_native_directory(*path.value());
        if(opened.value()) {
            request={};request.parent=std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
            auto network=prepare_native_journal_root(request,progress);
            assert(!network.value()&&network.state()==ObservationState::Unsupported);unc_checked=true;
        }
    }
    wchar_t required[8]{};
    if(GetEnvironmentVariableW(L"CK_FS_REQUIRE_UNC_JOURNAL_TEST",required,8)==1&&required[0]==L'1')assert(unc_checked);
    std::puts(unc_checked?"prepared journal root: UNC native scope refusal verified":"prepared journal root: UNC fixture unavailable; network qualification not run");
}
#endif
#ifdef __APPLE__
void inherited_acl(const NativeAbsolutePath& address,const std::shared_ptr<const DirectoryCursor>& parent) {
    auto path=child(address,"acl-parent");mkdir(path);int fd=open(path.posix_bytes()->c_str(),O_RDONLY|O_DIRECTORY);assert(fd>=0);
    acl_t acl=acl_init(1);assert(acl);acl_entry_t entry{};assert(acl_create_entry(&acl,&entry)==0&&acl_set_tag_type(entry,ACL_EXTENDED_ALLOW)==0);
    uuid_t principal{};assert(mbr_uid_to_uuid(geteuid(),principal)==0&&acl_set_qualifier(entry,principal)==0);
    acl_permset_t permissions{};assert(acl_get_permset(entry,&permissions)==0&&acl_add_perm(permissions,ACL_READ_DATA)==0&&acl_set_permset(entry,permissions)==0);
    acl_flagset_t flags{};assert(acl_get_flagset_np(entry,&flags)==0&&acl_add_flag_np(flags,ACL_ENTRY_DIRECTORY_INHERIT)==0&&
        acl_add_flag_np(flags,ACL_ENTRY_FILE_INHERIT)==0&&acl_add_flag_np(flags,ACL_ENTRY_ONLY_INHERIT)==0&&acl_set_flagset_np(entry,flags)==0);
    assert(acl_set_fd_np(fd,acl,ACL_TYPE_EXTENDED)==0&&acl_free(acl)==0);
    PreparedJournalRootRequest request;request.parent=hold(path);request.child=name("inherited");request.disposition=JournalRootDisposition::ProvisionChild;
    JournalRootPreparationProgress progress;auto denied=prepare_native_journal_root(request,progress);assert(!denied.value()&&denied.state()==ObservationState::Denied);
    acl=acl_init(0);assert(acl&&acl_set_fd_np(fd,acl,ACL_TYPE_EXTENDED)==0&&acl_free(acl)==0);assert(close(fd)==0);
    if(const auto* noowners=std::getenv("CK_FS_TEST_NOOWNERS_ROOT")) {
        request={};request.parent=hold(take(NativeAbsolutePath::from_posix(noowners)));request.disposition=JournalRootDisposition::AdoptHeld;
        auto unsupported=prepare_native_journal_root(request,progress);assert(!unsupported.value()&&unsupported.state()==ObservationState::Unsupported);
    }
    (void)parent;
}
#endif
ckfjr_snapshot_v1 wait_for(ckfjr_root* root,bool drain) {
    ckfjr_snapshot_v1 snapshot;ckfjr_snapshot_init_v1(&snapshot);
    for(unsigned step=0;step<1000;++step) {
        assert(ckfjr_poll_v1(root,&snapshot)==CKFE_API_OK);
        if(drain?snapshot.worker_drained:(snapshot.state!=CKFJR_PREPARING))return snapshot;
        assert(ckfjr_wait_v1(root,50)==CKFE_API_OK);
    }
    assert(false);return snapshot;
}
ckfjr_root* async_root(ckfe_directory& parent,const char* child_name) {
    ckfjr_options_v1 options;ckfjr_options_init_v1(&options);options.parent=&parent;options.disposition=CKFJR_PROVISION_CHILD;
    auto n=name(child_name);options.child.encoding=static_cast<uint32_t>(n.encoding());
#ifdef _WIN32
    options.child.data=n.windows_units()->data();options.child.byte_count=n.windows_units()->size()*2;
#else
    options.child.data=n.posix_bytes()->data();options.child.byte_count=n.posix_bytes()->size();
#endif
    ckfjr_root* root=nullptr;assert(ckfjr_start_v1(&options,&root)==CKFE_API_OK&&root);
    auto ready=wait_for(root,false);if(ready.state!=CKFJR_READY)std::fprintf(stderr,"C root failed: %s\n",ready.failure_operation);
    assert(ready.state==CKFJR_READY&&!ready.worker_drained);return root;
}
void c_lifetime(ckfe_directory& parent) {
    auto* root=async_root(parent,"async");ckfjr_root* alias{};assert(ckfjr_retain_v1(root,&alias)==CKFE_API_OK&&alias);ckfjr_release(alias);
    auto consumer=take(retain_prepared_journal_root(root));assert(ckfjr_finish_v1(root)==CKFE_API_OK);
    assert(!retain_prepared_journal_root(root).value());uint32_t drained=1;assert(ckfjr_worker_drained_v1(root,&drained)==CKFE_API_OK&&!drained);
    auto file=take(consumer->open_journal(name("still-owned"),true));bytes(*file);assert(take(file->finish_io()));file.reset();
    assert(ckfjr_wait_v1(root,30)==CKFE_API_OK);assert(ckfjr_worker_drained_v1(root,&drained)==CKFE_API_OK&&!drained);
    consumer.reset();auto final=wait_for(root,true);assert(final.state==CKFJR_COMPLETE);ckfjr_release(root);
}
std::atomic<ckfjr_root*> preparation_fault_root{nullptr};
std::atomic<bool> preparation_fault_armed{false};bool preparation_native_error=false;
std::int64_t native_io_error() noexcept {
#ifdef _WIN32
    return ERROR_WRITE_FAULT;
#else
    return EIO;
#endif
}
ErrorDomain native_io_domain() noexcept {
#ifdef _WIN32
    return ErrorDomain::Win32;
#else
    return ErrorDomain::Posix;
#endif
}
std::optional<std::int64_t> cancel_during_flush(detail::JournalRootFaultPoint point) {
    if(point!=detail::JournalRootFaultPoint::DirectoryFlush||!preparation_fault_armed.exchange(false))return {};
    auto* root=preparation_fault_root.load(std::memory_order_acquire);
    while(!root) {preparation_fault_root.wait(nullptr,std::memory_order_acquire);root=preparation_fault_root.load(std::memory_order_acquire);}
    assert(ckfjr_cancel_v1(root)==CKFE_API_OK);
    return preparation_native_error?std::optional<std::int64_t>{native_io_error()}:std::nullopt;
}
void c_preparation_cancel_classification(ckfe_directory& parent) {
    for(bool io_error:{false,true}) {
        ckfjr_options_v1 options;ckfjr_options_init_v1(&options);options.parent=&parent;options.disposition=CKFJR_PROVISION_CHILD;
        auto component=name(io_error?"cancel-native-error":"cancel-cooperative");options.child.encoding=static_cast<uint32_t>(component.encoding());
#ifdef _WIN32
        options.child.data=component.windows_units()->data();options.child.byte_count=component.windows_units()->size()*2;
#else
        options.child.data=component.posix_bytes()->data();options.child.byte_count=component.posix_bytes()->size();
#endif
        preparation_fault_root=nullptr;preparation_native_error=io_error;preparation_fault_armed=true;
        detail::journal_root_test_worker_fault=cancel_during_flush;
        ckfjr_root* root=nullptr;assert(ckfjr_start_v1(&options,&root)==CKFE_API_OK&&root);
        preparation_fault_root.store(root,std::memory_order_release);preparation_fault_root.notify_all();
        auto final=wait_for(root,true);detail::journal_root_test_worker_fault=nullptr;preparation_fault_root=nullptr;
        assert(final.recovery_required&&final.directory_creates==1);
        if(io_error)assert(final.state==CKFJR_FAILED&&final.failure_domain==static_cast<uint32_t>(native_io_domain())&&final.failure_code==native_io_error());
        else assert(final.state==CKFJR_CANCELLED&&final.failure_state==static_cast<uint32_t>(ObservationState::Changed)&&
            final.failure_domain==static_cast<uint32_t>(ErrorDomain::Adapter)&&final.failure_code==static_cast<std::int64_t>(AdapterError::InterruptedRead));
        ckfjr_release(root);
    }
}
std::atomic<unsigned> original_close_calls{0};std::atomic<bool> original_fault_armed{false};
detail::JournalRootFaultPoint original_fault_point=detail::JournalRootFaultPoint::DirectoryClose;
std::optional<std::int64_t> original_root_fault(detail::JournalRootFaultPoint point) {
    if(point==detail::JournalRootFaultPoint::DirectoryClose)++original_close_calls;
    if(point!=original_fault_point||!original_fault_armed.exchange(false))return {};
    fail_worker_allocation=true;return native_io_error();
}
void c_original_root_error_oom(ckfe_directory& parent) {
    for(bool close:{false,true}) {
        auto* root=async_root(parent,close?"original-close-oom":"original-flush-oom");
        ckfjr_snapshot_v1 ready;ckfjr_snapshot_init_v1(&ready);assert(ckfjr_poll_v1(root,&ready)==CKFE_API_OK);
        original_close_calls=0;original_fault_armed=true;allocation_failed=false;
        original_fault_point=close?detail::JournalRootFaultPoint::DirectoryClose:detail::JournalRootFaultPoint::DirectoryFlush;
        detail::journal_root_test_worker_fault=original_root_fault;
        assert(ckfjr_finish_v1(root)==CKFE_API_OK);auto final=wait_for(root,true);
        detail::journal_root_test_worker_fault=nullptr;fail_worker_allocation=false;
        assert(allocation_failed&&final.state==CKFJR_FAILED&&final.recovery_required&&final.failure_domain==static_cast<uint32_t>(native_io_domain())&&
            final.failure_code==native_io_error()&&original_close_calls==ready.acquired_directories);
#ifdef _WIN32
        const char* operation=close?"journal_root.directory_CloseHandle":"journal_root.directory_FlushFileBuffers";
#else
        const char* operation=close?"journal_root.directory_close":"journal_root.directory_fsync";
#endif
        assert(!std::strcmp(final.failure_operation,operation));
        std::printf("Root own %s+OOM: domain=%u code=%lld operation=%s explicit_closes=%u/%u\n",
            close?"close":"flush",final.failure_domain,static_cast<long long>(final.failure_code),final.failure_operation,
            original_close_calls.load(),ready.acquired_directories);
        const auto calls=original_close_calls.load();assert(ckfjr_finish_v1(root)==CKFE_API_OK);
        assert(ckfjr_poll_v1(root,&final)==CKFE_API_OK&&final.state==CKFJR_FAILED&&final.worker_drained&&original_close_calls==calls);
        ckfjr_release(root);
    }
}
std::atomic<bool> publication_paused{false},publication_release{false};
void pause_publication() noexcept {
    publication_paused.store(true,std::memory_order_release);publication_paused.notify_all();
    while(!publication_release.load(std::memory_order_acquire))publication_release.wait(false,std::memory_order_acquire);
}
void c_pending_publication(ckfe_directory& parent) {
    auto* root=async_root(parent,"async-pending-close");auto consumer=take(retain_prepared_journal_root(root));
    auto view=take(open_prepared_journal_directory(consumer));ckfjr_snapshot_v1 ready;ckfjr_snapshot_init_v1(&ready);
    assert(ckfjr_poll_v1(root,&ready)==CKFE_API_OK);publication_paused=false;publication_release=false;
    detail::journal_root_test_publication_pause=pause_publication;
    std::thread publisher([view=std::move(view)]() mutable {
        FaultScope inject(detail::JournalRootFaultPoint::DirectoryClose);assert(!view->finish_io().value());view.reset();
    });
    while(!publication_paused.load(std::memory_order_acquire))publication_paused.wait(false,std::memory_order_acquire);
    detail::PreparedJournalConsumerFailure slot;
    deny_allocations=true;
    assert(detail::read_prepared_journal_consumer_failure(*consumer,slot)&&slot.pending);
    ckfjr_root* blocked_alias=nullptr;
    assert(ckfjr_retain_v1(root,&blocked_alias)==CKFE_API_INVALID_ARGUMENT&&!blocked_alias);
    assert(detail::record_prepared_journal_consumer_failure(*consumer,ObservationState::Failed,ErrorDomain::Posix,999,"must_not_replace_first"));
    deny_allocations=false;
    // Debug STL Observation/string bookkeeping can allocate; the fixed read
    // and C clone guard above must not. All forms still refuse authority.
    assert(!consumer->revalidate().value()&&!detail::duplicate_prepared_journal_directory(*consumer).value());
    assert(!retain_prepared_journal_root(root).value());
    ckfjr_snapshot_v1 pending;ckfjr_snapshot_init_v1(&pending);assert(ckfjr_poll_v1(root,&pending)==CKFE_API_OK);
    assert(pending.state==CKFJR_FAILED&&pending.sequence==ready.sequence+1&&!pending.worker_drained);
    auto repeat=pending;assert(ckfjr_poll_v1(root,&repeat)==CKFE_API_OK&&repeat.sequence==pending.sequence);
    assert(!retain_prepared_journal_root(root).value());ckfjr_root* alias=reinterpret_cast<ckfjr_root*>(uintptr_t(1));
    assert(ckfjr_retain_v1(root,&alias)==CKFE_API_INVALID_ARGUMENT&&!alias);
    assert(ckfjr_poll_v1(root,&repeat)==CKFE_API_OK&&repeat.sequence==pending.sequence);
    publication_release.store(true,std::memory_order_release);publication_release.notify_all();publisher.join();
    detail::journal_root_test_publication_pause=nullptr;
    assert(detail::read_prepared_journal_consumer_failure(*consumer,slot)&&!slot.pending);
    ckfjr_snapshot_v1 published;ckfjr_snapshot_init_v1(&published);assert(ckfjr_poll_v1(root,&published)==CKFE_API_OK);
    assert(published.state==CKFJR_FAILED&&published.sequence==pending.sequence+1&&published.failure_domain==static_cast<uint32_t>(slot.domain)&&
        published.failure_code==slot.code&&!std::strcmp(published.failure_operation,"journal_root.enumeration_close"));
    assert(ckfjr_poll_v1(root,&repeat)==CKFE_API_OK&&repeat.sequence==published.sequence);
    assert(ckfjr_finish_v1(root)==CKFE_API_OK);consumer.reset();published=wait_for(root,true);
    assert(published.state==CKFJR_FAILED&&published.failure_code==slot.code&&!std::strcmp(published.failure_operation,slot.operation.data()));
    ckfjr_release(root);
}
void c_sticky_close_oom(ckfe_directory& parent) {
    auto* root=async_root(parent,"async-sticky-close");auto consumer=take(retain_prepared_journal_root(root));
    auto view=take(open_prepared_journal_directory(consumer));
    {FaultScope inject(detail::JournalRootFaultPoint::DirectoryClose);assert(!view->finish_io().value());}
    view.reset();detail::PreparedJournalConsumerFailure first;assert(detail::read_prepared_journal_consumer_failure(*consumer,first));
    ckfjr_snapshot_v1 state;ckfjr_snapshot_init_v1(&state);assert(ckfjr_poll_v1(root,&state)==CKFE_API_OK);
    assert(state.state==CKFJR_FAILED&&!state.worker_drained&&state.failure_domain==static_cast<uint32_t>(first.domain)&&state.failure_code==first.code);
    assert(!retain_prepared_journal_root(root).value());ckfjr_root* alias=reinterpret_cast<ckfjr_root*>(uintptr_t(1));
    assert(ckfjr_retain_v1(root,&alias)==CKFE_API_INVALID_ARGUMENT&&!alias);
    assert(ckfjr_finish_v1(root)==CKFE_API_OK);allocation_failed=false;fail_worker_allocation=true;
    consumer.reset();state=wait_for(root,true);fail_worker_allocation=false;
    assert(allocation_failed&&state.state==CKFJR_FAILED&&state.recovery_required&&state.failure_code==first.code&&
        state.failure_domain==static_cast<uint32_t>(first.domain)&&!std::strcmp(state.failure_operation,first.operation.data()));
    assert(ckfjr_finish_v1(root)==CKFE_API_OK);assert(ckfjr_poll_v1(root,&state)==CKFE_API_OK&&state.state==CKFJR_FAILED&&state.worker_drained);
    ckfjr_release(root);
}
void c_sticky_busy_code(ckfe_directory& parent) {
    auto* root=async_root(parent,"async-sticky-busy");auto consumer=take(retain_prepared_journal_root(root));
    assert(detail::record_prepared_journal_consumer_failure(*consumer,ObservationState::Changed,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidAccess),"journal_root.consumers_active"));
    assert(ckfjr_finish_v1(root)==CKFE_API_OK);consumer.reset();const auto state=wait_for(root,true);
    assert(state.state==CKFJR_FAILED&&state.failure_code==static_cast<std::int64_t>(AdapterError::InvalidAccess)&&
        !std::strcmp(state.failure_operation,"journal_root.consumers_active"));ckfjr_release(root);
}
void c_admission(ckfe_directory& parent) {
    std::array<ckfjr_root*,CKFJR_MAX_ROOTS> held{};
    ckfjr_options_v1 options;ckfjr_options_init_v1(&options);options.parent=&parent;
    for(auto& root:held) {
        assert(ckfjr_start_v1(&options,&root)==CKFE_API_OK&&root);
        assert(ckfjr_cancel_v1(root)==CKFE_API_OK);(void)wait_for(root,true);
    }
    ckfjr_root* extra=reinterpret_cast<ckfjr_root*>(uintptr_t(1));
    assert(ckfjr_start_v1(&options,&extra)==CKFE_API_BUSY&&!extra);
    for(auto* root:held)ckfjr_release(root);
}
void c_exception_with_consumer(ckfe_directory& parent) {
    auto* root=async_root(parent,"exception-held");auto consumer=take(retain_prepared_journal_root(root));
    detail::journal_root_test_worker_exception=true;assert(ckfjr_finish_v1(root)==CKFE_API_OK);
    ckfjr_snapshot_v1 failed;ckfjr_snapshot_init_v1(&failed);
    for(unsigned i=0;i<1000;++i) {
        assert(ckfjr_poll_v1(root,&failed)==CKFE_API_OK);
        if(failed.state==CKFJR_FAILED)break;
        assert(ckfjr_wait_v1(root,20)==CKFE_API_OK);
    }
    assert(failed.state==CKFJR_FAILED&&!failed.worker_drained);
    for(unsigned i=0;i<3;++i) {
        assert(ckfjr_finish_v1(root)==CKFE_API_OK);assert(!retain_prepared_journal_root(root).value());
        ckfjr_root* alias=reinterpret_cast<ckfjr_root*>(uintptr_t(1));
        assert(ckfjr_retain_v1(root,&alias)==CKFE_API_INVALID_ARGUMENT&&!alias);
        assert(ckfjr_poll_v1(root,&failed)==CKFE_API_OK&&failed.state==CKFJR_FAILED&&!failed.worker_drained);
    }
    consumer.reset();failed=wait_for(root,true);assert(failed.state==CKFJR_FAILED&&failed.recovery_required);ckfjr_release(root);
}
#ifndef _WIN32
void c_finalization_oom(const NativeAbsolutePath& address,ckfe_directory& parent) {
    auto* root=async_root(parent,"oom");auto consumer=take(retain_prepared_journal_root(root));
    assert(move(child(address,"oom"),child(address,"oom-moved")));
    allocation_failed=false;fail_worker_allocation=true;
    assert(ckfjr_finish_v1(root)==CKFE_API_OK);assert(ckfjr_wait_v1(root,30)==CKFE_API_OK);
    uint32_t drained=1;assert(ckfjr_worker_drained_v1(root,&drained)==CKFE_API_OK&&!drained&&!allocation_failed);
    consumer.reset();auto final=wait_for(root,true);fail_worker_allocation=false;
    std::fprintf(stderr,"metadata-revalidation OOM: allocated=%d state=%u failure_state=%u domain=%u code=%lld operation=%s drained=%u\n",
        int(allocation_failed.load()),final.state,final.failure_state,final.failure_domain,static_cast<long long>(final.failure_code),final.failure_operation,final.worker_drained);
    assert(allocation_failed&&final.state==CKFJR_FAILED&&final.recovery_required&&final.worker_drained&&
        final.failure_state==static_cast<uint32_t>(ObservationState::Unknown)&&
        final.failure_domain==static_cast<uint32_t>(ErrorDomain::Adapter)&&
        final.failure_code==static_cast<std::int64_t>(AdapterError::InvalidNativeResult)&&
        std::strcmp(final.failure_operation,"journal_root.finalizer_exception")==0);
    ckfjr_release(root);
}
#endif
int tests(NativeAbsolutePath address) {
    test_caller=true;std::setvbuf(stdout,nullptr,_IONBF,0);std::setvbuf(stderr,nullptr,_IONBF,0);
#ifdef _MSC_VER
    _set_error_mode(_OUT_TO_STDERR);
    _CrtSetReportMode(_CRT_ASSERT,_CRTDBG_MODE_FILE);_CrtSetReportFile(_CRT_ASSERT,_CRTDBG_FILE_STDERR);
#endif
    assert(journal_root_c_smoke()==0);
#ifdef __APPLE__
    assert(address.posix_bytes()&&(address.posix_bytes()->starts_with("/Volumes/PRO-BLADE/tmp/")||address.posix_bytes()->starts_with("/Volumes/S8T/tmp/")));
#endif
#ifdef _WIN32
    wchar_t policy[8]{};
    if(GetEnvironmentVariableW(L"CK_FS_REQUIRE_V_DEV_DRIVE",policy,8)==1&&policy[0]==L'1') {
        assert(GetFileAttributesW(L"V:\\")!=INVALID_FILE_ATTRIBUTES);
        const auto& p=*address.windows_units();assert(p.starts_with(u"V:\\tmp\\")||p.starts_with(u"\\\\?\\V:\\tmp\\"));
    }
#endif
    auto parent=hold(address);enumeration(parent);normal_and_held_adoption(address,parent);root_substitution(address,parent);
    durability_and_close_faults(address,parent);sticky_consumer_close(parent);
#ifdef _WIN32
    windows_boundaries(address,parent);
#endif
#ifdef __APPLE__
    inherited_acl(address,parent);
#endif
    ckfe_directory c_parent{parent,address};c_lifetime(c_parent);
    std::puts("Root test: exception");c_exception_with_consumer(c_parent);
    std::puts("Root test: consumer OOM");c_sticky_close_oom(c_parent);
    std::puts("Root test: busy code");c_sticky_busy_code(c_parent);
    std::puts("Root test: pending publication");c_pending_publication(c_parent);
    std::puts("Root test: cancellation");c_preparation_cancel_classification(c_parent);
    std::puts("Root test: own OOM");c_original_root_error_oom(c_parent);
#ifndef _WIN32
    c_finalization_oom(address,c_parent);
#endif
    c_admission(c_parent);
    std::puts("prepared journal root: native relative I/O, substitution, durability, close faults and C lifetime passed");return 0;
}
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {assert(argc==2);test_caller=true;return tests(take(NativeAbsolutePath::from_windows(std::u16string(argv[1],argv[1]+std::wcslen(argv[1])))));}
#else
int main(int argc,char** argv) {assert(argc==2);test_caller=true;return tests(take(NativeAbsolutePath::from_posix(argv[1])));}
#endif
