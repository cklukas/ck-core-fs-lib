// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../native_trash.hpp"
#include "../private_journal_scope.hpp"
#include "prepared_journal_root_bridge.hpp"
#include "native_windows_journal_volume.hpp"
#include "journal_root_test_faults.hpp"
#include "../windows_parent_record.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <sddl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>
#include <utility>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace ck::files {
WindowsTrashHandle::~WindowsTrashHandle() { if(value_&&value_!=INVALID_HANDLE_VALUE) CloseHandle(value_); }
WindowsTrashHandle::WindowsTrashHandle(WindowsTrashHandle&& o) noexcept : value_(std::exchange(o.value_,nullptr)) {}
void* WindowsTrashHandle::release() noexcept {return std::exchange(value_,nullptr);}
WindowsTrashHandle& WindowsTrashHandle::operator=(WindowsTrashHandle&& o) noexcept {
    if(this!=&o) { WindowsTrashHandle old(std::exchange(value_,std::exchange(o.value_,nullptr))); } return *this;
}
WindowsTrashScopeHandle::~WindowsTrashScopeHandle() {
    const auto raw=handle_.release();if(!raw||raw==INVALID_HANDLE_VALUE)return;
    if(!CloseHandle(raw)&&root_)detail::record_prepared_journal_consumer_failure(*root_,ObservationState::Unknown,
        ErrorDomain::Win32,GetLastError(),"trash.scope_token_close");
}
namespace detail {
// Only this translation unit can mint the token consumed by the genuine
// query-only metadata projection. The original native owner stays alive.
class WindowsTrashScopeIssuer final {
public:
    static Observation<std::unique_ptr<NativeTrashDirectoryProjection>> project(HANDLE held,std::shared_ptr<PreparedJournalRoot> root) {
        HANDLE raw=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),held,GetCurrentProcess(),&raw,0,FALSE,DUPLICATE_SAME_ACCESS))
            return Observation<std::unique_ptr<NativeTrashDirectoryProjection>>::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32,GetLastError(),"trash.scope_duplicate"});
        return project_windows_trash_directory(WindowsTrashScopeHandle(WindowsTrashHandle(raw),std::move(root)));
    }
};
}
namespace {
using Handle=WindowsTrashHandle;
ObservationState state(DWORD code) {
    if(code==ERROR_FILE_NOT_FOUND||code==ERROR_PATH_NOT_FOUND) return ObservationState::Gone;
    if(code==ERROR_ALREADY_EXISTS||code==ERROR_FILE_EXISTS||code==ERROR_DELETE_PENDING) return ObservationState::Changed;
    if(code==ERROR_ACCESS_DENIED||code==ERROR_SHARING_VIOLATION||code==ERROR_LOCK_VIOLATION) return ObservationState::Denied;
    if(code==ERROR_NOT_SUPPORTED||code==ERROR_INVALID_FUNCTION||code==ERROR_INVALID_PARAMETER) return ObservationState::Unsupported;
    return ObservationState::Failed;
}
template<class T> Observation<T> fail(DWORD code,const char* op) {
    return Observation<T>::unavailable(state(code),{ErrorDomain::Win32,code,op});
}
template<class T> Observation<T> reject(const char* op,ObservationState s=ObservationState::Unsupported) {
    return Observation<T>::unavailable(s,{ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::ProviderReviewRequired),op});
}
template<class T,class U> Observation<T> forward(const Observation<U>& r) {
    const auto& e=*r.unavailable_detail(); return Observation<T>::unavailable(e.state,e.error);
}
bool valid_name(const NativeName& n) {
    const auto* w=n.windows_units();
    return n.is_valid()&&w&&w->size()<=32767&&w->find(u':')==w->npos;
}
Observation<NativeDurableIdentity> native_id(HANDLE,bool);
class PrivateScope final {
public:
    explicit PrivateScope(std::shared_ptr<PreparedJournalRoot> root):root_(std::move(root)) {
        views_.reserve(5);guards_.reserve(6);
    }
    ~PrivateScope() {
        try {(void)finish_io();}
        catch(...) {if(root_)detail::record_prepared_journal_consumer_failure(*root_,ObservationState::Unknown,
            ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InvalidNativeResult),"trash.scope_finish_exception");}
    }
    Observation<std::shared_ptr<const DirectoryCursor>> project_directory(HANDLE handle) {
        auto projected=detail::WindowsTrashScopeIssuer::project(handle,root_);
        if(!projected.value())return forward<std::shared_ptr<const DirectoryCursor>>(projected);
        auto view=std::move(projected).take_value();
        auto cursor=view->cursor();views_.push_back(std::move(view));
        return Observation<std::shared_ptr<const DirectoryCursor>>::available(std::move(cursor));
    }
    Observation<bool> bind_destination(HANDLE handle,std::stop_token stop) {
        auto cursor=project_directory(handle);if(!cursor.value())return forward<bool>(cursor);
        auto guard=JournalScopeGuard::create_for_namespace_child(root_,*cursor.value(),stop);
        if(!guard.value())return forward<bool>(guard);
        guards_.push_back(std::move(guard).take_value());
        return check(stop);
    }
    Observation<bool> bind_source(HeldChild::Pointer source,std::stop_token stop) {
        auto guard=JournalScopeGuard::create_for_entry(root_,*source,stop);
        if(!guard.value())return forward<bool>(guard);
        source_=std::move(source);guards_.push_back(std::move(guard).take_value());
        return check(stop);
    }
    Observation<bool> bind_restore_source(HANDLE actual_held,bool directory,std::stop_token stop) {
        auto bound=capture_source(actual_held,directory,false);if(!bound.value())return bound;
        if(directory) {
            // Project the live receipt owner's actual object, not its name or
            // persisted ID. No namespace/path reopen grants this scope proof.
            auto cursor=project_directory(actual_held);if(!cursor.value())return forward<bool>(cursor);
            auto guard=JournalScopeGuard::create(root_,*cursor.value(),stop);
            if(!guard.value())return forward<bool>(guard);
            guards_.push_back(std::move(guard).take_value());
        }
        return check(stop);
    }
    Observation<bool> bind_mutation_source(HANDLE actual_held,bool directory,std::stop_token stop) {
        auto bound=capture_source(actual_held,directory,true);if(!bound.value())return bound;
        source_.reset(); // The qualified native rename owner now pins it.
        return check(stop);
    }
    Observation<bool> check(std::stop_token stop,bool membership=true) const {
        if(finished_||!root_)return reject<bool>("trash.scope_finished_or_unbound",ObservationState::Changed);
        if(stop.stop_requested())return reject<bool>("trash.scope_cancelled",ObservationState::Changed);
        for(size_t n=0;n<guards_.size();n+=2) {
            auto valid=n+1<guards_.size()?JournalScopeGuard::check_pair(guards_[n],guards_[n+1],stop):guards_[n]->check_root(stop);
            if(!valid.value())return valid;
            if(!*valid.value())return reject<bool>("trash.scope_false");
        }
        if(source_&&membership) {
            auto current=source_->refresh(stop);if(!current.value())return forward<bool>(current);
            if(!(*current.value())->continues(*source_))return reject<bool>("trash.scope_source_changed",ObservationState::Changed);
        }
        if(native_source_) {
            auto current=native_id(native_source_,native_directory_);if(!current.value())return forward<bool>(current);
            if(!native_source_identity_||*current.value()!=*native_source_identity_)
                return reject<bool>("trash.scope_live_source_changed",ObservationState::Changed);
        }
        if(source_)for(const auto& guard:guards_) {
            auto entry=guard->check_entry(*source_,stop);if(!entry.value())return entry;
            if(!*entry.value())return reject<bool>("trash.scope_entry_false");
        }
        return Observation<bool>::available(true);
    }
    bool source_bound() const noexcept {return mutation_source_bound_;}
    bool read_failure(detail::PreparedJournalConsumerFailure& failure)const noexcept {
        return detail::read_prepared_journal_consumer_failure(*root_,failure);
    }
    void record_failure(ObservationState state,ErrorDomain domain,int64_t code,std::string_view operation)noexcept {
        detail::record_prepared_journal_consumer_failure(*root_,state,domain,code,operation);
    }
    Observation<bool> finish_io() {
        if(finished_)return finish_result();
        source_.reset();native_source_=nullptr;mutation_source_bound_=false;guards_.clear();
        // Release query handles even if an earlier one fails. The provider
        // caches close outcomes and consumes each handle exactly once.
        for(const auto& view:views_)try {
            auto closed=view->finish_io();
            if(!closed.value()) {
                const auto& error=*closed.unavailable_detail();
                remember(error.state,error.error.domain,error.error.code,error.error.operation);
            } else if(!*closed.value())remember(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<int64_t>(AdapterError::InvalidNativeResult),"trash.scope_finish_false");
        } catch(...) {
            // The native projection publishes the real close error to Root
            // before allocating a returned diagnostic. Do not replace it by
            // a generic exception if diagnostic construction failed.
            detail::PreparedJournalConsumerFailure latched;
            if(detail::read_prepared_journal_consumer_failure(*root_,latched)&&!latched.pending)
                remember(latched.state,latched.domain,latched.code,latched.operation.data());
            else remember(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<int64_t>(AdapterError::InvalidNativeResult),"trash.scope_finish_exception");
        }
        views_.clear();
        detail::PreparedJournalConsumerFailure latched;
        if(detail::read_prepared_journal_consumer_failure(*root_,latched)&&!latched.pending)
            remember(latched.state,latched.domain,latched.code,latched.operation.data());
        finished_=true;
        return finish_result();
    }
private:
    Observation<bool> capture_source(HANDLE handle,bool directory,bool mutation_owner) {
        auto current=native_id(handle,directory);if(!current.value())return forward<bool>(current);
        if(native_source_identity_&&*current.value()!=*native_source_identity_)
            return reject<bool>("trash.scope_live_source_rebound",ObservationState::Changed);
        // The actual backend/receipt owner remains live until finish_io clears
        // this borrowed handle. The value never rehydrates native authority.
        native_source_=handle;native_directory_=directory;native_source_identity_=*current.value();
        mutation_source_bound_=mutation_owner;
        return Observation<bool>::available(true);
    }
    void remember(ObservationState state,ErrorDomain domain,int64_t code,std::string_view operation) noexcept {
        detail::record_prepared_journal_consumer_failure(*root_,state,domain,code,operation);
        if(finish_failure_.pending)return;
        finish_failure_.state=state;finish_failure_.domain=domain;finish_failure_.code=code;finish_failure_.pending=true;
        const auto size=std::min(operation.size(),finish_failure_.operation.size()-1);
        std::copy_n(operation.data(),size,finish_failure_.operation.data());
    }
    Observation<bool> finish_result() const {
        return finish_failure_.pending?Observation<bool>::unavailable(finish_failure_.state,
            {finish_failure_.domain,finish_failure_.code,finish_failure_.operation.data()}):Observation<bool>::available(true);
    }
    std::shared_ptr<PreparedJournalRoot> root_;
    HeldChild::Pointer source_;
    HANDLE native_source_=nullptr;
    std::optional<NativeDurableIdentity> native_source_identity_;
    bool native_directory_=false,mutation_source_bound_=false;
    std::vector<std::unique_ptr<NativeTrashDirectoryProjection>> views_;
    std::vector<JournalScopeGuard::Pointer> guards_;
    bool finished_=false;
    detail::PreparedJournalConsumerFailure finish_failure_;
};
Observation<Handle> component(HANDLE parent,const NativeName& n,ACCESS_MASK rights,std::optional<bool> directory,
    ULONG disposition=FILE_OPEN,bool guard=false,PSECURITY_DESCRIPTOR security=nullptr,bool pin_namespace=false) {
    if(!valid_name(n)) return reject<Handle>("trash.component_name",ObservationState::Failed);
    const auto& units=*n.windows_units(); std::wstring spelling(units.begin(),units.end());
    UNICODE_STRING name{}; name.Length=static_cast<USHORT>(spelling.size()*2); name.MaximumLength=name.Length; name.Buffer=spelling.data();
    OBJECT_ATTRIBUTES attrs{}; attrs.Length=sizeof(attrs); attrs.RootDirectory=parent; attrs.ObjectName=&name; attrs.SecurityDescriptor=security;
    IO_STATUS_BLOCK io{}; HANDLE raw=nullptr;
    const auto status=NtCreateFile(&raw,rights|SYNCHRONIZE,&attrs,&io,nullptr,
        FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,
        guard?FILE_SHARE_READ:(pin_namespace?FILE_SHARE_READ|FILE_SHARE_WRITE:FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE),disposition,
        FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT|
            (!directory?0:*directory?FILE_DIRECTORY_FILE:FILE_NON_DIRECTORY_FILE),nullptr,0);
    Handle out(raw);
    if(status<0) return Observation<Handle>::unavailable(state(RtlNtStatusToDosError(status)),
        {ErrorDomain::NtStatus,static_cast<uint32_t>(status),"trash.NtCreateFile"});
    if(!raw||raw==INVALID_HANDLE_VALUE) return reject<Handle>("trash.invalid_handle",ObservationState::Failed);
    return Observation<Handle>::available(std::move(out));
}
Observation<NativeDurableIdentity> native_id(HANDLE h,bool directory) {
    FILE_ID_INFO id{}; FILE_ATTRIBUTE_TAG_INFO tag{}; FILE_STANDARD_INFO standard{};
    if(!GetFileInformationByHandleEx(h,FileIdInfo,&id,sizeof(id))||
       !GetFileInformationByHandleEx(h,FileAttributeTagInfo,&tag,sizeof(tag))||
       !GetFileInformationByHandleEx(h,FileStandardInfo,&standard,sizeof(standard)))
        return fail<NativeDurableIdentity>(GetLastError(),"trash.handle_identity");
    constexpr DWORD review_flags=0x00400000|0x00040000|0x00100000|0x00080000|FILE_ATTRIBUTE_OFFLINE|FILE_ATTRIBUTE_REPARSE_POINT;
    if(standard.DeletePending) return reject<NativeDurableIdentity>("trash.identity_delete_pending",ObservationState::Changed);
    if(bool(tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory||(tag.FileAttributes&review_flags)||
        (!directory&&standard.NumberOfLinks!=1)) return reject<NativeDurableIdentity>("trash.kind_provider_links");
    NativeDurableIdentity out; out.scheme=IdentityScheme::WindowsFileId128;
    out.volume=NativeIdentifier::from_u64(id.VolumeSerialNumber);
    std::memcpy(out.object.bytes.data(),id.FileId.Identifier,16);
    return Observation<NativeDurableIdentity>::available(std::move(out));
}
// A separate native provider, deliberately exposing none of the ordinary
// Windows cursor's mutation/rights-upgrade methods. Every underlying handle
// carries query-only rights; parent opens use only kernel parent-ID evidence.
class QueryOwner final {
public:
    QueryOwner(Handle handle,std::shared_ptr<PreparedJournalRoot> root,AdapterScope scope) noexcept
        :handle_(std::move(handle)),root_(std::move(root)),scope_(std::move(scope)) {}
    QueryOwner(QueryOwner&& other) noexcept:handle_(std::move(other.handle_)),root_(std::move(other.root_)),
        scope_(std::move(other.scope_)),closed_(std::exchange(other.closed_,true)),failure_(other.failure_) {}
    ~QueryOwner(){close();}
    HANDLE handle() const noexcept{return handle_.get();}
    const AdapterScope& scope()const noexcept{return scope_;}
    const std::shared_ptr<PreparedJournalRoot>& root()const noexcept{return root_;}
    void close() noexcept {
        if(closed_)return;closed_=true;
        const auto raw=handle_.release();if(!raw||raw==INVALID_HANDLE_VALUE)return;
        if(!CloseHandle(raw))record(ObservationState::Unknown,ErrorDomain::Win32,GetLastError(),"trash.scope_query_close");
        try {
            if(const auto fault=detail::journal_root_fault(detail::JournalRootFaultPoint::DirectoryClose))
                record(ObservationState::Unknown,ErrorDomain::Win32,*fault,"trash.scope_query_close");
        } catch(...) {record(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<int64_t>(AdapterError::InvalidNativeResult),"trash.scope_query_close_exception");}
    }
    Observation<bool> finish_io() {
        close();
        detail::PreparedJournalConsumerFailure published;
        if(detail::read_prepared_journal_consumer_failure(*root_,published)&&!published.pending)
            return Observation<bool>::unavailable(published.state,{published.domain,published.code,published.operation.data()});
        return failure_.pending?Observation<bool>::unavailable(failure_.state,
            {failure_.domain,failure_.code,failure_.operation.data()}):Observation<bool>::available(true);
    }
    Observation<BasicMetadata> inspect()const {
        if(closed_)return reject<BasicMetadata>("trash.scope_query_finished",ObservationState::Changed);
        FILE_BASIC_INFO basic{};FILE_STANDARD_INFO standard{};FILE_ATTRIBUTE_TAG_INFO tag{};
        if(!GetFileInformationByHandleEx(handle(),FileBasicInfo,&basic,sizeof(basic))||
            !GetFileInformationByHandleEx(handle(),FileStandardInfo,&standard,sizeof(standard))||
            !GetFileInformationByHandleEx(handle(),FileAttributeTagInfo,&tag,sizeof(tag)))
            return fail<BasicMetadata>(GetLastError(),"trash.scope_query_metadata");
        const bool directory=(basic.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0;
        if(tag.ReparseTag||basic.FileAttributes!=tag.FileAttributes||standard.DeletePending||
            basic.ChangeTime.QuadPart<0||basic.LastWriteTime.QuadPart<0)
            return reject<BasicMetadata>("trash.scope_query_kind_or_time");
        auto id=native_id(handle(),directory);if(!id.value())return forward<BasicMetadata>(id);
        BasicMetadata result;
        result.identity=Observation<ObjectIdentity>::available({scope_,id.value()->scheme,id.value()->volume,id.value()->object,{}});
        result.kind=Observation<ObjectKind>::available(directory?ObjectKind::Directory:ObjectKind::RegularFile);
        result.link_count=Observation<uint64_t>::available(standard.NumberOfLinks);
        FILE_ID_INFO file_id{};
        if(!GetFileInformationByHandleEx(handle(),FileIdInfo,&file_id,sizeof(file_id)))return fail<BasicMetadata>(GetLastError(),"trash.scope_query_mount");
        result.mount_id=Observation<uint64_t>::available(file_id.VolumeSerialNumber);
        result.windows_attributes=Observation<uint32_t>::available(basic.FileAttributes);
        result.reparse_tag=Observation<uint32_t>::available(0);
        result.changed=Observation<FileTimestamp>::available(FileTimestamp::from_windows_ticks(static_cast<uint64_t>(basic.ChangeTime.QuadPart)));
        result.modified=Observation<FileTimestamp>::available(FileTimestamp::from_windows_ticks(static_cast<uint64_t>(basic.LastWriteTime.QuadPart)));
        if(!directory&&standard.EndOfFile.QuadPart>=0)result.logical_size=Observation<uint64_t>::available(static_cast<uint64_t>(standard.EndOfFile.QuadPart));
        return Observation<BasicMetadata>::available(std::move(result));
    }
private:
    void record(ObservationState state,ErrorDomain domain,int64_t code,std::string_view operation) noexcept {
        detail::record_prepared_journal_consumer_failure(*root_,state,domain,code,operation);
        if(failure_.pending)return;
        failure_.pending=true;failure_.state=state;failure_.domain=domain;failure_.code=code;
        std::copy_n(operation.data(),std::min(operation.size(),failure_.operation.size()-1),failure_.operation.data());
    }
    Handle handle_;
    std::shared_ptr<PreparedJournalRoot> root_;
    AdapterScope scope_;
    bool closed_=false;
    detail::PreparedJournalConsumerFailure failure_;
};
Observation<detail::WindowsParentIds> query_parent_ids(HANDLE handle) {
    READ_FILE_USN_DATA input{3,3};alignas(8) std::array<std::byte,65536+80> bytes{};DWORD count=0;
    if(!DeviceIoControl(handle,FSCTL_READ_FILE_USN_DATA,&input,sizeof(input),bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr))
        return fail<detail::WindowsParentIds>(GetLastError(),"trash.scope_parent_usn");
    if(count>bytes.size())return reject<detail::WindowsParentIds>("trash.scope_parent_usn_size");
    return detail::decode_windows_parent_record(std::span<const std::byte>(bytes).first(count),3);
}
Observation<std::shared_ptr<QueryOwner>> query_parent(const std::shared_ptr<QueryOwner>& child) {
    auto before=child->inspect();if(!before.value())return forward<std::shared_ptr<QueryOwner>>(before);
    if(!before.value()->kind.value()||*before.value()->kind.value()!=ObjectKind::Directory)
        return reject<std::shared_ptr<QueryOwner>>("trash.scope_parent_directory_required");
    auto ids=query_parent_ids(child->handle());if(!ids.value())return forward<std::shared_ptr<QueryOwner>>(ids);
    if(ids.value()->scheme!=IdentityScheme::WindowsFileId128||ids.value()->child!=before.value()->identity.value()->object||
        !(ids.value()->attributes&FILE_ATTRIBUTE_DIRECTORY))return reject<std::shared_ptr<QueryOwner>>("trash.scope_parent_child_changed",ObservationState::Changed);
    FILE_ID_DESCRIPTOR descriptor{};descriptor.dwSize=sizeof(descriptor);descriptor.Type=ExtendedFileIdType;
    std::memcpy(descriptor.ExtendedFileId.Identifier,ids.value()->parent.bytes.data(),16);
    Handle raw(OpenFileById(child->handle(),&descriptor,FILE_READ_ATTRIBUTES|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL));
    if(!raw.get()||raw.get()==INVALID_HANDLE_VALUE)return fail<std::shared_ptr<QueryOwner>>(GetLastError(),"trash.scope_parent_open_by_id");
    QueryOwner acquired(std::move(raw),child->root(),child->scope());
    auto parent=std::make_shared<QueryOwner>(std::move(acquired));
    auto metadata=parent->inspect();if(!metadata.value())return forward<std::shared_ptr<QueryOwner>>(metadata);
    const auto& actual=*metadata.value()->identity.value();
    if(!metadata.value()->kind.value()||*metadata.value()->kind.value()!=ObjectKind::Directory||
        actual.volume!=before.value()->identity.value()->volume||actual.object!=ids.value()->parent)
        return reject<std::shared_ptr<QueryOwner>>("trash.scope_parent_identity_changed",ObservationState::Changed);
    const auto proof=detail::prove_windows_journal_volume(parent->handle());
    if(!proof.qualified)return Observation<std::shared_ptr<QueryOwner>>::unavailable(proof.state,{proof.domain,proof.code,proof.operation});
    auto again=query_parent_ids(child->handle());if(!again.value())return forward<std::shared_ptr<QueryOwner>>(again);
    auto after=child->inspect();if(!after.value())return forward<std::shared_ptr<QueryOwner>>(after);
    if(*again.value()!=*ids.value()||compare_identity(*before.value()->identity.value(),*after.value()->identity.value())!=IdentityComparison::Same||
        *before.value()->changed.value()!=*after.value()->changed.value()||*before.value()->modified.value()!=*after.value()->modified.value())
        return reject<std::shared_ptr<QueryOwner>>("trash.scope_parent_changed",ObservationState::Changed);
    return Observation<std::shared_ptr<QueryOwner>>::available(std::move(parent));
}
class QueryEntry final:public OpenedEntry {
public:
    explicit QueryEntry(std::shared_ptr<QueryOwner> owner):owner_(std::move(owner)){}
    Observation<BasicMetadata> inspect_basic()const override{return owner_->inspect();}
    Observation<std::unique_ptr<OpenedEntry>> open_parent_directory()const override {
        auto parent=query_parent(owner_);if(!parent.value())return forward<std::unique_ptr<OpenedEntry>>(parent);
        return Observation<std::unique_ptr<OpenedEntry>>::available(std::make_unique<QueryEntry>(std::move(parent).take_value()));
    }
private:std::shared_ptr<QueryOwner> owner_;
};
class QueryDirectory final:public DirectoryCursor {
public:
    QueryDirectory(std::shared_ptr<QueryOwner> owner,ObjectIdentity id):DirectoryCursor(Observation<ObjectIdentity>::available(std::move(id))),owner_(std::move(owner)){}
    Observation<BasicMetadata> inspect_basic()const override{return owner_->inspect();}
    Observation<AdapterScope> source_scope()const override{return Observation<AdapterScope>::available(owner_->scope());}
    Observation<std::unique_ptr<OpenedEntry>> open_parent_directory()const override {
        auto parent=query_parent(owner_);if(!parent.value())return forward<std::unique_ptr<OpenedEntry>>(parent);
        return Observation<std::unique_ptr<OpenedEntry>>::available(std::make_unique<QueryEntry>(std::move(parent).take_value()));
    }
    Observation<std::unique_ptr<OpenedEntry>> open_child(const NativeName& name,EntryAccess access)const override {
        if(access!=EntryAccess::MetadataOnly)return reject<std::unique_ptr<OpenedEntry>>("trash.scope_query_only_access");
        auto child=open_query(name,{});if(!child.value())return forward<std::unique_ptr<OpenedEntry>>(child);
        return Observation<std::unique_ptr<OpenedEntry>>::available(std::make_unique<QueryEntry>(std::move(child).take_value()));
    }
    Observation<std::unique_ptr<DirectoryCursor>> open_directory_child(const NativeName& name)const override {
        auto child=open_query(name,true);if(!child.value())return forward<std::unique_ptr<DirectoryCursor>>(child);
        auto metadata=(*child.value())->inspect();if(!metadata.value())return forward<std::unique_ptr<DirectoryCursor>>(metadata);
        const auto proof=detail::prove_windows_journal_volume((*child.value())->handle());
        if(!proof.qualified)return Observation<std::unique_ptr<DirectoryCursor>>::unavailable(proof.state,{proof.domain,proof.code,proof.operation});
        return Observation<std::unique_ptr<DirectoryCursor>>::available(std::make_unique<QueryDirectory>(std::move(child).take_value(),*metadata.value()->identity.value()));
    }
    Observation<void*> duplicate()const {
        auto valid=owner_->inspect();if(!valid.value())return forward<void*>(valid);
        HANDLE raw=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),owner_->handle(),GetCurrentProcess(),&raw,0,FALSE,DUPLICATE_SAME_ACCESS))return fail<void*>(GetLastError(),"trash.scope_duplicate_query");
        return Observation<void*>::available(raw);
    }
protected:
    Observation<DirectoryStep> next_step()override{return reject<DirectoryStep>("trash.scope_no_enumeration");}
private:
    Observation<std::shared_ptr<QueryOwner>> open_query(const NativeName& name,std::optional<bool> directory)const {
        auto valid=owner_->inspect();if(!valid.value())return forward<std::shared_ptr<QueryOwner>>(valid);
        auto raw=component(owner_->handle(),name,FILE_READ_ATTRIBUTES|SYNCHRONIZE,directory);
        if(!raw.value())return forward<std::shared_ptr<QueryOwner>>(raw);
        QueryOwner acquired(std::move(raw).take_value(),owner_->root(),owner_->scope());
        auto result=std::make_shared<QueryOwner>(std::move(acquired));
        auto metadata=result->inspect();if(!metadata.value())return forward<std::shared_ptr<QueryOwner>>(metadata);
        return Observation<std::shared_ptr<QueryOwner>>::available(std::move(result));
    }
    std::shared_ptr<QueryOwner> owner_;
};
class DirectoryProjection final:public NativeTrashDirectoryProjection {
public:
    DirectoryProjection(std::shared_ptr<QueryOwner> owner,ObjectIdentity id):owner_(std::move(owner)),
        cursor_(std::make_shared<QueryDirectory>(owner_,std::move(id))){}
    const std::shared_ptr<const DirectoryCursor>& cursor()const noexcept override{return cursor_;}
    Observation<bool> finish_io()override {
        if(cursor_.use_count()!=1)return reject<bool>("trash.scope_query_consumers_active",ObservationState::Changed);
        return owner_->finish_io();
    }
private:
    std::shared_ptr<QueryOwner> owner_;
    std::shared_ptr<const DirectoryCursor> cursor_;
};
Observation<Handle> write_parent(HANDLE held,const NativeDurableIdentity& expected) {
    FILE_ID_DESCRIPTOR id{}; id.dwSize=sizeof(id); id.Type=ExtendedFileIdType;
    std::memcpy(id.ExtendedFileId.Identifier,expected.object.bytes.data(),16);
    Handle h(OpenFileById(held,&id,FILE_ADD_FILE|FILE_ADD_SUBDIRECTORY|FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL));
    if(!h.get()||h.get()==INVALID_HANDLE_VALUE) return fail<Handle>(GetLastError(),"trash.write_parent");
    auto actual=native_id(h.get(),true); if(!actual.value()) return forward<Handle>(actual);
    if(*actual.value()!=expected) return reject<Handle>("trash.parent_identity",ObservationState::Changed);
    return Observation<Handle>::available(std::move(h));
}
Observation<std::wstring> final_path(HANDLE h,DWORD flags) {
    std::vector<wchar_t> path(32768);
    const DWORD n=GetFinalPathNameByHandleW(h,path.data(),static_cast<DWORD>(path.size()),flags);
    if(!n) return fail<std::wstring>(GetLastError(),"trash.final_path");
    if(n>=path.size()) return reject<std::wstring>("trash.path_limit");
    return Observation<std::wstring>::available(std::wstring(path.data(),n));
}
Observation<std::wstring> original_parent_path(HANDLE parent) {
    auto dos=final_path(parent,FILE_NAME_OPENED|VOLUME_NAME_DOS);
    if(dos.value())return dos;
    const auto& error=dos.unavailable_detail()->error;
    // A local volume can have no DOS letter, including when reached through a
    // junction. Use its real extended-length volume GUID address for $I text.
    // This is a handle query only: acquisition/mutation/restore always use the
    // held parent/object identities, never reopen this informational address.
    if(error.domain!=ErrorDomain::Win32 || error.code!=ERROR_PATH_NOT_FOUND)return dos;
    auto guid=final_path(parent,FILE_NAME_OPENED|VOLUME_NAME_GUID);
    if(!guid.value())return guid;
    const auto end=guid.value()->find(L'}');
    if(!guid.value()->starts_with(L"\\\\?\\Volume{") || end==std::wstring::npos ||
        end+1>=guid.value()->size() || (*guid.value())[end+1]!=L'\\')
        return reject<std::wstring>("trash.original_local_volume");
    return guid;
}
struct User { std::vector<std::byte> token; std::wstring sid; };
Observation<User> current_user() {
    HANDLE raw=nullptr;
    if(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&raw)) {
        if(GetLastError()!=ERROR_NO_TOKEN||!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw)) return fail<User>(GetLastError(),"trash.token");
    }
    Handle token(raw); DWORD bytes=0; GetTokenInformation(token.get(),TokenUser,nullptr,0,&bytes);
    if(!bytes||bytes>65536) return reject<User>("trash.token_size");
    User user; user.token.resize(bytes);
    if(!GetTokenInformation(token.get(),TokenUser,user.token.data(),bytes,&bytes)) return fail<User>(GetLastError(),"trash.token_user");
    LPWSTR sid=nullptr;
    if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.token.data())->User.Sid,&sid)) return fail<User>(GetLastError(),"trash.token_sid");
    struct Local { void* p; ~Local(){LocalFree(p);} } guard{sid}; user.sid=sid;
    return Observation<User>::available(std::move(user));
}
Observation<bool> private_bin(HANDLE h,const User& user,bool protected_dacl=false) {
    PSID owner=nullptr; PACL acl=nullptr; PSECURITY_DESCRIPTOR raw=nullptr;
    const DWORD code=GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&raw);
    if(code!=ERROR_SUCCESS) return fail<bool>(code,"trash.bin_security");
    struct Local { void* p; ~Local(){LocalFree(p);} } guard{raw};
    const auto sid=reinterpret_cast<const TOKEN_USER*>(user.token.data())->User.Sid;
    if(!owner||!IsValidSid(owner)||!acl||!IsValidAcl(acl)) return reject<bool>("trash.bin_acl");
    SECURITY_DESCRIPTOR_CONTROL control{};DWORD revision=0;
    if(!GetSecurityDescriptorControl(raw,&control,&revision)) return fail<bool>(GetLastError(),"trash.security_control");
    if(protected_dacl&&!(control&SE_DACL_PROTECTED)) return reject<bool>("trash.metadata_inherited_dacl");
    BYTE system[SECURITY_MAX_SID_SIZE]{},admins[SECURITY_MAX_SID_SIZE]{}; DWORD sn=sizeof(system),an=sizeof(admins);
    if(!CreateWellKnownSid(WinLocalSystemSid,nullptr,system,&sn)||!CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,admins,&an))
        return fail<bool>(GetLastError(),"trash.well_known_sid");
    auto trusted=[&](PSID p){return EqualSid(p,sid)||EqualSid(p,system)||EqualSid(p,admins);};
    if(!trusted(owner)) return reject<bool>("trash.bin_owner");
    for(DWORD i=0;i<acl->AceCount;++i) {
        void* raw_ace=nullptr; if(!GetAce(acl,i,&raw_ace)) return fail<bool>(GetLastError(),"trash.bin_ace");
        const auto* header=static_cast<ACE_HEADER*>(raw_ace);
        // Inherit-only grants still apply to newly created $I files. Inspect
        // every allow ACE, including grants that do not apply to this directory.
        if(header->AceType==ACCESS_DENIED_ACE_TYPE) continue;
        if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE||header->AceSize<sizeof(ACCESS_ALLOWED_ACE)) return reject<bool>("trash.bin_unknown_ace");
        auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
        if(!IsValidSid(&ace->SidStart)||GetLengthSid(&ace->SidStart)>header->AceSize- offsetof(ACCESS_ALLOWED_ACE,SidStart)) return reject<bool>("trash.bin_ace_sid");
        if(ace->Mask&&!trusted(&ace->SidStart)) return reject<bool>("trash.bin_public_access");
    }
    return Observation<bool>::available(true);
}
struct Bin { Handle volume,root,user; NativeDurableIdentity id; NativeName sid; NativeDurableIdentity volume_id,root_id; };
Observation<Bin> open_bin(HANDLE parent,const NativeDurableIdentity& parent_id,bool create,
    const std::shared_ptr<PrivateScope>& scope={},std::stop_token stop={}) {
    auto path=final_path(parent,FILE_NAME_OPENED|VOLUME_NAME_GUID); if(!path.value()) return forward<Bin>(path);
    const auto end=path.value()->find(L'}');
    if(!path.value()->starts_with(L"\\\\?\\Volume{")||end==std::wstring::npos||end+1>=path.value()->size()||(*path.value())[end+1]!=L'\\')
        return reject<Bin>("trash.local_volume_required");
    const auto volume_path=path.value()->substr(0,end+2);
    Handle volume(CreateFileW(volume_path.c_str(),FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(!volume.get()||volume.get()==INVALID_HANDLE_VALUE) return fail<Bin>(GetLastError(),"trash.volume_root");
    auto vid=native_id(volume.get(),true); if(!vid.value()) return forward<Bin>(vid);
    if(vid.value()->volume!=parent_id.volume) return reject<Bin>("trash.volume_changed",ObservationState::Changed);
    auto user=current_user(); if(!user.value()) return forward<Bin>(user);
    if(scope) {auto valid=scope->bind_destination(volume.get(),stop);if(!valid.value()||!*valid.value())return forward<Bin>(valid);}
    auto root_name=*NativeName::from_windows(u"$Recycle.Bin");
    constexpr ACCESS_MASK directory_rights=FILE_LIST_DIRECTORY|FILE_ADD_FILE|FILE_ADD_SUBDIRECTORY|FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE;
    auto root=component(volume.get(),root_name,directory_rights,true,create?FILE_OPEN_IF:FILE_OPEN,false,nullptr,true);
    if(!root.value()) return forward<Bin>(root); auto rid=native_id(root.value()->get(),true); if(!rid.value()) return forward<Bin>(rid);
    if(rid.value()->volume!=parent_id.volume) return reject<Bin>("trash.bin_volume_changed",ObservationState::Changed);
    if(scope) {auto valid=scope->bind_destination(root.value()->get(),stop);if(!valid.value()||!*valid.value())return forward<Bin>(valid);}
    auto sid=*NativeName::from_windows(std::u16string(user.value()->sid.begin(),user.value()->sid.end()));
    const auto sddl=L"O:"+user.value()->sid+L"G:"+user.value()->sid+L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+user.value()->sid+L")";
    PSECURITY_DESCRIPTOR sd=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr)) return fail<Bin>(GetLastError(),"trash.private_descriptor");
    struct Local { void* p; ~Local(){LocalFree(p);} } security{sd};
    auto own=component(root.value()->get(),sid,directory_rights,true,create?FILE_OPEN_IF:FILE_OPEN,false,sd,true);
    if(!own.value()) return forward<Bin>(own);
    auto safe=private_bin(own.value()->get(),*user.value()); if(!safe.value()) return forward<Bin>(safe);
    auto id=native_id(own.value()->get(),true); if(!id.value()) return forward<Bin>(id);
    if(id.value()->volume!=parent_id.volume) return reject<Bin>("trash.user_bin_volume_changed",ObservationState::Changed);
    if(scope) {auto valid=scope->bind_destination(own.value()->get(),stop);if(!valid.value()||!*valid.value())return forward<Bin>(valid);}
    return Observation<Bin>::available({std::move(volume),std::move(root).take_value(),std::move(own).take_value(),*id.value(),std::move(sid),*vid.value(),*rid.value()});
}
Observation<bool> validate_bin(const Bin& bin) {
    for(const auto& pair:{std::pair{bin.volume.get(),&bin.volume_id},std::pair{bin.root.get(),&bin.root_id},std::pair{bin.user.get(),&bin.id}}) {
        auto id=native_id(pair.first,true);if(!id.value())return forward<bool>(id);
        if(*id.value()!=*pair.second)return reject<bool>("trash.held_bin_identity",ObservationState::Changed);
    }
    auto root=component(bin.volume.get(),*NativeName::from_windows(u"$Recycle.Bin"),FILE_READ_ATTRIBUTES,true);
    if(!root.value())return forward<bool>(root);auto rid=native_id(root.value()->get(),true);if(!rid.value())return forward<bool>(rid);
    if(*rid.value()!=bin.root_id)return reject<bool>("trash.bin_root_edge_changed",ObservationState::Changed);
    auto own=component(bin.root.get(),bin.sid,FILE_READ_ATTRIBUTES,true);
    if(!own.value())return forward<bool>(own);auto uid=native_id(own.value()->get(),true);if(!uid.value())return forward<bool>(uid);
    if(*uid.value()!=bin.id)return reject<bool>("trash.bin_sid_edge_changed",ObservationState::Changed);
    auto user=current_user();if(!user.value())return forward<bool>(user);
    if(*bin.sid.windows_units()!=std::u16string(user.value()->sid.begin(),user.value()->sid.end()))return reject<bool>("trash.bin_user_changed",ObservationState::Changed);
    return private_bin(bin.user.get(),*user.value());
}
struct FreeLocal {void operator()(void* p) const noexcept {if(p)LocalFree(p);}};
using Descriptor=std::unique_ptr<void,FreeLocal>;
Observation<Descriptor> private_file_descriptor(const User& user) {
    const auto sddl=L"O:"+user.sid+L"G:"+user.sid+L"D:P(A;;FA;;;SY)(A;;FA;;;"+user.sid+L")";
    PSECURITY_DESCRIPTOR raw=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&raw,nullptr))return fail<Descriptor>(GetLastError(),"trash.metadata_private_descriptor");
    return Observation<Descriptor>::available(Descriptor(raw));
}
Observation<Handle> pin_identity(HANDLE volume,const NativeDurableIdentity& expected,bool directory) {
    FILE_ID_DESCRIPTOR id{};id.dwSize=sizeof(id);id.Type=ExtendedFileIdType;std::memcpy(id.ExtendedFileId.Identifier,expected.object.bytes.data(),16);
    Handle out(OpenFileById(volume,&id,FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL));
    if(!out.get()||out.get()==INVALID_HANDLE_VALUE)return fail<Handle>(GetLastError(),"trash.pin_identity");
    auto actual=native_id(out.get(),directory);if(!actual.value())return forward<Handle>(actual);
    if(*actual.value()!=expected)return reject<Handle>("trash.pin_identity_changed",ObservationState::Changed);
    return Observation<Handle>::available(std::move(out));
}
class IdentityOwner final:public NativeTrashIdentityOwner {
public:
    Handle parent,object,metadata;Bin bin;
    NativeTrashReceipt binding;
    IdentityOwner* next=nullptr;
    IdentityOwner(Handle p,Handle o,Handle m,Bin b,const NativeTrashReceipt& receipt)
        :parent(std::move(p)),object(std::move(o)),metadata(std::move(m)),bin(std::move(b)),binding(receipt){binding.continuity.reset();}
    Observation<bool> validate(const NativeTrashReceipt& receipt) const {
        if(!receipt.metadata_identity||receipt.recycle_parent!=bin.id||receipt.user_sid!=bin.sid)return reject<bool>("restore.live_receipt_binding",ObservationState::Changed);
        if(receipt.object_kind!=binding.object_kind || receipt.metadata_retired || receipt.original_name!=binding.original_name ||
            receipt.data_name!=binding.data_name || receipt.metadata_name!=binding.metadata_name ||
            receipt.metadata_bytes!=binding.metadata_bytes)
            return reject<bool>("restore.live_receipt_fields_changed",ObservationState::Changed);
        for(const auto& pair:{std::pair{parent.get(),&receipt.original_parent},std::pair{object.get(),&receipt.object},std::pair{metadata.get(),&*receipt.metadata_identity}}) {
            const bool directory=pair.first==parent.get() ||
                (pair.first==object.get() && binding.object_kind==ObjectKind::Directory);
            auto id=native_id(pair.first,directory);if(!id.value())return forward<bool>(id);
            if(*id.value()!=*pair.second)return reject<bool>("restore.live_identity_changed",ObservationState::Changed);
        }
        return validate_bin(bin);
    }
};
// Intrusive retirement requires no allocation on the releasing/UI thread. The
// worker is initialized before any live receipt is exported and closes handles.
class IdentityRetirement {
    std::mutex mutex_;std::condition_variable cv_;IdentityOwner* head_=nullptr;
    IdentityRetirement() {std::thread([this]{for(;;){IdentityOwner* item=nullptr;{std::unique_lock lock(mutex_);cv_.wait(lock,[&]{return head_!=nullptr;});item=head_;head_=item->next;}delete item;}}).detach();}
public:
    static IdentityRetirement& instance(){static auto* queue=new IdentityRetirement;return *queue;}
    void enqueue(IdentityOwner* owner) noexcept {{std::lock_guard lock(mutex_);owner->next=head_;head_=owner;}cv_.notify_one();}
};
Observation<std::shared_ptr<const NativeTrashIdentityOwner>> identity_owner(const NativeTrashReceipt& receipt,const Bin& source) {
    using R=Observation<std::shared_ptr<const NativeTrashIdentityOwner>>;
    if(!receipt.metadata_identity)return reject<std::shared_ptr<const NativeTrashIdentityOwner>>("trash.receipt_metadata_identity");
    auto parent=pin_identity(source.volume.get(),receipt.original_parent,true);if(!parent.value())return forward<std::shared_ptr<const NativeTrashIdentityOwner>>(parent);
    auto object=pin_identity(source.volume.get(),receipt.object,receipt.object_kind==ObjectKind::Directory);if(!object.value())return forward<std::shared_ptr<const NativeTrashIdentityOwner>>(object);
    auto metadata=pin_identity(source.volume.get(),*receipt.metadata_identity,false);if(!metadata.value())return forward<std::shared_ptr<const NativeTrashIdentityOwner>>(metadata);
    auto volume=pin_identity(source.volume.get(),source.volume_id,true);if(!volume.value())return forward<std::shared_ptr<const NativeTrashIdentityOwner>>(volume);
    auto root=pin_identity(source.volume.get(),source.root_id,true);if(!root.value())return forward<std::shared_ptr<const NativeTrashIdentityOwner>>(root);
    auto own=pin_identity(source.volume.get(),source.id,true);if(!own.value())return forward<std::shared_ptr<const NativeTrashIdentityOwner>>(own);
    Bin bin{std::move(volume).take_value(),std::move(root).take_value(),std::move(own).take_value(),source.id,source.sid,source.volume_id,source.root_id};
    auto* queue=&IdentityRetirement::instance();
    std::shared_ptr<const NativeTrashIdentityOwner> out(new IdentityOwner(std::move(parent).take_value(),std::move(object).take_value(),std::move(metadata).take_value(),std::move(bin),receipt),
        [queue](const NativeTrashIdentityOwner* p){queue->enqueue(const_cast<IdentityOwner*>(static_cast<const IdentityOwner*>(p)));});
    return R::available(std::move(out));
}
Observation<bool> absent(HANDLE directory,const NativeName& n) {
    auto opened=component(directory,n,FILE_READ_ATTRIBUTES,std::nullopt);
    if(opened.value()) return reject<bool>("trash.destination_occupied",ObservationState::Changed);
    const auto& e=*opened.unavailable_detail();
    // Only STATUS_OBJECT_NAME_NOT_FOUND proves this final component absent;
    // STATUS_OBJECT_PATH_NOT_FOUND and generic Gone cannot reserve the name.
    if(e.error.domain==ErrorDomain::NtStatus&&static_cast<uint32_t>(e.error.code)==0xc0000034u) return Observation<bool>::available(true);
    return forward<bool>(opened);
}
Observation<bool> native_rename(HANDLE source,HANDLE target,const NativeName& n) {
    if(!valid_name(n)) return reject<bool>("trash.rename_name");
    const auto& w=*n.windows_units(); const size_t bytes=w.size()*2;
    std::vector<std::byte> storage(std::max(sizeof(FILE_RENAME_INFO),offsetof(FILE_RENAME_INFO,FileName)+bytes));
    auto* info=reinterpret_cast<FILE_RENAME_INFO*>(storage.data()); info->ReplaceIfExists=FALSE;
    info->RootDirectory=target; info->FileNameLength=static_cast<DWORD>(bytes); std::memcpy(info->FileName,w.data(),bytes);
    using Set=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
    const auto address=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetInformationFile");
    if(!address) return reject<bool>("trash.rename_api"); IO_STATUS_BLOCK io{};
    const auto status=std::bit_cast<Set>(address)(source,&io,info,static_cast<ULONG>(storage.size()),10);
    if(status<0) return Observation<bool>::unavailable(state(RtlNtStatusToDosError(status)),
        {ErrorDomain::NtStatus,static_cast<uint32_t>(status),"trash.rename_atomic"});
    return Observation<bool>::available(true);
}
Observation<bool> metadata_matches(HANDLE h,const NativeTrashReceipt& receipt) {
    auto id=native_id(h,false); if(!id.value()) return forward<bool>(id);
    if(!receipt.metadata_identity||*id.value()!=*receipt.metadata_identity) return reject<bool>("restore.metadata_identity",ObservationState::Changed);
    FILE_STANDARD_INFO standard{};
    if(!GetFileInformationByHandleEx(h,FileStandardInfo,&standard,sizeof(standard))) return fail<bool>(GetLastError(),"restore.metadata_size");
    if(standard.EndOfFile.QuadPart<0||static_cast<uint64_t>(standard.EndOfFile.QuadPart)!=receipt.metadata_bytes.size())
        return reject<bool>("restore.metadata_size_changed",ObservationState::Changed);
    std::vector<std::byte> bytes(receipt.metadata_bytes.size()); DWORD got=0;
    LARGE_INTEGER zero{}; if(!SetFilePointerEx(h,zero,nullptr,FILE_BEGIN)||
        !ReadFile(h,bytes.data(),static_cast<DWORD>(bytes.size()),&got,nullptr)) return fail<bool>(GetLastError(),"restore.metadata_read");
    if(got!=bytes.size()||bytes!=receipt.metadata_bytes) return reject<bool>("restore.metadata_changed",ObservationState::Changed);
    return Observation<bool>::available(true);
}
class Transaction final : public NativeTrashTransaction {
public:
    Transaction(NativeTrashReceipt receipt,Handle parent,Handle object,Bin bin,bool restore,Handle metadata=Handle{},
        std::shared_ptr<PrivateScope> scope={})
        : receipt_(std::move(receipt)),parent_(std::move(parent)),object_(std::move(object)),bin_(std::move(bin)),
          metadata_(std::move(metadata)),scope_(std::move(scope)),restore_(restore) {}
    ~Transaction() override {try {(void)finish_io();}catch(...) {}}
    const NativeTrashReceipt& receipt() const noexcept override { return receipt_; }
    bool mutation_attempted() const noexcept override { return attempted_; }
    Observation<bool> revalidate_private_scope(std::stop_token stop) const override {
        if(!scope_||!scope_->source_bound())return reject<bool>("trash.private_scope_unbound");
        return scope_->check(stop);
    }
    Observation<bool> finish_io() override {return finish_handles();}
    Observation<bool> commit(const NativeTrashJournal& journal,std::stop_token stop) override {
        if(started_) return reject<bool>("trash.one_shot",ObservationState::Changed); started_=true;
        if(stop.stop_requested()) return reject<bool>("trash.cancelled",ObservationState::Unknown);
        if(scope_) {auto valid=scope_->check(stop);if(!valid.value()||!*valid.value())return valid;}
        auto namespace_valid=validate_bin(bin_);if(!namespace_valid.value())return namespace_valid;
        for(auto s:{OperationJournalState::Planned,OperationJournalState::Prepared}) { auto r=journal(s,receipt_); if(!r.value()||!*r.value()) return r; }
        namespace_valid=validate_bin(bin_);if(!namespace_valid.value())return namespace_valid;
        if(!restore_) {
            if(scope_) {auto valid=scope_->check(stop);if(!valid.value()||!*valid.value())return valid;}
            auto clear=absent(bin_.user.get(),receipt_.data_name); if(!clear.value()) return clear;
            auto user=current_user();if(!user.value())return forward<bool>(user);
            auto sd=private_file_descriptor(*user.value());if(!sd.value())return forward<bool>(sd);
            auto created=component(bin_.user.get(),receipt_.metadata_name,FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|READ_CONTROL|DELETE,false,FILE_CREATE,true,sd.value()->get());
            if(!created.value()) return forward<bool>(created);
            metadata_=std::move(created).take_value(); attempted_=true;
            auto id=native_id(metadata_.get(),false); if(!id.value()) return forward<bool>(id); receipt_.metadata_identity=*id.value();
            auto privacy=private_bin(metadata_.get(),*user.value(),true);if(!privacy.value())return privacy;
            DWORD wrote=0;
            if(!WriteFile(metadata_.get(),receipt_.metadata_bytes.data(),static_cast<DWORD>(receipt_.metadata_bytes.size()),&wrote,nullptr)||
                !FlushFileBuffers(metadata_.get())) return fail<bool>(GetLastError(),"trash.metadata_write_flush");
            if(wrote!=receipt_.metadata_bytes.size()) return reject<bool>("trash.metadata_short_write",ObservationState::Failed);
            // Keep writer sharing exclusion through the namespace mutation.
            // Its explicit fallible close precedes terminal journal records;
            // no destructor-only close can turn an uncertain move into success.
        } else { auto m=metadata_matches(metadata_.get(),receipt_); if(!m.value()) return m; }
        auto intended=journal(OperationJournalState::CommitIntended,receipt_); if(!intended.value()||!*intended.value()) return intended;
        if(stop.stop_requested()) return reject<bool>("trash.cancelled_before_move",ObservationState::Unknown);
        namespace_valid=validate_bin(bin_);if(!namespace_valid.value())return namespace_valid;
        if(scope_) {auto valid=scope_->check(stop);if(!valid.value()||!*valid.value())return valid;}
        const auto target=restore_?parent_.get():bin_.user.get(); const auto& name=restore_?receipt_.original_name:receipt_.data_name;
        auto clear=absent(target,name); if(!clear.value()) return clear;
        const bool directory=receipt_.object_kind==ObjectKind::Directory;
        auto source_id=native_id(object_.get(),directory); if(!source_id.value()) return forward<bool>(source_id);
        if(*source_id.value()!=receipt_.object) return reject<bool>("trash.source_identity_changed",ObservationState::Changed);
        attempted_=true; auto moved=native_rename(object_.get(),target,name); if(!moved.value()) return moved;
        auto published=component(target,name,FILE_READ_ATTRIBUTES,directory); if(!published.value()) return forward<bool>(published);
        auto id=native_id(published.value()->get(),directory); if(!id.value()) return forward<bool>(id);
        if(*id.value()!=receipt_.object) return reject<bool>("trash.published_identity",ObservationState::Changed);
        if(!FlushFileBuffers(parent_.get())||!FlushFileBuffers(bin_.user.get())) return fail<bool>(GetLastError(),"trash.directory_flush");
        namespace_valid=validate_bin(bin_);if(!namespace_valid.value())return namespace_valid;
        if(!restore_){auto owner=identity_owner(receipt_,bin_);if(!owner.value())return forward<bool>(owner);receipt_.continuity=std::move(owner).take_value();}
        auto committed=journal(OperationJournalState::DestinationCommitted,receipt_); if(!committed.value()||!*committed.value()) return committed;
        auto removal=journal(OperationJournalState::SourceRemovalIntended,receipt_); if(!removal.value()||!*removal.value()) return removal;
        if(restore_) {
            if(scope_) {auto valid=scope_->check(stop,false);if(!valid.value()||!*valid.value())return valid;}
            // Only this verified $I metadata handle is disposed. The user's $R
            // object has already been published and verified at its original name.
            auto m=metadata_matches(metadata_.get(),receipt_); if(!m.value()) return m;
            FILE_DISPOSITION_INFO_EX disposition{};
            disposition.Flags=FILE_DISPOSITION_FLAG_DELETE|FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
            if(!SetFileInformationByHandle(metadata_.get(),FileDispositionInfoEx,&disposition,sizeof(disposition))) return fail<bool>(GetLastError(),"restore.metadata_cleanup");
            close_handle(metadata_,"restore.metadata_close");if(finish_failure_.pending)return finish_result();
            const auto gone=absent(bin_.user.get(),receipt_.metadata_name);if(!gone.value())return gone;
            if(!FlushFileBuffers(bin_.user.get())) return fail<bool>(GetLastError(),"restore.metadata_cleanup_flush");
            receipt_.metadata_retired=true;
        }
        const auto closed=finish_handles();if(!closed.value())return closed;
        for(auto s:{OperationJournalState::SourceRetired,OperationJournalState::Complete}) { auto r=journal(s,receipt_); if(!r.value()||!*r.value()) return r; }
        return Observation<bool>::available(true);
    }
private:
    Observation<bool> finish_handles() {
        if(finished_)return finish_result();
        if(scope_)try {
            const auto closed=scope_->finish_io();
            if(!closed.value())remember_finish(*closed.unavailable_detail());
        } catch(...) {
            detail::PreparedJournalConsumerFailure failure;
            if(scope_->read_failure(failure)&&!failure.pending)remember_finish(failure.state,failure.domain,failure.code,failure.operation.data());
            else remember_finish_exception("trash.scope_finish_exception");
        }
        for(const auto& item:{std::pair{&metadata_,"trash.metadata_close"},
            std::pair{&object_,"trash.object_close"},std::pair{&parent_,"trash.parent_close"},
            std::pair{&bin_.user,"trash.bin_close"},std::pair{&bin_.root,"trash.bin_root_close"},std::pair{&bin_.volume,"trash.volume_close"}}) {
            close_handle(*item.first,item.second);
        }
        finished_=true;return finish_result();
    }
    void remember_finish(const UnavailableObservation& error) noexcept {
        remember_finish(error.state,error.error.domain,error.error.code,error.error.operation);
    }
    void remember_finish(ObservationState state,ErrorDomain domain,int64_t code,std::string_view operation)noexcept {
        if(scope_)scope_->record_failure(state,domain,code,operation);
        if(finish_failure_.pending)return;
        finish_failure_.pending=true;finish_failure_.state=state;
        finish_failure_.domain=domain;finish_failure_.code=code;
        std::copy_n(operation.data(),std::min(operation.size(),finish_failure_.operation.size()-1),finish_failure_.operation.data());
    }
    void close_handle(Handle& handle,std::string_view operation)noexcept {
        const auto raw=handle.release();if(!raw||raw==INVALID_HANDLE_VALUE)return;
        if(!CloseHandle(raw))remember_finish(ObservationState::Unknown,ErrorDomain::Win32,GetLastError(),operation);
    }
    void remember_finish_exception(std::string_view operation) noexcept {
        if(finish_failure_.pending)return;
        finish_failure_.pending=true;finish_failure_.state=ObservationState::Unknown;
        finish_failure_.domain=ErrorDomain::Adapter;finish_failure_.code=static_cast<int64_t>(AdapterError::InvalidNativeResult);
        std::copy_n(operation.data(),std::min(operation.size(),finish_failure_.operation.size()-1),finish_failure_.operation.data());
    }
    Observation<bool> finish_result() const {
        return finish_failure_.pending?Observation<bool>::unavailable(finish_failure_.state,
            {finish_failure_.domain,finish_failure_.code,finish_failure_.operation.data()}):Observation<bool>::available(true);
    }
    NativeTrashReceipt receipt_; Handle parent_,object_; Bin bin_; Handle metadata_;
    std::shared_ptr<PrivateScope> scope_;
    detail::PreparedJournalConsumerFailure finish_failure_;
    bool restore_=false,started_=false,attempted_=false,finished_=false;
};
class Backend final : public NativeTrashBackend {
    using R=Observation<std::unique_ptr<NativeTrashTransaction>>;
    Observation<Handle> parent(std::shared_ptr<const DirectoryCursor> p,const NativeDurableIdentity& expected) const {
        auto qualified=p->qualify_identity_bound_rename(); if(!qualified.value()) return forward<Handle>(qualified);
        if(!*qualified.value()) return reject<Handle>("trash.parent_not_qualified");
        auto duplicate=duplicate_windows_trash_parent(*p); if(!duplicate.value()) return duplicate;
        auto id=native_id(duplicate.value()->get(),true); if(!id.value()) return forward<Handle>(id);
        if(*id.value()!=expected) return reject<Handle>("trash.parent_substituted",ObservationState::Changed);
        return write_parent(duplicate.value()->get(),expected);
    }
    R prepare_trash_impl(HeldChild::Pointer held,std::stop_token stop,const std::shared_ptr<PrivateScope>& scope) const {
        if(!held||stop.stop_requested()||!held->parent_identity().value()||!held->metadata().identity.value()||!valid_name(held->name()))
            return reject<std::unique_ptr<NativeTrashTransaction>>("trash.held_input");
        auto pid=NativeDurableIdentity::from_live(*held->parent_identity().value()); auto sid=NativeDurableIdentity::from_live(*held->metadata().identity.value());
        if(!pid||!sid||sid->scheme!=IdentityScheme::WindowsFileId128) return reject<std::unique_ptr<NativeTrashTransaction>>("trash.input_identity");
        const auto* kind=held->metadata().kind.value();
        if(!kind || (*kind!=ObjectKind::RegularFile && *kind!=ObjectKind::Directory))
            return reject<std::unique_ptr<NativeTrashTransaction>>("trash.input_kind");
        const bool directory=*kind==ObjectKind::Directory;
        if(scope) {auto valid=scope->bind_source(held,stop);if(!valid.value()||!*valid.value())return forward<std::unique_ptr<NativeTrashTransaction>>(valid);}
        auto p=parent(held->parent(),*pid); if(!p.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(p);
        auto object=component(p.value()->get(),held->name(),DELETE|FILE_READ_ATTRIBUTES|READ_CONTROL,directory,FILE_OPEN,true);
        if(!object.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(object);
        auto id=native_id(object.value()->get(),directory); if(!id.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(id);
        if(*id.value()!=*sid) return reject<std::unique_ptr<NativeTrashTransaction>>("trash.source_substituted",ObservationState::Changed);
        if(scope) {auto valid=scope->bind_mutation_source(object.value()->get(),directory,stop);if(!valid.value())return forward<std::unique_ptr<NativeTrashTransaction>>(valid);}
        auto path=original_parent_path(p.value()->get()); if(!path.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(path);
        std::wstring original=*path.value(); if(original.starts_with(L"\\\\?\\UNC\\")) return reject<std::unique_ptr<NativeTrashTransaction>>("trash.remote_namespace");
        if(original.starts_with(L"\\\\?\\")&&original.size()>=7&&original[5]==L':') original.erase(0,4);
        if(original.back()!=L'\\') original+=L'\\'; const auto& component_name=*held->name().windows_units(); original.append(component_name.begin(),component_name.end());
        FILE_STANDARD_INFO standard{}; if(!GetFileInformationByHandleEx(object.value()->get(),FileStandardInfo,&standard,sizeof(standard))) return fail<std::unique_ptr<NativeTrashTransaction>>(GetLastError(),"trash.source_size");
        if(standard.EndOfFile.QuadPart<0) return reject<std::unique_ptr<NativeTrashTransaction>>("trash.source_size");
        FILETIME time{}; GetSystemTimeAsFileTime(&time);
        auto bytes=windows_trash_metadata(std::u16string(original.begin(),original.end()),directory?0:static_cast<uint64_t>(standard.EndOfFile.QuadPart),
            (static_cast<uint64_t>(time.dwHighDateTime)<<32)|time.dwLowDateTime);
        if(!bytes.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(bytes);
        auto bin=open_bin(p.value()->get(),*pid,true,scope,stop); if(!bin.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(bin);
        if(directory && (*sid==bin.value()->volume_id || *sid==bin.value()->root_id || *sid==bin.value()->id))
            return reject<std::unique_ptr<NativeTrashTransaction>>("trash.protected_bin_ancestor");
        std::array<unsigned char,16> random{};
        const auto status=BCryptGenRandom(nullptr,random.data(),static_cast<ULONG>(random.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if(status<0) return reject<std::unique_ptr<NativeTrashTransaction>>("trash.random");
        std::u16string suffix; constexpr char16_t hex[]=u"0123456789abcdef";
        for(auto b:random) { suffix+=hex[b>>4]; suffix+=hex[b&15]; }
        auto data=*NativeName::from_windows(u"$R"+suffix); auto metadata=*NativeName::from_windows(u"$I"+suffix);
        auto clear=absent(bin.value()->user.get(),data); if(!clear.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(clear);
        clear=absent(bin.value()->user.get(),metadata); if(!clear.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(clear);
        NativeTrashReceipt receipt{held->name(),std::move(data),std::move(metadata),bin.value()->sid,*pid,*sid,bin.value()->id,{},std::move(bytes).take_value(),{}};
        receipt.object_kind=*kind;
        return R::available(std::make_unique<Transaction>(std::move(receipt),std::move(p).take_value(),std::move(object).take_value(),std::move(bin).take_value(),false,Handle{},scope));
    }
    R prepare_restore_impl(const NativeTrashReceipt& receipt,std::shared_ptr<const DirectoryCursor> original,std::stop_token stop,
        const std::shared_ptr<PrivateScope>& scope) const {
        if(!original||stop.stop_requested()||!valid_name(receipt.original_name)||!valid_name(receipt.data_name)||!valid_name(receipt.metadata_name)||
            !receipt.metadata_identity||receipt.metadata_bytes.size()>65564 ||
            (receipt.object_kind!=ObjectKind::RegularFile && receipt.object_kind!=ObjectKind::Directory))
            return reject<std::unique_ptr<NativeTrashTransaction>>("restore.receipt");
        auto owner=std::dynamic_pointer_cast<const IdentityOwner>(receipt.continuity);
        if(!owner)return reject<std::unique_ptr<NativeTrashTransaction>>("restore.live_identity_owner_required");
        auto continuous=owner->validate(receipt);if(!continuous.value())return forward<std::unique_ptr<NativeTrashTransaction>>(continuous);
        auto p=parent(std::move(original),receipt.original_parent); if(!p.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(p);
        if(scope) {auto valid=scope->bind_destination(p.value()->get(),stop);if(!valid.value()||!*valid.value())return forward<std::unique_ptr<NativeTrashTransaction>>(valid);}
        auto bin=open_bin(p.value()->get(),receipt.original_parent,false,scope,stop); if(!bin.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(bin);
        if(bin.value()->id!=receipt.recycle_parent||bin.value()->sid!=receipt.user_sid) return reject<std::unique_ptr<NativeTrashTransaction>>("restore.bin_identity",ObservationState::Changed);
        const bool directory=receipt.object_kind==ObjectKind::Directory;
        if(scope) {
            auto valid=scope->bind_restore_source(owner->object.get(),directory,stop);
            if(!valid.value())return forward<std::unique_ptr<NativeTrashTransaction>>(valid);
        }
        auto object=component(bin.value()->user.get(),receipt.data_name,DELETE|FILE_READ_ATTRIBUTES|READ_CONTROL,directory,FILE_OPEN,true);
        if(!object.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(object);
        auto id=native_id(object.value()->get(),directory); if(!id.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(id);
        if(*id.value()!=receipt.object) return reject<std::unique_ptr<NativeTrashTransaction>>("restore.object_identity",ObservationState::Changed);
        if(scope) {
            auto valid=scope->bind_mutation_source(object.value()->get(),directory,stop);
            if(!valid.value())return forward<std::unique_ptr<NativeTrashTransaction>>(valid);
        }
        auto metadata=component(bin.value()->user.get(),receipt.metadata_name,FILE_READ_DATA|FILE_READ_ATTRIBUTES|READ_CONTROL|DELETE,false,FILE_OPEN,true);
        if(!metadata.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(metadata);
        auto user=current_user();if(!user.value())return forward<std::unique_ptr<NativeTrashTransaction>>(user);
        auto privacy=private_bin(metadata.value()->get(),*user.value(),true);if(!privacy.value())return forward<std::unique_ptr<NativeTrashTransaction>>(privacy);
        auto matches=metadata_matches(metadata.value()->get(),receipt); if(!matches.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(matches);
        auto clear=absent(p.value()->get(),receipt.original_name); if(!clear.value()) return forward<std::unique_ptr<NativeTrashTransaction>>(clear);
        return R::available(std::make_unique<Transaction>(receipt,std::move(p).take_value(),std::move(object).take_value(),std::move(bin).take_value(),true,std::move(metadata).take_value(),scope));
    }
    R complete_preparation(R result,const std::shared_ptr<PrivateScope>& scope) const {
        if(!result.value()) {auto closed=scope->finish_io();if(!closed.value())return forward<std::unique_ptr<NativeTrashTransaction>>(closed);}
        return result;
    }
public:
    R prepare_trash(HeldChild::Pointer held,std::stop_token stop) const override {
        return prepare_trash_impl(std::move(held),stop,{});
    }
    R prepare_restore(const NativeTrashReceipt& receipt,std::shared_ptr<const DirectoryCursor> original,std::stop_token stop) const override {
        return prepare_restore_impl(receipt,std::move(original),stop,{});
    }
    R prepare_trash_scoped(HeldChild::Pointer held,std::shared_ptr<PreparedJournalRoot> root,std::stop_token stop) const override {
        if(!root)return reject<std::unique_ptr<NativeTrashTransaction>>("trash.private_root_missing");
        auto scope=std::make_shared<PrivateScope>(std::move(root));
        return complete_preparation(prepare_trash_impl(std::move(held),stop,scope),scope);
    }
    R prepare_restore_scoped(const NativeTrashReceipt& receipt,std::shared_ptr<const DirectoryCursor> original,
        std::shared_ptr<PreparedJournalRoot> root,std::stop_token stop) const override {
        if(!root)return reject<std::unique_ptr<NativeTrashTransaction>>("restore.private_root_missing");
        auto scope=std::make_shared<PrivateScope>(std::move(root));
        return complete_preparation(prepare_restore_impl(receipt,std::move(original),stop,scope),scope);
    }
};
}
Observation<std::unique_ptr<NativeTrashDirectoryProjection>> project_windows_trash_directory(WindowsTrashScopeHandle token) {
    using R=Observation<std::unique_ptr<NativeTrashDirectoryProjection>>;
    if(!token.root_)return reject<std::unique_ptr<NativeTrashDirectoryProjection>>("trash.scope_projection_root_required");
    AdapterScope scope;
    QueryOwner incoming(std::move(token.handle_),token.root_,scope);
    HANDLE raw=nullptr;
    // Deliberately reduce the issuer's SAME_ACCESS duplicate. Even a consumer
    // of the trusted inspection bridge receives query-only native rights.
    if(!DuplicateHandle(GetCurrentProcess(),incoming.handle(),GetCurrentProcess(),&raw,
        FILE_READ_ATTRIBUTES|SYNCHRONIZE,FALSE,0))return fail<std::unique_ptr<NativeTrashDirectoryProjection>>(GetLastError(),"trash.scope_reduce_rights");
    QueryOwner reduced(Handle(raw),token.root_,scope);
    const auto closed=incoming.finish_io();if(!closed.value())return forward<std::unique_ptr<NativeTrashDirectoryProjection>>(closed);
    const auto proof=detail::prove_windows_journal_volume(reduced.handle());
    if(!proof.qualified)return R::unavailable(proof.state,{proof.domain,proof.code,proof.operation});
    auto metadata=reduced.inspect();if(!metadata.value())return forward<std::unique_ptr<NativeTrashDirectoryProjection>>(metadata);
    if(!metadata.value()->kind.value()||*metadata.value()->kind.value()!=ObjectKind::Directory)
        return reject<std::unique_ptr<NativeTrashDirectoryProjection>>("trash.scope_projection_directory_required");
    auto owner=std::make_shared<QueryOwner>(std::move(reduced));
    return R::available(std::make_unique<DirectoryProjection>(std::move(owner),*metadata.value()->identity.value()));
}
Observation<void*> detail::duplicate_windows_trash_scope_directory(const DirectoryCursor& cursor) {
    const auto* native=dynamic_cast<const QueryDirectory*>(&cursor);
    if(!native)return reject<void*>("trash.genuine_scope_projection_required");
    return native->duplicate();
}
std::shared_ptr<const NativeTrashBackend> native_trash_backend() { return std::make_shared<Backend>(); }
} // namespace ck::files
