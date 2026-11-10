// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../private_journal_membership.hpp"
#include "prepared_journal_root_bridge.hpp"
#include "native_journal_directory_bridge.hpp"
#include "native_windows_journal_volume.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <new>
#include <string>

namespace ck::files::detail {
namespace {
ObservationState state(DWORD code) noexcept {
    if(code==ERROR_ACCESS_DENIED||code==ERROR_SHARING_VIOLATION||code==ERROR_PRIVILEGE_NOT_HELD)return ObservationState::Denied;
    if(code==ERROR_FILE_NOT_FOUND||code==ERROR_PATH_NOT_FOUND||code==ERROR_DELETE_PENDING)return ObservationState::Changed;
    if(code==ERROR_NOT_SUPPORTED||code==ERROR_INVALID_FUNCTION||code==ERROR_CALL_NOT_IMPLEMENTED)return ObservationState::Unsupported;
    return ObservationState::Failed;
}
void native_error(PrivateMembershipFailure& failure,DWORD code,const char* op) noexcept {
    failure.record(state(code),ErrorDomain::Win32,code,op);
}
void closed(PreparedJournalRoot& root,PrivateMembershipFailure& failure,DWORD code) noexcept {
    if(!code)try {
        if(auto fault=private_membership_fault(PrivateMembershipFaultPoint::Close))code=static_cast<DWORD>(*fault);
    } catch(...) {
        record_prepared_journal_consumer_failure(root,ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_membership.close_hook");
        failure.record(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_membership.close_hook");return;
    }
    if(code) {
        record_prepared_journal_consumer_failure(root,state(code),ErrorDomain::Win32,code,"journal_membership.handle_close");
        native_error(failure,code,"journal_membership.handle_close");
    }
}
struct Handle {
    HANDLE value=nullptr;PreparedJournalRoot* root=nullptr;PrivateMembershipFailure* failure=nullptr;
    Handle(HANDLE h,PreparedJournalRoot& r,PrivateMembershipFailure& f) noexcept:value(h),root(&r),failure(&f){}
    Handle(Handle&& other) noexcept:value(other.value),root(other.root),failure(other.failure){other.value=nullptr;}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;Handle& operator=(Handle&&)=delete;
    ~Handle(){reset();}
    explicit operator bool() const noexcept{return value&&value!=INVALID_HANDLE_VALUE;}
    void reset() noexcept {
        if(*this){const auto h=value;value=nullptr;const BOOL result=CloseHandle(h);const DWORD error=result?0:GetLastError();closed(*root,*failure,error);}
    }
};
struct Snapshot {FILE_ID_INFO id{};FILE_BASIC_INFO basic{};FILE_STANDARD_INFO standard{};FILE_ATTRIBUTE_TAG_INFO tag{};};
NativeIdentifier object(const FILE_ID_128& id) noexcept {
    NativeIdentifier result;std::memcpy(result.bytes.data(),id.Identifier,16);return result;
}
bool identity_same(const Snapshot& a,const Snapshot& b) noexcept {
    return a.id.VolumeSerialNumber==b.id.VolumeSerialNumber&&object(a.id.FileId)==object(b.id.FileId);
}
bool directory_same(const Snapshot& a,const Snapshot& b) noexcept {
    return identity_same(a,b)&&a.basic.FileAttributes==b.basic.FileAttributes&&a.tag.ReparseTag==b.tag.ReparseTag&&
        a.basic.CreationTime.QuadPart==b.basic.CreationTime.QuadPart&&
        a.basic.LastWriteTime.QuadPart==b.basic.LastWriteTime.QuadPart&&a.basic.ChangeTime.QuadPart==b.basic.ChangeTime.QuadPart&&
        a.standard.NumberOfLinks==b.standard.NumberOfLinks&&!b.standard.DeletePending&&b.standard.Directory;
}
bool attributes(DWORD value,DWORD reparse,PrivateMembershipFailure& failure) {
    constexpr DWORD ordinary=FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|
        FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_TEMPORARY|
        FILE_ATTRIBUTE_SPARSE_FILE|FILE_ATTRIBUTE_COMPRESSED|FILE_ATTRIBUTE_NOT_CONTENT_INDEXED|
        FILE_ATTRIBUTE_ENCRYPTED|FILE_ATTRIBUTE_INTEGRITY_STREAM|FILE_ATTRIBUTE_NO_SCRUB_DATA;
    if(reparse||(value&~ordinary)){failure.unsafe("journal_membership.attributes_unqualified");return false;}
    return true;
}
bool snapshot(HANDLE h,Snapshot& out,PrivateMembershipFailure& failure) {
    if(!GetFileInformationByHandleEx(h,FileIdInfo,&out.id,sizeof(out.id))||
        !GetFileInformationByHandleEx(h,FileBasicInfo,&out.basic,sizeof(out.basic))||
        !GetFileInformationByHandleEx(h,FileStandardInfo,&out.standard,sizeof(out.standard))||
        !GetFileInformationByHandleEx(h,FileAttributeTagInfo,&out.tag,sizeof(out.tag))) {
        native_error(failure,GetLastError(),"journal_membership.handle_information");return false;
    }
    if(out.standard.DeletePending||!out.standard.Directory||
        !(out.basic.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)) {failure.changed("journal_membership.directory_changed");return false;}
    return attributes(out.basic.FileAttributes,out.tag.ReparseTag,failure);
}
Handle by_id(HANDLE volume,const FILE_ID_INFO& expected,PreparedJournalRoot& root,
    PrivateMembershipFailure& failure,bool guard) {
    FILE_ID_DESCRIPTOR descriptor{};descriptor.dwSize=sizeof(descriptor);descriptor.Type=ExtendedFileIdType;
    descriptor.ExtendedFileId=expected.FileId;
    Handle result(OpenFileById(volume,&descriptor,FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|(guard?0:FILE_SHARE_DELETE),nullptr,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL),root,failure);
    if(!result)native_error(failure,GetLastError(),"journal_membership.open_directory_id");
    return result;
}
struct Record {std::wstring name;FILE_ID_128 id{};DWORD attributes=0,reparse=0;};
bool record_less(const Record& a,const Record& b){return a.name<b.name;}
bool record_same(const Record& a,const Record& b) noexcept {
    return a.name==b.name&&object(a.id)==object(b.id)&&a.attributes==b.attributes&&a.reparse==b.reparse;
}
struct Node {
    Handle handle;Snapshot before;std::size_t depth;std::vector<Record> records;
    Node(Handle h,Snapshot s,std::size_t d):handle(std::move(h)),before(s),depth(d){}
    Node(Node&&)=default;
};
struct Scan {
    PreparedJournalRoot& root;PrivateMembershipFailure& failure;const HeldChild& entry;
    const PrivateJournalMembershipLimits& limits;std::stop_token stop;std::vector<Node> nodes;
    std::size_t records_seen=0,names_seen=0;
    Scan(PreparedJournalRoot& r,PrivateMembershipFailure& f,const HeldChild& e,const PrivateJournalMembershipLimits& l,
        std::stop_token s):root(r),failure(f),entry(e),limits(l),stop(s){}
    bool running() {
        if(failure)return false;
        if(stop.stop_requested()){failure.record(ObservationState::Changed,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InterruptedRead),"journal_membership.cancelled");return false;}
        return true;
    }
    bool hook(PrivateMembershipFaultPoint point) {
        if(auto fault=private_membership_fault(point)) {
            native_error(failure,static_cast<DWORD>(*fault),"journal_membership.read_hook");return false;
        }
        return running();
    }
    bool enumerate(HANDLE h,std::vector<Record>& records,std::size_t& count,std::size_t& names,bool protected_inventory=true) {
        alignas(8) std::array<std::byte,65536> buffer{};bool first=true;
        for(;;) {
            if(!running())return false;
            const auto kind=first?FileIdExtdDirectoryRestartInfo:FileIdExtdDirectoryInfo;first=false;
            if(!GetFileInformationByHandleEx(h,kind,buffer.data(),static_cast<DWORD>(buffer.size()))) {
                const auto code=GetLastError();if(code==ERROR_NO_MORE_FILES)break;
                native_error(failure,code,"journal_membership.enumeration");return false;
            }
            std::size_t offset=0;
            for(;;) {
                constexpr std::size_t header=offsetof(FILE_ID_EXTD_DIR_INFO,FileName);
                if(offset>buffer.size()-header){failure.unsafe("journal_membership.record_extent");return false;}
                const auto* info=reinterpret_cast<const FILE_ID_EXTD_DIR_INFO*>(buffer.data()+offset);
                const auto remaining=buffer.size()-offset;
                if(!info->FileNameLength||(info->FileNameLength%sizeof(WCHAR))||info->FileNameLength>remaining-header||
                    (info->NextEntryOffset&&(info->NextEntryOffset%8||info->NextEntryOffset<header+info->FileNameLength||
                     info->NextEntryOffset>remaining))) {failure.unsafe("journal_membership.name_extent");return false;}
                const auto units=info->FileNameLength/sizeof(WCHAR);
                const bool dot=units==1&&info->FileName[0]==L'.';
                const bool dotdot=units==2&&info->FileName[0]==L'.'&&info->FileName[1]==L'.';
                if(!dot&&!dotdot) {
                    if(count>=limits.max_records||info->FileNameLength>limits.max_name_bytes-names) {
                        failure.unsafe("journal_membership.record_limit");return false;
                    }
                    if(protected_inventory&&(!attributes(info->FileAttributes,info->ReparsePointTag,failure)||
                        object(info->FileId)==NativeIdentifier{})) {
                        failure.unsafe("journal_membership.record_identity");return false;
                    }
                    std::wstring name(info->FileName,units);
                    if(name.find_first_of(L"\\/:")!=name.npos||name.find(L'\0')!=name.npos) {
                        failure.unsafe("journal_membership.native_name");return false;
                    }
                    records.push_back({std::move(name),info->FileId,info->FileAttributes,info->ReparsePointTag});
                    ++count;names+=info->FileNameLength;
                }
                if(!info->NextEntryOffset)break;
                offset+=info->NextEntryOffset;
            }
        }
        std::sort(records.begin(),records.end(),record_less);
        for(std::size_t n=1;n<records.size();++n)if(records[n-1].name==records[n].name) {
            failure.changed("journal_membership.duplicate_name");return false;
        }
        return true;
    }
    bool selected_name(HANDLE parent,const Snapshot& expected_parent,const BasicMetadata& selected) {
        auto independent=by_id(parent,expected_parent.id,root,failure,false);if(!independent)return false;
        Snapshot current{};if(!snapshot(independent.value,current,failure))return false;
        if(!identity_same(expected_parent,current)){failure.changed("journal_membership.parent_changed");return false;}
        std::size_t count=0,names=0;std::vector<Record> records;
        if(!enumerate(independent.value,records,count,names,false))return false;
        const auto* units=entry.name().windows_units();if(!units){failure.unsafe("journal_membership.source_name");return false;}
        const std::wstring name(units->begin(),units->end());
        const auto at=std::lower_bound(records.begin(),records.end(),Record{name,{},0,0},record_less);
        if(at==records.end()||at->name!=name||object(at->id)!=selected.identity.value()->object||
            (at->attributes&FILE_ATTRIBUTE_DIRECTORY)) {failure.changed("journal_membership.selected_name_changed");return false;}
        if(!attributes(at->attributes,at->reparse,failure))return false;
        return true;
    }
    void run() {
        auto duplicate=duplicate_prepared_journal_directory(root);
        if(!duplicate.value()){failure.record(*duplicate.unavailable_detail());return;}
        Handle original(static_cast<HANDLE>(*duplicate.value()),root,failure);
        auto parent_dup=duplicate_windows_journal_directory(*entry.parent());
        if(!parent_dup.value()){failure.record(*parent_dup.unavailable_detail());return;}
        Handle parent(static_cast<HANDLE>(*parent_dup.value()),root,failure);
        for(const auto h:{original.value,parent.value}) {
            const auto proof=prove_windows_journal_volume(h);
            if(!proof.qualified){failure.record(proof.state,proof.domain,proof.code,proof.operation);return;}
        }
        auto source=entry.inspect_basic();if(!source.value()){failure.record(*source.unavailable_detail());return;}
        if(!private_membership_entry_qualified(*source.value())||
            source.value()->identity.value()->scheme!=IdentityScheme::WindowsFileId128||
            source.value()->identity.value()->generation) {failure.unsafe("journal_membership.source_unqualified");return;}
        if(!private_membership_entry_same(entry.metadata(),*source.value())){failure.changed("journal_membership.source_changed");return;}
        Snapshot parent_before{},root_before{};
        if(!snapshot(parent.value,parent_before,failure)||!snapshot(original.value,root_before,failure))return;
        const auto& source_id=*source.value()->identity.value();
        if(source_id.volume!=NativeIdentifier::from_u64(parent_before.id.VolumeSerialNumber)||
            *source.value()->mount_id.value()!=parent_before.id.VolumeSerialNumber) {
            failure.changed("journal_membership.source_mount");return;
        }
        if(!selected_name(parent.value,parent_before,*source.value()))return;
        auto start=by_id(original.value,root_before.id,root,failure,false);if(!start)return;
        Snapshot opened{};if(!snapshot(start.value,opened,failure))return;
        if(!directory_same(root_before,opened)){failure.changed("journal_membership.root_changed");return;}
        original.reset();if(!running())return;
        nodes.emplace_back(std::move(start),opened,0);
        for(std::size_t index=0;index<nodes.size()&&running();++index) {
            std::vector<Record> records;
            if(!enumerate(nodes[index].handle.value,records,records_seen,names_seen))return;
            for(const auto& record:records) {
                if(!running())return;
                if(!(record.attributes&FILE_ATTRIBUTE_DIRECTORY)) {
                    if(source_id.volume==NativeIdentifier::from_u64(root_before.id.VolumeSerialNumber)&&
                        source_id.object==object(record.id)) {failure.unsafe("journal_membership.private_alias");return;}
                    continue;
                }
                const auto depth=nodes[index].depth+1;
                if(nodes.size()>=limits.max_directories||depth>limits.max_depth) {
                    failure.unsafe("journal_membership.directory_limit");return;
                }
                FILE_ID_INFO wanted{};wanted.VolumeSerialNumber=root_before.id.VolumeSerialNumber;wanted.FileId=record.id;
                auto child=by_id(nodes[index].handle.value,wanted,root,failure,true);if(!child)return;
                Snapshot held{};if(!snapshot(child.value,held,failure))return;
                if(held.id.VolumeSerialNumber!=wanted.VolumeSerialNumber||object(held.id.FileId)!=object(wanted.FileId)) {
                    failure.changed("journal_membership.child_changed");return;
                }
                for(const auto& previous:nodes)if(identity_same(previous.before,held)) {
                    failure.unsafe("journal_membership.directory_alias");return;
                }
                nodes.emplace_back(std::move(child),held,depth);
            }
            nodes[index].records=std::move(records);
            if(!hook(PrivateMembershipFaultPoint::DirectoryReadComplete))return;
        }
        if(!running()||!hook(PrivateMembershipFaultPoint::BeforeFinalCheck))return;
        std::size_t final_count=0,final_names=0;
        for(const auto& node:nodes) {
            std::vector<Record> current;
            if(!enumerate(node.handle.value,current,final_count,final_names))return;
            if(current.size()!=node.records.size()||!std::equal(current.begin(),current.end(),node.records.begin(),record_same)) {
                failure.changed("journal_membership.namespace_changed");return;
            }
            Snapshot now{};if(!snapshot(node.handle.value,now,failure))return;
            if(!directory_same(node.before,now)){failure.changed("journal_membership.directory_changed");return;}
        }
        auto after=entry.inspect_basic();if(!after.value()){failure.record(*after.unavailable_detail());return;}
        Snapshot parent_after{};if(!snapshot(parent.value,parent_after,failure))return;
        if(!private_membership_entry_same(*source.value(),*after.value())||!identity_same(parent_before,parent_after)) {
            failure.changed("journal_membership.source_changed");return;
        }
        if(!selected_name(parent.value,parent_after,*after.value()))return;
        auto valid=root.revalidate();if(!valid.value())failure.record(*valid.unavailable_detail());
        else if(!*valid.value())failure.unsafe("journal_membership.root_false");
    }
};
}
Observation<bool> native_private_journal_disjointness(PreparedJournalRoot& root,const HeldChild& entry,
    const PrivateJournalMembershipLimits& limits,std::stop_token stop) {
    PrivateMembershipFailure failure;
    try {Scan scan(root,failure,entry,limits,stop);scan.run();}
    catch(const std::bad_alloc&) {failure.record(ObservationState::Unknown,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_membership.allocation");}
    catch(...) {failure.record(ObservationState::Unknown,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_membership.exception");}
    return failure.result();
}
} // namespace ck::files::detail
