// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_filesystem.hpp"
#include "native_trash.hpp"
#include "private_journal_scope.hpp"
#include "platform/journal_root_test_faults.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <source_location>
#include <vector>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif
using namespace ck::files;
namespace {
unsigned checks=0;
#define CHECK(x) do {++checks;if(!(x)){std::fprintf(stderr,"native_action_scope:%d: %s\n",__LINE__,#x);std::abort();}}while(false)
template<class T>T take(Observation<T> value,const std::source_location location=std::source_location::current()) {
    if(!value.value()) {const auto& e=*value.unavailable_detail();std::fprintf(stderr,"line=%u %s state=%u domain=%u code=%lld\n",
        unsigned(location.line()),e.error.operation.c_str(),unsigned(e.state),unsigned(e.error.domain),static_cast<long long>(e.error.code));}
    CHECK(value.value());return std::move(value).take_value();
}
#ifdef _WIN32
NativeName name(const char* ascii){return *NativeName::from_windows(std::u16string(ascii,ascii+std::char_traits<char>::length(ascii)));}
std::shared_ptr<const DirectoryCursor> child(std::shared_ptr<const DirectoryCursor> parent,const NativeName& name) {
    return std::shared_ptr<const DirectoryCursor>(take(parent->open_directory_child(name)));
}
std::shared_ptr<const DirectoryCursor> mkdir(std::shared_ptr<const DirectoryCursor> parent,const char* leaf) {
    return std::shared_ptr<const DirectoryCursor>(take(parent->create_child_directory(name(leaf))));
}
void file(std::shared_ptr<const DirectoryCursor> parent,const NativeName& leaf) {
    auto writer=take(parent->create_child_file(leaf));const std::array<std::byte,3> bytes{std::byte{1},std::byte{2},std::byte{3}};
    CHECK(take(writer->write_content(0,bytes))==bytes.size());CHECK(take(writer->finish_content_writes()));
}
PreparedJournalRoot::Pointer prepare(std::shared_ptr<const DirectoryCursor> parent) {
    PreparedJournalRootRequest request;request.parent=std::move(parent);request.disposition=JournalRootDisposition::AdoptHeld;
    JournalRootPreparationProgress progress;return take(prepare_native_journal_root(std::move(request),progress));
}
std::wstring volume(std::shared_ptr<const DirectoryCursor> parent) {
    auto handle=take(duplicate_windows_trash_parent(*parent));wchar_t label[128]{},filesystem[32]{};
    CHECK(GetVolumeInformationByHandleW(handle.get(),label,128,nullptr,nullptr,nullptr,filesystem,32));
    CHECK(std::wstring(label)==L"CKFEA05SCOPE"&&std::wstring(filesystem)==L"NTFS");
    std::vector<wchar_t> path(32768);const auto size=GetFinalPathNameByHandleW(handle.get(),path.data(),static_cast<DWORD>(path.size()),FILE_NAME_OPENED|VOLUME_NAME_GUID);
    CHECK(size&&size<path.size());std::wstring value(path.data(),size);const auto end=value.find(L'}');
    CHECK(value.starts_with(L"\\\\?\\Volume{")&&end!=value.npos&&value[end+1]==L'\\');return value.substr(0,end+2);
}
std::u16string sid() {
    HANDLE token=nullptr;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));DWORD size=0;
    GetTokenInformation(token,TokenUser,nullptr,0,&size);CHECK(size&&size<65536);std::vector<std::byte> bytes(size);
    CHECK(GetTokenInformation(token,TokenUser,bytes.data(),size,&size));CHECK(CloseHandle(token));
    wchar_t* string=nullptr;CHECK(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid,&string));
    const std::wstring value(string);LocalFree(string);return std::u16string(value.begin(),value.end());
}
unsigned journal_sequence=0;
void commit(PreparedJournalRoot::Pointer root,std::unique_ptr<NativeTrashTransaction>& transaction) {
    CHECK(take(transaction->revalidate_private_scope({})));
    const auto basename=name(("scope-"+std::to_string(++journal_sequence)+".journal").c_str());
    auto writer=take(root->open_journal(basename,true));OperationJournalId id{};id.bytes[0]=std::byte(journal_sequence);
    auto journal=take(OperationJournal::create(FileOperation::Move,id,{1,16,256*1024}));
    auto result=transaction->commit([&](OperationJournalState state,const NativeTrashReceipt& receipt) {
        auto bytes=encode_native_trash_receipt(receipt);
        if(!bytes.value())return Observation<bool>::unavailable(bytes.state(),bytes.unavailable_detail()->error);
        return append_operation_journal_file(*writer,*journal,{journal->records().size()+1,0,state,std::move(bytes).take_value()});
    },{});
    CHECK(take(transaction->finish_io()));CHECK(take(writer->finish_io()));writer.reset();CHECK(take(std::move(result)));
    CHECK(journal->state(0)==OperationJournalState::Complete);
}
void roundtrip(PreparedJournalRoot::Pointer root,std::shared_ptr<const DirectoryCursor> parent,const char* leaf) {
    const auto selected=name(leaf);file(parent,selected);auto source=take(HeldChild::observe(parent,selected));
    const auto expected=*source->metadata().identity.value();auto backend=native_trash_backend();
    auto trash=take(backend->prepare_trash_scoped(source,root,{}));commit(root,trash);const auto receipt=trash->receipt();trash.reset();
    auto gone=take(parent->lookup_child(selected,ChildLookupMode::NativeDefault));CHECK(gone.state()==ChildLookupState::Missing);
    auto restore=take(backend->prepare_restore_scoped(receipt,parent,root,{}));commit(root,restore);restore.reset();
    auto restored=take(HeldChild::observe_with_access(parent,selected,EntryAccess::ContentRead));
    CHECK(compare_identity(expected,*restored->metadata().identity.value())==IdentityComparison::Same);
    const auto bytes=take(restored->read_content());CHECK(bytes.complete&&bytes.bytes==std::vector<std::byte>({std::byte{1},std::byte{2},std::byte{3}}));
}
void refusal(PreparedJournalRoot::Pointer root,std::shared_ptr<const DirectoryCursor> source_parent,const char* leaf,
    std::shared_ptr<const DirectoryCursor> bin) {
    const auto selected=name(leaf);file(source_parent,selected);auto source=take(HeldChild::observe(source_parent,selected));
    const auto before=take(bin->inspect_basic());auto prepared=native_trash_backend()->prepare_trash_scoped(source,root,{});
    CHECK(!prepared.value()&&prepared.state()==ObservationState::Unsupported);
    auto current=take(source->refresh());CHECK(current->continues(*source));
    const auto after=take(bin->inspect_basic());
    CHECK(*before.modified.value()==*after.modified.value()&&*before.changed.value()==*after.changed.value());
}
void cancelled(PreparedJournalRoot::Pointer root,std::shared_ptr<const DirectoryCursor> parent,
    std::shared_ptr<const DirectoryCursor> bin) {
    const auto leaf=name("cancel-before-effects");file(parent,leaf);
    auto source=take(HeldChild::observe(parent,leaf));
    auto transaction=take(native_trash_backend()->prepare_trash_scoped(source,root,{}));
    const auto data=transaction->receipt().data_name,metadata=transaction->receipt().metadata_name;
    std::stop_source stop;stop.request_stop();unsigned journal_calls=0;
    auto result=transaction->commit([&](OperationJournalState,const NativeTrashReceipt&) {
        ++journal_calls;return Observation<bool>::available(true);
    },stop.get_token());
    CHECK(!result.value()&&!transaction->mutation_attempted()&&!journal_calls);
    CHECK(take(transaction->finish_io()));transaction.reset();
    CHECK(take(source->refresh())->continues(*source));
    CHECK(take(bin->lookup_child(data,ChildLookupMode::NativeDefault)).state()==ChildLookupState::Missing);
    CHECK(take(bin->lookup_child(metadata,ChildLookupMode::NativeDefault)).state()==ChildLookupState::Missing);
}
void privacy_changed(PreparedJournalRoot::Pointer root,std::shared_ptr<const DirectoryCursor> parent,
    const NativeAbsolutePath& root_address) {
    const auto leaf=name("stale-root-before-effects");file(parent,leaf);
    auto source=take(HeldChild::observe(parent,leaf));
    auto transaction=take(native_trash_backend()->prepare_trash_scoped(source,root,{}));
    auto path=*root_address.windows_units();
    if(!path.starts_with(u"\\\\?\\"))path=u"\\\\?\\"+path;
    const auto raw=CreateFileW(reinterpret_cast<const wchar_t*>(path.c_str()),READ_CONTROL|WRITE_DAC,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    CHECK(raw!=INVALID_HANDLE_VALUE);
    PSECURITY_DESCRIPTOR original=nullptr;PACL original_dacl=nullptr;
    CHECK(GetSecurityInfo(raw,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&original_dacl,nullptr,&original)==ERROR_SUCCESS);
    SECURITY_DESCRIPTOR_CONTROL control{};DWORD revision=0;
    CHECK(GetSecurityDescriptorControl(original,&control,&revision));
    PSECURITY_DESCRIPTOR public_descriptor=nullptr;
    CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;WD)",SDDL_REVISION_1,&public_descriptor,nullptr));
    BOOL present=FALSE,defaulted=FALSE;PACL public_dacl=nullptr;
    CHECK(GetSecurityDescriptorDacl(public_descriptor,&present,&public_dacl,&defaulted)&&present);
    CHECK(SetSecurityInfo(raw,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,nullptr,public_dacl,nullptr)==ERROR_SUCCESS);
    unsigned journal_calls=0;
    auto valid=transaction->revalidate_private_scope({});CHECK(!valid.value());
    auto result=transaction->commit([&](OperationJournalState,const NativeTrashReceipt&) {
        ++journal_calls;return Observation<bool>::available(true);
    },{});
    CHECK(!result.value()&&!transaction->mutation_attempted()&&!journal_calls);
    CHECK(SetSecurityInfo(raw,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|
        ((control&SE_DACL_PROTECTED)?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION),
        nullptr,nullptr,original_dacl,nullptr)==ERROR_SUCCESS);
    LocalFree(public_descriptor);LocalFree(original);CHECK(CloseHandle(raw));
    CHECK(take(transaction->finish_io()));transaction.reset();
    CHECK(take(source->refresh())->continues(*source));
}
std::optional<int64_t> query_close_fault(detail::JournalRootFaultPoint point) {
    return point==detail::JournalRootFaultPoint::DirectoryClose?std::optional<int64_t>{5}:std::nullopt;
}
NativeTrashReceipt close_failure(PreparedJournalRoot::Pointer root,std::shared_ptr<const DirectoryCursor> parent) {
    const auto leaf=name("close-fault-file");file(parent,leaf);
    auto transaction=take(native_trash_backend()->prepare_trash_scoped(take(HeldChild::observe(parent,leaf)),root,{}));
    auto writer=take(root->open_journal(name("native-close-failure.journal"),true));OperationJournalId id{};id.bytes[0]=std::byte{99};
    auto journal=take(OperationJournal::create(FileOperation::Move,id,{1,16,256*1024}));
    const auto previous=detail::journal_root_test_fault;
    auto result=transaction->commit([&](OperationJournalState state,const NativeTrashReceipt& receipt) {
        auto encoded=take(encode_native_trash_receipt(receipt));
        auto saved=append_operation_journal_file(*writer,*journal,{journal->records().size()+1,0,state,std::move(encoded)});
        if(state==OperationJournalState::DestinationCommitted)detail::journal_root_test_fault=query_close_fault;
        return saved;
    },{});
    detail::journal_root_test_fault=previous;
    CHECK(!result.value()&&result.unavailable_detail()->error.domain==ErrorDomain::Win32&&result.unavailable_detail()->error.code==5);
    CHECK(transaction->mutation_attempted()&&journal->state(0)!=OperationJournalState::Complete);
    auto repeated=transaction->commit([](OperationJournalState,const NativeTrashReceipt&){return Observation<bool>::available(true);},{});
    CHECK(!repeated.value()&&repeated.state()==ObservationState::Changed); // No replay after publication.
    auto closed=transaction->finish_io();CHECK(!closed.value()&&closed.unavailable_detail()->error.code==5);
    (void)writer->finish_io();writer.reset();auto receipt=transaction->receipt();transaction.reset();
    CHECK(take(parent->lookup_child(leaf,ChildLookupMode::NativeDefault)).state()==ChildLookupState::Missing);
    return receipt;
}
void run(const std::filesystem::path& path) {
    wchar_t isolated[2]{};
    CHECK(GetEnvironmentVariableW(L"CKFEA_ISOLATED_SCOPE_VOLUME",isolated,2)==1&&isolated[0]==L'1');
    CHECK(GetEnvironmentVariableW(L"TMPDIR",nullptr,0)>1&&GetEnvironmentVariableW(L"TEMP",nullptr,0)>1&&
        GetEnvironmentVariableW(L"TMP",nullptr,0)>1);
    CHECK(path.native().starts_with(L"V:\\tmp\\")||path.native().starts_with(L"\\\\?\\V:\\tmp\\"));
    NativeFileSystem fs;auto base=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(path)));
    const auto native_volume=volume(base); // Refuse Main's shared Disk5 label.
    auto sources=mkdir(base,"sources");auto control=mkdir(base,"control");
    CHECK(take(prepare_native_operation_journal_root(take(NativeAbsolutePath::from_host(path/L"control")))));
    auto active=prepare(control);file(sources,name("bootstrap"));
    // Native facility setup, without creating $I or moving this test object.
    auto bootstrap=take(native_trash_backend()->prepare_trash(take(HeldChild::observe(sources,name("bootstrap"))),{}));
    CHECK(take(bootstrap->finish_io()));bootstrap.reset();
    auto bin_address=take(NativeAbsolutePath::from_windows(std::u16string(native_volume.begin(),native_volume.end())+u"$Recycle.Bin"));
    auto bin=std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(bin_address)));
    auto user=child(bin,*NativeName::from_windows(sid()));
    cancelled(active,sources,user);
    privacy_changed(active,sources,take(NativeAbsolutePath::from_host(path/L"control")));
    // Only this newly-created, explicitly labelled task volume is tightened.
    CHECK(take(prepare_native_operation_journal_root(bin_address)));
    auto bin_root=prepare(bin);refusal(bin_root,sources,"root-ancestor-of-target",user);
    CHECK(take(bin_root->finish_io()));bin_root.reset();
    const auto user_address=take(bin_address.child_address(*NativeName::from_windows(sid())));
    CHECK(take(prepare_native_operation_journal_root(user_address)));
    auto same=prepare(user);refusal(same,sources,"root-equals-target",user);
    CHECK(take(same->finish_io()));same.reset();
    const auto fixture_leaf=path.filename().native();
    const auto nested_name=*NativeName::from_windows(u"scope-private-"+std::u16string(fixture_leaf.begin(),fixture_leaf.end()));
    auto nested=std::shared_ptr<const DirectoryCursor>(take(user->create_child_directory(nested_name)));
    auto nested_address=take(bin_address.child_address(*NativeName::from_windows(sid())));
    nested_address=take(nested_address.child_address(nested_name));
    CHECK(take(prepare_native_operation_journal_root(nested_address)));
    auto below=prepare(nested);roundtrip(below,sources,"target-ancestor-of-root-allowed");
    CHECK(take(below->finish_io()));below.reset();
    // A directory source containing the active Root is refused before bin I/O.
    // Initial fixture navigation only. The wrapper may nest its temporary
    // directory below another cohort directory, not directly under the volume.
    const auto fixture_address=take(NativeAbsolutePath::from_host(path));
    auto physical_parent=std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(take(fixture_address.parent_address()))));
    const auto leaf=path.filename().native();auto containing_name=*NativeName::from_windows(std::u16string(leaf.begin(),leaf.end()));
    auto containing=take(HeldChild::observe(physical_parent,containing_name));
    CHECK(containing->metadata().identity.value()&&base->identity().value()&&compare_identity(*containing->metadata().identity.value(),*base->identity().value())==IdentityComparison::Same);
    auto rejected=native_trash_backend()->prepare_trash_scoped(containing,active,{});
    CHECK(!rejected.value()&&rejected.state()==ObservationState::Unsupported);
    auto folder=mkdir(sources,"restore-directory");file(folder,name("payload"));folder.reset();
    auto trash=take(native_trash_backend()->prepare_trash_scoped(take(HeldChild::observe(sources,name("restore-directory"))),active,{}));
    commit(active,trash);const auto receipt=trash->receipt();trash.reset();
    auto retained=child(user,receipt.data_name);auto inside=mkdir(retained,"new-active-root");
    auto retained_address=take(bin_address.child_address(*NativeName::from_windows(sid())));
    retained_address=take(retained_address.child_address(receipt.data_name));auto inside_address=take(retained_address.child_address(name("new-active-root")));
    CHECK(take(prepare_native_operation_journal_root(inside_address)));auto inside_root=prepare(inside);
    const auto before=take(retained->inspect_basic());
    auto denied=native_trash_backend()->prepare_restore_scoped(receipt,sources,inside_root,{});
    CHECK(!denied.value()&&denied.state()==ObservationState::Unsupported);
    const auto after=take(retained->inspect_basic());CHECK(*before.modified.value()==*after.modified.value()&&*before.changed.value()==*after.changed.value());
    CHECK(take(inside_root->finish_io()));inside_root.reset();inside.reset();retained.reset();
    // The old, now inactive Root is ordinary retained data; only the passed
    // active owner is protected. A global lease is a separate client gate.
    auto restore=take(native_trash_backend()->prepare_restore_scoped(receipt,sources,active,{}));commit(active,restore);restore.reset();
    const auto uncertain=close_failure(active,sources);
    const auto closed=active->finish_io();CHECK(!closed.value()&&closed.unavailable_detail()->error.code==5);active.reset();
    // Explicit current review using a still-live native receipt, not a journal
    // replay or value-only reconstruction. A fresh healthy Root owns this job.
    auto reviewed=prepare(control);auto recover=take(native_trash_backend()->prepare_restore_scoped(uncertain,sources,reviewed,{}));
    commit(reviewed,recover);recover.reset();CHECK(take(reviewed->finish_io()));reviewed.reset();
    std::puts("native scope: target inside/equal Root refused; target ancestor allowed; source/restore directories containing Root refused; native file+directory roundtrips passed");
}
#endif
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {
    CHECK(argc==2);run(std::filesystem::path(argv[1]));std::printf("native_action_scope: %u checks passed\n",checks);
}
#else
int main(int argc,char** argv) {
    (void)argc;(void)argv;(void)checks;std::puts("native_action_scope: Windows native Trash scope only; POSIX strong scope remains Unsupported");
}
#endif
