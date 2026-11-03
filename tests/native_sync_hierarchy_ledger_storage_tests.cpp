// SPDX-License-Identifier: LGPL-2.0-or-later
// Actual private native journal I/O of representative codec records. These
// values are NOT a native data-tree review, Session/CAS or execution authority.
#define main hierarchy_ledger_codec_entry
#include "native_sync_hierarchy_ledger_tests.cpp"
#undef main
#include "native_filesystem.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "windows_name.hpp"
#else
#include <unistd.h>
#include <sys/stat.h>
#endif
namespace {
struct Store {
    std::filesystem::path parent_path,store_path;
    PreparedJournalRoot::Pointer root;bool cleaned=false;
    Store(){
#ifdef _WIN32
        const DWORD needed=GetEnvironmentVariableW(L"TEMP",nullptr,0);CHECK(needed&&needed<=32768);std::wstring temp(needed,L'\0');CHECK(GetEnvironmentVariableW(L"TEMP",temp.data(),needed)==needed-1);temp.resize(needed-1);
        auto extended=windows_extended_path(temp);CHECK(extended);temp=std::move(*extended);
        wchar_t policy[2]{};const auto policy_length=GetEnvironmentVariableW(L"CK_FS_REQUIRE_V_DEV_DRIVE",policy,2);if(policy_length==1&&policy[0]==L'1')CHECK(temp.starts_with(L"\\\\?\\V:\\tmp\\"));
        static unsigned sequence=0;parent_path=std::filesystem::path(temp)/(L"hierarchy-ledger-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(sequence++));
        CHECK(CreateDirectoryW(parent_path.c_str(),nullptr));auto child=*NativeName::from_windows(u"store");store_path=parent_path/L"store";
#else
        const char* temp=std::getenv("TMPDIR");CHECK(temp&&*temp);std::string pattern=std::string(temp)+"/hierarchy-ledger.XXXXXX";CHECK(mkdtemp(pattern.data()));parent_path=pattern;auto child=posix("store");store_path=parent_path/"store";
#endif
        NativeFileSystem fs;PreparedJournalRootRequest request;request.parent=std::shared_ptr<const DirectoryCursor>(get(fs.open_native_directory(get(NativeAbsolutePath::from_host(parent_path)))));
        request.child=child;request.disposition=JournalRootDisposition::ProvisionChild;request.navigation_hint=get(NativeAbsolutePath::from_host(store_path));JournalRootPreparationProgress progress;root=get(prepare_native_journal_root(std::move(request),progress));
    }
    void remove(const NativeName& name){
#ifdef _WIN32
        auto p=store_path/std::wstring(name.windows_units()->begin(),name.windows_units()->end());CHECK(DeleteFileW(p.c_str()));
#else
        CHECK(unlink((store_path / *name.posix_bytes()).c_str())==0);
#endif
    }
    void cleanup(){CHECK(!root);
#ifdef _WIN32
        CHECK(RemoveDirectoryW(store_path.c_str()));CHECK(RemoveDirectoryW(parent_path.c_str()));
#else
        CHECK(rmdir(store_path.c_str())==0);CHECK(rmdir(parent_path.c_str())==0);
#endif
        cleaned=true;
    }
    ~Store(){if(cleaned)return;if(root)try{(void)root->finish_io();}catch(...){}root.reset();
#ifdef _WIN32
        RemoveDirectoryW(store_path.c_str());RemoveDirectoryW(parent_path.c_str());
#else
        rmdir(store_path.c_str());rmdir(parent_path.c_str());
#endif
    }
};
void native_storage(){
    Store store;
#ifdef _WIN32
    auto e=nested(true);auto name=*NativeName::from_windows(u".ck-sync-ledger-hierarchy-storage");
#else
    CHECK(getuid()!=0);auto e=nested(false);auto name=posix(".ck-sync-ledger-hierarchy-storage");
#endif
    OperationJournalId id;id.bytes[0]=std::byte{0x63};
    auto journal=get(NativeSyncLedger::create_hierarchy(store.root,name,id,e));CHECK(get(journal->append(OperationJournalState::Prepared,e)));
    auto bad=e;bad.artifacts[0].parent.object=NativeIdentifier::from_u64(99);rejected(journal->append(OperationJournalState::Prepared,bad),"native_sync.hierarchy_ledger_artifact_parent_binding");CHECK(journal->journal().records().size()==2);
    e.proposed_baseline=SyncBaseline{e.session.policy,{}};for(const auto& p:e.paths)e.proposed_baseline->rows.push_back({p.opaque_key,p.left,p.right});
    for(auto phase:{OperationJournalState::Copied,OperationJournalState::Verified,OperationJournalState::CommitIntended,OperationJournalState::DestinationCommitted,OperationJournalState::Complete})CHECK(get(journal->append(phase,e)));
    CHECK(get(journal->finish_io()));CHECK(get(journal->finish_io()));journal.reset();
    auto loaded=get(load_native_sync_ledgers(store.root));CHECK(loaded.size()==1&&loaded[0].journal->state(0)==OperationJournalState::Complete);CHECK(loaded[0].evidence.paths[2].components==e.paths[2].components&&loaded[0].evidence.proposed_baseline==e.proposed_baseline);
    auto reopened=get(NativeSyncLedger::reopen(store.root,name,id));CHECK(reopened->journal().state(0)==OperationJournalState::Complete);CHECK(get(reopened->finish_io()));reopened.reset();loaded.clear();
    CHECK(get(store.root->finish_io()));store.root.reset();store.remove(name);store.cleanup();
}
}
int main(){try{native_storage();std::printf("NATIVE_HIERARCHY_LEDGER_STORAGE checks=%u PASS (native private journal API barriers; no power-loss or data-tree/CAS claim)\n",checks);return 0;}catch(const std::exception& e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
