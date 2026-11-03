// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_filesystem.hpp"
#include "native_sync_observation.hpp"
#include "native_sync_ledger.hpp"
#include "private_journal_scope.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "platform/native_directory_reader.hpp"
#include "metadata_capture_job.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <cstdarg>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
using namespace ck::files;
namespace {
bool rename_armed=false,close_armed=false;dev_t selected_dev{};ino_t selected_ino{};unsigned rename_hits=0,close_hits=0;
const char* pending="pending-ledger";const char* reserved=".ck-sync-ledger-prepopulation";
void check(bool b,const char*s){if(!b){std::fprintf(stderr,"FAIL %s\n",s);std::abort();}}
template<class T>T get(Observation<T>o){if(!o.value()){auto&e=*o.unavailable_detail();std::fprintf(stderr,"%s state%u code%lld\n",e.error.operation.c_str(),unsigned(e.state),(long long)e.error.code);std::abort();}return std::move(o).take_value();}
NativeName name(const char*s){return *NativeName::from_posix(s);}
struct Fixture{
 std::string path;NativeFileSystem fs;std::shared_ptr<const DirectoryCursor> root;
 Fixture(){const char*t=getenv("TMPDIR");check(t&&*t,"explicit TMPDIR");path=std::string(t)+"/dir-reader.XXXXXX";check(mkdtemp(path.data()),"mkdtemp");root=std::shared_ptr<const DirectoryCursor>(get(fs.open_directory(path)));}
 ~Fixture(){root.reset();std::filesystem::remove_all(path);}
 void data(const char*n){int fd=open((path+"/"+n).c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);check(fd>=0,"data create");check(write(fd,"native",6)==6&&!close(fd),"data finish");}
 void select(){struct stat s{};check(!stat(path.c_str(),&s),"selectroot");selected_dev=s.st_dev;selected_ino=s.st_ino;}
};
MetadataReplayPolicy policy(){MetadataReplayPolicy p;p.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;p.ownership=MetadataOwnership::CurrentCaller;return p;}
struct Latch final:MetadataCaptureFailureLatch{PreparedJournalRoot::Pointer root;mutable std::optional<MetadataCaptureCleanupError>first;explicit Latch(PreparedJournalRoot::Pointer p):root(std::move(p)){}void record_first(MetadataCaptureCleanupError e)const noexcept override{if(!first){first=e;detail::record_prepared_journal_consumer_failure(*root,e.state,e.domain,e.code,e.operation);}}};
void root_reader(){Fixture f; // This native OFD is deliberately opened empty.
 f.data("a");f.data("b");NativeSyncProofLimits limits;NativeSyncProofBudget budget;
 auto first=get(observe_native_sync_root(f.root,policy(),limits,budget));std::printf("native first inventory size=%zu expected2\n",first->files.size());std::fflush(stdout);check(first->files.size()==2,"prepopulation root omitted native entries");
 first.reset();budget={};auto second=get(observe_native_sync_root(f.root,policy(),limits,budget));check(second->files.size()==2,"second root enumeration reused consumed reader");
 check(get(f.root->lookup_child(name("a"),ChildLookupMode::NativeDefault)).state()==ChildLookupState::Found,"caller anchor closed");
 auto child=get(f.root->create_child_directory(name("new")));std::shared_ptr<const DirectoryCursor> directory(std::move(child));
 auto file=get(directory->create_child_file(name("child")));get(file->finish_content_writes());file.reset();
 auto nested=get(observe_native_sync_root(directory,policy(),limits,budget));check(nested->files.size()==1,"new directory prepopulation reader omitted child");
 std::puts("PASS genuine prepopulation root/create_child_directory + repeated fresh native observation");}
void ledger_reader(){Fixture f;auto address=get(NativeAbsolutePath::from_posix(f.path));get(prepare_native_operation_journal_root(address));auto root=get(acquire_native_journal_root(address));
 NativeSyncLedgerEvidence evidence;OperationJournalId id{};id.bytes[0]=std::byte{5};auto ledger=get(NativeSyncLedger::create(root,name(reserved),id,evidence));get(ledger->finish_io());ledger.reset();
 check(!rename((f.path+"/"+reserved).c_str(),(f.path+"/"+pending).c_str()),"stage pending ledger");f.select();rename_armed=true;
 auto raced=load_native_sync_ledgers(root);rename_armed=false;check(rename_hits==1,"native enum-open rename injection not hit");
 std::printf("native raced ledger available=%u size=%zu state=%u expectedChanged\n",unsigned(raced.value()!=nullptr),raced.value()?raced.value()->size():0,unsigned(raced.state()));std::fflush(stdout);check(!raced.value()&&raced.state()==ObservationState::Changed,"ledger changed after checkpoint silently omitted");
 auto actual=get(load_native_sync_ledgers(root));check(actual.size()==1,"fresh ledger retry missed native journal");actual.clear();get(root->finish_io());root.reset();
 std::puts("PASS actual kernel namespace insertion after enumeration open refuses changed ledger inventory; fresh retry discovers journal");}
void close_reader(){Fixture f;f.data("a");check(!mkdir((f.path+"/private").c_str(),0700),"private root");auto address=get(NativeAbsolutePath::from_posix(f.path+"/private"));get(prepare_native_operation_journal_root(address));auto root=get(acquire_native_journal_root(address));
 // Observe separate flat data directory, not the private Root child.
 check(!mkdir((f.path+"/data").c_str(),0700),"data dir");auto data=std::shared_ptr<const DirectoryCursor>(get(f.fs.open_directory(f.path+"/data")));int fd=open((f.path+"/data/a").c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);check(fd>=0&&write(fd,"x",1)==1&&!close(fd),"close data");
 struct stat s{};check(!stat((f.path+"/data").c_str(),&s),"close select");selected_dev=s.st_dev;selected_ino=s.st_ino;auto latch=std::make_shared<Latch>(root);detail::MetadataCaptureCleanupScope scope(latch.get());close_armed=true;
 NativeSyncProofBudget budget;auto observed=observe_native_sync_root(data,policy(),{},budget);close_armed=false;
 check(!observed.value()&&close_hits==1&&latch->first,"native consumed closedir error lost");detail::PreparedJournalConsumerFailure failure;check(detail::read_prepared_journal_consumer_failure(*root,failure)&&failure.code==EIO,"Root first error missing");
 check(get(data->lookup_child(name("a"),ChildLookupMode::NativeDefault)).state()==ChildLookupState::Found,"caller data cursor closed by reader drain");
 check(!root->finish_io().value(),"Root error cleared");root.reset();std::puts("PASS explicit reader close consumes once and preserves genuine Root first-POD; caller anchor retained");}
}
extern "C" int openat(int dir,const char*path,int flags,...){mode_t mode=0;if((flags&O_CREAT)||((flags&O_TMPFILE)==O_TMPFILE)){va_list a;va_start(a,flags);mode=va_arg(a,unsigned int);va_end(a);}int fd=(int)syscall(SYS_openat,dir,path,flags,mode);
 if(fd>=0&&rename_armed&&path&&std::strcmp(path,".")==0){struct stat s{};if(!fstat(dir,&s)&&s.st_dev==selected_dev&&s.st_ino==selected_ino){rename_armed=false;check(syscall(SYS_renameat,dir,pending,dir,reserved)==0,"injected rename");++rename_hits;}}return fd;}
extern "C" int closedir(DIR*d){int fd=dirfd(d);struct stat s{};bool match=close_armed&&!fstat(fd,&s)&&s.st_dev==selected_dev&&s.st_ino==selected_ino;using Fn=int(*)(DIR*);static auto real=(Fn)dlsym((void*)-1L,"closedir");int result=real(d);if(!result&&match){close_armed=false;++close_hits;errno=EIO;return -1;}return result;}
int main(int argc,char**argv){if(argc==2&&strcmp(argv[1],"--ledger-only")==0){ledger_reader();return 0;}root_reader();ledger_reader();close_reader();}
