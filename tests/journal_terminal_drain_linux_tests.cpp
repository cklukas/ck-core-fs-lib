// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_finalization_fixture_linux.hpp"
#include "native_filesystem.hpp"
#include "prepared_journal_root.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
using namespace ck::files;
namespace {
std::atomic<bool> oom=false;
struct Control {PreparedJournalRoot* root=nullptr;dev_t device{};ino_t file{},parent{};bool armed=false,fail_file_flush=false,fail_parent_flush=false,fail_file_close=false,fail_parent_close=false,oom_at_fault=false;unsigned file_closes=0,parent_closes=0,allocations=0,first_allocation_file_closes=0,first_allocation_parent_closes=0;detail::PreparedJournalConsumerFailure first_allocation{};}*control=nullptr;
void denied()noexcept{if(control&&!control->allocations++){control->first_allocation_file_closes=control->file_closes;control->first_allocation_parent_closes=control->parent_closes;detail::read_prepared_journal_consumer_failure(*control->root,control->first_allocation);}}
}
void* operator new(std::size_t n){if(oom){denied();throw std::bad_alloc();}if(void*p=std::malloc(n?n:1))return p;throw std::bad_alloc();}void* operator new[](std::size_t n){return ::operator new(n);}void operator delete(void*p)noexcept{std::free(p);}void operator delete[](void*p)noexcept{std::free(p);}void operator delete(void*p,std::size_t)noexcept{std::free(p);}void operator delete[](void*p,std::size_t)noexcept{std::free(p);}
namespace {
#define CHECK(x) do{if(!(x)){oom=false;throw std::runtime_error(#x);}}while(false)
template<class T>T take(Observation<T> o){if(!o.value()){oom=false;throw std::runtime_error(o.unavailable_detail()->error.operation);}return std::move(o).take_value();}
NativeName name(const char*s){return *NativeName::from_posix(s);}
int kind(int fd)noexcept{if(!control||!control->armed)return 0;struct stat s{};if(fstat(fd,&s)||s.st_dev!=control->device)return 0;return s.st_ino==control->file?1:s.st_ino==control->parent?2:0;}
void run(std::string_view mode){
 std::string path=native_finalization_fixture::base()+"/journal-drain.XXXXXX";CHECK(mkdtemp(path.data()));
 struct Cleanup{std::string path;~Cleanup(){oom=false;control=nullptr;std::filesystem::remove_all(path);}}cleanup{path};
 NativeFileSystem fs;auto parent=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(path)));PreparedJournalRootRequest request;request.parent=parent;request.child=name("journal");request.disposition=JournalRootDisposition::ProvisionChild;JournalRootPreparationProgress progress;auto root=take(prepare_native_journal_root(std::move(request),progress));auto file=take(root->open_journal(name("state"),true));
 std::array<std::byte,4> data{std::byte{1},std::byte{2},std::byte{3},std::byte{4}};CHECK(take(file->write_at(0,data))==data.size());CHECK(take(file->flush()));
 struct stat s{};Control c;c.root=root.get();CHECK(!lstat((path+"/journal/state").c_str(),&s));c.device=s.st_dev;c.file=s.st_ino;CHECK(!lstat((path+"/journal").c_str(),&s));c.parent=s.st_ino;c.oom_at_fault=mode.find("oom")!=mode.npos;
 c.fail_file_flush=mode.starts_with("flush-file");c.fail_parent_flush=mode.starts_with("flush-parent");c.fail_file_close=mode.starts_with("close-file");c.fail_parent_close=mode.starts_with("close-parent")||mode=="flush-file-close-parent";
 const bool prior=mode=="prior-oom",fault=mode!="clean";const int expected=prior?EDQUOT:(c.fail_file_flush||c.fail_file_close)?EIO:ENOSPC;
 if(prior)CHECK(detail::record_prepared_journal_consumer_failure(*root,ObservationState::Failed,ErrorDomain::Posix,EDQUOT,"journal_test.prior_root_error"));control=&c;c.armed=true;if(prior)oom=true;
 bool threw=false;try{auto result=file->finish_io();if(fault)CHECK(!result.value()&&result.unavailable_detail()->error.domain==ErrorDomain::Posix&&result.unavailable_detail()->error.code==expected);else CHECK(take(std::move(result)));}catch(const std::bad_alloc&){threw=true;}
 const bool was_oom=oom.exchange(false);CHECK(!c.oom_at_fault||(was_oom&&threw&&c.allocations>0));CHECK(c.file_closes==1&&c.parent_closes==1);
 detail::PreparedJournalConsumerFailure failure{};const bool failed=detail::read_prepared_journal_consumer_failure(*root,failure);CHECK(fault?failed&&!failure.pending&&failure.domain==ErrorDomain::Posix&&failure.code==expected:!failed);
 if(c.oom_at_fault){CHECK(c.first_allocation.code==expected&&!c.first_allocation.pending);if(!prior)CHECK(c.first_allocation_file_closes==1&&c.first_allocation_parent_closes==1);}
 for(unsigned i=0;i<3;++i){auto again=file->finish_io();CHECK(fault?!again.value()&&again.unavailable_detail()->error.code==expected:take(std::move(again)));}CHECK(c.file_closes==1&&c.parent_closes==1);
 file.reset();CHECK(c.file_closes==1&&c.parent_closes==1);c.armed=false;control=nullptr;auto final=root->finish_io();CHECK(fault?!final.value()&&final.unavailable_detail()->error.code==expected:take(std::move(final)));root.reset();parent.reset();
 std::printf("PASS journal mode=%.*s fileClose=1 parentClose=1 firstCode=%d OOM=%d allocations=%u nativeClosuresBeforeFirstDiagnostic=%u/%u no-retry\n",int(mode.size()),mode.data(),fault?expected:0,int(was_oom),c.allocations,c.first_allocation_file_closes,c.first_allocation_parent_closes);
}
}
extern "C" int __wrap_fsync(int fd){const int k=kind(fd);const int rc=static_cast<int>(syscall(SYS_fsync,fd));const int saved=errno;if(rc==0&&control&&((k==1&&control->fail_file_flush)||(k==2&&control->fail_parent_flush))){oom=control->oom_at_fault;errno=k==1?EIO:ENOSPC;return -1;}errno=saved;return rc;}
extern "C" int __wrap_close(int fd){const int k=kind(fd);const int rc=static_cast<int>(syscall(SYS_close,fd));const int saved=errno;if(control){if(k==1)++control->file_closes;if(k==2)++control->parent_closes;if(rc==0&&((k==1&&control->fail_file_close)||(k==2&&control->fail_parent_close))){oom=control->oom_at_fault;errno=k==1?EIO:ENOSPC;return -1;}}errno=saved;return rc;}
int main(int argc,char**argv){try{const auto mode=native_finalization_fixture::parse(argc,argv,{"clean","flush-file","flush-parent","close-file","close-parent","flush-file-close-parent","flush-file-oom","flush-parent-oom","close-file-oom","close-parent-oom","prior-oom"});run(mode);return 0;}catch(const std::exception&e){oom=false;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
