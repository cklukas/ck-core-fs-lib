// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_archive_write_job.hpp"
#include "native_filesystem.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "sha256.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
using namespace ck::files;
namespace {
bool deny_new=false,arm=false,stage_known=false,publication_linked=false,journal_known=false;
dev_t journal_dev=0,dest_dev=0;ino_t journal_ino=0,dest_ino=0;int journal_closes=0;
const char* mode="positive";dev_t stage_dev=0;ino_t stage_ino=0;
int close_calls=0,reused_fd=-1,partial_calls=0;unsigned native_calls=0,stage_content_calls=0;bool injected=false,close_injected=false;
bool stage(int fd){struct stat s{};return stage_known&&fstat(fd,&s)==0&&s.st_dev==stage_dev&&s.st_ino==stage_ino;}
}
void* operator new(std::size_t n){if(deny_new)throw std::bad_alloc();if(void* p=std::malloc(n?n:1))return p;throw std::bad_alloc();}
void operator delete(void* p)noexcept{std::free(p);} void operator delete(void* p,std::size_t)noexcept{std::free(p);}
extern "C" int __real_ftruncate(int,off_t);
extern "C" int __wrap_ftruncate(int fd,off_t size){if(arm)++native_calls;
 if(arm){struct stat s{};assert(fstat(fd,&s)==0);stage_known=true;stage_dev=s.st_dev;stage_ino=s.st_ino;
  if(!strcmp(mode,"resize")){injected=true;errno=ENOSPC;return -1;}}
 return __real_ftruncate(fd,size);
}
extern "C" ssize_t __real_pwrite(int,const void*,size_t,off_t);
extern "C" ssize_t __wrap_pwrite(int fd,const void* data,size_t n,off_t off){if(arm){++native_calls;if(stage(fd))++stage_content_calls;}
 if(arm&&!stage(fd)){struct stat st{};if(fstat(fd,&st)==0&&S_ISREG(st.st_mode)){journal_known=true;journal_dev=st.st_dev;journal_ino=st.st_ino;
 if(!strcmp(mode,"journal-write")){injected=true;errno=ENOSPC;return -1;}}}
 if(arm&&stage(fd)){if(!strcmp(mode,"write")){injected=true;errno=ENOSPC;return -1;}
  if(!strcmp(mode,"partial")&&n>3){++partial_calls;return __real_pwrite(fd,data,3,off);}}
 return __real_pwrite(fd,data,n,off);
}
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd){if(arm)++native_calls;
 if(arm&&publication_linked&&!injected){struct stat s{};assert(fstat(fd,&s)==0);
  if((!strcmp(mode,"post-link-file-flush")&&stage(fd))||(!strcmp(mode,"post-link-parent-flush")&&s.st_dev==dest_dev&&s.st_ino==dest_ino)){injected=true;errno=EIO;return -1;}}
if(arm&&stage(fd)&&(!strcmp(mode,"flush")||!strcmp(mode,"first-enospc-close-oom"))&&!injected){injected=true;errno=!strcmp(mode,"flush")?EIO:ENOSPC;return -1;}return __real_fsync(fd);}
extern "C" int __real_close(int);
extern "C" int __wrap_close(int fd){if(arm)++native_calls;
 const bool ours=arm&&stage(fd);if(ours)++close_calls;
 struct stat js{};if(arm&&journal_known&&fstat(fd,&js)==0&&js.st_dev==journal_dev&&js.st_ino==journal_ino)++journal_closes;
 const int r=__real_close(fd);
 if(ours&&(!strcmp(mode,"close")||!strcmp(mode,"close-oom")||!strcmp(mode,"first-enospc-close-oom"))&&!close_injected){
  injected=true;close_injected=true;assert(r==0);reused_fd=open("/dev/null",O_RDONLY|O_CLOEXEC);assert(reused_fd==fd);
  if(!strcmp(mode,"close-oom")||!strcmp(mode,"first-enospc-close-oom"))deny_new=true;errno=EIO;return -1;}
 return r;
}
extern "C" int __real_linkat(int,const char*,int,const char*,int);
extern "C" int __wrap_linkat(int a,const char* b,int c,const char* d,int e){if(arm)++native_calls;
 if(arm&&!strcmp(mode,"publish")){injected=true;errno=EACCES;return -1;}
 const int result=__real_linkat(a,b,c,d,e);if(arm&&result==0)publication_linked=true;return result;
}
extern "C" ssize_t __real_pread(int,void*,size_t,off_t);
extern "C" ssize_t __wrap_pread(int fd,void* data,size_t n,off_t off){if(arm){++native_calls;if(stage(fd))++stage_content_calls;}return __real_pread(fd,data,n,off);}
namespace {
template<class T>T take(Observation<T> r){if(!r.value()){std::fprintf(stderr,"unavailable %d/%lld %s\n",int(r.state()),(long long)r.unavailable_detail()->error.code,r.unavailable_detail()->error.operation.c_str());std::abort();}return std::move(r).take_value();}
NativeName name(const char* s){return *NativeName::from_posix(s);}
std::vector<std::byte> bytes(const char* s){auto b=reinterpret_cast<const std::byte*>(s);return {b,b+strlen(s)};}
}
int main(int argc,char** argv){assert(argc==3);mode=argv[2];assert(getuid()!=0);
 std::string base=argv[1];assert(mkdir((base+"/dest").c_str(),0700)==0);
 struct stat destination_stat{};assert(stat((base+"/dest").c_str(),&destination_stat)==0);dest_dev=destination_stat.st_dev;dest_ino=destination_stat.st_ino;
 NativeFileSystem fs;
 auto directory=std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(take(NativeAbsolutePath::from_posix(base+"/dest")))));
 auto parent=std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(take(NativeAbsolutePath::from_posix(base)))));
 PreparedJournalRootRequest rr{parent,name("private"),JournalRootDisposition::ProvisionChild};JournalRootPreparationProgress rp;
 auto root=take(prepare_native_journal_root(std::move(rr),rp));
 OperationJournalId id{};id.bytes[0]=std::byte{1};
 constexpr std::uint64_t size=2*1024*1024+17;
 NativeArchiveWriteRequest request{directory,root,name("archive"),name("hint"),name("journal"),id};
 request.logical_size=size;request.step_bytes=16384;request.minimum_unallocated_bytes=1024*1024;
 request.extents={{0,bytes("ARCHIVE HEADER")},{1024*1024,bytes("middle payload")},{size-4,bytes("TAIL")}};
 if(!strcmp(mode,"invalid")){request.extents.push_back({0,bytes("overlap")});assert(!NativeArchiveWriteJob::begin(std::move(request)).value());assert(take(root->finish_io()));return 0;}
 if(!strcmp(mode,"root-overlap")){auto rd=take(root->open_journal(name("unused"),true));take(rd->finish_io());rd.reset();
  auto inside=std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(take(NativeAbsolutePath::from_posix(base+"/private")))));
  request.destination=std::move(inside);assert(!NativeArchiveWriteJob::begin(std::move(request)).value());assert(take(root->finish_io()));return 0;}
 if(!strcmp(mode,"occupied")){int fd=open((base+"/dest/archive").c_str(),O_CREAT|O_EXCL|O_WRONLY,0600);assert(fd>=0);assert(write(fd,"original",8)==8);assert(close(fd)==0);}
 const bool crash_before=!strcmp(mode,"crash-before-publish"),crash_after=!strcmp(mode,"crash-after-publish");
 if(crash_before||crash_after){
  const pid_t child=fork();assert(child>=0);
  if(child>0){int status=0;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==73);
   auto jf=take(root->open_journal(name("journal"),false));auto decoded=take(load_operation_journal(*jf));
   assert(!decoded.tail&&decoded.journal->state(0)==OperationJournalState::CommitIntended);take(jf->finish_io());jf.reset();
   struct stat s{};const int exists=stat((base+"/dest/archive").c_str(),&s);
   if(crash_before)assert(exists!=0&&errno==ENOENT);
   else {assert(exists==0&&s.st_size==size);int fd=open((base+"/dest/archive").c_str(),O_RDONLY|O_CLOEXEC);assert(fd>=0);
    std::vector<std::byte> actual(size),expected(size);assert(pread(fd,actual.data(),actual.size(),0)==(ssize_t)actual.size());
    for(const auto& e:request.extents)std::copy(e.bytes.begin(),e.bytes.end(),expected.begin()+e.offset);
    assert(actual==expected&&close(fd)==0);}
   assert(lstat((base+"/dest/hint").c_str(),&s)!=0&&errno==ENOENT);
   request.journal_root.reset();assert(take(root->finish_io()));std::printf("archive mode=%s PASS child-exit=73 journal=CommitIntended publication=%d no-restart-cleanup\n",mode,crash_after);return 0;
  }
 }
 auto job=take(NativeArchiveWriteJob::begin(std::move(request)));arm=true;
 NativeArchiveProgress p;std::stop_source stop;
 for(unsigned i=0;i<2000;++i){
  if((!strcmp(mode,"cancel")&&job->progress().written_bytes)||(!strcmp(mode,"cancel-after-publish")&&job->progress().published))stop.request_stop();
  if(!strcmp(mode,"cancel-before"))stop.request_stop();
  const auto prior_io=stage_content_calls;auto prior=job->progress();p=job->advance(stop.get_token());assert(stage_content_calls-prior_io<=1);
  if((crash_before&&p.phase==NativeArchivePhase::Publish)||(crash_after&&p.phase==NativeArchivePhase::Committed))_exit(73);assert(p.content_calls-prior.content_calls<=1);
  if(p.phase==NativeArchivePhase::Complete||p.phase==NativeArchivePhase::Cancelled||p.phase==NativeArchivePhase::NeedsReconciliation)break;
 }
 const bool success=!strcmp(mode,"positive")||!strcmp(mode,"partial")||!strcmp(mode,"cancel-after-publish");
 if(success){assert(p.phase==NativeArchivePhase::Complete&&p.published&&p.drained&&!p.failure);assert(p.verified_bytes==size&&p.written_bytes==32&&p.unallocated_bytes>=1024*1024);}
 else if(!strcmp(mode,"cancel")||!strcmp(mode,"cancel-before")){assert(p.phase==NativeArchivePhase::Cancelled&&p.drained&&!p.published);}
 else {assert(p.phase==NativeArchivePhase::NeedsReconciliation&&p.drained&&p.failure);if(strcmp(mode,"occupied"))assert(injected);}
 const auto calls=close_calls;const auto all_native=native_calls;for(unsigned i=0;i<10;++i){auto repeat=job->advance();assert(repeat.phase==p.phase);job->finish_io();}assert(native_calls==all_native);assert(close_calls==calls&&close_calls==((!strcmp(mode,"cancel-before")||!strcmp(mode,"journal-write"))?0:1));
 if(reused_fd>=0){assert(fcntl(reused_fd,F_GETFD)>=0);deny_new=false;__real_close(reused_fd);}
 deny_new=false;assert(journal_closes==(!strcmp(mode,"cancel-before")?0:1));arm=false;
 if(success){int fd=open((base+"/dest/archive").c_str(),O_RDONLY|O_CLOEXEC);assert(fd>=0);struct stat s{};assert(fstat(fd,&s)==0&&s.st_size==size&&s.st_blocks*512<size/4);
  assert(lseek(fd,4096,SEEK_HOLE)==4096);std::vector<std::byte> image(size);assert(pread(fd,image.data(),image.size(),0)==(ssize_t)image.size());
  auto expected=std::vector<std::byte>(size);for(const auto& e:std::vector<NativeArchiveExtent>{{0,bytes("ARCHIVE HEADER")},{1024*1024,bytes("middle payload")},{size-4,bytes("TAIL")}})std::copy(e.bytes.begin(),e.bytes.end(),expected.begin()+e.offset);
  assert(image==expected);Sha256 hash;hash.update(image);assert(hash.digest()==p.digest);assert(close(fd)==0);
  auto journal=take(root->open_journal(name("journal"),false));auto decoded=take(load_operation_journal(*journal));assert(!decoded.tail&&decoded.journal->state(0)==OperationJournalState::Complete);take(journal->finish_io());
 }else if(!strcmp(mode,"occupied")){char b[8];int fd=open((base+"/dest/archive").c_str(),O_RDONLY);assert(fd>=0&&read(fd,b,8)==8&&!memcmp(b,"original",8));assert(close(fd)==0);}
 else if(!strcmp(mode,"post-link-file-flush")||!strcmp(mode,"post-link-parent-flush")){
  assert(publication_linked&&p.publication_attempted&&!p.published);struct stat s{};assert(stat((base+"/dest/archive").c_str(),&s)==0&&s.st_size==size);
  detail::PreparedJournalConsumerFailure f;assert(detail::read_prepared_journal_consumer_failure(*root,f)&&!f.pending&&f.code==EIO);
 }else if(strcmp(mode,"close")&&strcmp(mode,"close-oom")&&strcmp(mode,"first-enospc-close-oom")){struct stat s{};assert(lstat((base+"/dest/archive").c_str(),&s)!=0&&errno==ENOENT);}
 struct stat hint{};assert(lstat((base+"/dest/hint").c_str(),&hint)!=0&&errno==ENOENT);
 if(!strcmp(mode,"first-enospc-close-oom"))assert(!p.published);
 if(p.failure)assert(p.failure->operation[0]);
 if(!strcmp(mode,"close")||!strcmp(mode,"close-oom")||!strcmp(mode,"first-enospc-close-oom")){detail::PreparedJournalConsumerFailure f;assert(detail::read_prepared_journal_consumer_failure(*root,f)&&!f.pending&&f.domain==ErrorDomain::Posix&&f.code==(!strcmp(mode,"first-enospc-close-oom")?ENOSPC:EIO));assert(p.failure&&p.failure->code==f.code&&p.failure->domain==f.domain&&p.failure->operation==f.operation);}
 job.reset();directory.reset();parent.reset();auto finish=root->finish_io();if(success||!strcmp(mode,"cancel")||!strcmp(mode,"cancel-before"))assert(finish.value());
 std::printf("archive mode=%s PASS close=%d sparse=%d published=%d\n",mode,close_calls,success,p.published);
}
