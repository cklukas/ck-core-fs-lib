// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_hierarchy_binding.hpp"
#include "private_journal_scope.hpp"
#include "operation_journal_file.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <new>
#include <thread>
#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#else
#error Windows native fixture qualification is a separate required supplement; do not register this POSIX fixture there.
#endif
using namespace ck::files;
namespace fault {thread_local bool armed=false,oom_after_close=false,fail_alloc=false,persistent_oom=false;thread_local dev_t dev=0;thread_local ino_t ino=0;thread_local unsigned hits=0;}
void* operator new(std::size_t size){if(fault::fail_alloc){if(!fault::persistent_oom)fault::fail_alloc=false;throw std::bad_alloc();}if(void* p=std::malloc(size?size:1))return p;throw std::bad_alloc();}
void operator delete(void* p)noexcept{std::free(p);}void operator delete(void* p,std::size_t)noexcept{std::free(p);}
extern "C" int close(int fd){struct stat st{};const bool selected=fault::armed&&fstat(fd,&st)==0&&st.st_dev==fault::dev&&st.st_ino==fault::ino;const int result=static_cast<int>(syscall(SYS_close,fd));const int saved=errno;if(selected&&result==0){fault::armed=false;++fault::hits;fault::fail_alloc=fault::oom_after_close;errno=EIO;return -1;}errno=saved;return result;}
namespace {
unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x))throw std::runtime_error(std::string("line ")+std::to_string(__LINE__)+": "+#x);}while(false)
template<class T>T get(Observation<T> o){if(auto e=o.unavailable_detail())throw std::runtime_error(e->error.operation+" code="+std::to_string(e->error.code));return std::move(o).take_value();}
void yes(Observation<bool> o){CHECK(get(std::move(o)));}
NativeName n(const char* text){return *NativeName::from_posix(text);}
std::vector<NativeName> path(std::initializer_list<const char*> names){std::vector<NativeName> result;for(auto s:names)result.push_back(n(s));return result;}
unsigned fds(){DIR* p=opendir("/proc/self/fd");CHECK(p);unsigned count=0;while(auto e=readdir(p))if(e->d_name[0]!='.')++count;CHECK(closedir(p)==0);return count;}
struct Fixture {
 std::filesystem::path root;PreparedJournalRoot::Pointer journal;
 Fixture(){auto temp=std::getenv("TMPDIR");CHECK(temp&&*temp);std::string p=std::string(temp)+"/hierarchy.XXXXXX";CHECK(mkdtemp(p.data()));root=p;for(auto s:{"store","left","right","left/d","left/d/e"})CHECK(mkdir((root/s).c_str(),0700)==0);write("left/d/e/file");yes(prepare_native_operation_journal_root(address("store")));journal=get(acquire_native_journal_root(address("store")));}
 void write(const char* s){const auto p=root/s;int fd=open(p.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);CHECK(fd>=0);CHECK(write_bytes(fd)==1);CHECK(fsync(fd)==0);CHECK(close(fd)==0);}
 static ssize_t write_bytes(int fd){const char b='a';return ::write(fd,&b,1);}
 NativeAbsolutePath address(const char* s){return get(NativeAbsolutePath::from_posix((root/s).string()));}
 NativeHierarchyContext::Pointer context(NativeHierarchyLimits limits={}){return get(NativeHierarchyContext::open(journal,address("left"),address("right"),limits));}
 ~Fixture(){fault::armed=fault::fail_alloc=fault::persistent_oom=false;if(journal)journal->finish_io();journal.reset();std::filesystem::remove_all(root);}
};
struct ForeignRoot final:PreparedJournalRoot {
 PreparedJournalRoot::Pointer real;unsigned opens=0;
 explicit ForeignRoot(PreparedJournalRoot::Pointer value):real(std::move(value)){}
 Observation<std::unique_ptr<OperationJournalFile>> open_journal(const NativeName&,bool)override{++opens;return Observation<std::unique_ptr<OperationJournalFile>>::unavailable(ObservationState::Unsupported,{ErrorDomain::Adapter,4,"foreign"});}
 Observation<bool> revalidate()const override{return Observation<bool>::available(true);}
 Observation<bool> sync()override{return Observation<bool>::available(true);}
 Observation<bool> finish_io()override{return Observation<bool>::available(true);}
 const ObjectIdentity& identity()const noexcept override{return real->identity();}
 NameEncoding encoding()const noexcept override{return real->encoding();}
 const std::optional<NativeAbsolutePath>& navigation_address()const noexcept override{return real->navigation_address();}
};
void foreign(){Fixture f;auto root=std::make_shared<ForeignRoot>(f.journal);auto result=NativeHierarchyContext::open(root,f.address("left"),f.address("right"));CHECK(!result.value()&&result.state()==ObservationState::Unsupported&&result.unavailable_detail()->error.domain==ErrorDomain::Adapter&&result.unavailable_detail()->error.code==5&&result.unavailable_detail()->error.operation=="journal_root.foreign_provider"&&root->opens==0);}
void raw_name(){Fixture f;const auto raw=std::string("raw-")+char(0xff)+". ";const auto absolute=f.root/"left/d/e"/raw;int fd=open(absolute.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);CHECK(fd>=0&&close(fd)==0);auto c=f.context();auto names=path({"d","e"});names.push_back(*NativeName::from_posix(raw));auto b=get(c->bind(false,names));CHECK(b->presence()==NativeHierarchyPresence::Present);yes(b->revalidate());yes(c->finish_io());}
void positive(){Fixture f;auto before=fds();auto c=f.context();auto b=get(c->bind(false,path({"d","e","file"})));CHECK(b->presence()==NativeHierarchyPresence::Present&&b->epoch()!=0);CHECK(*get(b->metadata()).kind.value()==ObjectKind::RegularFile);yes(b->revalidate());CHECK(c->usage().reads>0&&c->usage().fd_opens>0&&c->usage().wire_bytes>0);auto keep=b->epoch();yes(b->finish_io());yes(b->finish_io());CHECK(!b->revalidate().value());yes(c->finish_io());yes(c->finish_io());CHECK(b->epoch()==keep&&fds()==before);}
void absence(){Fixture f;auto c=f.context();auto a=get(c->bind(false,path({"d","missing","child"})));CHECK(a->presence()==NativeHierarchyPresence::Missing&&a->missing_component()==1);yes(a->revalidate());CHECK(!a->metadata().value());CHECK(mkdir((f.root/"left/d/missing").c_str(),0700)==0);auto stale=a->revalidate();CHECK(!stale.value()&&stale.state()==ObservationState::Changed);yes(a->finish_io());auto b=get(c->bind(false,path({"d","missing","child"})));CHECK(b->presence()==NativeHierarchyPresence::Missing&&b->missing_component()==2);yes(c->finish_io());CHECK(!b->revalidate().value());}
void substitution(){Fixture f;auto c=f.context();auto b=get(c->bind(false,path({"d","e","file"})));CHECK(rename((f.root/"left/d/e").c_str(),(f.root/"left/d/old").c_str())==0);CHECK(mkdir((f.root/"left/d/e").c_str(),0700)==0);f.write("left/d/e/file");auto stale=b->revalidate();CHECK(!stale.value()&&stale.state()==ObservationState::Changed);yes(c->finish_io());}
void kinds(){Fixture f;CHECK(symlink("d",(f.root/"left/link").c_str())==0);auto c=f.context();auto link=c->bind(false,path({"link","e","file"}));CHECK(!link.value()&&link.state()==ObservationState::Unsupported);auto regular=c->bind(false,path({"d","e","file","child"}));CHECK(!regular.value()&&regular.state()==ObservationState::Unsupported&&regular.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::NotDirectory));CHECK(chmod((f.root/"left/d").c_str(),0000)==0);auto denied=c->bind(false,path({"d","e","file"}));CHECK(!denied.value()&&denied.state()==ObservationState::Denied);CHECK(chmod((f.root/"left/d").c_str(),0700)==0);yes(c->finish_io());}
void private_alias(){Fixture f;auto secret=get(f.journal->open_journal(n("secret"),true));std::array<std::byte,1> content{std::byte{3}};CHECK(get(secret->write_at(0,content))==1);yes(secret->finish_io());secret.reset();CHECK(link((f.root/"store/secret").c_str(),(f.root/"left/d/e/alias").c_str())==0);auto c=f.context();auto b=c->bind(false,path({"d","e","alias"}));CHECK(!b.value()&&b.state()==ObservationState::Unsupported&&b.unavailable_detail()->error.domain==ErrorDomain::Adapter&&b.unavailable_detail()->error.code==18);yes(c->finish_io());}
void overlapping_locks(){Fixture f;auto c=f.context();auto other=NativeHierarchyContext::open(f.journal,f.address("left/d"),f.address("right"));CHECK(!other.value()&&other.unavailable_detail()->error.domain==ErrorDomain::Posix&&other.unavailable_detail()->error.operation=="sync_session.overlap_lock"&&(other.unavailable_detail()->error.code==EAGAIN||other.unavailable_detail()->error.code==EWOULDBLOCK));yes(c->finish_io());}
void limits(){Fixture f;NativeHierarchyLimits l;l.max_depth=2;auto c=f.context(l);auto deep=c->bind(false,path({"d","e","file"}));CHECK(!deep.value()&&deep.unavailable_detail()->error.code==9);yes(c->finish_io());l={};l.max_wire_bytes=2;c=f.context(l);CHECK(!c->bind(false,path({"d","e","file"})).value());yes(c->finish_io());l={};l.max_entries=1;c=f.context(l);CHECK(!c->bind(false,path({"d","e","file"})).value());yes(c->finish_io());l={};l.max_reads=1;CHECK(!NativeHierarchyContext::open(f.journal,f.address("left"),f.address("right"),l).value());l={};l.max_fd_opens=16384;CHECK(!NativeHierarchyContext::open(f.journal,f.address("left"),f.address("right"),l).value());l={};l.max_retained_fds=16392;c=f.context(l);CHECK(!c->bind(false,path({"d"})).value());yes(c->finish_io());l={};l.max_elapsed=std::chrono::milliseconds(100);c=f.context(l);std::this_thread::sleep_for(std::chrono::milliseconds(120));auto expired=c->bind(false,path({"d"}));CHECK(!expired.value()&&expired.unavailable_detail()->error.code==9);yes(c->finish_io());c=f.context();std::stop_source stop;stop.request_stop();auto cancelled=c->bind(false,path({"d"}),stop.get_token());CHECK(!cancelled.value()&&cancelled.unavailable_detail()->error.code==6);yes(c->finish_io());}
void close_fault(bool oom){Fixture f;auto before=fds();auto c=f.context();auto b=get(c->bind(false,path({"d","e","file"})));struct stat st{};CHECK(lstat((f.root/"left/d/e/file").c_str(),&st)==0);fault::dev=st.st_dev;fault::ino=st.st_ino;fault::hits=0;fault::oom_after_close=oom;fault::armed=true;
 bool threw=false,unavailable=false;
 try{auto result=b->finish_io();unavailable=!result.value()&&result.unavailable_detail()->error.domain==ErrorDomain::Posix&&result.unavailable_detail()->error.code==EIO;}
 catch(const std::bad_alloc&){(void)c->drain();threw=true;}
 fault::fail_alloc=false;const auto raw=b->first_failure();CHECK((oom?threw:unavailable)&&raw.present&&raw.domain==ErrorDomain::Posix&&raw.code==EIO&&fault::hits==1);
 auto again=b->finish_io();CHECK(!again.value()&&again.unavailable_detail()->error.code==EIO&&fault::hits==1);detail::PreparedJournalConsumerFailure first;CHECK(detail::read_prepared_journal_consumer_failure(*f.journal,first)&&first.domain==ErrorDomain::Posix&&first.code==EIO);CHECK(!c->bind(false,path({"d"})).value());CHECK(!c->finish_io().value());CHECK(fds()==before);}
void transient_close_fault(bool oom){Fixture f;auto before=fds();auto c=f.context();struct stat st{};CHECK(lstat((f.root/"left/d/e/file").c_str(),&st)==0);fault::dev=st.st_dev;fault::ino=st.st_ino;fault::hits=0;fault::oom_after_close=oom;fault::armed=true;
 bool threw=false,unavailable=false;
 try{auto b=c->bind(false,path({"d","e","file"}));unavailable=!b.value()&&b.unavailable_detail()->error.domain==ErrorDomain::Posix&&b.unavailable_detail()->error.code==EIO;}
 catch(const std::bad_alloc&){(void)c->drain();threw=true;}
 fault::fail_alloc=false;auto raw=c->first_failure();CHECK((oom?threw:unavailable)&&raw.present&&raw.domain==ErrorDomain::Posix&&raw.code==EIO&&fault::hits==1);auto blocked=c->bind(false,path({"d"}));CHECK(!blocked.value()&&blocked.unavailable_detail()->error.domain==ErrorDomain::Posix&&blocked.unavailable_detail()->error.code==EIO);CHECK(!c->finish_io().value()&&fds()==before);}

}
int main(){try{CHECK(getuid()!=0);foreign();raw_name();positive();absence();substitution();kinds();private_alias();overlapping_locks();limits();close_fault(false);close_fault(true);transient_close_fault(false);transient_close_fault(true);std::printf("NATIVE_HIERARCHY_BINDING checks=%u PASS\n",checks);return 0;}catch(const std::exception& e){fault::armed=fault::fail_alloc=false;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
