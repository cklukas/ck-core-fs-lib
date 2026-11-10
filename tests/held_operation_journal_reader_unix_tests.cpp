// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "operation_journal_file.hpp"
#include "native_filesystem.hpp"
#include "platform/journal_root_test_faults.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
using namespace ck::files;
namespace counter {
std::atomic<bool> active{false};
std::atomic<dev_t> device{};
std::atomic<ino_t> root{},file{};
std::atomic<unsigned> flushes{},writes{},modes{};
bool tracked(int fd) {
    if(!active.load(std::memory_order_acquire))return false;
    struct stat s{};
    return !::fstat(fd,&s)&&s.st_dev==device.load()&&
        (s.st_ino==root.load()||s.st_ino==file.load());
}
template<class F> F real(const char* name) {
    auto* raw=dlsym(RTLD_NEXT,name);
    if(!raw)std::abort();
    return std::bit_cast<F>(raw);
}
void reset(){flushes=0;writes=0;modes=0;active.store(true,std::memory_order_release);}
void stop(){active.store(false,std::memory_order_release);}
}
// Process-local, pass-through counters. Every observed call invokes libc's
// real native operation. No OS settings, memory/IAT patching or fake filesystem.
extern "C" int fsync(int fd) {
    static auto fn=counter::real<int(*)(int)>("fsync");
    if(counter::tracked(fd))++counter::flushes;
    return fn(fd);
}
extern "C" ssize_t pwrite(int fd,const void* bytes,size_t count,off_t offset) {
    static auto fn=counter::real<ssize_t(*)(int,const void*,size_t,off_t)>("pwrite");
    if(counter::tracked(fd))++counter::writes;
    return fn(fd,bytes,count,offset);
}
extern "C" int fchmod(int fd,mode_t mode)
#ifdef __linux__
    noexcept
#endif
{
    static auto fn=counter::real<int(*)(int,mode_t)>("fchmod");
    if(counter::tracked(fd))++counter::modes;
    return fn(fd,mode);
}
namespace {
unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x)){std::fprintf(stderr,"FAIL line=%u expr=%s errno=%d\n",unsigned(__LINE__),#x,errno);std::abort();}}while(false)
template<class T> T take(Observation<T> value) {
    if(!value.value()) {
        const auto& e=*value.unavailable_detail();
        std::fprintf(stderr,"UNAVAILABLE state=%u domain=%u code=%lld operation=%s\n",unsigned(e.state),unsigned(e.error.domain),static_cast<long long>(e.error.code),e.error.operation.c_str());
    }
    CHECK(value.value());return std::move(value).take_value();
}
void okay(Observation<bool> value){CHECK(take(std::move(value)));}
NativeAbsolutePath path(const std::string& p){return take(NativeAbsolutePath::from_posix(p));}
NativeName name(const std::string& p){auto n=NativeName::from_posix(p);CHECK(n);return *n;}
void make_dir(const std::string& p){CHECK(::mkdir(p.c_str(),0700)==0);}
struct Identity {dev_t dev;ino_t ino;};
Identity identity(const std::string& p){struct stat s{};CHECK(!::lstat(p.c_str(),&s));return{s.st_dev,s.st_ino};}
void set_ids(const std::string& root,const std::string& file){const auto a=identity(root),b=identity(file);CHECK(a.dev==b.dev);counter::device=a.dev;counter::root=a.ino;counter::file=b.ino;}
std::vector<std::byte> bytes(const std::string& p) {
    const int fd=::open(p.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);CHECK(fd>=0);
    struct stat s{};CHECK(!::fstat(fd,&s)&&S_ISREG(s.st_mode)&&s.st_size>0&&s.st_size<1024*1024);
    std::vector<std::byte> out(static_cast<size_t>(s.st_size));size_t done=0;
    while(done<out.size()){const auto n=::pread(fd,out.data()+done,out.size()-done,static_cast<off_t>(done));CHECK(n>0);done+=static_cast<size_t>(n);}
    CHECK(!::close(fd));return out;
}
int held_fd(Identity expected) {
    DIR* scan=::opendir("/dev/fd");CHECK(scan);const int probe=::dirfd(scan);int found=-1;unsigned count=0;
    while(const auto* item=::readdir(scan)) {
        char* end=nullptr;const long raw=std::strtol(item->d_name,&end,10);
        if(!end||*end||raw<0||raw>100000||raw==probe)continue;
        struct stat s{};if(!::fstat(static_cast<int>(raw),&s)&&s.st_dev==expected.dev&&s.st_ino==expected.ino){found=static_cast<int>(raw);++count;}
    }
    CHECK(!::closedir(scan));CHECK(count==1);return found;
}
std::vector<std::byte> produce(const std::string& root,const NativeName& basename,unsigned marker) {
    okay(prepare_native_operation_journal_root(path(root)));
    OperationJournalId id{};id.bytes[0]=std::byte{static_cast<unsigned char>(marker)};
    auto journal=take(OperationJournal::create(FileOperation::Copy,id));
    okay(journal->append({1,0,OperationJournalState::Planned,{std::byte{static_cast<unsigned char>(marker)}}}));
    auto encoded=take(encode_operation_journal(*journal));
    auto writer=take(open_native_operation_journal_file(path(root),basename,true));
    size_t done=0;
    while(done<encoded.size()){auto n=take(writer->write_at(done,std::span<const std::byte>(encoded).subspan(done)));CHECK(n&&n<=encoded.size()-done);done+=n;}
    okay(writer->flush());okay(writer->finish_io());return encoded;
}
void no_mutation(){CHECK(counter::flushes==0);CHECK(counter::writes==0);CHECK(counter::modes==0);counter::stop();}
unsigned close_fault_calls=0;
std::optional<std::int64_t> close_fault(detail::JournalRootFaultPoint p){if(p==detail::JournalRootFaultPoint::JournalClose){++close_fault_calls;return EIO;}return std::nullopt;}
void run(const std::string& parent,bool long_case) {
    std::string root=parent+(long_case?"/long":"/ordinary");make_dir(root);
    if(long_case){for(unsigned i=0;root.size()<=420&&i<8;++i){root+="/"+std::string(72,static_cast<char>('a'+i));make_dir(root);}CHECK(root.size()>340&&root.size()<900);}
    const auto journal_name=name(".ck-copy-journal-native-reader.");const std::string file=root+"/"+*journal_name.posix_bytes();
    const auto root_id=identity(root);counter::device=root_id.dev;counter::root=root_id.ino;counter::file=0;counter::reset();
    const auto expected=produce(root,journal_name,7);counter::stop();
    // The initial writer exists before this exact inode is tracked. A second
    // real flush/write on that writer is the pass-through counter control.
    set_ids(root,file);counter::reset();
    {auto writer=take(open_native_operation_journal_file(path(root),journal_name,false));CHECK(take(writer->write_at(0,expected))==expected.size());okay(writer->flush());okay(writer->finish_io());}
    CHECK(counter::flushes>0&&counter::writes>0);counter::stop();
    CHECK(bytes(file)==expected);
    counter::reset();auto cursor=take(open_native_operation_journal_directory(path(root)));
    auto batch=cursor->read(16);CHECK(batch.state!=DirectoryReadState::Error);CHECK(std::find(batch.names.begin(),batch.names.end(),journal_name)!=batch.names.end());
    const int root_fd=held_fd(identity(root));
    auto reader=take(open_held_operation_journal_file(*cursor,journal_name));
    const int file_fd=held_fd(identity(file));CHECK((::fcntl(file_fd,F_GETFL)&O_ACCMODE)==O_RDONLY);
    CHECK(take(reader->size())==expected.size());std::vector<std::byte> got(expected.size());CHECK(take(reader->read_at(0,got))==got.size());CHECK(got==expected);
    const auto write=reader->write_at(0,std::span<const std::byte>(got));CHECK(!write.value()&&write.state()==ObservationState::Denied&&write.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::InvalidAccess));
    const auto flush=reader->flush();CHECK(!flush.value()&&flush.state()==ObservationState::Denied);
    auto decoded=take(load_operation_journal(*reader));CHECK(!decoded.tail&&decoded.journal&&decoded.journal->records().size()==1);
    okay(reader->finish_io());okay(reader->finish_io());errno=0;CHECK(::fcntl(file_fd,F_GETFD)==-1&&errno==EBADF);reader.reset();
    okay(finish_operation_journal_directory(*cursor));okay(finish_operation_journal_directory(*cursor));errno=0;CHECK(::fcntl(root_fd,F_GETFD)==-1&&errno==EBADF);cursor.reset();no_mutation();
    CHECK(bytes(file)==expected);
    // Held directory remains authoritative after its old address is replaced.
    auto retained=take(open_native_operation_journal_directory(path(root)));
    const auto moved=root+"-moved";CHECK(!::rename(root.c_str(),moved.c_str()));make_dir(root);
    const auto alternate=produce(root,journal_name,9);CHECK(alternate!=expected);
    counter::reset();auto original=take(open_held_operation_journal_file(*retained,journal_name));got.assign(expected.size(),std::byte{});CHECK(take(original->read_at(0,got))==got.size()&&got==expected);okay(original->finish_io());okay(finish_operation_journal_directory(*retained));no_mutation();retained.reset();
    root=moved;const auto moved_file=root+"/"+*journal_name.posix_bytes();set_ids(root,moved_file);
    auto scan=take(open_native_operation_journal_directory(path(root)));
    CHECK(!::symlink(journal_name.posix_bytes()->c_str(),(root+"/journal-link").c_str()));
    counter::reset();auto symlink_result=open_held_operation_journal_file(*scan,name("journal-link"));CHECK(!symlink_result.value()&&symlink_result.state()==ObservationState::Denied);no_mutation();CHECK(!::unlink((root+"/journal-link").c_str()));
    CHECK(!::link(moved_file.c_str(),(root+"/journal-hard").c_str()));counter::reset();auto hard=open_held_operation_journal_file(*scan,journal_name);CHECK(!hard.value()&&hard.state()==ObservationState::Denied);no_mutation();CHECK(!::unlink((root+"/journal-hard").c_str()));
    CHECK(!::chmod(moved_file.c_str(),0644));counter::reset();auto public_file=open_held_operation_journal_file(*scan,journal_name);CHECK(!public_file.value()&&public_file.state()==ObservationState::Denied);no_mutation();CHECK(!::chmod(moved_file.c_str(),0600));
    CHECK(!::chmod(root.c_str(),0755));counter::reset();auto public_root=open_native_operation_journal_directory(path(root));CHECK(!public_root.value()&&public_root.state()==ObservationState::Denied);no_mutation();CHECK(!::chmod(root.c_str(),0700));
    auto bad_close=take(open_held_operation_journal_file(*scan,journal_name));const int fault_fd=held_fd(identity(moved_file));
    close_fault_calls=0;detail::journal_root_test_fault=close_fault;counter::reset();const auto failed=bad_close->finish_io();detail::journal_root_test_fault=nullptr;
    CHECK(!failed.value()&&failed.unavailable_detail()->error.domain==ErrorDomain::Posix&&failed.unavailable_detail()->error.code==EIO);const auto again=bad_close->finish_io();CHECK(!again.value()&&again.unavailable_detail()->error==failed.unavailable_detail()->error);CHECK(close_fault_calls==1);errno=0;CHECK(::fcntl(fault_fd,F_GETFD)==-1&&errno==EBADF);no_mutation();bad_close.reset();
    counter::reset();okay(finish_operation_journal_directory(*scan));okay(finish_operation_journal_directory(*scan));no_mutation();scan.reset();CHECK(bytes(moved_file)==expected);
    std::printf("HELD_JOURNAL_READER_PASS case=%s root=%s root_bytes=%zu checks=%u observed_file_dev=%llu ino=%llu no_reader_pwrite_fsync_fchmod=1 generic_cursor_not_authority_restricted=1\n",long_case?"long":"ordinary",root.c_str(),root.size(),checks,static_cast<unsigned long long>(identity(moved_file).dev),static_cast<unsigned long long>(identity(moved_file).ino));
}
}
int main(int argc,char** argv){CHECK(argc==2);run(argv[1],false);run(argv[1],true);std::printf("ALL_PASS checks=%u no_power_loss_durability_claim=1\n",checks);}
