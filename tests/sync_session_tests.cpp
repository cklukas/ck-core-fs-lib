// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "sync_session.hpp"
#include "operation_journal_file.hpp"
#include "ck_fs_session.h"
#include "windows_name.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/acl.h>
#include <sys/mount.h>
#include <membership.h>
#include <grp.h>
#endif
#endif
using namespace ck::files;
namespace {
unsigned checks=0;
#define CHECK(x) do { ++checks; if(!(x)) { std::fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); std::abort(); } } while(false)
using Bytes=std::vector<std::byte>;
SyncDigest digest(unsigned n) { SyncDigest d{}; d[0]=std::byte(n); return d; }
SyncEntryStatus file(unsigned n) { return {SyncPresence::Present,SyncKind::File,digest(n),digest(8)}; }
std::vector<SyncBaselineUpdate> updates(unsigned n) {
    return {{{"a",file(n),file(n)},SyncBaselineUpdateState::ConfirmedEqual},
        {{"b",file(n),file(n)},SyncBaselineUpdateState::ConfirmedEqual}};
}
struct Disk {
    std::map<std::string,Bytes> live,durable;
    std::size_t calls=0,fail_at=0;
    bool invalid=false;
    bool tick() { return ++calls!=fail_at; }
    void crash(bool persist_namespace=false) { if(!persist_namespace) live=durable; else durable=live; fail_at=calls=0; }
};
class Memory final:public SyncSessionBackend {
    std::shared_ptr<Disk> d;
    SyncDigest left=digest(1),right=digest(2);
    Observation<bool> tick() {
        if(d->tick()) return Observation<bool>::available(true);
        return Observation<bool>::unavailable(ObservationState::Failed,{ErrorDomain::Posix,5,"test.injected"});
    }
public:
    explicit Memory(std::shared_ptr<Disk> disk,bool reverse=false):d(std::move(disk)) { if(reverse) std::swap(left,right); }
    const SyncDigest& left_identity() const noexcept override { return left; }
    const SyncDigest& right_identity() const noexcept override { return right; }
    std::intptr_t root_handle(bool) const noexcept override { return -1; }
    Observation<bool> revalidate() override {
        if(d->invalid) return Observation<bool>::unavailable(ObservationState::Changed);
        return Observation<bool>::available(true);
    }
    Observation<std::optional<Bytes>> read(std::string_view name,std::size_t) override {
        auto it=d->live.find(std::string(name));
        return Observation<std::optional<Bytes>>::available(it==d->live.end()?std::nullopt:std::optional<Bytes>(it->second));
    }
    Observation<bool> stage(std::string_view name,std::span<const std::byte> bytes) override {
        // Separate partial write, completion and file flush failure points.
        auto r=tick(); if(!r.value()) return r;
        d->live[std::string(name)]=Bytes(bytes.begin(),bytes.begin()+bytes.size()/2);
        r=tick(); if(!r.value()) return r;
        d->live[std::string(name)]=Bytes(bytes.begin(),bytes.end());
        return tick();
    }
    Observation<bool> publish(std::string_view from,std::string_view to) override {
        auto r=tick(); if(!r.value()) return r;
        auto it=d->live.find(std::string(from)); CHECK(it!=d->live.end());
        d->live[std::string(to)]=std::move(it->second); d->live.erase(it); return r;
    }
    Observation<bool> remove(std::string_view name) override {
        auto r=tick(); if(!r.value()) return r; d->live.erase(std::string(name)); return r;
    }
    Observation<bool> flush_directory() override {
        auto r=tick(); if(!r.value()) return r; d->durable=d->live; return r;
    }
};
std::unique_ptr<SyncSession> memory(std::shared_ptr<Disk> d,unsigned policy=3) {
    auto s=SyncSession::open(std::make_unique<Memory>(std::move(d)),digest(policy));
    CHECK(s.value()); return std::move(s).take_value();
}
std::string key(const Disk& d,std::string_view suffix) {
    for(const auto& [n,b]:d.live) { (void)b; if(n.ends_with(suffix)) return n; }
    CHECK(false); return {};
}
void basic() {
    auto d=std::make_shared<Disk>(); auto s=memory(d);
    CHECK(s->snapshot().state==SyncSessionState::FirstRun);
    CHECK(!s->commit(0,updates(1)).value());
    CHECK(s->commit(0,updates(1),true).value());
    CHECK(s->snapshot().generation==1);
    const auto id=s->identity(); s.reset(); s=memory(d);
    CHECK(s->identity().pair==id.pair && s->snapshot().generation==1);
    CHECK(!s->commit(0,updates(2)).value());
    std::array pending{SyncBaselineUpdate{{"a",file(4),file(5)},SyncBaselineUpdateState::Pending}};
    auto a=s->commit(1,pending); CHECK(a.value());
    CHECK(a.value()->pending_paths.size()==2);
    CHECK(s->snapshot().baseline->rows[0].left==file(1));
    CHECK(s->snapshot().baseline->rows[1].left==file(1));
    CHECK(s->snapshot().previous && s->snapshot().previous->rows[0].left==file(1));
    s.reset(); s=memory(d); CHECK(s->snapshot().generation==2);
    auto changed=memory(d,9); CHECK(changed->identity().pair!=id.pair);
    CHECK(changed->snapshot().state==SyncSessionState::HistoryChanged);
    CHECK(!changed->commit(0,updates(3)).value());
    auto reverse=SyncSession::open(std::make_unique<Memory>(d,true),digest(3));
    CHECK(reverse.value() && (*reverse.value())->snapshot().state==SyncSessionState::HistoryChanged);
    CHECK(!s->commit(2,updates(3),false,[]{return true;}).value());
    CHECK(s->snapshot().generation==2);
    d->invalid=true; CHECK(!s->commit(2,updates(3)).value()); d->invalid=false;
    CHECK(s->refresh().value()); CHECK(s->snapshot().generation==2);
}
void corrupt_and_cas() {
    auto d=std::make_shared<Disk>(); auto a=memory(d),b=memory(d);
    CHECK(a->commit(0,updates(1),true).value());
    CHECK(!b->commit(0,updates(2),true).value());
    CHECK(b->snapshot().generation==1);
    CHECK(a->commit(1,updates(2)).value());
    auto current=key(*d,".baseline"); auto previous=key(*d,".previous");
    const auto good=d->live[current];
    d->live[current][0]^=std::byte{1}; CHECK(a->refresh().value());
    CHECK(a->snapshot().state==SyncSessionState::ReviewRequired && a->snapshot().previous);
    CHECK(!a->commit(0,updates(9),true).value());
    d->live[current]=good; d->live.erase(previous); CHECK(a->refresh().value());
    CHECK(a->snapshot().state==SyncSessionState::ReviewRequired);
    // Losing a current generation with a surviving previous is not first-run.
    d->live[previous]=good; d->live.erase(current); CHECK(a->refresh().value());
    CHECK(a->snapshot().state==SyncSessionState::ReviewRequired);
    d->live.clear(); d->live[current]=Bytes{std::byte{0}}; CHECK(a->refresh().value());
    CHECK(a->snapshot().state==SyncSessionState::ReviewRequired);
}
void initialized_history_loss() {
    for(unsigned generations:{1,2}) {
        auto d=std::make_shared<Disk>();auto s=memory(d);
        for(unsigned g=0;g<generations;++g) CHECK(s->commit(g,updates(g+1),g==0).value());
        const auto name=key(*d,".history");const auto bytes=d->live.at(name);
        d->live.clear();d->live[name]=bytes;d->durable=d->live;s.reset();
        s=memory(d);CHECK(s->snapshot().state==SyncSessionState::ReviewRequired);
        CHECK(!s->commit(0,updates(9),true).value());CHECK(d->live.size()==1 && d->live.at(name)==bytes);
        CHECK(s->refresh().value() && s->snapshot().state==SyncSessionState::ReviewRequired);
    }
    bool exercised=false;
    for(std::size_t point=1;point<30 && !exercised;++point) {
        auto d=std::make_shared<Disk>();auto s=memory(d);d->calls=0;d->fail_at=point;
        auto result=s->commit(0,updates(1),true);s.reset();d->crash(true);
        if(result.value() || d->live.size()!=1 || !d->live.begin()->first.ends_with(".history")) continue;
        s=memory(d);CHECK(s->snapshot().state==SyncSessionState::FirstRun);
        CHECK(s->commit(0,updates(2),true).value());CHECK(s->snapshot().generation==1);
        exercised=true;
    }
    CHECK(exercised);
}
void crash_matrix() {
    for(unsigned start:{0,1,2}) {
        auto seed=std::make_shared<Disk>(); auto initial=memory(seed);
        for(unsigned g=0;g<start;++g) CHECK(initial->commit(g,updates(g+1),g==0).value());
        initial.reset(); seed->calls=0;
        auto counter=std::make_shared<Disk>(*seed); auto probe=memory(counter);
        CHECK(probe->commit(start,updates(9),start==0).value()); const auto operations=counter->calls;
        for(std::size_t point=1;point<=operations;++point) for(bool persist:{false,true}) {
            auto d=std::make_shared<Disk>(*seed); auto s=memory(d); d->calls=0; d->fail_at=point;
            CHECK(!s->commit(start,updates(9),start==0).value());
            CHECK(!s->commit(start,updates(9),start==0).value()); // uncertain session
            s.reset(); d->crash(persist); s=memory(d);
            CHECK(s->snapshot().state!=SyncSessionState::ReviewRequired);
            CHECK(s->snapshot().generation==start || s->snapshot().generation==start+1);
            if(s->snapshot().generation==start+1) CHECK(s->snapshot().baseline->rows[0].left==file(9));
            else if(start) CHECK(s->snapshot().baseline->rows[0].left==file(start));
            const auto generation=s->snapshot().generation;
            CHECK(s->refresh().value()); CHECK(s->snapshot().generation==generation);
            s.reset(); d->crash(); s=memory(d); CHECK(s->snapshot().generation==generation);
        }
    }
    // Crash again DURING recovery, before each of its own mutations/flushes.
    // A second restart must still settle to one exact generation, once only.
    auto seed=std::make_shared<Disk>(); auto initial=memory(seed);
    CHECK(initial->commit(0,updates(1),true).value()); initial.reset();
    for(std::size_t commit_point=1;commit_point<18;++commit_point) {
        auto interrupted=std::make_shared<Disk>(*seed); auto s=memory(interrupted);
        interrupted->calls=0; interrupted->fail_at=commit_point;
        (void)s->commit(1,updates(2)); s.reset(); interrupted->crash(true);
        bool has_intent=false; for(const auto& [name,bytes]:interrupted->live) {
            (void)bytes; has_intent |= name.ends_with(".intent");
        }
        if(!has_intent) continue;
        for(std::size_t recovery_point=1;recovery_point<9;++recovery_point) for(bool persist:{false,true}) {
            auto disk=std::make_shared<Disk>(*interrupted); disk->calls=0; disk->fail_at=recovery_point;
            auto recovering=SyncSession::open(std::make_unique<Memory>(disk),digest(3));
            recovering={}; disk->crash(persist); auto recovered=memory(disk);
            CHECK(recovered->snapshot().generation==2);
            CHECK(recovered->snapshot().baseline->rows[0].left==file(2));
            CHECK(recovered->snapshot().previous && recovered->snapshot().previous->rows.size()==2);
            CHECK(recovered->snapshot().previous->rows[0].left==file(1));
            CHECK(recovered->refresh().value() && recovered->snapshot().generation==2);
        }
        // Corrupt intent or its staged payload cannot authorize roll forward.
        auto damaged=std::make_shared<Disk>(*interrupted); auto name=key(*damaged,".intent");
        damaged->live[name][0]^=std::byte{1}; auto review=memory(damaged);
        CHECK(review->snapshot().state==SyncSessionState::ReviewRequired);
    }
    // Cancellation before intent leaves old baseline; once intent publication
    // starts, cancellation cannot roll back a filesystem mutation or baseline.
    for(unsigned stop:{1,2,3,4,5}) {
        auto d=std::make_shared<Disk>(); auto s=memory(d); CHECK(s->commit(0,updates(1),true).value());
        unsigned checks_cancel=0;
        auto r=s->commit(1,updates(2),false,[&]{return ++checks_cancel>=stop;});
        if(stop<=3) CHECK(!r.value()); else CHECK(r.value());
        s.reset(); d->crash(true); s=memory(d);
        CHECK(s->snapshot().generation==(stop<=3?1:2));
    }
}
#ifndef _WIN32
struct Fixture {
    std::string base,store,left,right,other,child;
    explicit Fixture(const char* selected_root=nullptr) {
        const char* temp=selected_root?selected_root:std::getenv("TMPDIR"); CHECK(temp && *temp);
#ifdef __APPLE__
        const std::string_view temporary_root(temp);
        CHECK(temporary_root=="/Volumes/S8T/tmp" || temporary_root.starts_with("/Volumes/S8T/tmp/") ||
              temporary_root=="/Volumes/PRO-BLADE/tmp" || temporary_root.starts_with("/Volumes/PRO-BLADE/tmp/"));
        struct statfs fs{};CHECK(statfs(temp,&fs)==0);
        // Positive private-storage fixtures use ONLY the explicitly selected
        // TMPDIR. The qualification runner selects an ownership-enforcing root
        // independently of its build directory; never choose another volume.
        if(!selected_root) CHECK(!(fs.f_flags&MNT_IGNORE_OWNERSHIP));
#endif
        std::string pattern=std::string(temp)+"/native.XXXXXX";
        CHECK(mkdtemp(pattern.data())); base=pattern; store=base+"/store"; left=base+"/left";
        right=base+"/right"; other=base+"/other"; child=left+"/child";
        for(const auto& p:{store,left,right,other,child,base+"/store2",right+"/child"}) CHECK(mkdir(p.c_str(),0700)==0);
    }
    static void cleanup(const std::string& p) {
        DIR* d=opendir(p.c_str()); if(!d) { unlink(p.c_str()); return; }
        while(auto* e=readdir(d)) { if(!std::strcmp(e->d_name,".")||!std::strcmp(e->d_name,"..")) continue;
            std::string child=p+"/"+e->d_name; struct stat st{}; CHECK(lstat(child.c_str(),&st)==0);
            if(S_ISDIR(st.st_mode)) cleanup(child); else CHECK(unlink(child.c_str())==0);
        } closedir(d); CHECK(rmdir(p.c_str())==0);
    }
    ~Fixture() { cleanup(base); }
};
NativeAbsolutePath address(const std::string& s) {
    auto p=NativeAbsolutePath::from_posix(s); CHECK(p.value()); return std::move(p).take_value();
}
Observation<std::unique_ptr<SyncSessionBackend>> backend(const Fixture& f,SyncSessionFaults faults={}) {
    return open_native_sync_session_backend(address(f.store),address(f.left),address(f.right),std::move(faults));
}
std::unique_ptr<SyncSession> native(const Fixture& f,SyncSessionFaults faults={}) {
    auto b=backend(f,std::move(faults));
    if(!b.value()) { std::fprintf(stderr,"native open: state=%d code=%lld op=%s\n",int(b.state()),
        static_cast<long long>(b.unavailable_detail()->error.code),b.unavailable_detail()->error.operation.c_str()); }
    CHECK(b.value()); auto s=SyncSession::open(std::move(b).take_value(),digest(3)); CHECK(s.value());
    return std::move(s).take_value();
}
#ifdef __APPLE__
void extended_grant(int fd,bool directory,bool inherit_only=false) {
    auto* group=getgrnam("everyone");CHECK(group);
    uuid_t principal{};CHECK(mbr_gid_to_uuid(group->gr_gid,principal)==0);
    acl_t acl=acl_init(1);CHECK(acl);acl_entry_t entry=nullptr;
    CHECK(acl_create_entry(&acl,&entry)==0);CHECK(acl_set_tag_type(entry,ACL_EXTENDED_ALLOW)==0);
    CHECK(acl_set_qualifier(entry,principal)==0);acl_permset_t perms=nullptr;
    CHECK(acl_get_permset(entry,&perms)==0);CHECK(acl_clear_perms(perms)==0);
    CHECK(acl_add_perm(perms,directory?ACL_LIST_DIRECTORY:ACL_READ_DATA)==0);
    CHECK(acl_add_perm(perms,directory?ACL_ADD_FILE:ACL_WRITE_DATA)==0);
    CHECK(acl_set_permset(entry,perms)==0);
    if(inherit_only) {
        acl_flagset_t flags=nullptr;CHECK(acl_get_flagset_np(entry,&flags)==0);
        CHECK(acl_add_flag_np(flags,ACL_ENTRY_ONLY_INHERIT)==0);
        CHECK(acl_add_flag_np(flags,ACL_ENTRY_FILE_INHERIT)==0);
        CHECK(acl_set_flagset_np(entry,flags)==0);
    }
    CHECK(acl_set_fd_np(fd,acl,ACL_TYPE_EXTENDED)==0);CHECK(acl_free(acl)==0);
}
void clear_extended_acl(int fd) {
    acl_t acl=acl_init(0);CHECK(acl);CHECK(acl_set_fd_np(fd,acl,ACL_TYPE_EXTENDED)==0);CHECK(acl_free(acl)==0);
}
void darwin_privacy_tests() {
    Fixture f;int directory=open(f.store.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);CHECK(directory>=0);
    auto b=backend(f);CHECK(b.value());extended_grant(directory,true);
    struct stat mode{};CHECK(fstat(directory,&mode)==0 && (mode.st_mode&07777)==0700);
    auto checked=(*b.value())->revalidate();CHECK(!checked.value() && checked.state()==ObservationState::Denied);b={};
    b=backend(f);CHECK(!b.value() && b.state()==ObservationState::Denied);
    clear_extended_acl(directory);b=backend(f);CHECK(b.value());b={};
    // Even an inherit-only grant is unsafe for future private generation files.
    extended_grant(directory,true,true);b=backend(f);CHECK(!b.value() && b.state()==ObservationState::Denied);
    clear_extended_acl(directory);
    auto s=native(f);CHECK(s->commit(0,updates(1),true).value());
    DIR* listing=opendir(f.store.c_str());CHECK(listing);std::string baseline;
    while(auto* e=readdir(listing)) if(std::string_view(e->d_name).ends_with(".baseline")) baseline=e->d_name;
    CHECK(closedir(listing)==0 && !baseline.empty());
    int file_fd=openat(directory,baseline.c_str(),O_RDWR|O_CLOEXEC|O_NOFOLLOW);CHECK(file_fd>=0);
    extended_grant(file_fd,false);CHECK(fstat(file_fd,&mode)==0 && (mode.st_mode&07777)==0600);
    checked=s->refresh();CHECK(!checked.value() && checked.state()==ObservationState::Denied);
    CHECK(!s->commit(1,updates(2)).value());s.reset();
    b=backend(f);CHECK(b.value());auto denied=(*b.value())->read(baseline,1024*1024);
    CHECK(!denied.value() && denied.state()==ObservationState::Denied);b={};
    clear_extended_acl(file_fd);CHECK(close(file_fd)==0);CHECK(close(directory)==0);
    s=native(f);CHECK(s->snapshot().generation==1);s.reset();
    const auto* root=std::getenv("CK_SYNC_SESSION_NOOWNERS_FIXTURE_ROOT");
    if(!root) {
        // The preferred scratch volume is a negative privacy fixture on this
        // Mac. Select a unique child there; positive fixtures still use TMPDIR.
        struct statfs fs{};
        if(statfs("/Volumes/S8T/tmp",&fs)==0 && (fs.f_flags&MNT_IGNORE_OWNERSHIP)) root="/Volumes/S8T/tmp";
    }
    if(root) {
        Fixture ignored(root);struct statfs fs{};CHECK(statfs(ignored.store.c_str(),&fs)==0 && (fs.f_flags&MNT_IGNORE_OWNERSHIP));
        auto rejected=backend(ignored);CHECK(!rejected.value() && rejected.state()==ObservationState::Unsupported);
        CHECK(rejected.unavailable_detail()->error.operation=="posix_private_storage.ownership_mount");
    }
}
#endif
void journal_privacy_tests() {
    Fixture f;const auto root=address(f.store);const auto name=*NativeName::from_posix("private-journal");
    CHECK(prepare_native_operation_journal_root(root).value());
    auto opened=open_native_operation_journal_file(root,name,true);CHECK(opened.value());
    auto journal=std::move(opened).take_value();
    const std::array data{std::byte{1},std::byte{2},std::byte{3},std::byte{4}};std::array<std::byte,4> read{};
    CHECK(journal->write_at(0,data).value() && *journal->size().value()==data.size());CHECK(journal->flush().value());
    CHECK(journal->read_at(0,read).value() && read==data);
    const auto denied=[&]() {
        auto size=journal->size();auto input=journal->read_at(0,read);auto output=journal->write_at(0,data);auto flush=journal->flush();
        CHECK(!size.value() && size.state()==ObservationState::Denied);
        CHECK(!input.value() && input.state()==ObservationState::Denied);
        CHECK(!output.value() && output.state()==ObservationState::Denied);
        CHECK(!flush.value() && flush.state()==ObservationState::Denied);
    };
    int directory=open(f.store.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);CHECK(directory>=0);
    int file_fd=openat(directory,"private-journal",O_RDWR|O_NOFOLLOW|O_CLOEXEC);CHECK(file_fd>=0);
    CHECK(fchmod(file_fd,0640)==0);denied();
    CHECK(!open_native_operation_journal_file(root,name,false).value());CHECK(fchmod(file_fd,0600)==0);
    CHECK(fchmod(directory,0755)==0);denied();
    CHECK(prepare_native_operation_journal_root(root).value()); // Safe app-owned root tightening.
    CHECK(journal->flush().value());
#ifdef __APPLE__
    extended_grant(directory,true);denied();
    CHECK(!open_native_operation_journal_file(root,name,false).value());
    CHECK(!prepare_native_operation_journal_root(root).value());clear_extended_acl(directory);
    extended_grant(directory,true,true);denied();clear_extended_acl(directory);
    extended_grant(file_fd,false);denied();
    auto unsafe=open_native_operation_journal_file(root,name,false);CHECK(!unsafe.value() && unsafe.state()==ObservationState::Denied);
    clear_extended_acl(file_fd);
#endif
    // Revalidation also preserves the original single-link security boundary.
    CHECK(linkat(directory,"private-journal",directory,"alias",0)==0);denied();CHECK(unlinkat(directory,"alias",0)==0);
    CHECK(journal->read_at(0,read).value() && read==data);CHECK(journal->flush().value());
    CHECK(close(file_fd)==0);CHECK(close(directory)==0);journal.reset();
    opened=open_native_operation_journal_file(root,name,false);CHECK(opened.value());
    CHECK((*opened.value())->read_at(0,read).value() && read==data);opened={};
#ifdef __APPLE__
    const auto* noowners=std::getenv("CK_SYNC_SESSION_NOOWNERS_FIXTURE_ROOT");
    if(!noowners) {struct statfs fs{};if(statfs("/Volumes/S8T/tmp",&fs)==0 && (fs.f_flags&MNT_IGNORE_OWNERSHIP)) noowners="/Volumes/S8T/tmp";}
    if(noowners) {
        Fixture ignored(noowners);const auto ignored_root=address(ignored.store);struct stat before{},after{};
        CHECK(chmod(ignored.store.c_str(),0755)==0 && stat(ignored.store.c_str(),&before)==0);
        auto prepared=prepare_native_operation_journal_root(ignored_root);
        CHECK(!prepared.value() && prepared.state()==ObservationState::Unsupported);
        CHECK(stat(ignored.store.c_str(),&after)==0 && (before.st_mode&07777)==(after.st_mode&07777));
        auto rejected=open_native_operation_journal_file(ignored_root,name,true);
        CHECK(!rejected.value() && rejected.state()==ObservationState::Unsupported);
        CHECK(access((ignored.store+"/private-journal").c_str(),F_OK)!=0 && errno==ENOENT);
    }
#endif
}
void native_tests() {
#ifdef __APPLE__
    darwin_privacy_tests();
#endif
    journal_privacy_tests();
    Fixture f; SyncSessionFaults short_writes; short_writes.max_write_bytes=7;
    auto s=native(f,short_writes); CHECK(s->commit(0,updates(1),true).value()); auto id=s->identity();
    CHECK(s->snapshot().generation==1); CHECK(!backend(f).value());
    CHECK(!open_native_sync_session_backend(address(f.store),address(f.left),address(f.child)).value());
    CHECK(!open_native_sync_session_backend(address(f.store),address(f.right+"/child"),address(f.right)).value());
    // An unrelated pair remains available despite sharing namespace ancestors.
    CHECK(mkdir((f.base+"/free").c_str(),0700)==0);
    auto disjoint=open_native_sync_session_backend(address(f.store),address(f.other),address(f.base+"/free"));
    CHECK(disjoint.value()); disjoint={};
    auto child=fork(); CHECK(child>=0);
    if(!child) {
        auto a=open_native_sync_session_backend(address(f.base+"/store2"),address(f.child),address(f.other));
        auto b=open_native_sync_session_backend(address(f.base+"/store2"),address(f.other),address(f.right+"/child"));
        _exit(!a.value() && a.state()==ObservationState::Changed && !b.value() && b.state()==ObservationState::Changed ? 0:1);
    }
    int status=0; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    CHECK(symlink(f.left.c_str(),(f.base+"/alias").c_str())==0);
    CHECK(!open_native_sync_session_backend(address(f.store),address(f.base+"/alias"),address(f.other)).value());
    CHECK(rename(f.left.c_str(),(f.left+"-moved").c_str())==0); CHECK(mkdir(f.left.c_str(),0700)==0);
    CHECK(!s->revalidate().value()); CHECK(!s->commit(1,updates(2)).value());
    s.reset(); CHECK(rmdir(f.left.c_str())==0); CHECK(rename((f.left+"-moved").c_str(),f.left.c_str())==0);
    s=native(f); CHECK(s->identity().pair==id.pair && s->snapshot().generation==1); s.reset();
    // Native failures after short writes and at each durability/publication kind.
    for(const auto kind:{SyncSessionIo::Write,SyncSessionIo::FileFlush,SyncSessionIo::Publish,SyncSessionIo::ParentFlush,SyncSessionIo::Remove,SyncSessionIo::FileClose}) {
        auto enabled=std::make_shared<bool>(false); auto count=std::make_shared<unsigned>(0);
        SyncSessionFaults fault; fault.max_write_bytes=13;
        fault.before=[=](SyncSessionIo k) { return !(*enabled && k==kind && ++*count==2); };
        s=native(f,fault); const auto gen=s->snapshot().generation; *enabled=true;
        CHECK(!s->commit(gen,updates(2)).value()); s.reset(); s=native(f);
        if(kind==SyncSessionIo::FileClose) CHECK(s->snapshot().generation==gen);
        CHECK(s->snapshot().state!=SyncSessionState::ReviewRequired);
        CHECK(s->snapshot().generation==gen || s->snapshot().generation==gen+1); s.reset();
    }
    CHECK(chmod(f.store.c_str(),0755)==0); CHECK(!backend(f).value()); CHECK(chmod(f.store.c_str(),0700)==0);
}
void c_api_tests();
void receipt_tests();
void absence_budget_tests();
#else
struct Fixture {
    std::wstring base,store,left,right,other;
    std::vector<std::wstring> directories;
    static std::wstring extended(const std::wstring& p) { auto e=windows_extended_path(p); CHECK(e); return *e; }
    explicit Fixture() {
        wchar_t temp[32768]{},tmp[32768]{};
        const auto temp_length=GetEnvironmentVariableW(L"TEMP",temp,32768);
        const auto tmp_length=GetEnvironmentVariableW(L"TMP",tmp,32768);
        CHECK(temp_length>0 && temp_length<32768 && tmp_length>0 && tmp_length<32768);
        CHECK(std::wstring_view(temp)==tmp && windows_extended_path(temp).has_value());
        if(const auto* require_v=std::getenv("CK_FS_REQUIRE_V_DEV_DRIVE"); require_v && std::string_view(require_v)=="1")
            CHECK(std::wstring_view(temp).starts_with(L"V:\\tmp\\"));
        static unsigned serial=0;
        base=std::wstring(temp)+L"\\native-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(++serial)+L"-"+std::to_wstring(GetTickCount64());
        add(base); store=base+L"\\store"; left=base+L"\\left"; right=base+L"\\right"; other=base+L"\\other";
        add(left); add(right); add(other);
        HANDLE raw=nullptr; CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw));
        DWORD size=0; GetTokenInformation(raw,TokenUser,nullptr,0,&size); std::vector<std::byte> token(size);
        CHECK(GetTokenInformation(raw,TokenUser,token.data(),size,&size)); CloseHandle(raw);
        wchar_t* sid=nullptr; CHECK(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(token.data())->User.Sid,&sid));
        std::wstring sddl=L"O:"+std::wstring(sid)+L"D:P(A;;FA;;;"+sid+L")(A;;FA;;;SY)"; LocalFree(sid);
        PSECURITY_DESCRIPTOR sd=nullptr; CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr));
        SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE}; CHECK(CreateDirectoryW(extended(store).c_str(),&sa)); LocalFree(sd);
        directories.push_back(store);
    }
    void add(const std::wstring& p) { CHECK(CreateDirectoryW(extended(p).c_str(),nullptr)); directories.push_back(p); }
    ~Fixture() {
        WIN32_FIND_DATAW data{}; HANDLE find=FindFirstFileW((extended(store)+L"\\*").c_str(),&data);
        if(find!=INVALID_HANDLE_VALUE) {
            do { if(std::wstring_view(data.cFileName)==L"." || std::wstring_view(data.cFileName)==L"..") continue;
                CHECK(DeleteFileW((extended(store)+L"\\"+data.cFileName).c_str()));
            } while(FindNextFileW(find,&data)); FindClose(find);
        }
        for(auto i=directories.rbegin();i!=directories.rend();++i) CHECK(RemoveDirectoryW(extended(*i).c_str()));
    }
};
NativeAbsolutePath address(const std::wstring& p) {
    std::u16string units; for(auto c:p) units+=static_cast<char16_t>(c);
    auto path=NativeAbsolutePath::from_windows(units); CHECK(path.value()); return std::move(path).take_value();
}
void native_tests() {
    Fixture f; f.add(f.left+L"\\child"); f.add(f.right+L"\\child");
    CHECK(!open_native_sync_session_backend(address(f.store),address(f.left),address(f.left+L"\\child")).value());
    CHECK(!open_native_sync_session_backend(address(f.store),address(f.right+L"\\child"),address(f.right)).value());
    auto unc=NativeAbsolutePath::from_windows(u"\\\\localhost\\unavailable-share\\root"); CHECK(unc.value());
    auto denied=open_native_sync_session_backend(address(f.store),*unc.value(),address(f.right));
    CHECK(!denied.value() && denied.state()==ObservationState::Unsupported);
    SyncSessionFaults partial; partial.max_write_bytes=7;
    auto b=open_native_sync_session_backend(address(f.store),address(f.left),address(f.right),partial);
    if(!b.value() && b.state()==ObservationState::Unsupported) {
        std::printf("Windows native durability unsupported (fail closed): %s\n",b.unavailable_detail()->error.operation.c_str()); return;
    }
    if(!b.value()) std::fprintf(stderr,"Windows backend error: %s %lld\n",b.unavailable_detail()->error.operation.c_str(),static_cast<long long>(b.unavailable_detail()->error.code));
    CHECK(b.value()); auto opened=SyncSession::open(std::move(b).take_value(),digest(3)); CHECK(opened.value());
    auto s=std::move(opened).take_value(); CHECK(s->commit(0,updates(1),true).value());
    const auto pair=s->identity().pair;
    auto overlap=open_native_sync_session_backend(address(f.store),address(f.left+L"\\child"),address(f.other));
    CHECK(!overlap.value() && overlap.state()==ObservationState::Changed);
    wchar_t self[32768]{}; CHECK(GetModuleFileNameW(nullptr,self,32768)>0);
    std::wstring command=L"\""+std::wstring(self)+L"\" --lock-probe \""+f.store+L"\" \""+f.left+L"\\child\" \""+f.other+L"\"";
    STARTUPINFOW startup{}; startup.cb=sizeof(startup); PROCESS_INFORMATION process{};
    auto application=Fixture::extended(self);
    CHECK(CreateProcessW(application.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,Fixture::extended(f.base).c_str(),&startup,&process));
    CHECK(WaitForSingleObject(process.hProcess,30000)==WAIT_OBJECT_0); DWORD result=1; CHECK(GetExitCodeProcess(process.hProcess,&result) && result==0);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    s.reset(); b=open_native_sync_session_backend(address(f.store),address(f.left),address(f.right)); CHECK(b.value());
    opened=SyncSession::open(std::move(b).take_value(),digest(3)); CHECK(opened.value()); s=std::move(opened).take_value();
    CHECK(s->snapshot().generation==1 && s->identity().pair==pair); s.reset();
    // Faults in each native storage boundary leave either the old generation
    // or the intended new generation, recoverable without trusting caller data.
    for(const auto kind:{SyncSessionIo::Write,SyncSessionIo::FileFlush,SyncSessionIo::Publish,SyncSessionIo::ParentFlush,SyncSessionIo::Remove,SyncSessionIo::FileClose}) {
        auto enabled=std::make_shared<bool>(false); auto count=std::make_shared<unsigned>(0);
        SyncSessionFaults fault; fault.max_write_bytes=13;
        fault.before=[=](SyncSessionIo k) { return !(*enabled && k==kind && ++*count==2); };
        b=open_native_sync_session_backend(address(f.store),address(f.left),address(f.right),fault); CHECK(b.value());
        opened=SyncSession::open(std::move(b).take_value(),digest(3)); CHECK(opened.value()); s=std::move(opened).take_value();
        const auto generation=s->snapshot().generation; *enabled=true;
        CHECK(!s->commit(generation,updates(2)).value()); s.reset();
        b=open_native_sync_session_backend(address(f.store),address(f.left),address(f.right)); CHECK(b.value());
        opened=SyncSession::open(std::move(b).take_value(),digest(3)); CHECK(opened.value()); s=std::move(opened).take_value();
        CHECK(s->snapshot().state!=SyncSessionState::ReviewRequired);
        CHECK(s->snapshot().generation==generation || s->snapshot().generation==generation+1); s.reset();
    }
    b=open_native_sync_session_backend(address(f.store),address(f.left),address(f.right)); CHECK(b.value());
    opened=SyncSession::open(std::move(b).take_value(),digest(3)); CHECK(opened.value()); s=std::move(opened).take_value();
    const auto moved=f.left+L"-moved";
    CHECK(MoveFileExW(Fixture::extended(f.left).c_str(),Fixture::extended(moved).c_str(),0));
    CHECK(CreateDirectoryW(Fixture::extended(f.left).c_str(),nullptr));
    CHECK(!s->revalidate().value()); CHECK(!s->commit(s->snapshot().generation,updates(8)).value()); s.reset();
    CHECK(RemoveDirectoryW(Fixture::extended(f.left).c_str()));
    CHECK(MoveFileExW(Fixture::extended(moved).c_str(),Fixture::extended(f.left).c_str(),0));
    const auto alias=f.base+L"\\alias";
    if(CreateSymbolicLinkW(Fixture::extended(alias).c_str(),Fixture::extended(f.left).c_str(),
        SYMBOLIC_LINK_FLAG_DIRECTORY|SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        f.directories.push_back(alias);
        b=open_native_sync_session_backend(address(f.store),address(alias),address(f.right)); CHECK(!b.value());
    } else CHECK(GetLastError()==ERROR_PRIVILEGE_NOT_HELD);
    // Long paths and exact counted UTF-16, including a lone surrogate and a
    // trailing dot/space component, pass through held NT relative opens.
    auto longroot=f.base;
    for(unsigned i=0;i<5;++i) { longroot+=L"\\"+std::wstring(80,L'x'); f.add(longroot); }
    std::wstring exact=longroot+L"\\raw "; exact+=wchar_t(0xd800); exact+=L". "; f.add(exact);
    b=open_native_sync_session_backend(address(f.store),address(exact),address(f.right)); CHECK(b.value()); b={};
    // A nonprivate coordinator ACL is rejected, never trusted as session state.
    b=open_native_sync_session_backend(address(f.other),address(f.left),address(f.right)); CHECK(!b.value());
}

void c_api_tests();
void receipt_tests();
void absence_budget_tests();
#endif
} // namespace
#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {
    if(argc==5 && std::wstring_view(argv[1])==L"--lock-probe") {
        auto b=open_native_sync_session_backend(address(argv[2]),address(argv[3]),address(argv[4]));
        return !b.value() && b.state()==ObservationState::Changed ? 0:1;
    }
#else
int main() {
#endif
    basic(); corrupt_and_cas(); initialized_history_loss(); crash_matrix(); native_tests(); c_api_tests(); receipt_tests(); absence_budget_tests();
    std::printf("sync_session_tests: %u checks passed\n",checks);
}
namespace {
void c_api_tests() {
    ckfss_options options; ckfss_options_init(&options); ckfss_error error{}; ckfss_session* session=nullptr;
    CHECK(ckfss_session_open(nullptr,&session,&error)==CKFSS_INVALID_ARGUMENT && !session);
    ckfss_snapshot snapshot{};
    CHECK(ckfss_session_get_snapshot(nullptr,&snapshot)==CKFSS_INVALID_ARGUMENT);
    CHECK(ckfss_session_commit(nullptr,0,nullptr,0,0,&snapshot,&error)==CKFSS_INVALID_ARGUMENT);
    ckfss_session_request_cancel(nullptr); ckfss_session_clear_cancel(nullptr); ckfss_session_destroy(nullptr);
#ifndef _WIN32
    Fixture f;
    auto p=[](const std::string& s) { return ckfss_native_path{s.data(),s.size(),CKFSS_POSIX_BYTES,0}; };
    options.coordinator=p(f.store); options.left=p(f.left); options.right=p(f.right);
    options.policy_fingerprint[0]=3;
    CHECK(ckfss_session_open(&options,&session,&error)==CKFSS_OK && session);
    CHECK(ckfss_session_get_snapshot(session,&snapshot)==CKFSS_OK && snapshot.state==CKFSS_FIRST_RUN);
    ckfss_update update; ckfss_update_init(&update); update.relative_key="a"; update.relative_key_bytes=1;
    update.state=CKFSS_CONFIRMED_EQUAL;
    update.left.presence=CKFSS_PRESENT; update.left.kind=CKFSS_FILE; update.left.content_digest[0]=4;
    update.left.required_metadata_digest[0]=8; update.right=update.left;
    CHECK(ckfss_session_commit(session,0,&update,1,0,&snapshot,&error)==CKFSS_UNAVAILABLE);
    // Forged equality cannot create native baseline authority.
    CHECK(ckfss_session_commit(session,0,&update,1,1,&snapshot,&error)==CKFSS_UNAVAILABLE);
    CHECK(error.observation==1 && error.code==static_cast<int64_t>(AdapterError::UnsupportedQuery));
    CHECK(ckfss_session_get_snapshot(session,&snapshot)==CKFSS_OK && snapshot.generation==0);
    ckfss_session_destroy(session); session=nullptr;
    // Seed durable state using the trusted C++ adapter contract. The C boundary
    // can inspect/recover it but cannot advance caller-asserted equality.
    auto seed=native(f); CHECK(seed->commit(0,updates(4),true).value()); seed.reset();
    CHECK(ckfss_session_open(&options,&session,&error)==CKFSS_OK);
    CHECK(ckfss_session_get_snapshot(session,&snapshot)==CKFSS_OK);
    CHECK(snapshot.generation==1 && snapshot.rows==2 && snapshot.has_baseline);
    ckfss_row row{}; uint64_t required=0; char key[2]{};
    CHECK(ckfss_session_get_row(session,0,0,&row,nullptr,0,&required)==CKFSS_BUFFER_TOO_SMALL && required==1);
    CHECK(ckfss_session_get_row(session,0,0,&row,key,sizeof(key),&required)==CKFSS_OK && key[0]=='a');
    CHECK(row.left.content_digest[0]==4 && row.relative_key_bytes==1);
    update.reserved=1;
    CHECK(ckfss_session_commit(session,1,&update,1,0,&snapshot,&error)==CKFSS_INVALID_ARGUMENT); update.reserved=0;
    ckfss_session_request_cancel(session);
    CHECK(ckfss_session_commit(session,1,&update,1,0,&snapshot,&error)==CKFSS_UNAVAILABLE);
    ckfss_session_clear_cancel(session); update.state=CKFSS_PENDING; update.right.content_digest[0]=5;
    CHECK(ckfss_session_commit(session,1,&update,1,0,&snapshot,&error)==CKFSS_UNAVAILABLE);
    CHECK(ckfss_session_get_pending_key(session,0,key,sizeof(key),&required)==CKFSS_INVALID_ARGUMENT);
    CHECK(ckfss_session_get_row(session,0,0,&row,key,sizeof(key),&required)==CKFSS_OK && row.right.content_digest[0]==4);
    CHECK(ckfss_session_revalidate(session,&error)==CKFSS_OK);
    ckfss_session_destroy(session); session=nullptr;
    CHECK(ckfss_session_open(&options,&session,&error)==CKFSS_OK);
    CHECK(ckfss_session_get_snapshot(session,&snapshot)==CKFSS_OK && snapshot.generation==1 && snapshot.pending_rows==0);
    CHECK(ckfss_session_refresh(session,&error)==CKFSS_OK); ckfss_session_destroy(session); session=nullptr;
    options.reserved[0]=1; CHECK(ckfss_session_open(&options,&session,&error)==CKFSS_INVALID_ARGUMENT && !session);
#endif
}
}
namespace {
#ifdef _WIN32
using TestPath=std::wstring;
TestPath child_path(const TestPath& p,const char* name) { std::wstring w;for(;*name;++name)w+=*name;return p+L"\\"+w; }
ckfss_native_path native_text(const TestPath& p) { return {p.data(),p.size(),CKFSS_WINDOWS_UTF16,0}; }
void write_test_file(const TestPath& p,const char* bytes) {
    auto extended=Fixture::extended(p);HANDLE h=CreateFileW(extended.c_str(),GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    CHECK(h!=INVALID_HANDLE_VALUE);DWORD count=0;CHECK(WriteFile(h,bytes,static_cast<DWORD>(std::strlen(bytes)),&count,nullptr));
    CHECK(count==std::strlen(bytes));ULARGE_INTEGER ticks{};ticks.QuadPart=UINT64_C(133444736001234567);
    FILETIME time{ticks.LowPart,ticks.HighPart};CHECK(SetFileTime(h,nullptr,&time,&time));CHECK(FlushFileBuffers(h));CloseHandle(h);
}
void delete_test_file(const TestPath& p) { CHECK(DeleteFileW(Fixture::extended(p).c_str())); }
#else
using TestPath=std::string;
TestPath child_path(const TestPath& p,const char* name) { return p+"/"+name; }
ckfss_native_path native_text(const TestPath& p) { return {p.data(),p.size(),CKFSS_POSIX_BYTES,0}; }
void write_test_file(const TestPath& p,const char* bytes) {
    int fd=open(p.c_str(),O_CREAT|O_WRONLY|O_TRUNC|O_CLOEXEC,0600);CHECK(fd>=0);
    CHECK(write(fd,bytes,std::strlen(bytes))==static_cast<ssize_t>(std::strlen(bytes)));
    const timespec times[2]{{1700000000,123456700},{1700000000,123456700}};
    CHECK(futimens(fd,times)==0);CHECK(fsync(fd)==0);CHECK(close(fd)==0);
}
void delete_test_file(const TestPath& p) { CHECK(unlink(p.c_str())==0); }
#endif
uint64_t process_handle_count() {
#ifdef _WIN32
    DWORD count=0;CHECK(GetProcessHandleCount(GetCurrentProcess(),&count));return count;
#else
    DIR* d=opendir("/dev/fd");CHECK(d);uint64_t count=0;
    while(auto* e=readdir(d)) if(std::strcmp(e->d_name,".") && std::strcmp(e->d_name,"..")) ++count;
    CHECK(closedir(d)==0);return count;
#endif
}
void absence_budget_tests() {
    Fixture f;const auto right=child_path(f.base,"budget-right");
#ifdef _WIN32
    f.add(right);
#else
    CHECK(mkdir(right.c_str(),0700)==0);
#endif
    std::vector<TestPath> directories;
    for(const auto& root:{f.other,right}) {
        auto next=root;
        for(const auto* name:{"d1","d2"}) {
            next=child_path(next,name);directories.push_back(next);
#ifdef _WIN32
            f.add(next);
#else
            CHECK(mkdir(next.c_str(),0700)==0);
#endif
        }
    }
    const auto d1=child_path(TestPath{},"d1").substr(1),d2=child_path(TestPath{},"d2").substr(1);
    const auto missing0=child_path(TestPath{},"missing0").substr(1),missing1=child_path(TestPath{},"missing1").substr(1);
    ckfss_native_path c0[]{native_text(d1),native_text(d2),native_text(missing0)};
    ckfss_native_path c1[]{native_text(d1),native_text(d2),native_text(missing1)};
    ckfss_exact_path paths[]{{c0,3,CKFSS_VERIFY_PATH,0},{c1,3,CKFSS_VERIFY_PATH,0}};
    ckfss_options options;ckfss_options_init(&options);options.coordinator=native_text(f.store);
    options.left=native_text(f.other);options.right=native_text(right);
    ckfss_metadata_policy policy;ckfss_metadata_policy_init(&policy);policy.scope=CKFSS_METADATA_ORDINARY_V1;
    ckfss_error error{};ckfss_session* s=nullptr;ckfss_receipt* receipt=nullptr;
    // Byte budget must reject even pure absence BEFORE the first cursor opens.
    policy.max_total_metadata_bytes=1;
    CHECK(ckfss_session_open_verified(&options,&policy,&s,&error)==CKFSS_OK);
    const auto before=process_handle_count();
    CHECK(ckfss_session_verify_exact_paths(s,paths,2,&policy,&receipt,&error)==CKFSS_UNAVAILABLE && !receipt);
    CHECK(error.code==static_cast<int64_t>(AdapterError::InventoryLimit) && std::strcmp(error.operation,"sync_session.parent_proof_limit")==0);
    CHECK(process_handle_count()<=before);ckfss_session_destroy(s);s=nullptr;
    policy.max_total_metadata_bytes=16*1024*1024;policy.max_parent_entries=7;
    CHECK(ckfss_session_open_verified(&options,&policy,&s,&error)==CKFSS_OK);
    const auto baseline_handles=process_handle_count();
    for(unsigned attempt=0;attempt<12;++attempt) {
        CHECK(ckfss_session_verify_exact_paths(s,paths,2,&policy,&receipt,&error)==CKFSS_UNAVAILABLE && !receipt);
        CHECK(error.code==static_cast<int64_t>(AdapterError::InventoryLimit) && std::strcmp(error.operation,"sync_session.aggregate_handle_limit")==0);
        CHECK(process_handle_count()<=baseline_handles);
    }
    // One deep missing path fits six retained cursors; a second must not bypass
    // the same aggregate limit merely because each final component is absent.
    CHECK(ckfss_session_verify_exact_paths(s,paths,1,&policy,&receipt,&error)==CKFSS_OK && receipt);
    uint64_t confirmed=0,pending=0;CHECK(ckfss_receipt_get_counts(receipt,&confirmed,&pending)==CKFSS_OK && confirmed==1 && !pending);
    ckfss_snapshot snapshot{};
    // Commit must account for the original receipt's retained cursors too.
    CHECK(ckfss_session_commit_verified(s,receipt,1,&snapshot,&error)==CKFSS_UNAVAILABLE);
    CHECK(std::strcmp(error.operation,"sync_session.aggregate_handle_limit")==0);
    ckfss_receipt_destroy(receipt);receipt=nullptr;CHECK(process_handle_count()<=baseline_handles);
    ckfss_session_destroy(s);
}
void receipt_tests() {
    Fixture f;ckfss_options options;ckfss_options_init(&options);
    options.coordinator=native_text(f.store);options.left=native_text(f.left);options.right=native_text(f.right);
    ckfss_metadata_policy policy;ckfss_metadata_policy_init(&policy);policy.scope=CKFSS_METADATA_ORDINARY_V1;
    ckfss_error error{};ckfss_session* s=nullptr;
    auto opened=ckfss_session_open_verified(&options,&policy,&s,&error);
    if(opened==CKFSS_UNAVAILABLE && error.observation==1) {
        std::printf("receipt storage unsupported: %s\n",error.operation);
        CHECK(!std::getenv("CK_SYNC_SESSION_REQUIRE_NATIVE_SUCCESS"));return;
    }
    CHECK(opened==CKFSS_OK && s);
    uint64_t supported=0,conditional=0;
    CHECK(ckfss_session_get_capabilities(s,&supported,&conditional)==CKFSS_OK);
    CHECK(supported==(CKFSS_CAP_OVERLAP_SESSION_LOCKS|CKFSS_CAP_DURABLE_BASELINE));
    CHECK(conditional==(CKFSS_CAP_REGULAR_RECEIPT|CKFSS_CAP_FINAL_ABSENCE_RECEIPT));
    CHECK(!(conditional&(CKFSS_CAP_DIRECTORY_TREE_RECEIPT|CKFSS_CAP_TWO_WAY_EXECUTION)));
    const auto missing=TestPath(
#ifdef _WIN32
        L"missing"
#else
        "missing"
#endif
    );
    auto missing_component=native_text(missing);ckfss_exact_path absent{&missing_component,1,CKFSS_VERIFY_PATH,0};
    ckfss_receipt* absence=nullptr;
    CHECK(ckfss_session_verify_exact_paths(s,&absent,1,&policy,&absence,&error)==CKFSS_OK && absence);
    uint64_t confirmed=0,pending=0;
    CHECK(ckfss_receipt_get_counts(absence,&confirmed,&pending)==CKFSS_OK && confirmed==1 && pending==0);
    ckfss_snapshot snapshot{};
    CHECK(ckfss_session_commit_verified(s,absence,1,&snapshot,&error)==CKFSS_OK && snapshot.generation==1);
    CHECK(ckfss_session_commit_verified(s,absence,1,&snapshot,&error)==CKFSS_UNAVAILABLE);
    ckfss_receipt_destroy(absence);absence=nullptr;
    const auto a=TestPath(
#ifdef _WIN32
        L"a"
#else
        "a"
#endif
    );
    const auto b=TestPath(
#ifdef _WIN32
        L"b"
#else
        "b"
#endif
    );
    for(const auto& root:{f.left,f.right}) { write_test_file(child_path(root,"a"),"same");write_test_file(child_path(root,"b"),"same"); }
    ckfss_native_path components[]{native_text(a),native_text(b)};
    ckfss_exact_path paths[]{{&components[0],1,CKFSS_VERIFY_PATH,0},{&components[1],1,CKFSS_VERIFY_PATH,0}};
    ckfss_receipt *receipt=nullptr,*stale=nullptr;
    auto verified=ckfss_session_verify_exact_paths(s,paths,2,&policy,&receipt,&error);
    if(verified==CKFSS_UNAVAILABLE && (error.observation==1 || error.observation==3)) {
        std::printf("regular receipt metadata unsupported/denied: %s\n",error.operation);
        CHECK(!std::getenv("CK_SYNC_SESSION_REQUIRE_NATIVE_SUCCESS"));
        ckfss_session_destroy(s);
        for(const auto& root:{f.left,f.right}) { delete_test_file(child_path(root,"a"));delete_test_file(child_path(root,"b")); }
        return;
    }
    if(verified!=CKFSS_OK) std::fprintf(stderr,"receipt verify error=%u native=%lld op=%s\n",error.observation,static_cast<long long>(error.code),error.operation);
    CHECK(verified==CKFSS_OK && receipt);
    CHECK(ckfss_receipt_get_counts(receipt,&confirmed,&pending)==CKFSS_OK && confirmed==2 && pending==0);
    CHECK(ckfss_session_verify_exact_paths(s,paths,2,&policy,&stale,&error)==CKFSS_OK);
    CHECK(ckfss_session_commit_verified(s,receipt,0,&snapshot,&error)==CKFSS_OK && snapshot.generation==2 && snapshot.rows==3);
    CHECK(ckfss_session_commit_verified(s,stale,0,&snapshot,&error)==CKFSS_UNAVAILABLE);
    ckfss_receipt_destroy(receipt);receipt=nullptr;
    // A receipt cannot be transferred even to another handle for the SAME
    // durable pair and generation. Opaque native evidence is instance-bound.
    ckfss_receipt_destroy(stale);stale=nullptr;
    CHECK(ckfss_session_verify_exact_paths(s,paths,2,&policy,&stale,&error)==CKFSS_OK);
    ckfss_session_destroy(s);s=nullptr;
    CHECK(ckfss_session_open_verified(&options,&policy,&s,&error)==CKFSS_OK);
    CHECK(ckfss_session_commit_verified(s,stale,0,&snapshot,&error)==CKFSS_UNAVAILABLE);
    ckfss_receipt_destroy(stale);stale=nullptr;
    CHECK(ckfss_session_get_snapshot(s,&snapshot)==CKFSS_OK && snapshot.generation==2);
    ckfss_row old{};uint64_t required=0;char key[128]{};
    CHECK(ckfss_session_get_row(s,0,0,&old,key,sizeof(key),&required)==CKFSS_OK);
    // Content equality alone cannot establish required metadata convergence.
    CHECK(ckfss_session_verify_exact_paths(s,paths,2,&policy,&receipt,&error)==CKFSS_OK);
#ifdef _WIN32
    CHECK(SetFileAttributesW(Fixture::extended(child_path(f.left,"a")).c_str(),FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_ARCHIVE));
#else
    CHECK(chmod(child_path(f.left,"a").c_str(),0640)==0);
#endif
    CHECK(ckfss_session_commit_verified(s,receipt,0,&snapshot,&error)==CKFSS_UNAVAILABLE);
    ckfss_receipt_destroy(receipt);receipt=nullptr;
    CHECK(ckfss_session_verify_exact_paths(s,paths,2,&policy,&receipt,&error)==CKFSS_OK);
    CHECK(ckfss_receipt_get_counts(receipt,&confirmed,&pending)==CKFSS_OK && confirmed==1 && pending==1);
    ckfss_receipt_destroy(receipt);receipt=nullptr;
#ifdef _WIN32
    CHECK(SetFileAttributesW(Fixture::extended(child_path(f.left,"a")).c_str(),FILE_ATTRIBUTE_ARCHIVE));
#else
    CHECK(chmod(child_path(f.left,"a").c_str(),0600)==0);
#endif
    // Different content is Pending and preserves the old baseline row.
    write_test_file(child_path(f.left,"a"),"diff");
    paths[1].disposition=CKFSS_SKIP_PATH;
    CHECK(ckfss_session_verify_exact_paths(s,paths,2,&policy,&receipt,&error)==CKFSS_OK);
    CHECK(ckfss_receipt_get_counts(receipt,&confirmed,&pending)==CKFSS_OK && confirmed==0 && pending==2);
    CHECK(ckfss_session_commit_verified(s,receipt,0,&snapshot,&error)==CKFSS_OK && snapshot.generation==3 && snapshot.pending_rows==3);
    ckfss_receipt_destroy(receipt);receipt=nullptr;paths[1].disposition=CKFSS_VERIFY_PATH;
    ckfss_row retained{};
    CHECK(ckfss_session_get_row(s,0,0,&retained,key,sizeof(key),&required)==CKFSS_OK);
    CHECK(std::memcmp(&old.left,&retained.left,sizeof(old.left))==0 && std::memcmp(&old.right,&retained.right,sizeof(old.right))==0);
    write_test_file(child_path(f.left,"a"),"same");
    CHECK(ckfss_session_verify_exact_paths(s,paths,2,&policy,&receipt,&error)==CKFSS_OK);
    // A write with restored mtime still changes its native version/content.
    write_test_file(child_path(f.left,"a"),"edit");
    CHECK(ckfss_session_commit_verified(s,receipt,0,&snapshot,&error)==CKFSS_UNAVAILABLE);
    ckfss_receipt_destroy(receipt);receipt=nullptr;
    CHECK(ckfss_session_get_snapshot(s,&snapshot)==CKFSS_OK && snapshot.generation==3);
    ckfss_session_request_cancel(s);
    CHECK(ckfss_session_verify_exact_paths(s,paths,2,&policy,&receipt,&error)==CKFSS_UNAVAILABLE && !receipt);
    ckfss_session_clear_cancel(s);
    // Qualified absence is invalidated if a name appears before commit.
    CHECK(ckfss_session_verify_exact_paths(s,&absent,1,&policy,&receipt,&error)==CKFSS_OK);
    write_test_file(child_path(f.left,"missing"),"appeared");
    CHECK(ckfss_session_commit_verified(s,receipt,0,&snapshot,&error)==CKFSS_UNAVAILABLE);
    ckfss_receipt_destroy(receipt);receipt=nullptr;delete_test_file(child_path(f.left,"missing"));
    ckfss_session_destroy(s);s=nullptr;
    auto changed=policy;changed.scope=CKFSS_METADATA_COMPLETE_V1;
    CHECK(ckfss_session_open_verified(&options,&changed,&s,&error)==CKFSS_OK);
    CHECK(ckfss_session_get_snapshot(s,&snapshot)==CKFSS_OK && snapshot.state==CKFSS_HISTORY_CHANGED);
    CHECK(ckfss_session_verify_exact_paths(s,paths,2,&changed,&receipt,&error)==CKFSS_UNAVAILABLE && !receipt);
    ckfss_session_destroy(s);s=nullptr;
    auto bounded=policy;bounded.max_file_bytes=1;
    CHECK(ckfss_session_open_verified(&options,&bounded,&s,&error)==CKFSS_OK);
    CHECK(ckfss_session_verify_exact_paths(s,paths,2,&bounded,&receipt,&error)==CKFSS_UNAVAILABLE && !receipt);
    CHECK(error.code==static_cast<int64_t>(AdapterError::InventoryLimit));
    ckfss_session_destroy(s);
    for(const auto& root:{f.left,f.right}) { delete_test_file(child_path(root,"a"));delete_test_file(child_path(root,"b")); }
}
}
