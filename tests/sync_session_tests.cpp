// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "sync_session.hpp"
#include "native_sync_coordinator.hpp"
#include "native_filesystem.hpp"
#include "native_sync_ledger.hpp"
#include "native_sync_observation.hpp"
#include "operation_journal_file.hpp"
#include "ck_fs_session.h"
#include "ck_fs_journal_root.h"
#include "journal_root_handles.hpp"
#include "prepared_journal_directory.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "platform/journal_root_test_faults.hpp"
#include "windows_name.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <memory>
#include <stdexcept>
#include <type_traits>
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
namespace { void coordinator_tests(); void native_finish_tests(); }
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
void native_finish_tests();
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
        const auto normalized=[](std::wstring path) {
            std::replace(path.begin(),path.end(),L'/',L'\\');
            const auto letter=[](wchar_t c){return (c>=L'A'&&c<=L'Z')||(c>=L'a'&&c<=L'z');};
            // Strip only an extended DOS prefix, never UNC/device namespaces.
            if(path.size()>=7&&path.starts_with(L"\\\\?\\")&&letter(path[4])&&path[5]==L':'&&path[6]==L'\\')path.erase(0,4);
            if(path.size()>=3&&path[1]==L':'&&path[2]==L'\\'&&path[0]>=L'a'&&path[0]<=L'z')path[0]-=L'a'-L'A';
            return path;
        };
        const auto temp_path=normalized(std::wstring(temp,temp_length)),tmp_path=normalized(std::wstring(tmp,tmp_length));
        CHECK(temp_path==tmp_path && windows_extended_path(temp_path).has_value());
        if(const auto* require_v=std::getenv("CK_FS_REQUIRE_V_DEV_DRIVE"); require_v && std::string_view(require_v)=="1") {
            const auto drive=GetFileAttributesW(L"V:\\");
            CHECK(drive!=INVALID_FILE_ATTRIBUTES && (drive&FILE_ATTRIBUTE_DIRECTORY));
            CHECK(std::wstring_view(temp_path).starts_with(L"V:\\tmp\\"));
        }
        static unsigned serial=0;
        base=temp_path+L"\\native-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(++serial)+L"-"+std::to_wstring(GetTickCount64());
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
    basic(); corrupt_and_cas(); initialized_history_loss(); crash_matrix(); native_tests(); c_api_tests(); receipt_tests(); absence_budget_tests(); native_finish_tests(); coordinator_tests();
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
void native_finish_tests() {
    for(unsigned mode=0;mode<4;++mode) {
        Fixture f;NativeFileSystem fs;PreparedJournalRootRequest request;
        request.parent=std::move(fs.open_native_directory(address(f.store))).take_value();
        JournalRootPreparationProgress progress;auto prepared=prepare_native_journal_root(std::move(request),progress);
        if(!prepared.value()){CHECK(prepared.state()==ObservationState::Unsupported);CHECK(!std::getenv("CK_SYNC_SESSION_REQUIRE_NATIVE_SUCCESS"));return;}
        auto owner=std::move(prepared).take_value();const auto root_handles=process_handle_count();unsigned closes=0;
        SyncSessionFaults faults;faults.before=[&](SyncSessionIo io){if(io!=SyncSessionIo::NativeHandleClose)return true;++closes;
            if(closes==1){if(mode==1)throw std::bad_alloc();if(mode==2)throw std::runtime_error("test.close_observer");return false;}return true;};
        auto backend=open_native_sync_session_backend(owner,address(f.left),address(f.right),faults);CHECK(backend.value());
        auto opened=SyncSession::open(std::move(backend).take_value(),digest(90));CHECK(opened.value());auto session=std::move(opened).take_value();
        CHECK(session->commit(0,{},true).value());const auto active_handles=process_handle_count();CHECK(active_handles>root_handles);
        if(mode==3)session.reset();
        else {
            auto finished=session->finish_io();CHECK(!finished.value());const auto attempted=closes;CHECK(attempted>0);
            CHECK(!session->finish_io().value()&&closes==attempted);
            CHECK(session->root_handle(false)==-1&&session->root_handle(true)==-1);
            CHECK(!session->revalidate().value()&&!session->refresh().value()&&!session->commit(1,{}).value());
            CHECK(session->snapshot().generation==1);session.reset();
        }
        CHECK(process_handle_count()==root_handles);CHECK(closes>0);
        detail::PreparedJournalConsumerFailure failure;CHECK(detail::read_prepared_journal_consumer_failure(*owner,failure));
#ifdef _WIN32
        CHECK(failure.domain==ErrorDomain::Win32&&failure.code==ERROR_WRITE_FAULT);
#else
        CHECK(failure.domain==ErrorDomain::Posix&&failure.code==EIO);
#endif
        CHECK(!owner->finish_io().value());CHECK(!owner->finish_io().value());
        // Closing a failed session releases both root locks; another private
        // coordinator can acquire the same exact pair. No arbitrary-writer
        // exclusion or cleanup authority is inferred from this session lease.
        Fixture separate;auto other=open_native_sync_session_backend(address(separate.store),address(f.left),address(f.right));CHECK(other.value());
        CHECK((*other.value())->finish_io().value());
    }
    // A legacy path factory owns its newly minted Root lifecycle. It reports
    // original-root close failures after all consumer duplicates have closed.
    Fixture f;const auto handles=process_handle_count();auto backend=open_native_sync_session_backend(address(f.store),address(f.left),address(f.right));CHECK(backend.value());
    auto opened=SyncSession::open(std::move(backend).take_value(),digest(91));CHECK(opened.value());auto session=std::move(opened).take_value();
    const auto previous=detail::journal_root_test_fault;
    detail::journal_root_test_fault=+[](detail::JournalRootFaultPoint point)->std::optional<std::int64_t>{
        if(point==detail::JournalRootFaultPoint::DirectoryClose)return
#ifdef _WIN32
            ERROR_WRITE_FAULT;
#else
            EIO;
#endif
        return {};};
    auto failed=session->finish_io();detail::journal_root_test_fault=previous;
    CHECK(!failed.value()&&!session->finish_io().value());CHECK(process_handle_count()==handles);
    CHECK(!session->revalidate().value());session.reset();
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

namespace session_coordinator_codec {
std::size_t checks=0;
#define SYNC_COORD_CHECK(x) do {++checks;if(!(x)){std::fprintf(stderr,"line %d: %s\n",__LINE__,#x);std::abort();}}while(false)
template<class T>T take(Observation<T> value) {if(!value.value()){std::fprintf(stderr,"unexpected %s\n",value.unavailable_detail()->error.operation.c_str());std::abort();}return std::move(value).take_value();}
SyncDigest digest(unsigned n){SyncDigest d{};d[0]=std::byte(n);return d;}
NativeSyncLedgerEvidence fixture() {
    NativeSyncLedgerEvidence e;e.session={digest(1),digest(2),digest(3),digest(4)};e.expected_generation=7;e.reviewed_plan=digest(5);
    // The opaque comparison label deliberately differs from its native name.
    // Decode must preserve BOTH fields and must never parse the label as a path.
    NativeSyncPathRecord path;path.opaque_key="opaque-comparison-label";path.components={*NativeName::from_posix("native:exact\\name")};
    path.left={SyncPresence::Absent,SyncKind::Unknown,{},{}};path.right=path.left;e.paths.push_back(path);
    NativeSyncArtifact a;a.components={*NativeName::from_posix("not-prefix-filtered")};a.parent={IdentityScheme::PosixDeviceInode,NativeIdentifier::from_u64(8),NativeIdentifier::from_u64(9),{}};
    a.object={IdentityScheme::PosixDeviceInode,NativeIdentifier::from_u64(8),NativeIdentifier::from_u64(10),11};
    a.status={SyncPresence::Present,SyncKind::File,digest(6),digest(7)};e.artifacts.push_back(a);return e;
}
struct Disk {std::vector<std::byte> live,durable;std::size_t writes=0,flushes=0,closes=0,short_write=3,fail_write=0,fail_flush=0;bool fail_close=false;unsigned throw_close=0;};
class Memory final:public OperationJournalFile {
    std::shared_ptr<Disk> disk;
    static Observation<bool> failure(){return Observation<bool>::unavailable(ObservationState::Failed,{ErrorDomain::Posix,5,"test.fault"});}
public:
    explicit Memory(std::shared_ptr<Disk> d):disk(std::move(d)){}
    Observation<std::uint64_t> size()override{return Observation<std::uint64_t>::available(disk->live.size());}
    Observation<std::size_t> read_at(std::uint64_t offset,std::span<std::byte> bytes)override {
        if(offset>disk->live.size())return Observation<std::size_t>::unavailable(ObservationState::Failed);
        auto n=std::min(bytes.size(),disk->live.size()-static_cast<std::size_t>(offset));std::copy_n(disk->live.data()+offset,n,bytes.data());return Observation<std::size_t>::available(n);
    }
    Observation<std::size_t> write_at(std::uint64_t offset,std::span<const std::byte> bytes)override {
        if(++disk->writes==disk->fail_write)return Observation<std::size_t>::unavailable(ObservationState::Failed,{ErrorDomain::Posix,5,"test.partial_write"});
        auto n=std::min(bytes.size(),disk->short_write);if(offset+n>disk->live.size())disk->live.resize(offset+n);
        std::copy_n(bytes.data(),n,disk->live.data()+offset);return Observation<std::size_t>::available(n);
    }
    Observation<bool> flush()override {if(++disk->flushes==disk->fail_flush)return failure();disk->durable=disk->live;return Observation<bool>::available(true);}
    Observation<bool> finish_io()override {++disk->closes;if(disk->throw_close==1)throw std::runtime_error("test.finalizer");if(disk->throw_close==2)throw std::bad_alloc();auto f=flush();if(!f.value())return f;return disk->fail_close?failure():Observation<bool>::available(true);}
};
OperationJournalId id(){OperationJournalId value{};value.bytes[0]=std::byte(1);return value;}
void codec_tests() {
    using Owned=std::unique_ptr<NativeSyncInventory>;
    static_assert(std::is_nothrow_move_constructible_v<Owned> && std::is_nothrow_move_assignable_v<Owned>);
    static_assert(std::is_nothrow_move_constructible_v<Observation<Owned>> && std::is_nothrow_move_assignable_v<Observation<Owned>>);
    auto inventory=std::make_unique<NativeSyncInventory>();auto* original=inventory.get();
    inventory->files.emplace("native-label",NativeSyncFileProof{});auto* node=&inventory->files.begin()->second;
    auto observation=Observation<Owned>::available(std::move(inventory));SYNC_COORD_CHECK(!inventory);
    auto moved=std::move(observation);auto transferred=std::move(moved).take_value();
    SYNC_COORD_CHECK(transferred.get()==original&&transferred->files.size()==1);
    SYNC_COORD_CHECK(&transferred->files.at("native-label")==node);
    SYNC_COORD_CHECK(observation.value()&&!observation.value()->get());
    SYNC_COORD_CHECK(!moved.value()&&moved.state()==ObservationState::Unknown);
    auto evidence=fixture();auto wire=take(encode_native_sync_ledger(evidence));auto decoded=take(decode_native_sync_ledger(wire));
    SYNC_COORD_CHECK(decoded.paths[0].opaque_key=="opaque-comparison-label");SYNC_COORD_CHECK(*decoded.paths[0].components[0].posix_bytes()=="native:exact\\name");
    SYNC_COORD_CHECK(decoded.artifacts[0].components==evidence.artifacts[0].components);SYNC_COORD_CHECK(decoded.artifacts[0].object==evidence.artifacts[0].object);
    SYNC_COORD_CHECK(decoded.artifacts[0].status==evidence.artifacts[0].status);SYNC_COORD_CHECK(take(encode_native_sync_ledger(decoded))==wire);
    for(std::size_t n=0;n<wire.size();++n)SYNC_COORD_CHECK(!decode_native_sync_ledger(std::span(wire).first(n)).value());
    auto trailing=wire;trailing.push_back(std::byte{});SYNC_COORD_CHECK(!decode_native_sync_ledger(trailing).value());
    auto bad=evidence;bad.artifacts.push_back(bad.artifacts[0]);SYNC_COORD_CHECK(!encode_native_sync_ledger(bad).value());
    bad=evidence;bad.paths.push_back(bad.paths[0]);SYNC_COORD_CHECK(!encode_native_sync_ledger(bad).value());
    bad=evidence;bad.artifacts[0].components.push_back(*NativeName::from_posix("nested"));SYNC_COORD_CHECK(!encode_native_sync_ledger(bad).value());
    bad=evidence;bad.proposed_baseline=SyncBaseline{digest(99),{}};SYNC_COORD_CHECK(!encode_native_sync_ledger(bad).value());
    auto present=evidence;present.paths[0].left=present.artifacts[0].status;present.paths[0].left_object=present.artifacts[0].object;present.paths[0].action=SyncAction::CopyLeftToRight;
    auto present_wire=take(encode_native_sync_ledger(present));auto present_decoded=take(decode_native_sync_ledger(present_wire));
    SYNC_COORD_CHECK(present_decoded.paths[0].left==present.paths[0].left&&present_decoded.paths[0].left_object==present.paths[0].left_object);
    present.paths[0].left_object.reset();SYNC_COORD_CHECK(!encode_native_sync_ledger(present).value());
    auto windows=evidence;windows.paths[0].components={*NativeName::from_windows(std::u16string{u'a',char16_t(0xd800),u'.',u' '})};
    auto winwire=take(encode_native_sync_ledger(windows));SYNC_COORD_CHECK(take(decode_native_sync_ledger(winwire)).paths[0].components==windows.paths[0].components);
    NativeSyncLedgerLimits tight_limits;tight_limits.max_total_wire_bytes=wire.size()-1;SYNC_COORD_CHECK(!encode_native_sync_ledger(evidence,tight_limits).value());SYNC_COORD_CHECK(!decode_native_sync_ledger(wire,tight_limits).value());
    tight_limits={};tight_limits.max_artifacts=0;SYNC_COORD_CHECK(!encode_native_sync_ledger(evidence,tight_limits).value());
}
void fault_tests() {
    auto e=fixture();auto d=std::make_shared<Disk>();auto ledger=take(NativeSyncLedger::create_on_file(std::make_unique<Memory>(d),id(),e));
    SYNC_COORD_CHECK(d->writes>1);SYNC_COORD_CHECK(d->flushes==1);SYNC_COORD_CHECK(ledger->journal().state(0)==OperationJournalState::Planned);
    auto changed=e;changed.reviewed_plan[0]^=std::byte(1);SYNC_COORD_CHECK(!ledger->append(OperationJournalState::Prepared,changed).value());
    SYNC_COORD_CHECK(ledger->journal().records().size()==1);
    SYNC_COORD_CHECK(ledger->append(OperationJournalState::Prepared,e).value());auto durable=d->durable;auto records=ledger->journal().records().size();
    d->fail_write=d->writes+2;auto proposal=e;proposal.proposed_baseline=SyncBaseline{e.session.policy,{}};
    SYNC_COORD_CHECK(!ledger->append(OperationJournalState::Copied,proposal).value());SYNC_COORD_CHECK(ledger->journal().records().size()==records);SYNC_COORD_CHECK(d->durable==durable);
    d->live=d->durable;d->fail_write=0;d->fail_flush=d->flushes+1;SYNC_COORD_CHECK(!ledger->append(OperationJournalState::Copied,proposal).value());SYNC_COORD_CHECK(ledger->journal().records().size()==records);SYNC_COORD_CHECK(d->durable==durable);
    d->live=d->durable;d->fail_flush=0;SYNC_COORD_CHECK(ledger->append(OperationJournalState::Copied,proposal).value());
    SYNC_COORD_CHECK(ledger->append(OperationJournalState::Verified,proposal).value());SYNC_COORD_CHECK(ledger->append(OperationJournalState::CommitIntended,proposal).value());
    d->fail_close=true;SYNC_COORD_CHECK(!ledger->finish_io().value());SYNC_COORD_CHECK(d->closes==1);SYNC_COORD_CHECK(!ledger->finish_io().value());SYNC_COORD_CHECK(d->closes==1);
    SYNC_COORD_CHECK(!ledger->append(OperationJournalState::DestinationCommitted,proposal).value());
    Memory recovered(d);auto loaded=take(load_operation_journal(recovered));SYNC_COORD_CHECK(!loaded.tail);SYNC_COORD_CHECK(loaded.journal->state(0)==OperationJournalState::CommitIntended);
    // An exception after native finalization has begun must poison retries;
    // an empty optional failure must never be mistaken for completed I/O.
    for(unsigned exception:{1U,2U}) {
        auto throwing=std::make_shared<Disk>();auto uncertain=take(NativeSyncLedger::create_on_file(std::make_unique<Memory>(throwing),id(),e));
        throwing->throw_close=exception;bool caught=false;
        try {(void)uncertain->finish_io();}catch(const std::runtime_error&){caught=exception==1;}catch(const std::bad_alloc&){caught=exception==2;}
        SYNC_COORD_CHECK(caught&&throwing->closes==1);
        for(unsigned retry=0;retry<3;++retry) {
            auto result=uncertain->finish_io();SYNC_COORD_CHECK(!result.value());
            SYNC_COORD_CHECK(result.unavailable_detail()->state==ObservationState::Unknown);
            SYNC_COORD_CHECK(result.unavailable_detail()->error.operation=="native_sync.ledger_finish_incomplete");
        }
        SYNC_COORD_CHECK(throwing->closes==1);SYNC_COORD_CHECK(!uncertain->append(OperationJournalState::Prepared,e).value());
        Memory preserved(throwing);auto durable=take(load_operation_journal(preserved));
        SYNC_COORD_CHECK(!durable.tail&&durable.journal->state(0)==OperationJournalState::Planned);
    }
    auto success=std::make_shared<Disk>();auto finished=take(NativeSyncLedger::create_on_file(std::make_unique<Memory>(success),id(),e));
    SYNC_COORD_CHECK(finished->finish_io().value());SYNC_COORD_CHECK(finished->finish_io().value());SYNC_COORD_CHECK(success->closes==1);
    // First planned-frame durability failure grants no durable plan authority.
    auto empty=std::make_shared<Disk>();empty->fail_flush=1;SYNC_COORD_CHECK(!NativeSyncLedger::create_on_file(std::make_unique<Memory>(empty),id(),e).value());SYNC_COORD_CHECK(empty->durable.empty());
    for(std::size_t fail=1;fail<8;++fail) {auto partial=std::make_shared<Disk>();partial->fail_write=fail;SYNC_COORD_CHECK(!NativeSyncLedger::create_on_file(std::make_unique<Memory>(partial),id(),e).value());SYNC_COORD_CHECK(partial->durable.empty());}
}
}
#undef SYNC_COORD_CHECK

namespace session_coordinator_native {
std::size_t checks=0;
#define SYNC_COORD_CHECK(x) do {++checks;if(!(x)){std::fprintf(stderr,"line %d: %s\n",__LINE__,#x);std::abort();}}while(false)
template<class T>T take(Observation<T> o){if(!o.value()){std::fprintf(stderr,"unexpected op=%s state=%d\n",o.unavailable_detail()->error.operation.c_str(),int(o.state()));std::abort();}return std::move(o).take_value();}
#ifndef _WIN32
struct Fixture {
    std::string base;
    Fixture() {
        const char* root=std::getenv("TMPDIR");SYNC_COORD_CHECK(root&&*root);std::string pattern=std::string(root)+"/native-sync-coordinator.XXXXXX";SYNC_COORD_CHECK(mkdtemp(pattern.data()));base=pattern;
        for(auto s:{"store","left","right"}){SYNC_COORD_CHECK(!mkdir(path(s).c_str(),0700));sync(path(s));}
        sync(base);sync(root);
    }
    std::string path(std::string s)const{return base+"/"+s;}
    static void sync(const std::string& p){int fd=open(p.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);SYNC_COORD_CHECK(fd>=0);SYNC_COORD_CHECK(!fsync(fd));SYNC_COORD_CHECK(!close(fd));}
    void write(const char* name,const char* data){auto p=path(name);int fd=open(p.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);SYNC_COORD_CHECK(fd>=0);auto n=std::strlen(data);SYNC_COORD_CHECK(::write(fd,data,n)==static_cast<ssize_t>(n));
        timespec times[2]{{1000000000,0},{1000000000,0}};SYNC_COORD_CHECK(!futimens(fd,times));SYNC_COORD_CHECK(!fsync(fd));SYNC_COORD_CHECK(!close(fd));}
    void remove(const char* name){SYNC_COORD_CHECK(!unlink(path(name).c_str()));}
    NativeSyncCoordinatorRequest request(){return {take(NativeAbsolutePath::from_posix(path("store"))),take(NativeAbsolutePath::from_posix(path("left"))),take(NativeAbsolutePath::from_posix(path("right"))),{},MetadataReplayPolicy{1,RegularMetadataScope::OrdinaryCallerVisibleV1,MetadataOwnership::Original,false,{}},{},{},{},{},{}};}
    static void cleanup(const std::string& p){DIR* dir=opendir(p.c_str());if(!dir){SYNC_COORD_CHECK(!unlink(p.c_str()));return;}for(;;){auto* e=readdir(dir);if(!e)break;std::string n=e->d_name;if(n=="."||n=="..")continue;cleanup(p+"/"+n);}SYNC_COORD_CHECK(!closedir(dir));SYNC_COORD_CHECK(!rmdir(p.c_str()));}
    ~Fixture(){cleanup(base);}
};
std::vector<NativeSyncDecision> proposals(const NativeSyncCoordinator& c){std::vector<NativeSyncDecision>d;for(auto& row:c.rows())d.push_back({row.exact_key,NativeSyncChoice::Proposal});return d;}
void drain(NativeSyncCoordinator& c){for(unsigned n=0;n<256;++n){auto s=c.advance();if(s==NativeSyncCoordinatorState::Complete||s==NativeSyncCoordinatorState::NeedsReview||s==NativeSyncCoordinatorState::Cancelled)return;}SYNC_COORD_CHECK(false);}
class ForeignRoot final:public PreparedJournalRoot {
public:
    mutable unsigned calls=0;ObjectIdentity object{};std::optional<NativeAbsolutePath> hint;
    Observation<std::unique_ptr<OperationJournalFile>> open_journal(const NativeName&,bool) override {++calls;return Observation<std::unique_ptr<OperationJournalFile>>::unavailable(ObservationState::Unsupported);}
    Observation<bool> revalidate()const override {++calls;return Observation<bool>::available(true);}
    Observation<bool> sync()override {++calls;return Observation<bool>::available(true);}
    Observation<bool> finish_io()override {++calls;return Observation<bool>::available(true);}
    const ObjectIdentity& identity()const noexcept override {++calls;return object;}
    NameEncoding encoding()const noexcept override {++calls;return NameEncoding::PosixBytes;}
    const std::optional<NativeAbsolutePath>& navigation_address()const noexcept override {++calls;return hint;}
};
PreparedJournalRoot::Pointer held_root(Fixture& f,const char* relative="store") {
    NativeFileSystem fs;PreparedJournalRootRequest request;
    request.parent=take(fs.open_native_directory(take(NativeAbsolutePath::from_posix(f.path(relative)))));
    // Deliberately points at DATA. It must never be used for native I/O.
    request.navigation_hint=take(NativeAbsolutePath::from_posix(f.path("left")));
    JournalRootPreparationProgress progress;return take(prepare_native_journal_root(std::move(request),progress));
}
void inventory_owner_tests() {
    Fixture f;f.write("left/observed","native payload");NativeFileSystem fs;
    const auto address=take(NativeAbsolutePath::from_posix(f.path("left")));
    MetadataReplayPolicy policy{1,RegularMetadataScope::OrdinaryCallerVisibleV1,MetadataOwnership::Original,false,{}};
    NativeSyncProofLimits limits;NativeSyncProofBudget budget;
    auto observed=take(observe_native_sync_root(take(fs.open_native_directory(address)),policy,limits,budget));
    SYNC_COORD_CHECK(observed&&observed->files.size()==1);
    const auto expected=observed->files.begin()->second.status;auto* original=observed.get();
    Observation<std::unique_ptr<NativeSyncInventory>> owner=Observation<std::unique_ptr<NativeSyncInventory>>::available(std::move(observed));
    auto transferred=std::move(owner).take_value();SYNC_COORD_CHECK(!observed&&transferred.get()==original);
    SYNC_COORD_CHECK(transferred->files.begin()->second.status==expected);
    // A failed fresh capture publishes no inventory and cannot disturb the
    // previously qualified owned snapshot. No data/baseline writes occur.
    limits.max_entries=0;budget={};auto failed=observe_native_sync_root(take(fs.open_native_directory(address)),policy,limits,budget);
    SYNC_COORD_CHECK(!failed.value());SYNC_COORD_CHECK(transferred->files.size()==1&&transferred->files.begin()->second.status==expected);
}
void held_storage_tests() {
    Fixture f;auto left=take(NativeAbsolutePath::from_posix(f.path("left"))),right=take(NativeAbsolutePath::from_posix(f.path("right")));
    auto foreign=std::make_shared<ForeignRoot>();
    SYNC_COORD_CHECK(!open_native_sync_session_backend(foreign,left,right).value());
    SYNC_COORD_CHECK(!load_native_sync_ledgers(foreign).value());SYNC_COORD_CHECK(!foreign->calls);
    auto root=held_root(f);
    f.write("store/a","one");f.write("store/b","two");
    auto first=take(open_prepared_journal_directory(root));auto second=take(open_prepared_journal_directory(root));
    // Independent directory views must each observe every name, even when reads
    // are interleaved. A dup sharing the native enumeration offset is unsafe.
    auto names=[](PreparedJournalDirectory& view){std::set<std::string> out;for(;;){auto batch=view.read(1);SYNC_COORD_CHECK(batch.state!=DirectoryReadState::Error);for(auto& n:batch.names)out.insert(*n.posix_bytes());if(batch.state==DirectoryReadState::End)break;}return out;};
    auto a=first->read(1),b=second->read(1);SYNC_COORD_CHECK(a.state!=DirectoryReadState::Error&&b.state!=DirectoryReadState::Error);
    auto rest_a=names(*first),rest_b=names(*second);for(const auto& n:a.names)rest_a.insert(*n.posix_bytes());for(const auto& n:b.names)rest_b.insert(*n.posix_bytes());if(rest_a!=rest_b||rest_a.size()!=2){for(const auto& n:rest_a)std::fprintf(stderr,"view A: %s\n",n.c_str());for(const auto& n:rest_b)std::fprintf(stderr,"view B: %s\n",n.c_str());}
    SYNC_COORD_CHECK(rest_a==rest_b&&rest_a.size()==2);
    SYNC_COORD_CHECK(first->finish_io().value()&&second->finish_io().value());first.reset();second.reset();
    f.remove("store/a");f.remove("store/b");
    bool swap=false,swapped=false;SyncSessionFaults faults;
    faults.before=[&](SyncSessionIo io){if(swap&&!swapped&&io==SyncSessionIo::Remove){SYNC_COORD_CHECK(!rename(f.path("store").c_str(),f.path("held").c_str()));SYNC_COORD_CHECK(!mkdir(f.path("store").c_str(),0700));swapped=true;}return true;};
    auto session=take(SyncSession::open(take(open_native_sync_session_backend(root,left,right,faults)),{}));
    SYNC_COORD_CHECK(session->storage_root()==root);SYNC_COORD_CHECK(session->commit(0,{},true).value());
    SYNC_COORD_CHECK(!root->finish_io().value());
    swap=true;SYNC_COORD_CHECK(!session->commit(1,{}).value()&&swapped);
    DIR* replacement=opendir(f.path("store").c_str());SYNC_COORD_CHECK(replacement);unsigned children=0;while(auto* e=readdir(replacement))if(std::strcmp(e->d_name,".")&&std::strcmp(e->d_name,".."))++children;
    SYNC_COORD_CHECK(!closedir(replacement)&&!children);SYNC_COORD_CHECK(!rmdir(f.path("store").c_str()));SYNC_COORD_CHECK(!rename(f.path("held").c_str(),f.path("store").c_str()));
    SYNC_COORD_CHECK(session->refresh().value()&&session->snapshot().generation==1);session.reset();
    auto r=f.request();r.coordinator.reset();r.prepared_journal_root=root;
    // Existing session uses a different policy, so another fixture establishes
    // a genuine same-owner coordinator without rebasing that durable history.
    Fixture coordinated;coordinated.write("left/equal","same");coordinated.write("right/equal","same");
    auto coordinator_root=held_root(coordinated);auto request=coordinated.request();request.coordinator.reset();request.prepared_journal_root=coordinator_root;
    auto worker=take(NativeSyncCoordinator::open(std::move(request)));SYNC_COORD_CHECK(worker->approve(proposals(*worker),true).value());drain(*worker);
    SYNC_COORD_CHECK(worker->result().state==NativeSyncCoordinatorState::Complete&&worker->result().generation==1);worker.reset();
    auto ledgers=take(load_native_sync_ledgers(coordinator_root));SYNC_COORD_CHECK(ledgers.size()==1&&ledgers[0].journal->state(0)==OperationJournalState::Complete);
    // The misleading data-root hint has never received private ledger files.
    DIR* data=opendir(coordinated.path("left").c_str());SYNC_COORD_CHECK(data);unsigned entries=0;while(auto* e=readdir(data))if(std::strcmp(e->d_name,".")&&std::strcmp(e->d_name,".."))++entries;SYNC_COORD_CHECK(!closedir(data)&&entries==1);
    r.prepared_journal_root.reset();SYNC_COORD_CHECK(root->finish_io().value());
}
void c_held_storage_tests() {
    Fixture f;ckfe_engine* engine=nullptr;ckfe_directory* directory=nullptr;ckfe_error native_error{};
    SYNC_COORD_CHECK(ckfe_engine_create(&engine)==CKFE_API_OK);
    SYNC_COORD_CHECK(ckfe_directory_open_utf8(engine,f.path("store").c_str(),0,&directory,&native_error)==CKFE_API_OK);
    ckfjr_options_v1 options;ckfjr_options_init_v1(&options);options.parent=directory;options.disposition=CKFJR_ADOPT_HELD;
    ckfjr_root* root=nullptr;SYNC_COORD_CHECK(ckfjr_start_v1(&options,&root)==CKFE_API_OK);
    ckfe_directory_destroy(directory);ckfe_engine_destroy(engine);ckfe_error_free(&native_error);
    ckfjr_snapshot_v1 state;ckfjr_snapshot_init_v1(&state);
    for(unsigned i=0;i<500;++i){SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK);if(state.state!=CKFJR_PREPARING)break;SYNC_COORD_CHECK(ckfjr_wait_v1(root,20)==CKFE_API_OK);}
    SYNC_COORD_CHECK(state.state==CKFJR_READY);
    ckfss_options session_options;ckfss_options_init(&session_options);auto l=f.path("left"),r=f.path("right");
    session_options.left={l.data(),l.size(),CKFSS_POSIX_BYTES,0};session_options.right={r.data(),r.size(),CKFSS_POSIX_BYTES,0};
    ckfss_error error{};ckfss_session* session=nullptr;ckfss_metadata_policy policy;ckfss_metadata_policy_init(&policy);policy.scope=CKFSS_METADATA_ORDINARY_V1;
    SYNC_COORD_CHECK(ckfss_session_open_verified_with_journal_root(&session_options,&policy,root,&session,&error)==CKFSS_OK);
    SYNC_COORD_CHECK(ckfjr_finish_v1(root)==CKFE_API_OK);ckfss_session* rejected=nullptr;
    SYNC_COORD_CHECK(ckfss_session_open_with_journal_root(&session_options,root,&rejected,&error)==CKFSS_UNAVAILABLE&&!rejected);
    SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK&&!state.worker_drained);
    ckfss_receipt* receipt=nullptr;SYNC_COORD_CHECK(ckfss_session_verify_exact_paths(session,nullptr,0,&policy,&receipt,&error)==CKFSS_OK);
    ckfss_snapshot snapshot{};SYNC_COORD_CHECK(ckfss_session_commit_verified(session,receipt,1,&snapshot,&error)==CKFSS_OK&&snapshot.generation==1);
    ckfss_receipt_destroy(receipt);
    SYNC_COORD_CHECK(ckfss_session_finish_io(session,&error)==CKFSS_OK);SYNC_COORD_CHECK(ckfss_session_finish_io(session,&error)==CKFSS_OK);
    SYNC_COORD_CHECK(ckfss_session_refresh(session,&error)==CKFSS_UNAVAILABLE&&!std::strcmp(error.operation,"sync_session.finished"));
    SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK&&!state.worker_drained);
    ckfss_session_destroy(session);
    for(unsigned i=0;i<500;++i){SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK);if(state.worker_drained)break;SYNC_COORD_CHECK(ckfjr_wait_v1(root,20)==CKFE_API_OK);}
    SYNC_COORD_CHECK(state.worker_drained&&state.state==CKFJR_COMPLETE);ckfjr_release(root);
}
void c_root_consumer_failure_tests() {
    Fixture f;f.write("left/equal","same");f.write("right/equal","same");
    ckfe_engine* engine=nullptr;ckfe_directory* directory=nullptr;ckfe_error native_error{};
    SYNC_COORD_CHECK(ckfe_engine_create(&engine)==CKFE_API_OK);
    SYNC_COORD_CHECK(ckfe_directory_open_utf8(engine,f.path("store").c_str(),0,&directory,&native_error)==CKFE_API_OK);
    ckfjr_options_v1 prepare;ckfjr_options_init_v1(&prepare);prepare.parent=directory;prepare.disposition=CKFJR_ADOPT_HELD;
    ckfjr_root* root=nullptr;SYNC_COORD_CHECK(ckfjr_start_v1(&prepare,&root)==CKFE_API_OK);
    ckfe_directory_destroy(directory);ckfe_engine_destroy(engine);ckfe_error_free(&native_error);
    ckfjr_snapshot_v1 state;ckfjr_snapshot_init_v1(&state);
    for(unsigned i=0;i<500;++i){SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK);if(state.state!=CKFJR_PREPARING)break;SYNC_COORD_CHECK(ckfjr_wait_v1(root,20)==CKFE_API_OK);}
    SYNC_COORD_CHECK(state.state==CKFJR_READY);
    auto request=f.request();request.coordinator.reset();request.prepared_journal_root=take(retain_prepared_journal_root(root));
    unsigned closes=0;request.storage_faults.before=[&](SyncSessionIo io){return io!=SyncSessionIo::NativeHandleClose||++closes!=1;};
    auto worker=take(NativeSyncCoordinator::open(std::move(request)));SYNC_COORD_CHECK(worker->approve(proposals(*worker),true).value());drain(*worker);
    SYNC_COORD_CHECK(worker->result().state==NativeSyncCoordinatorState::Complete&&worker->result().generation==1);
    auto failed=worker->finish_io();SYNC_COORD_CHECK(!failed.value());SYNC_COORD_CHECK(failed.unavailable_detail()->error.domain==ErrorDomain::Posix&&failed.unavailable_detail()->error.code==EIO);
    SYNC_COORD_CHECK(worker->result().state==NativeSyncCoordinatorState::NeedsReview&&worker->result().failure&&worker->result().failure->error.code==EIO);
    const auto attempted=closes;SYNC_COORD_CHECK(!worker->finish_io().value()&&closes==attempted);
    // The C Root refuses NEW consumers even before finish/drain, using its
    // native provider's sticky error rather than a process-local registry.
    ckfss_options options;ckfss_options_init(&options);auto left=f.path("left"),right=f.path("right");
    options.left={left.data(),left.size(),CKFSS_POSIX_BYTES,0};options.right={right.data(),right.size(),CKFSS_POSIX_BYTES,0};
    ckfss_session* refused=nullptr;ckfss_error error{};
    SYNC_COORD_CHECK(ckfss_session_open_with_journal_root(&options,root,&refused,&error)==CKFSS_UNAVAILABLE&&!refused);
    SYNC_COORD_CHECK(error.observation==static_cast<std::uint32_t>(ObservationState::Changed)&&
        error.domain==static_cast<std::uint32_t>(ErrorDomain::Adapter)&&error.code==static_cast<std::int64_t>(AdapterError::InvalidAccess));
    SYNC_COORD_CHECK(!std::strcmp(error.operation,"journal_root.not_ready"));
    SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK&&state.failure_domain==static_cast<std::uint32_t>(ErrorDomain::Posix)&&state.failure_code==EIO);
    SYNC_COORD_CHECK(ckfjr_finish_v1(root)==CKFE_API_OK);SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK&&!state.worker_drained);
    worker.reset();
    for(unsigned i=0;i<500;++i){SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK);if(state.worker_drained)break;SYNC_COORD_CHECK(ckfjr_wait_v1(root,20)==CKFE_API_OK);}
    SYNC_COORD_CHECK(state.worker_drained&&state.state==CKFJR_FAILED);
    SYNC_COORD_CHECK(state.failure_domain==static_cast<std::uint32_t>(ErrorDomain::Posix)&&state.failure_code==EIO);
    SYNC_COORD_CHECK(!std::strcmp(state.failure_operation,"sync_session.directory_close"));ckfjr_release(root);
}
void c_two_way_held_storage_tests() {
    Fixture f;f.write("left/equal","same");f.write("right/equal","same");
    ckfe_engine* engine=nullptr;ckfe_directory* directory=nullptr;ckfe_error native_error{};
    SYNC_COORD_CHECK(ckfe_engine_create(&engine)==CKFE_API_OK);
    SYNC_COORD_CHECK(ckfe_directory_open_utf8(engine,f.path("store").c_str(),0,&directory,&native_error)==CKFE_API_OK);
    ckfjr_options_v1 prepare;ckfjr_options_init_v1(&prepare);prepare.parent=directory;prepare.disposition=CKFJR_ADOPT_HELD;
    ckfjr_root* root=nullptr;SYNC_COORD_CHECK(ckfjr_start_v1(&prepare,&root)==CKFE_API_OK);
    ckfe_directory_destroy(directory);ckfe_engine_destroy(engine);ckfe_error_free(&native_error);
    ckfjr_snapshot_v1 state;ckfjr_snapshot_init_v1(&state);
    for(unsigned i=0;i<500;++i){SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK);if(state.state!=CKFJR_PREPARING)break;SYNC_COORD_CHECK(ckfjr_wait_v1(root,20)==CKFE_API_OK);}
    SYNC_COORD_CHECK(state.state==CKFJR_READY);
    ckfss_options options;ckfss_options_init(&options);auto left=f.path("left"),right=f.path("right");
    options.left={left.data(),left.size(),CKFSS_POSIX_BYTES,0};options.right={right.data(),right.size(),CKFSS_POSIX_BYTES,0};
    ckfss_metadata_policy policy;ckfss_metadata_policy_init(&policy);policy.scope=CKFSS_METADATA_ORDINARY_V1;
    ckfss_two_way_policy execution;ckfss_two_way_policy_init(&execution);ckfss_error error{};ckfss_two_way* worker=nullptr;
    SYNC_COORD_CHECK(ckfss_two_way_open_with_journal_root(&options,&policy,&execution,root,&worker,&error)==CKFSS_OK);
    ckfss_two_way_review* receipt=nullptr;SYNC_COORD_CHECK(ckfss_two_way_assess_rules(worker,nullptr,0,1,&receipt,&error)==CKFSS_OK);
    SYNC_COORD_CHECK(ckfss_two_way_approve_review(worker,receipt,1,&error)==CKFSS_OK);ckfss_two_way_review_destroy(receipt);
    ckfss_two_way_info info{};SYNC_COORD_CHECK(ckfss_two_way_get_info(worker,&info)==CKFSS_OK);
    for(unsigned n=0;n<32&&info.state!=CKFSS_TW_COMPLETE;++n)SYNC_COORD_CHECK(ckfss_two_way_advance(worker,&info,&error)==CKFSS_OK);
    SYNC_COORD_CHECK(info.state==CKFSS_TW_COMPLETE&&info.generation==1);ckfss_two_way_destroy(worker);worker=nullptr;
    // The legacy managed-baseline guard enumerates the SAME retained root even
    // though options.coordinator is empty and offers no usable pathname.
    ckfss_session* legacy=nullptr;SYNC_COORD_CHECK(ckfss_session_open_verified_with_journal_root(&options,&policy,root,&legacy,&error)==CKFSS_OK);
    ckfss_receipt* forbidden=nullptr;SYNC_COORD_CHECK(ckfss_session_verify_exact_paths(legacy,nullptr,0,&policy,&forbidden,&error)==CKFSS_UNAVAILABLE&&!forbidden);
    SYNC_COORD_CHECK(!std::strcmp(error.operation,"sync_session.coordinator_managed_baseline"));ckfss_session_destroy(legacy);
    SYNC_COORD_CHECK(ckfss_two_way_open_with_journal_root(&options,&policy,&execution,root,&worker,&error)==CKFSS_OK);
    SYNC_COORD_CHECK(ckfjr_finish_v1(root)==CKFE_API_OK);SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK&&!state.worker_drained);
    ckfss_two_way_request_cancel(worker);SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK&&!state.worker_drained);
    SYNC_COORD_CHECK(ckfss_two_way_finish_io(worker,&error)==CKFSS_OK);SYNC_COORD_CHECK(ckfss_two_way_finish_io(worker,&error)==CKFSS_OK);
    SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK&&!state.worker_drained);
    ckfss_two_way_destroy(worker);
    for(unsigned i=0;i<500;++i){SYNC_COORD_CHECK(ckfjr_poll_v1(root,&state)==CKFE_API_OK);if(state.worker_drained)break;SYNC_COORD_CHECK(ckfjr_wait_v1(root,20)==CKFE_API_OK);}
    SYNC_COORD_CHECK(state.worker_drained&&state.state==CKFJR_COMPLETE);ckfjr_release(root);
}
void baseline_native(){Fixture f;f.write("left/equal","native");f.write("right/equal","native");auto c=take(NativeSyncCoordinator::open(f.request()));SYNC_COORD_CHECK(c->rows().size()==1);SYNC_COORD_CHECK(c->rows()[0].proposal==SyncAction::Unchanged);SYNC_COORD_CHECK(!c->approve(proposals(*c),false).value());SYNC_COORD_CHECK(c->approve(proposals(*c),true).value());drain(*c);
    if(c->result().state!=NativeSyncCoordinatorState::Complete&&c->result().failure)std::fprintf(stderr,"native equal failure %s\n",c->result().failure->error.operation.c_str());
    SYNC_COORD_CHECK(c->result().state==NativeSyncCoordinatorState::Complete);SYNC_COORD_CHECK(c->result().generation==1);SYNC_COORD_CHECK(c->result().completed_operations==0);c.reset();
    c=take(NativeSyncCoordinator::open(f.request()));SYNC_COORD_CHECK(c->result().generation==1);SYNC_COORD_CHECK(c->rows()[0].proposal==SyncAction::Unchanged);c.reset();
    f.remove("left/equal");f.remove("right/equal");c=take(NativeSyncCoordinator::open(f.request()));SYNC_COORD_CHECK(c->rows().size()==1);SYNC_COORD_CHECK(c->rows()[0].left.presence==SyncPresence::Absent);SYNC_COORD_CHECK(c->rows()[0].right.presence==SyncPresence::Absent);
    SYNC_COORD_CHECK(c->approve(proposals(*c)).value());drain(*c);SYNC_COORD_CHECK(c->result().state==NativeSyncCoordinatorState::Complete);SYNC_COORD_CHECK(c->result().generation==2);c.reset();
    auto changed=f.request();changed.application_policy[0]=std::byte(99);auto no=NativeSyncCoordinator::open(std::move(changed));SYNC_COORD_CHECK(!no.value());SYNC_COORD_CHECK(no.unavailable_detail()->error.operation=="native_sync.history_changed");
}
void mixed_native(){Fixture f;f.write("left/left-only","left");f.write("right/right-only","right");auto c=take(NativeSyncCoordinator::open(f.request()));SYNC_COORD_CHECK(c->rows().size()==2);SYNC_COORD_CHECK(c->rows()[0].proposal==SyncAction::CopyLeftToRight);SYNC_COORD_CHECK(c->rows()[1].proposal==SyncAction::CopyRightToLeft);SYNC_COORD_CHECK(c->approve(proposals(*c),true).value());drain(*c);
#ifdef __APPLE__
    SYNC_COORD_CHECK(c->result().state==NativeSyncCoordinatorState::NeedsReview);SYNC_COORD_CHECK(c->result().failure);SYNC_COORD_CHECK(c->result().failure->state==ObservationState::Unsupported);SYNC_COORD_CHECK(c->result().generation==0);
#else
    SYNC_COORD_CHECK(c->result().state==NativeSyncCoordinatorState::Complete);SYNC_COORD_CHECK(c->result().generation==1);SYNC_COORD_CHECK(c->result().completed_operations==2);
#endif
    c.reset();
#ifdef __APPLE__
    auto blocked=NativeSyncCoordinator::open(f.request());SYNC_COORD_CHECK(!blocked.value());SYNC_COORD_CHECK(blocked.unavailable_detail()->error.operation=="native_sync.unresolved_intent");
#else
    auto reopened=take(NativeSyncCoordinator::open(f.request()));SYNC_COORD_CHECK(reopened->rows().size()==2);for(const auto& row:reopened->rows())SYNC_COORD_CHECK(row.proposal==SyncAction::Unchanged);
#endif
}
void recovery_native() {
    for(auto failure:{NativeSyncCoordinatorEvent::BeforeLedgerClose,NativeSyncCoordinatorEvent::BeforeBaselineCommit,NativeSyncCoordinatorEvent::AfterBaselineCommit}) {
        Fixture f;f.write("left/equal","native");f.write("right/equal","native");auto request=f.request();
        request.before_event=[failure](auto event){return event!=failure;};
        auto c=take(NativeSyncCoordinator::open(std::move(request)));SYNC_COORD_CHECK(c->approve(proposals(*c),true).value());drain(*c);
        SYNC_COORD_CHECK(c->result().state==NativeSyncCoordinatorState::NeedsReview);c.reset();
        c=take(NativeSyncCoordinator::open(f.request()));SYNC_COORD_CHECK(c->result().generation==1);SYNC_COORD_CHECK(c->rows()[0].proposal==SyncAction::Unchanged);c.reset();
        c=take(NativeSyncCoordinator::open(f.request()));SYNC_COORD_CHECK(c->result().generation==1);SYNC_COORD_CHECK(c->rows()[0].proposal==SyncAction::Unchanged);
    }
    Fixture overlap;auto r=overlap.request();r.coordinator=take(NativeAbsolutePath::from_posix(overlap.path("left")));
    auto refused=NativeSyncCoordinator::open(std::move(r));SYNC_COORD_CHECK(!refused.value());
}
void skip_and_cancel(){Fixture f;f.write("left/conflict","left");f.write("right/conflict","right");auto c=take(NativeSyncCoordinator::open(f.request()));SYNC_COORD_CHECK(c->rows()[0].proposal==SyncAction::Conflict);auto decisions=proposals(*c);SYNC_COORD_CHECK(!c->approve(decisions,true).value());decisions[0].choice=NativeSyncChoice::Skip;SYNC_COORD_CHECK(c->approve(decisions,true).value());drain(*c);SYNC_COORD_CHECK(c->result().state==NativeSyncCoordinatorState::Complete);SYNC_COORD_CHECK(c->result().pending_keys.size()==1);c.reset();
    c=take(NativeSyncCoordinator::open(f.request()));SYNC_COORD_CHECK(c->rows()[0].proposal==SyncAction::Conflict);c.reset();
    Fixture cancel;auto job=take(NativeSyncCoordinator::open(cancel.request()));SYNC_COORD_CHECK(job->approve({},true).value());std::stop_source stop;stop.request_stop();SYNC_COORD_CHECK(job->advance(stop.get_token())==NativeSyncCoordinatorState::Cancelled);SYNC_COORD_CHECK(job->result().generation==0);
}
#endif
}
#undef SYNC_COORD_CHECK


#ifndef _WIN32
namespace session_coordinator_native {
#define TW_C_CHECK(x) do {++checks;if(!(x)){std::fprintf(stderr,"line %d: %s\n",__LINE__,#x);std::abort();}}while(false)
ckfss_native_path c_path(const std::string& s){return {s.data(),s.size(),CKFSS_POSIX_BYTES,0};}
void c_worker_tests() {
    Fixture f;f.write("left/native:exact\\name","content");f.write("right/native:exact\\name","content");
    ckfss_options options;ckfss_options_init(&options);const auto store=f.path("store"),left=f.path("left"),right=f.path("right");
    options.coordinator=c_path(store);options.left=c_path(left);options.right=c_path(right);
    ckfss_metadata_policy metadata;ckfss_metadata_policy_init(&metadata);metadata.scope=CKFSS_METADATA_ORDINARY_V1;
    ckfss_two_way_policy policy;ckfss_two_way_policy_init(&policy);ckfss_two_way* worker=nullptr;ckfss_error error{};
    TW_C_CHECK(ckfss_two_way_open(nullptr,&metadata,&policy,&worker,&error)==CKFSS_INVALID_ARGUMENT&&!worker);
    TW_C_CHECK(ckfss_two_way_open(&options,&metadata,&policy,&worker,&error)==CKFSS_OK&&worker);
    uint64_t supported=0,conditional=0;TW_C_CHECK(ckfss_two_way_get_capabilities(worker,&supported,&conditional)==CKFSS_OK);
    TW_C_CHECK((supported&CKFSS_CAP_OVERLAP_SESSION_LOCKS)&&(conditional&CKFSS_CAP_TWO_WAY_EXECUTION)&&!(conditional&CKFSS_CAP_DIRECTORY_TREE_RECEIPT));
    ckfss_session* competing=nullptr;TW_C_CHECK(ckfss_session_open_verified(&options,&metadata,&competing,&error)==CKFSS_UNAVAILABLE&&!competing);
    ckfss_two_way_info info{};TW_C_CHECK(ckfss_two_way_get_info(worker,&info)==CKFSS_OK&&info.rows==1&&info.state==CKFSS_TW_AWAITING_REVIEW);
    ckfss_two_way_row row{};uint64_t required=0;
    TW_C_CHECK(ckfss_two_way_get_row(worker,0,&row,nullptr,0,&required)==CKFSS_BUFFER_TOO_SMALL&&required&&row.proposed_action==CKFSS_TW_UNCHANGED);
    uint32_t encoding=99;TW_C_CHECK(ckfss_two_way_get_component(worker,0,0,&encoding,nullptr,0,&required)==CKFSS_BUFFER_TOO_SMALL&&encoding==CKFSS_POSIX_BYTES);
    std::string exact(static_cast<std::size_t>(required),'\0');TW_C_CHECK(ckfss_two_way_get_component(worker,0,0,&encoding,exact.data(),exact.size(),&required)==CKFSS_OK&&exact=="native:exact\\name");
    ckfss_two_way_decision decision{0,CKFSS_TW_PROPOSAL,0};TW_C_CHECK(ckfss_two_way_approve(worker,&decision,1,0,&error)==CKFSS_UNAVAILABLE);
    decision.row_index=1;TW_C_CHECK(ckfss_two_way_approve(worker,&decision,1,1,&error)==CKFSS_INVALID_ARGUMENT);decision.row_index=0;
    TW_C_CHECK(ckfss_two_way_approve(worker,&decision,1,1,&error)==CKFSS_OK);
    for(unsigned n=0;n<32&&info.state!=CKFSS_TW_COMPLETE;++n)TW_C_CHECK(ckfss_two_way_advance(worker,&info,&error)==CKFSS_OK);
    TW_C_CHECK(info.state==CKFSS_TW_COMPLETE&&info.generation==1&&info.completed_operations==0);ckfss_two_way_destroy(worker);worker=nullptr;
    // The companion shares the verified C-session metadata policy binding.
    ckfss_session* session=nullptr;TW_C_CHECK(ckfss_session_open_verified(&options,&metadata,&session,&error)==CKFSS_OK);
    ckfss_snapshot snapshot{};TW_C_CHECK(ckfss_session_get_snapshot(session,&snapshot)==CKFSS_OK&&snapshot.state==CKFSS_READY&&snapshot.generation==1);
    ckfss_receipt* forbidden=nullptr;
    TW_C_CHECK(ckfss_session_verify_exact_paths(session,nullptr,0,&metadata,&forbidden,&error)==CKFSS_UNAVAILABLE&&!forbidden);
    TW_C_CHECK(std::strcmp(error.operation,"sync_session.coordinator_managed_baseline")==0);
    TW_C_CHECK(ckfss_session_get_snapshot(session,&snapshot)==CKFSS_OK&&snapshot.generation==1);
    ckfss_session_destroy(session);
    ckfss_two_way_request_cancel(nullptr);ckfss_two_way_destroy(nullptr);
}
void recovery_changed_unchanged_row() {
    Fixture f;f.write("left/equal","native");f.write("right/equal","native");
    auto initial=take(NativeSyncCoordinator::open(f.request()));TW_C_CHECK(initial->approve(proposals(*initial),true).value());drain(*initial);TW_C_CHECK(initial->result().generation==1);initial.reset();
    auto request=f.request();request.before_event=[](auto event){return event!=NativeSyncCoordinatorEvent::BeforeBaselineCommit;};
    auto interrupted=take(NativeSyncCoordinator::open(std::move(request)));TW_C_CHECK(interrupted->approve(proposals(*interrupted)).value());drain(*interrupted);TW_C_CHECK(interrupted->result().state==NativeSyncCoordinatorState::NeedsReview);interrupted.reset();
    // A selected unchanged row still needs fresh convergence. Omitting it as
    // pending would reproduce the old baseline and falsely appear to verify it.
    f.remove("left/equal");f.remove("right/equal");f.write("left/equal","late");f.write("right/equal","late");
    auto recovery=NativeSyncCoordinator::open(f.request());TW_C_CHECK(!recovery.value());TW_C_CHECK(recovery.unavailable_detail()->error.operation=="native_sync.recovery_convergence_changed");
}
void protected_artifact_tests() {
    Fixture f;f.write("left/actual-retained","old");f.write("left/.ck-sync-retained-ordinary","ordinary");
    auto coordinator=take(NativeSyncCoordinator::open(f.request()));auto decisions=proposals(*coordinator);for(auto& d:decisions)d.choice=NativeSyncChoice::Skip;
    TW_C_CHECK(coordinator->approve(decisions,true).value());drain(*coordinator);TW_C_CHECK(coordinator->result().state==NativeSyncCoordinatorState::Complete);
    auto identity=coordinator->identity();coordinator.reset();
    // Internal trusted-store fixture for a modeled completed retention. Public
    // legacy C receipts must NOT advance an adopted coordinator baseline.
    auto backend=take(open_native_sync_session_backend(take(NativeAbsolutePath::from_posix(f.path("store"))),take(NativeAbsolutePath::from_posix(f.path("left"))),take(NativeAbsolutePath::from_posix(f.path("right")))));
    const auto request=f.request();
    auto trusted=take(SyncSession::open(std::move(backend),native_sync_policy_binding(request.application_policy,request.metadata)));TW_C_CHECK(trusted->snapshot().generation==1);
    TW_C_CHECK(trusted->commit(1,{}).value());trusted.reset();
    NativeFileSystem fs;auto root=std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(take(NativeAbsolutePath::from_posix(f.path("left"))))));
    NativeSyncProofBudget budget;auto proof=take(observe_native_sync_file(root,*NativeName::from_posix("actual-retained"),f.request().metadata,{},budget));
    auto parent=NativeDurableIdentity::from_live(*root->identity().value()),object=NativeDurableIdentity::from_live(*proof.metadata.basic.identity.value());TW_C_CHECK(parent&&object);
    NativeSyncLedgerEvidence evidence;evidence.session=identity;evidence.expected_generation=1;evidence.reviewed_plan=SyncDigest{};evidence.reviewed_plan[0]=std::byte(77);
    evidence.artifacts.push_back({false,proof.components,*parent,*object,proof.status});evidence.proposed_baseline=SyncBaseline{identity.policy,{}};
    auto planned=evidence;planned.proposed_baseline.reset();OperationJournalId id{};id.bytes[0]=std::byte(77);
    auto ledger=take(NativeSyncLedger::create(take(NativeAbsolutePath::from_posix(f.path("store"))),*NativeName::from_posix(".ck-sync-ledger-test-protected"),id,planned));
    TW_C_CHECK(ledger->append(OperationJournalState::Prepared,planned).value());
    for(auto state:{OperationJournalState::Copied,OperationJournalState::Verified,OperationJournalState::CommitIntended,OperationJournalState::DestinationCommitted,OperationJournalState::Complete})TW_C_CHECK(ledger->append(state,evidence).value());
    TW_C_CHECK(ledger->finish_io().value());ledger.reset();root.reset();
    coordinator=take(NativeSyncCoordinator::open(f.request()));TW_C_CHECK(coordinator->protected_artifacts().size()==1);
    TW_C_CHECK(coordinator->protected_artifacts()[0].artifact.components==proof.components);TW_C_CHECK(coordinator->rows().size()==1);
    TW_C_CHECK(*coordinator->components(0)[0].posix_bytes()==".ck-sync-retained-ordinary");coordinator.reset();
    // Restart observations grant no cleanup/rename authority. A moved retained
    // object needs review even though its held object and bytes remain intact.
    TW_C_CHECK(!rename(f.path("left/actual-retained").c_str(),f.path("left/moved-retained").c_str()));
    auto moved=NativeSyncCoordinator::open(f.request());TW_C_CHECK(!moved.value());TW_C_CHECK(moved.unavailable_detail()->error.operation=="native_sync.protected_artifact_changed");
}
ckfss_two_way* bulk_worker(Fixture& fixture) {
    const auto store=fixture.path("store"),left=fixture.path("left"),right=fixture.path("right");
    ckfss_options options;ckfss_options_init(&options);options.coordinator=c_path(store);options.left=c_path(left);options.right=c_path(right);
    ckfss_metadata_policy metadata;ckfss_metadata_policy_init(&metadata);metadata.scope=CKFSS_METADATA_ORDINARY_V1;
    ckfss_two_way_policy policy;ckfss_two_way_policy_init(&policy);ckfss_two_way* worker=nullptr;ckfss_error error{};
    const auto result=ckfss_two_way_open(&options,&metadata,&policy,&worker,&error);
    if(result!=CKFSS_OK)std::fprintf(stderr,"bulk open: %s\n",error.operation);
    TW_C_CHECK(result==CKFSS_OK&&worker);return worker;
}
ckfss_two_way_review* bulk_assess(ckfss_two_way* worker,std::span<const ckfss_two_way_rule> rules,std::uint64_t quantum=1) {
    ckfss_two_way_review* review=nullptr;ckfss_error error{};
    const auto result=ckfss_two_way_assess_rules(worker,rules.data(),rules.size(),quantum,&review,&error);
    if(result!=CKFSS_OK)std::fprintf(stderr,"bulk assess: %s\n",error.operation);
    TW_C_CHECK(result==CKFSS_OK&&review);return review;
}
ckfss_two_way_rule_result bulk_result(ckfss_two_way_review* review,std::uint64_t index=0) {
    ckfss_two_way_rule_result result{};TW_C_CHECK(ckfss_two_way_review_get_row(review,index,&result)==CKFSS_OK);return result;
}
void bulk_rule_tests() {
    Fixture f;f.write("left/a","incoming");f.write("right/a","existing");
    timespec times[2]{{2000000000,0},{2000000000,0}};TW_C_CHECK(!utimensat(AT_FDCWD,f.path("left/a").c_str(),times,AT_SYMLINK_NOFOLLOW));
    auto* worker=bulk_worker(f);ckfss_two_way_raw_facts facts{};ckfss_error error{};
    TW_C_CHECK(ckfss_two_way_get_facts(worker,0,&facts,&error)==CKFSS_OK);
    TW_C_CHECK(facts.left.size==8&&facts.right.size==8&&facts.left.modified_seconds==2000000000&&facts.right.modified_seconds==1000000000);
    TW_C_CHECK(facts.left.known_fields&(CKFSS_FACT_SIZE|CKFSS_FACT_MODIFIED));TW_C_CHECK(!facts.left_retention_available&&!facts.right_retention_available);
    ckfss_two_way_rule rule;ckfss_two_way_rule_init(&rule);rule.choice=CKFSS_RULE_NEWEST;rule.direction=CKFSS_DIRECTION_LEFT_TO_RIGHT;
    auto* newest=bulk_assess(worker,std::span(&rule,1));auto result=bulk_result(newest);
    TW_C_CHECK(result.choice==CKFSS_RULE_KEEP_LEFT&&result.state==CKFSS_DECISION_REVIEW&&result.reason==CKFSS_RULE_REASON_RETENTION_UNAVAILABLE);
    TW_C_CHECK(ckfss_two_way_approve_review(worker,newest,1,&error)==CKFSS_UNAVAILABLE);
    rule.direction=CKFSS_DIRECTION_RIGHT_TO_LEFT;auto* reversed=bulk_assess(worker,std::span(&rule,1));result=bulk_result(reversed);
    TW_C_CHECK(result.choice==CKFSS_RULE_KEEP_LEFT&&result.reason==CKFSS_RULE_REASON_RETENTION_UNAVAILABLE);
    ckfss_two_way_review_destroy(newest);ckfss_two_way_review_destroy(reversed);
    rule.direction=CKFSS_DIRECTION_SOURCE_TO_TARGET;rule.choice=CKFSS_RULE_USE_SOURCE;
    auto* source=bulk_assess(worker,std::span(&rule,1));result=bulk_result(source);
    TW_C_CHECK(result.choice==CKFSS_RULE_USE_SOURCE&&result.reason==CKFSS_RULE_REASON_RETENTION_UNAVAILABLE);ckfss_two_way_review_destroy(source);
    rule.choice=CKFSS_RULE_KEEP_BOTH_INCOMING;auto* both=bulk_assess(worker,std::span(&rule,1));result=bulk_result(both);
    TW_C_CHECK(result.state==CKFSS_DECISION_REVIEW&&result.reason==CKFSS_RULE_REASON_SEPARATE_POLICY);ckfss_two_way_review_destroy(both);
    rule.choice=CKFSS_RULE_KEEP_TARGET;auto* keep=bulk_assess(worker,std::span(&rule,1));result=bulk_result(keep);
    TW_C_CHECK(result.state==CKFSS_DECISION_APPLY&&result.selected_choice==CKFSS_TW_SKIP);
    auto malformed=rule;malformed.scope=999;ckfss_two_way_review* bad=nullptr;
    TW_C_CHECK(ckfss_two_way_assess_rules(worker,&malformed,1,1,&bad,&error)==CKFSS_INVALID_ARGUMENT&&!bad);
    TW_C_CHECK(ckfss_two_way_approve_review(worker,keep,1,&error)==CKFSS_UNAVAILABLE);ckfss_two_way_review_destroy(keep);
    auto stale_generation=rule;stale_generation.expected_generation=1;
    TW_C_CHECK(ckfss_two_way_assess_rules(worker,&stale_generation,1,1,&bad,&error)==CKFSS_UNAVAILABLE&&!bad&&error.code==static_cast<int64_t>(AdapterError::PlanDecisionStale));
    keep=bulk_assess(worker,std::span(&rule,1));
    auto conflict=rule;conflict.choice=CKFSS_RULE_ASK;ckfss_two_way_rule contradictory[]{rule,conflict};
    auto* rejected=bulk_assess(worker,contradictory);result=bulk_result(rejected);TW_C_CHECK(result.state==CKFSS_DECISION_INVALID&&result.reason==CKFSS_RULE_REASON_CONTRADICTORY);
    TW_C_CHECK(ckfss_two_way_approve_review(worker,keep,1,&error)==CKFSS_UNAVAILABLE);ckfss_two_way_review_destroy(keep);ckfss_two_way_review_destroy(rejected);
    // Selected-item skip wins over the broader Newest policy IN THE ENGINE.
    uint64_t selected=0;auto item=rule;item.choice=CKFSS_RULE_SKIP;item.scope=CKFSS_SCOPE_ITEM;item.selected_rows=&selected;item.selected_count=1;
    auto job=rule;job.choice=CKFSS_RULE_NEWEST;ckfss_two_way_rule priority[]{job,item};
    keep=bulk_assess(worker,priority);result=bulk_result(keep);TW_C_CHECK(result.state==CKFSS_DECISION_APPLY&&result.choice==CKFSS_RULE_SKIP&&result.rule_index==1);
    // Another worker cannot use the receipt, even for the same pair/generation.
    ckfss_two_way_destroy(worker);worker=bulk_worker(f);TW_C_CHECK(ckfss_two_way_approve_review(worker,keep,1,&error)==CKFSS_UNAVAILABLE);ckfss_two_way_review_destroy(keep);
    keep=bulk_assess(worker,std::span(&rule,1));TW_C_CHECK(ckfss_two_way_approve_review(worker,keep,0,&error)==CKFSS_UNAVAILABLE);
    TW_C_CHECK(ckfss_two_way_approve_review(worker,keep,1,&error)==CKFSS_OK);
    TW_C_CHECK(ckfss_two_way_approve_review(worker,keep,1,&error)==CKFSS_UNAVAILABLE);
    ckfss_two_way_info info{};TW_C_CHECK(ckfss_two_way_get_info(worker,&info)==CKFSS_OK);
    for(unsigned n=0;n<32&&info.state!=CKFSS_TW_COMPLETE;++n)TW_C_CHECK(ckfss_two_way_advance(worker,&info,&error)==CKFSS_OK);
    TW_C_CHECK(info.state==CKFSS_TW_COMPLETE&&info.generation==1&&info.pending_rows==1&&!info.completed_operations);
    ckfss_two_way_review_destroy(keep);ckfss_two_way_destroy(worker);
    // Zero-length protection survives assessment before retention qualification.
    Fixture zero;zero.write("left/a","");zero.write("right/a","nonempty");worker=bulk_worker(zero);rule.choice=CKFSS_RULE_USE_SOURCE;
    auto* protected_zero=bulk_assess(worker,std::span(&rule,1));result=bulk_result(protected_zero);
    TW_C_CHECK(result.state==CKFSS_DECISION_REVIEW&&result.reason==CKFSS_RULE_REASON_ZERO_LENGTH);ckfss_two_way_review_destroy(protected_zero);
    ckfss_two_way_request_cancel(worker);ckfss_two_way_review* cancelled=nullptr;TW_C_CHECK(ckfss_two_way_assess_rules(worker,&rule,1,1,&cancelled,&error)==CKFSS_UNAVAILABLE&&!cancelled);
    ckfss_two_way_destroy(worker);
    // Equal-time tie fallback is the common engine's explicit target/skip rule.
    Fixture equal;equal.write("left/a","one");equal.write("right/a","two");worker=bulk_worker(equal);
    rule.choice=CKFSS_RULE_NEWEST;rule.tie=CKFSS_RULE_KEEP_TARGET;auto* tie=bulk_assess(worker,std::span(&rule,1));result=bulk_result(tie);
    TW_C_CHECK(result.state==CKFSS_DECISION_APPLY&&result.used_fallback&&result.choice==CKFSS_RULE_KEEP_TARGET);
    ckfss_two_way_review_destroy(tie);ckfss_two_way_destroy(worker);
    Fixture absent;absent.write("left/a","same");absent.write("right/a","same");worker=bulk_worker(absent);
    auto* native_default=bulk_assess(worker,{});TW_C_CHECK(ckfss_two_way_approve_review(worker,native_default,1,&error)==CKFSS_OK);
    TW_C_CHECK(ckfss_two_way_get_info(worker,&info)==CKFSS_OK);
    for(unsigned n=0;n<32&&info.state!=CKFSS_TW_COMPLETE;++n)TW_C_CHECK(ckfss_two_way_advance(worker,&info,&error)==CKFSS_OK);
    TW_C_CHECK(info.state==CKFSS_TW_COMPLETE&&info.generation==1);ckfss_two_way_review_destroy(native_default);ckfss_two_way_destroy(worker);
    absent.remove("left/a");absent.remove("right/a");worker=bulk_worker(absent);
    TW_C_CHECK(ckfss_two_way_get_facts(worker,0,&facts,&error)==CKFSS_OK&&facts.left.status.presence==CKFSS_ABSENT&&facts.right.status.presence==CKFSS_ABSENT);
    native_default=bulk_assess(worker,{});TW_C_CHECK(ckfss_two_way_approve_review(worker,native_default,0,&error)==CKFSS_OK);
    TW_C_CHECK(ckfss_two_way_get_info(worker,&info)==CKFSS_OK);
    for(unsigned n=0;n<32&&info.state!=CKFSS_TW_COMPLETE;++n)TW_C_CHECK(ckfss_two_way_advance(worker,&info,&error)==CKFSS_OK);
    TW_C_CHECK(info.state==CKFSS_TW_COMPLETE&&info.generation==2);ckfss_two_way_review_destroy(native_default);ckfss_two_way_destroy(worker);
}

#undef TW_C_CHECK
}
#endif
namespace {
void coordinator_tests() {
    session_coordinator_codec::codec_tests();session_coordinator_codec::fault_tests();
    checks+=static_cast<unsigned>(session_coordinator_codec::checks);
#ifndef _WIN32
    session_coordinator_native::inventory_owner_tests();session_coordinator_native::held_storage_tests();session_coordinator_native::c_held_storage_tests();session_coordinator_native::c_two_way_held_storage_tests();session_coordinator_native::c_root_consumer_failure_tests();
    session_coordinator_native::baseline_native();session_coordinator_native::mixed_native();
    session_coordinator_native::skip_and_cancel();session_coordinator_native::recovery_native();
    session_coordinator_native::c_worker_tests();session_coordinator_native::protected_artifact_tests();
    session_coordinator_native::recovery_changed_unchanged_row();session_coordinator_native::bulk_rule_tests();
    checks+=static_cast<unsigned>(session_coordinator_native::checks);
#endif
}
}
