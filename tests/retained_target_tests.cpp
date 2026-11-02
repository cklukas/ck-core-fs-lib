// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "retained_target.hpp"
#include "native_filesystem.hpp"
#include <cassert>
#include <cstring>
#include <map>
#include <functional>
#include <cstdio>
#include <cstdlib>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

using namespace ck::files;
namespace {
NativeName name(const char* p) { return *NativeName::from_posix(p); }
ObjectIdentity id(const AdapterScope& s, unsigned n) {
    ObjectIdentity r; r.scope=s; r.scheme=IdentityScheme::PosixDeviceInode;
    r.volume=NativeIdentifier::from_u64(1); r.object=NativeIdentifier::from_u64(n); return r;
}
struct Node {
    BasicMetadata metadata; std::vector<std::byte> data;
    bool writable_mapping = false, stable = true, proof_false = false;
    unsigned rename_guards = 0, reads = 0;
    std::function<void()> after_read;
};
class Directory;
class Entry final: public OpenedEntry {
public:
    Entry(std::shared_ptr<Node> n, NativeName source, bool rename, bool proof)
        :n_(std::move(n)),source_(std::move(source)),rename_(rename),proof_(proof) { if(rename_) ++n_->rename_guards; }
    ~Entry() override { if(rename_) --n_->rename_guards; }
    Observation<bool> qualify_stable_content() const override {
        if (!proof_ || !rename_) return OpenedEntry::qualify_stable_content();
        if (n_->proof_false) return Observation<bool>::available(false);
        if (n_->writable_mapping || !n_->stable) return Observation<bool>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"test.stable_guard_lost_or_mapped"});
        return Observation<bool>::available(true);
    }
    Observation<BasicMetadata> inspect_basic() const override { return Observation<BasicMetadata>::available(n_->metadata); }
    Observation<ContentRead> read_content(ContentReadLimits l,uint64_t offset,std::stop_token) const override {
        assert(offset<=n_->data.size()); const auto count=std::min(l.max_bytes,n_->data.size()-static_cast<size_t>(offset));
        ++n_->reads;
        ContentRead out{{n_->data.begin()+offset,n_->data.begin()+offset+count},offset+count==n_->data.size()};
        if (n_->after_read) n_->after_read();
        return Observation<ContentRead>::available(std::move(out));
    }
    Observation<bool> rename_noreplace(const DirectoryCursor&,const DirectoryCursor&,const NativeName&) const override;
    std::shared_ptr<Node> n_; NativeName source_; bool rename_, proof_;
};
class Directory final: public DirectoryCursor {
public:
    static const AdapterScope& scope() { static AdapterScope s; return s; }
    Directory():DirectoryCursor(Observation<ObjectIdentity>::available(id(scope(),1))) {}
    mutable std::map<NativeName,std::shared_ptr<Node>,NativeNameLess> nodes;
    mutable unsigned renames=0; bool capable=true, stable_capable=true;
    mutable std::function<void()> on_guard_open;
    Observation<BasicMetadata> inspect_basic() const override {
        BasicMetadata out; out.identity = identity(); out.kind = Observation<ObjectKind>::available(ObjectKind::Directory);
        return Observation<BasicMetadata>::available(std::move(out));
    }
    Observation<bool> attempt_move(const NativeName& source, const NativeName& destination) const {
        auto found = nodes.find(source);
        if (found == nodes.end()) return Observation<bool>::unavailable(ObservationState::Gone);
        if (found->second->rename_guards) return Observation<bool>::unavailable(ObservationState::Denied);
        if (nodes.contains(destination)) return Observation<bool>::unavailable(ObservationState::Changed);
        auto held = found->second; nodes.erase(found); nodes.emplace(destination, std::move(held));
        return Observation<bool>::available(true);
    }
    std::shared_ptr<Node> add(const char* text,unsigned inode=2) {
        auto n=std::make_shared<Node>(); n->metadata.identity=Observation<ObjectIdentity>::available(id(scope(),inode));
        n->metadata.kind=Observation<ObjectKind>::available(ObjectKind::RegularFile);
        n->metadata.logical_size=Observation<uint64_t>::available(8); n->metadata.link_count=Observation<uint64_t>::available(1);
        n->metadata.modified=n->metadata.changed=Observation<FileTimestamp>::available(*FileTimestamp::from_unix(1,0));
        n->data.assign(8,std::byte(inode)); nodes[name(text)]=n; return n;
    }
    Observation<bool> qualify_identity_bound_rename() const override {
        return capable ? Observation<bool>::available(true) : Observation<bool>::unavailable(ObservationState::Unsupported);
    }
    Observation<std::unique_ptr<OpenedEntry>> open_child(const NativeName& n,EntryAccess access) const override {
        auto p=nodes.find(n); if(p==nodes.end()) return Observation<std::unique_ptr<OpenedEntry>>::unavailable(ObservationState::Gone);
        auto opened = std::make_unique<Entry>(p->second,n,requests_rename_source(access),stable_capable);
        if (requests_rename_source(access) && on_guard_open) { auto callback = std::move(on_guard_open); callback(); }
        return Observation<std::unique_ptr<OpenedEntry>>::available(std::move(opened));
    }
private: Observation<DirectoryStep> next_step() override { return Observation<DirectoryStep>::available(DirectoryEnd{}); }
};
Observation<bool> Entry::rename_noreplace(const DirectoryCursor& from,const DirectoryCursor& to,const NativeName& n) const {
    assert(rename_); auto& d=dynamic_cast<const Directory&>(from); assert(&from==&to);
    if(d.nodes.contains(n)) return Observation<bool>::unavailable(ObservationState::Changed);
    const auto p=d.nodes.find(source_);
    if (p!=d.nodes.end() && p->second==n_) {
        auto held=p->second; d.nodes.erase(p); d.nodes.emplace(n,std::move(held)); ++d.renames;
        return Observation<bool>::available(true);
    }
    return Observation<bool>::unavailable(ObservationState::Changed);
}
struct Bytes { std::vector<std::byte> live,durable; unsigned flushes=0,fail_at=0; bool close_fails=false; unsigned finishes=0; std::function<void(unsigned)> on_flush; };
class Journal final: public OperationJournalFile {
    std::shared_ptr<Bytes> b_;
public:
    explicit Journal(std::shared_ptr<Bytes> b):b_(std::move(b)) {}
    Observation<uint64_t> size() override { return Observation<uint64_t>::available(b_->live.size()); }
    Observation<size_t> read_at(uint64_t,std::span<std::byte>) override { return Observation<size_t>::unavailable(ObservationState::Unsupported); }
    Observation<size_t> write_at(uint64_t offset,std::span<const std::byte> bytes) override {
        b_->live.resize(offset+bytes.size()); std::memcpy(b_->live.data()+offset,bytes.data(),bytes.size());
        return Observation<size_t>::available(bytes.size());
    }
    Observation<bool> flush() override {
        if(++b_->flushes==b_->fail_at) return Observation<bool>::unavailable(ObservationState::Failed,{ErrorDomain::Posix,5,"test.flush"});
        b_->durable=b_->live; if(b_->on_flush) b_->on_flush(b_->flushes); return Observation<bool>::available(true);
    }
    Observation<bool> finish_io() override {
        ++b_->finishes;
        if (b_->close_fails) return Observation<bool>::unavailable(ObservationState::Failed,{ErrorDomain::Posix,5,"test.retention_close"});
        return flush();
    }
};
struct Fixture {
    std::shared_ptr<Directory> directory=std::make_shared<Directory>();
    std::shared_ptr<Node> original=directory->add("target");
    std::shared_ptr<Bytes> bytes=std::make_shared<Bytes>();
    HeldChild::Pointer target;
    NativeAbsolutePath root;
    std::function<void()> on_ancestry;
    explicit Fixture(NativeAbsolutePath r):root(std::move(r)) { target=*HeldChild::observe(directory,name("target")).value(); }
    Observation<RetainedTarget::Pointer> create(bool ancestor=true,bool wrong_digest=false) {
        Sha256 hash; hash.update(original->data); auto digest=hash.digest(); if(wrong_digest) digest[0]^=std::byte{1};
        OperationJournalId jid{}; jid.bytes[0]=std::byte{1};
        RetainedTargetRequest r{target,name("version"),digest,root,jid,{},[this,ancestor]{if(on_ancestry) on_ancestry(); return Observation<bool>::available(ancestor);}};
        r.chunk_bytes=3; r.open_journal=[b=bytes](const auto&,const auto&,bool) {
            return Observation<std::unique_ptr<OperationJournalFile>>::available(std::make_unique<Journal>(b));
        };
        return RetainedTarget::create(std::move(r));
    }
};
void verify(RetainedTarget& t) { while(t.state()==RetainedTargetState::Verifying) t.advance(); }
NativeName native_name(const char* text) {
#ifdef _WIN32
    std::u16string units; for (const unsigned char c : std::string(text)) units.push_back(c);
    return *NativeName::from_windows(std::move(units));
#else
    return name(text);
#endif
}
#ifdef _WIN32
std::wstring extended(const std::filesystem::path& path) {
    auto units=path.native();
    if (units.starts_with(L"\\\\?\\")) return units;
    if (units.starts_with(L"\\\\")) return L"\\\\?\\UNC\\"+units.substr(2);
    assert(units.size()>2 && units[1]==L':' && units[2]==L'\\');
    return L"\\\\?\\"+units;
}
#endif
struct NativeFixture {
    NativeFileSystem filesystem;
    NativeAbsolutePath root, source_address, former_address, retained_address;
    NativeName source, former, retained;
    std::shared_ptr<const DirectoryCursor> directory;
    unsigned journals=0;
    explicit NativeFixture(const NativeAbsolutePath& r,const char* suffix)
        :root(r),source_address(*r.child_address(native_name((std::string("native-source-")+suffix).c_str())).value()),
         former_address(*r.child_address(native_name((std::string("native-former-")+suffix).c_str())).value()),
         retained_address(*r.child_address(native_name((std::string("native-retained-")+suffix).c_str())).value()),
         source(native_name((std::string("native-source-")+suffix).c_str())),
         former(native_name((std::string("native-former-")+suffix).c_str())),
         retained(native_name((std::string("native-retained-")+suffix).c_str())) {
        auto opened=filesystem.open_native_directory(root); assert(opened.value());
        directory=std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
        create_source(std::byte{0x2a});
    }
    void create_source(std::byte value) {
        auto created=directory->create_child_file(source); assert(created.value());
        std::array<std::byte,8> bytes; bytes.fill(value);
        auto written=(*created.value())->write_content(0,bytes); assert(written.value() && *written.value()==bytes.size());
        auto flushed=(*created.value())->flush_content(); assert(flushed.value() && *flushed.value());
    }
    ~NativeFixture() {
        directory.reset();
        for(const auto* address:{&source_address,&former_address,&retained_address}) {
            const auto path=address->host_path(); assert(path.value());
#ifdef _WIN32
            DeleteFileW(extended(*path.value()).c_str());
#else
            ::unlink(path.value()->c_str());
#endif
        }
    }
    HeldChild::Pointer observe_source() const {
        auto observed=HeldChild::observe(directory,source); assert(observed.value()); return *observed.value();
    }
    Observation<RetainedTarget::Pointer> create(const HeldChild::Pointer& target,unsigned marker) {
        std::array<std::byte,8> bytes; bytes.fill(std::byte{0x2a}); Sha256 hash; hash.update(bytes);
        OperationJournalId jid{}; jid.bytes[0]=std::byte(marker);
        RetainedTargetRequest r{target,retained,hash.digest(),root,jid,root,[]{return Observation<bool>::available(true);}};
        r.chunk_bytes=3;
        r.open_journal=[this](const auto& journal_root,const auto& component,bool fresh) {
            ++journals; return open_native_operation_journal_file(journal_root,component,fresh);
        };
        return RetainedTarget::create(std::move(r));
    }
    bool move_source() const {
        const auto from=source_address.host_path(), to=former_address.host_path(); assert(from.value() && to.value());
#ifdef _WIN32
        return MoveFileExW(extended(*from.value()).c_str(),extended(*to.value()).c_str(),0)!=0;
#else
        return ::rename(from.value()->c_str(),to.value()->c_str())==0;
#endif
    }
    bool retained_missing() const {
        auto lookup=directory->lookup_child(retained,ChildLookupMode::NativeDefault);
        return lookup.value() && lookup.value()->state()==ChildLookupState::Missing;
    }
};
// Keep a writable shared mapping alive after its write handle has closed. A
// share-only guard cannot revoke this view and must not qualify retention.
void native_writable_mapping(const NativeAbsolutePath& root) {
    NativeFixture f(root,"mapping"); auto target=f.observe_source();
    const auto path=f.source_address.host_path(); assert(path.value());
#ifdef _WIN32
    HANDLE file=CreateFileW(extended(*path.value()).c_str(),GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    assert(file!=INVALID_HANDLE_VALUE);
    HANDLE mapping=CreateFileMappingW(file,nullptr,PAGE_READWRITE,0,0,nullptr); assert(mapping);
    void* view=MapViewOfFile(mapping,FILE_MAP_WRITE,0,0,8); assert(view);
    assert(CloseHandle(file));
#else
    int descriptor=::open(path.value()->c_str(),O_RDWR|O_NOFOLLOW|O_CLOEXEC); assert(descriptor>=0);
    void* view=::mmap(nullptr,8,PROT_READ|PROT_WRITE,MAP_SHARED,descriptor,0); assert(view!=MAP_FAILED);
    assert(::close(descriptor)==0);
#endif
    const auto made=f.create(target,91);
    assert(!made.value());
    assert(made.state()==ObservationState::Unsupported || made.state()==ObservationState::Denied);
    assert(!f.journals && f.retained_missing());
    static_cast<std::byte*>(view)[0]=std::byte{0x5b}; // view still has actual write authority
#ifdef _WIN32
    assert(FlushViewOfFile(view,8)); assert(UnmapViewOfFile(view)); assert(CloseHandle(mapping));
#else
    assert(::msync(view,8,MS_SYNC)==0); assert(::munmap(view,8)==0);
#endif
}
void native_former_name(const NativeAbsolutePath& root) {
    NativeFixture f(root,"former"); auto original=f.observe_source();
    assert(f.move_source()); f.create_source(std::byte{0x63});
    auto replacement=f.observe_source();
    assert(compare_identity(*original->metadata().identity.value(),*replacement->metadata().identity.value())==IdentityComparison::Different);
    const auto made=f.create(original,92);
    assert(!made.value());
    assert(made.state()==ObservationState::Unsupported || made.state()==ObservationState::Denied || made.state()==ObservationState::Changed);
    assert(!f.journals && f.retained_missing());
    auto old=HeldChild::observe(f.directory,f.former); assert(old.value());
    assert(compare_identity(*original->metadata().identity.value(),*(*old.value())->metadata().identity.value())==IdentityComparison::Same);
}
void native_namespace_guard(const NativeAbsolutePath& root) {
    NativeFixture f(root,"namespace");
    auto guard=HeldChild::observe_with_access(f.directory,f.source,EntryAccess::ContentRead|EntryAccess::RenameSource);
#ifdef _WIN32
    assert(guard.value());
    // The same owning DELETE handle will perform any eventual rename; other
    // DELETE opens must be refused even while stable-content proof is absent.
    assert(!f.move_source());
    const auto stable=(*guard.value())->qualify_stable_content();
    if (!stable.value()) assert(stable.state()==ObservationState::Unsupported);
    auto owner=std::move(guard).take_value(); owner.reset();
    assert(f.move_source());
#else
    assert(!guard.value() && guard.state()==ObservationState::Unsupported);
    assert(f.move_source());
#endif
    assert(f.retained_missing());
}

}
int main(int argc,char** argv) {
    assert(argc==2); auto parsed=NativeAbsolutePath::from_host(std::filesystem::path(argv[1])); assert(parsed.value()); const auto root=*parsed.value();
#ifdef __APPLE__
    assert(root.posix_bytes() && (root.posix_bytes()->starts_with("/Volumes/S8T/tmp/") || root.posix_bytes()->starts_with("/Volumes/PRO-BLADE/tmp/")));
#endif
#ifdef _WIN32
    if (const auto* require_v=std::getenv("CK_FS_REQUIRE_V_DEV_DRIVE"); require_v && std::string(require_v)=="1") {
        assert(GetFileAttributesW(L"V:\\")!=INVALID_FILE_ATTRIBUTES);
        auto units=*root.windows_units();
        assert(units.starts_with(u"V:\\tmp\\") || units.starts_with(u"\\\\?\\V:\\tmp\\"));
    }
#endif
    {
        Fixture f(root); auto made=f.create(); assert(made.value()); auto t=*made.value(); verify(*t);
        assert(t->state()==RetainedTargetState::Ready && f.directory->renames==0);
        assert(t->retain().value() && t->state()==RetainedTargetState::Retained);
        assert(!f.directory->nodes.contains(name("target")) && f.directory->nodes.at(name("version"))==f.original);
        assert(t->retain().value() && f.directory->renames==1);
        auto journal=decode_operation_journal(f.bytes->durable); assert(journal.value());
        assert(journal.value()->journal->state(0)==OperationJournalState::Complete);
    }
    for(unsigned fail=1;fail<=7;++fail) {
        Fixture f(root); f.bytes->fail_at=fail; auto made=f.create();
        if(fail==1) { assert(!made.value() && f.directory->renames==0); continue; }
        assert(made.value()); auto t=*made.value(); verify(*t);
        if(fail==2) { assert(t->state()==RetainedTargetState::NeedsReconciliation && f.directory->renames==0); continue; }
        assert(!t->retain().value());
        assert(t->state()==RetainedTargetState::NeedsReconciliation);
        assert(f.directory->renames==(fail>=4 ? 1u:0u));
        assert(f.directory->nodes.at(name(fail>=4 ? "version":"target"))==f.original);
    }
    {
        Fixture f(root); f.directory->capable=false; assert(f.create().state()==ObservationState::Unsupported); assert(!f.bytes->flushes);
    }
    {
        Fixture f(root); auto t=*f.create(true,true).value(); verify(*t); assert(t->state()==RetainedTargetState::Failed && !f.directory->renames);
    }
    {
        Fixture f(root); auto t=*f.create(false).value(); verify(*t); assert(!t->retain().value() && !f.directory->renames);
    }
    {
        Fixture f(root); auto t=*f.create().value(); verify(*t); auto replacement=f.directory->add("target",3);
        assert(!t->retain().value() && !f.directory->renames && f.directory->nodes.at(name("target"))==replacement);
    }
    {
        Fixture f(root); auto t=*f.create().value(); std::stop_source stop; stop.request_stop();
        assert(t->advance(stop.get_token())==RetainedTargetState::Cancelled && !f.directory->renames);
    }
    {
        Fixture f(root); f.directory->stable_capable=false;
        assert(f.create().state()==ObservationState::Unsupported);
        assert(!f.original->reads && !f.bytes->flushes && !f.directory->renames);
    }
    {
        Fixture f(root); f.original->proof_false=true;
        assert(f.create().state()==ObservationState::Unsupported);
        assert(!f.original->reads && !f.bytes->flushes);
    }
    {
        Fixture f(root); f.original->writable_mapping=true;
        assert(f.create().state()==ObservationState::Unsupported);
        assert(!f.original->reads && !f.bytes->flushes && !f.directory->renames);
    }
    {
        Fixture f(root);
        f.directory->on_guard_open=[&] {
            auto old=f.directory->nodes.extract(name("target")); old.key()=name("former"); f.directory->nodes.insert(std::move(old));
            f.directory->add("target",3);
        };
        assert(f.create().state()==ObservationState::Changed);
        assert(!f.original->reads && !f.bytes->flushes && !f.directory->renames);
        assert(f.directory->nodes.at(name("former"))==f.original);
    }
    {
        Fixture f(root); auto t=*f.create().value(); verify(*t);
        assert(f.directory->attempt_move(name("target"),name("former")).state()==ObservationState::Denied);
        assert(f.directory->nodes.at(name("target"))==f.original && !f.directory->nodes.contains(name("former")));
        assert(t->retain().value() && f.directory->renames==1);
    }
    {
        Fixture f(root); auto t=*f.create().value();
        f.original->after_read=[&] { f.original->writable_mapping=true; };
        verify(*t);
        assert(t->state()==RetainedTargetState::Failed && !f.directory->renames);
        assert(t->failure() && t->failure()->state==ObservationState::Unsupported);
        auto journal=decode_operation_journal(f.bytes->durable); assert(journal.value());
        assert(journal.value()->journal->state(0)==OperationJournalState::Failed);
    }
    {
        Fixture f(root); auto t=*f.create().value(); verify(*t);
        f.on_ancestry=[&] { f.original->stable=false; };
        assert(!t->retain().value() && t->state()==RetainedTargetState::Failed && !f.directory->renames);
    }
    {
        Fixture f(root); auto t=*f.create().value(); verify(*t);
        f.bytes->on_flush=[&](unsigned phase) { if(phase==3) f.original->stable=false; };
        assert(!t->retain().value() && !f.directory->renames && t->state()==RetainedTargetState::Failed);
        assert(f.directory->nodes.at(name("target"))==f.original);
    }
    {
        Fixture f(root); auto t=*f.create().value(); verify(*t);
        auto old=f.directory->nodes.extract(name("target")); old.key()=name("former"); f.directory->nodes.insert(std::move(old));
        assert(!t->retain().value() && !f.directory->renames);
        assert(f.directory->nodes.at(name("former"))==f.original && !f.directory->nodes.contains(name("version")));
    }

    {
        Fixture f(root); f.bytes->close_fails=true;
        auto t=*f.create().value(); verify(*t);
        assert(!t->retain().value() && t->state()==RetainedTargetState::NeedsReconciliation);
        assert(t->failure() && t->failure()->error.operation=="test.retention_close");
        assert(f.directory->renames==1 && !f.directory->nodes.contains(name("target")));
        assert(f.directory->nodes.at(name("version"))==f.original && f.bytes->finishes==1);
        assert(!t->retain().value() && f.bytes->finishes==1);
    }
    native_writable_mapping(root);
    native_former_name(root);
    native_namespace_guard(root);
    std::puts("retained_target: model guard/failure tests and native mapping/former-name regressions passed");

}
