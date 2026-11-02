// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_actions.h"
#include "native_handles.hpp"
#include "action_jobs.hpp"
#include "sha256.hpp"
#undef NDEBUG
#include <cassert>
#include <chrono>
#include <cstdio>
#include <condition_variable>
#include <atomic>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#endif
#include <cstring>
#include <map>
#include <mutex>
#include <thread>

using namespace ck::files;
namespace {
NativeName name(const char* s) { return *NativeName::from_posix(s); }
NativeName host_name(const std::string& s) {
#ifdef _WIN32
    return *NativeName::from_windows(std::u16string(s.begin(),s.end()));
#else
    return name(s.c_str());
#endif
}
ObjectIdentity make_id(const AdapterScope& scope,uint64_t n) {
    ObjectIdentity id; id.scope=scope; id.scheme=IdentityScheme::PosixDeviceInode;
    id.volume=NativeIdentifier::from_u64(1); id.object=NativeIdentifier::from_u64(n); return id;
}
struct Node { BasicMetadata metadata; std::vector<std::byte> bytes; };
class Entry final : public OpenedEntry {
    std::shared_ptr<Node> node_;
public:
    explicit Entry(std::shared_ptr<Node> n):node_(std::move(n)) {}
    Observation<BasicMetadata> inspect_basic() const override { return Observation<BasicMetadata>::available(node_->metadata); }
    Observation<ContentRead> read_content(ContentReadLimits l,uint64_t offset,std::stop_token) const override {
        if (offset>node_->bytes.size()) return Observation<ContentRead>::unavailable(ObservationState::Failed);
        const auto n=std::min(l.max_bytes,node_->bytes.size()-static_cast<size_t>(offset));
        return Observation<ContentRead>::available({{node_->bytes.begin()+static_cast<ptrdiff_t>(offset),
            node_->bytes.begin()+static_cast<ptrdiff_t>(offset+n)},offset+n==node_->bytes.size()});
    }
};
struct Block { std::mutex mutex; std::condition_variable cv; bool entered=false, release=false; };
class Directory final : public DirectoryCursor {
public:
    AdapterScope scope;
    mutable std::mutex mutex;
    mutable std::map<NativeName,std::shared_ptr<Node>,NativeNameLess> nodes;
    mutable uint64_t next=2;
    bool insensitive=false;
    std::shared_ptr<Block> block;
    Directory():DirectoryCursor(Observation<ObjectIdentity>::available(make_id(scope_for_parent(),1))),scope(scope_for_parent()) {}
    // One shared namespace is intentional for all fake native objects.
    static const AdapterScope& scope_for_parent() { static AdapterScope s; return s; }
    auto find(const NativeName& key) const {
        auto it=nodes.find(key);
        if (it!=nodes.end() || !insensitive) return it;
        auto lower=[](std::string s) { for(auto& c:s) if(c>='A'&&c<='Z') c=static_cast<char>(c+32); return s; };
        if (!key.posix_bytes()) return nodes.end();
        for(auto j=nodes.begin();j!=nodes.end();++j)
            if(j->first.posix_bytes()&&lower(*j->first.posix_bytes())==lower(*key.posix_bytes())) return j;
        return nodes.end();
    }
    std::shared_ptr<Node> add(const char* n,const char* content="payload") {
        std::lock_guard lock(mutex);
        auto node=std::make_shared<Node>();
        node->metadata.identity=Observation<ObjectIdentity>::available(make_id(scope,next++));
        node->metadata.kind=Observation<ObjectKind>::available(ObjectKind::RegularFile);
        node->metadata.link_count=Observation<uint64_t>::available(1);
        const auto* p=reinterpret_cast<const std::byte*>(content);
        node->bytes.assign(p,p+std::strlen(content));
        node->metadata.logical_size=Observation<uint64_t>::available(node->bytes.size());
        nodes.insert_or_assign(name(n),node); return node;
    }
    bool has(const char* n) const { std::lock_guard lock(mutex); return nodes.contains(name(n)); }
    Observation<bool> qualify_identity_bound_rename() const override { return Observation<bool>::available(true); }
    Observation<BasicMetadata> inspect_basic() const override {
        if (block) { std::unique_lock lock(block->mutex); block->entered=true; block->cv.notify_all();
            block->cv.wait(lock,[&]{return block->release;}); }
        BasicMetadata m; m.identity=identity(); m.kind=Observation<ObjectKind>::available(ObjectKind::Directory);
        return Observation<BasicMetadata>::available(std::move(m));
    }
    Observation<std::unique_ptr<OpenedEntry>> open_child(const NativeName& n,EntryAccess) const override {
        std::lock_guard lock(mutex); auto it=find(n);
        if(it==nodes.end()) return Observation<std::unique_ptr<OpenedEntry>>::unavailable(ObservationState::Gone,{ErrorDomain::Posix,2,"fake.open"});
        return Observation<std::unique_ptr<OpenedEntry>>::available(std::make_unique<Entry>(it->second));
    }
    Observation<ChildLookup> lookup_child(const NativeName& n,ChildLookupMode mode) const override {
        auto opened=open_child(n,EntryAccess::MetadataOnly);
        ChildLookupContext context{n,mode,identity()};
        return opened.value()?Observation<ChildLookup>::available(ChildLookup::found(std::move(context),std::move(opened).take_value())):
            Observation<ChildLookup>::available(ChildLookup::missing(std::move(context),{ErrorDomain::Posix,2,"fake.lookup"}));
    }
private:
    Observation<DirectoryStep> next_step() override { return Observation<DirectoryStep>::available(DirectoryEnd{}); }
};
class Boundary final : public ActionNativeBoundary {
public:
    mutable unsigned calls=0;
    unsigned fail_count=0;
    bool ambiguous=false, substitute=false, replace_on_failure=false, unknown_name_rules=false;
    bool source_bound_rename() const noexcept override { return true; }
    Observation<bool> distinct_targets(const HeldChild&,const NativeName& a,const NativeName& b) const override {
        if(unknown_name_rules) return Observation<bool>::unavailable(ObservationState::Unsupported);
        return Observation<bool>::available(a!=b);
    }
    Observation<bool> rename(const HeldChild& source,const NativeName& target,bool case_only) const override {
        auto* d=dynamic_cast<const Directory*>(source.parent().get()); assert(d);
        std::lock_guard lock(d->mutex); ++calls;
        if(calls<=fail_count) {
            if(replace_on_failure) {
                auto it=d->find(source.name()); assert(it!=d->nodes.end());
                auto replacement=std::make_shared<Node>(*it->second);
                replacement->metadata.identity=Observation<ObjectIdentity>::available(make_id(d->scope,999));
                it->second=std::move(replacement);
            }
            return Observation<bool>::unavailable(ObservationState::Unknown,
            {ErrorDomain::Win32,32,ambiguous?"rename_child_noreplace.directory_flush":"rename_child_noreplace.atomic_primitive"}); }
        auto it=d->find(source.name());
        if(it==d->nodes.end()) return Observation<bool>::unavailable(ObservationState::Changed);
        if(substitute) it->second->metadata.identity=Observation<ObjectIdentity>::available(make_id(d->scope,1000));
        if(compare_identity(*it->second->metadata.identity.value(),*source.metadata().identity.value())!=IdentityComparison::Same)
            return Observation<bool>::unavailable(ObservationState::Changed);
        auto occupied=d->find(target);
        if(occupied!=d->nodes.end()&&(!case_only||occupied!=it)) return Observation<bool>::unavailable(ObservationState::Changed);
        auto node=it->second; d->nodes.erase(it); d->nodes.emplace(target,std::move(node));
        return Observation<bool>::available(true);
    }
};
HeldChild::Pointer held(std::shared_ptr<Directory> d,const char* n) {
    auto result=HeldChild::observe(d,name(n)); assert(result.value()); return *result.value();
}
std::optional<NativeAbsolutePath> root;
unsigned journal_sequence=0;
ActionRequest rename_request(std::initializer_list<std::pair<HeldChild::Pointer,const char*>> rows) {
    ActionRequest r; r.journal_directory=root;
    r.journal_name=host_name("actions-"+std::to_string(++journal_sequence)+".journal");
    for(const auto& [s,n]:rows) r.items.push_back({s,name(n),false}); return r;
}
std::shared_ptr<ActionJob> start(ActionRequest r,std::shared_ptr<Boundary> b) {
    auto j=std::make_shared<ActionJob>(std::move(r),std::move(b)); j->start();
    for(unsigned i=0;i<20&&j->summary().state==CKFEA_PREVIEWING;++i) j->wait(1000);
    assert(j->summary().state==CKFEA_AWAITING_RECEIPT); return j;
}
ckfea_result item(const std::shared_ptr<ActionJob>& j,uint32_t n) { ckfea_result r{}; assert(j->item(n,r)==CKFEA_OK); return r; }
void execute(const std::shared_ptr<ActionJob>& j) {
    ckfea_receipt receipt{}; assert(j->receipt(receipt)==CKFEA_OK);
    assert(j->execute(receipt)==CKFEA_OK); assert(j->execute(receipt)==CKFEA_NOT_READY);
    for(unsigned i=0;i<20&&j->summary().state==CKFEA_RUNNING;++i) j->wait(1000);
    assert(j->summary().state==CKFEA_FINISHED);
}
template<class T> T output() { T out{}; out.version=CKFEA_VERSION; out.struct_size=sizeof(T); return out; }
ckfea_native_text text(const char* p) {
    ckfea_native_text t; ckfea_native_text_init(&t); t.data=p; t.byte_count=std::strlen(p); return t;
}
void wait_c(ckfea_job* j) {
    for(unsigned i=0;i<20;++i) { auto s=output<ckfea_summary>(); assert(ckfea_job_summary(j,&s)==CKFEA_OK);
        if(s.state!=CKFEA_PREVIEWING&&s.state!=CKFEA_RUNNING)return; ckfea_job_wait(j,1000); }
    assert(false);
}
void abi_tests() {
    auto d=std::make_shared<Directory>(); d->add("original");
    ckfe_entry entry{}; entry.child=held(d,"original"); ckfea_item i; ckfea_item_init(&i); i.source=&entry; i.destination_name=text("renamed");
    ckfea_request r; ckfea_request_init(&r); r.items=&i; r.item_count=1;
    ckfea_job* j=reinterpret_cast<ckfea_job*>(1);
    auto bad=r; ++bad.version; assert(ckfea_job_create(&bad,&j)==CKFEA_INVALID_ARGUMENT&&!j);
    bad=r; --bad.struct_size; assert(ckfea_job_create(&bad,&j)==CKFEA_INVALID_ARGUMENT&&!j);
    bad=r; bad.reserved[3]=1; assert(ckfea_job_create(&bad,&j)==CKFEA_INVALID_ARGUMENT&&!j);
    bad=r; bad.retry_limit=3; assert(ckfea_job_create(&bad,&j)==CKFEA_INVALID_ARGUMENT&&!j);
    bad=r; bad.item_count=CKFEA_MAX_ITEMS+1; assert(ckfea_job_create(&bad,&j)==CKFEA_INVALID_ARGUMENT&&!j);
    auto saved=i; i.flags=2; assert(ckfea_job_create(&r,&j)==CKFEA_INVALID_ARGUMENT&&!j); i=saved;
    i.destination_name=text("../bad"); assert(ckfea_job_create(&r,&j)==CKFEA_INVALID_ARGUMENT&&!j); i=saved;
    i.destination_name.reserved=1; assert(ckfea_job_create(&r,&j)==CKFEA_INVALID_ARGUMENT&&!j); i=saved;
    i.destination_name.encoding=CKFEA_WINDOWS_UTF16; i.destination_name.byte_count=3;
    assert(ckfea_job_create(&r,&j)==CKFEA_INVALID_ARGUMENT&&!j); i=saved;
    assert(ckfea_job_create(&r,&j)==CKFEA_OK); wait_c(j);
    auto summary=output<ckfea_summary>(); assert(ckfea_job_summary(j,&summary)==CKFEA_OK);
    auto result=output<ckfea_result>(); assert(ckfea_job_item(j,0,&result)==CKFEA_OK);
#ifndef _WIN32
    assert(result.state==CKFEA_UNSUPPORTED&&result.reason==CKFEA_REASON_SOURCE_NOT_BOUND);
#else
    assert(result.state==CKFEA_UNSUPPORTED&&result.reason==CKFEA_REASON_JOURNAL_REQUIRED);
#endif
    auto receipt=output<ckfea_receipt>(); assert(ckfea_job_receipt(j,&receipt)==CKFEA_OK);
    ++receipt.job_id; assert(ckfea_job_execute(j,&receipt)==CKFEA_STALE_RECEIPT); --receipt.job_id;
    receipt.reserved[0]=1; assert(ckfea_job_execute(j,&receipt)==CKFEA_INVALID_ARGUMENT); receipt.reserved[0]=0;
    assert(ckfea_job_execute(j,&receipt)==CKFEA_OK); wait_c(j);
    assert(d->has("original")&&!d->has("renamed"));
    auto evidence=output<ckfea_evidence>(); assert(ckfea_job_evidence(j,0,&evidence)==CKFEA_OK);
    assert(evidence.sequence==1&&evidence.result.source_identity.scheme!=0);
    summary.reserved=1; const auto copy=summary;
    assert(ckfea_job_summary(j,&summary)==CKFEA_INVALID_ARGUMENT&&std::memcmp(&copy,&summary,sizeof(copy))==0);
    result=output<ckfea_result>(); assert(ckfea_job_item(j,99,&result)==CKFEA_INVALID_ARGUMENT&&result.state==0);
    assert(ckfea_job_wait(j,1001)==CKFEA_INVALID_ARGUMENT); ckfea_job_destroy(j);
    for(auto op:{CKFEA_TRASH,CKFEA_RESTORE}) {
        i.destination_name={}; ckfea_native_text_init(&i.destination_name); r.operation=op;
        for(auto caps:{0u,op==CKFEA_TRASH?uint32_t(CKFEA_ALLOW_NATIVE_TRASH):uint32_t(CKFEA_ALLOW_NATIVE_RESTORE)}) {
            r.capabilities=caps;
            assert(ckfea_job_create(&r,&j)==CKFEA_OK); wait_c(j);
            result=output<ckfea_result>(); assert(ckfea_job_item(j,0,&result)==CKFEA_OK);
            assert(result.state==CKFEA_UNSUPPORTED);
            assert(result.reason==(caps?(op==CKFEA_TRASH?CKFEA_REASON_JOURNAL_REQUIRED:CKFEA_REASON_NATIVE_RECEIPT_UNAVAILABLE):CKFEA_REASON_CAPABILITY_REQUIRED));
            ckfea_job_destroy(j);
        }
    }
    assert(d->has("original"));
}
void rename_tests() {
    auto d=std::make_shared<Directory>(); auto a=d->add("a"); d->add("b");
    auto b=std::make_shared<Boundary>(); auto r=rename_request({{held(d,"a"),"b"},{held(d,"b"),"c"}});
    const auto journal_name=*r.journal_name;
    auto j=start(std::move(r),b); assert(item(j,0).state==CKFEA_READY&&item(j,1).state==CKFEA_READY);
    execute(j);
    if(item(j,0).state!=CKFEA_VERIFIED||item(j,1).state!=CKFEA_VERIFIED) {
        auto x=item(j,0); auto y=item(j,1);
        std::fprintf(stderr,"chain failed: states %u/%u errors %u:%lld/%u:%lld calls %u\n",x.state,y.state,x.error_domain,(long long)x.error_code,y.error_domain,(long long)y.error_code,b->calls);
    }
    assert(item(j,0).state==CKFEA_VERIFIED&&item(j,1).state==CKFEA_VERIFIED&&b->calls==2);
    assert(!d->has("a")&&d->has("b")&&d->has("c"));
    auto file=open_native_operation_journal_file(*root,journal_name,false); assert(file.value());
    auto loaded=load_operation_journal(**file.value()); assert(loaded.value()&&!loaded.value()->tail);
    assert(loaded.value()->journal->records().size()==14);
    auto inspection=inspect_native_operation_recovery_evidence(*loaded.value()->journal); assert(inspection.value());
    // A rename journal is evidence, never a content-verification replay token.
    assert(!inspection.value()->has_untrusted_evidence);
    d=std::make_shared<Directory>(); d->add("a"); d->add("b"); b=std::make_shared<Boundary>();
    j=start(rename_request({{held(d,"a"),"b"},{held(d,"b"),"a"}}),b);
    assert(item(j,0).state==CKFEA_CYCLE&&item(j,1).state==CKFEA_CYCLE); execute(j); assert(!b->calls);
    j=start(rename_request({{held(d,"a"),"x"},{held(d,"b"),"y"}}),b);
    assert(item(j,0).state==CKFEA_READY&&item(j,1).state==CKFEA_READY); j->cancel();
    b->unknown_name_rules=true;
    j=start(rename_request({{held(d,"a"),"x"},{held(d,"b"),"y"}}),b);
    assert(item(j,0).state==CKFEA_REVIEW_REQUIRED&&item(j,1).state==CKFEA_REVIEW_REQUIRED); execute(j); assert(!b->calls);
    b->unknown_name_rules=false;
    j=start(rename_request({{held(d,"a"),"c"},{held(d,"b"),"c"}}),b);
    assert(item(j,0).state==CKFEA_COLLISION&&item(j,1).state==CKFEA_COLLISION); execute(j); assert(!b->calls);
    j=start(rename_request({{held(d,"a"),"b"}}),b); assert(item(j,0).state==CKFEA_COLLISION); execute(j); assert(!b->calls);
    j=start(rename_request({{held(d,"a"),"a"}}),b); assert(item(j,0).state==CKFEA_NO_CHANGE); execute(j); assert(!b->calls);
    j=start(rename_request({{held(d,"a"),"z"}}),b); d->add("a"); execute(j); assert(item(j,0).state==CKFEA_CHANGED&&!b->calls);
    j=start(rename_request({{held(d,"a"),"z"}}),b); d->add("z"); execute(j); assert(item(j,0).state==CKFEA_COLLISION&&!b->calls);
    j=start(rename_request({{held(d,"a"),"x"}}),b); j->cancel();
    for(unsigned n=0;n<20&&j->summary().state!=CKFEA_CANCELLED;++n) std::this_thread::yield();
    ckfea_receipt receipt{}; assert(j->receipt(receipt)==CKFEA_NOT_READY);
    d=std::make_shared<Directory>(); d->insensitive=true; d->add("lower"); b=std::make_shared<Boundary>();
    r=rename_request({{held(d,"lower"),"LOWER"}}); r.items[0].case_only=true;
    j=start(std::move(r),b); assert(item(j,0).state==CKFEA_READY); execute(j);
    assert(item(j,0).state==CKFEA_VERIFIED&&d->has("LOWER")&&!d->has("lower"));
}
void exact_names_tests() {
    for(const auto& names:std::vector<std::pair<std::string,std::string>>{
        {std::string("raw-\xff",5),std::string("other-\xfe",7)},
        {"猫-ß","Копия-猫 (2)"}}) {
        auto d=std::make_shared<Directory>(); d->add(names.first.c_str());
        auto boundary=std::make_shared<Boundary>();
        auto j=start(rename_request({{held(d,names.first.c_str()),names.second.c_str()}}),boundary);
        assert(item(j,0).state==CKFEA_READY); execute(j);
        assert(item(j,0).state==CKFEA_VERIFIED&&!d->has(names.first.c_str())&&d->has(names.second.c_str()));
    }
    // Exact UTF-16 including unpaired surrogates is carried through the private
    // native boundary and journal codec on every test host, with no UTF-8 step.
    auto d=std::make_shared<Directory>(); auto node=d->add("temporary");
    auto source=*NativeName::from_windows(std::u16string{u's',char16_t(0xd800)});
    auto destination=*NativeName::from_windows(std::u16string{u't',char16_t(0xdc00)});
    { std::lock_guard lock(d->mutex); d->nodes.clear(); d->nodes.emplace(source,node); }
    auto h=HeldChild::observe(d,source); assert(h.value());
    auto r=rename_request({}); r.items.push_back({*h.value(),destination,false});
    auto j=start(std::move(r),std::make_shared<Boundary>()); assert(item(j,0).state==CKFEA_READY); execute(j);
    assert(item(j,0).state==CKFEA_VERIFIED);
    { std::lock_guard lock(d->mutex); assert(d->nodes.contains(destination)&&!d->nodes.contains(source)); }
    // KeepBoth chooses a new exact native name; the original target survives.
    d=std::make_shared<Directory>(); d->add("incoming"); auto original=d->add("target");
    j=start(rename_request({{held(d,"incoming"),"target (2)"}}),std::make_shared<Boundary>()); execute(j);
    assert(item(j,0).state==CKFEA_VERIFIED&&d->has("target")&&d->has("target (2)"));
    { std::lock_guard lock(d->mutex); assert(d->nodes.at(name("target"))==original); }
}
void journal_failure_test() {
    auto d=std::make_shared<Directory>(); d->add("a"); auto b=std::make_shared<Boundary>();
    auto r=rename_request({{held(d,"a"),"b"}});
    auto file=open_native_operation_journal_file(*root,*r.journal_name,true); assert(file.value());
    auto j=start(std::move(r),b); assert(item(j,0).state==CKFEA_READY); execute(j);
    assert(!b->calls&&d->has("a")&&!d->has("b")&&item(j,0).state!=CKFEA_VERIFIED);
}
void retry_tests() {
    for(bool ambiguous:{false,true}) {
        auto d=std::make_shared<Directory>(); d->add("a"); auto b=std::make_shared<Boundary>();
        b->fail_count=1; b->ambiguous=ambiguous;
        auto r=rename_request({{held(d,"a"),"b"}}); r.retry_limit=2; auto j=start(std::move(r),b); execute(j);
        assert(b->calls==(ambiguous?1u:2u));
        assert(item(j,0).state==(ambiguous?CKFEA_REVIEW_REQUIRED:CKFEA_VERIFIED));
    }
    auto d=std::make_shared<Directory>(); d->add("a"); auto b=std::make_shared<Boundary>(); b->fail_count=9;
    auto r=rename_request({{held(d,"a"),"b"}}); r.retry_limit=2; auto j=start(std::move(r),b); execute(j);
    assert(b->calls==3&&item(j,0).attempts==3&&d->has("a"));
    d=std::make_shared<Directory>(); d->add("a"); b=std::make_shared<Boundary>();
    b->fail_count=1; b->replace_on_failure=true;
    r=rename_request({{held(d,"a"),"b"}}); r.retry_limit=2; j=start(std::move(r),b); execute(j);
    assert(b->calls==1&&item(j,0).state==CKFEA_CHANGED&&d->has("a")&&!d->has("b"));
    d=std::make_shared<Directory>(); d->add("a"); b=std::make_shared<Boundary>(); b->substitute=true;
    j=start(rename_request({{held(d,"a"),"b"}}),b); execute(j);
    assert(item(j,0).state==CKFEA_REVIEW_REQUIRED&&d->has("a")&&!d->has("b"));
}
ActionRequest recovery_request(std::shared_ptr<Directory> d,bool wrong_digest=false) {
    auto node=d->add("published","verified data"); const auto id=*node->metadata.identity.value();
    const auto parent=*d->identity().value();
    NativeOperationRecoveryEvidence evidence{name("staged"),name("published"),*NativeDurableIdentity::from_live(parent),
        *NativeDurableIdentity::from_live(id),*NativeDurableIdentity::from_live(parent),{},{},{},NativeDurableIdentity::from_live(id)};
    Sha256 hash; hash.update(node->bytes); evidence.content_digest=hash.digest();
    if(wrong_digest) (*evidence.content_digest)[0]^=std::byte{1};
    ActionRequest r; r.operation=CKFEA_VERIFY_RECOVERY; r.max_verify_bytes=1024;
    r.recovery_destination=d; r.recovery.emplace();
    r.recovery->artifacts.push_back({0,OperationJournalState::DestinationCommitted,std::move(evidence),{}}); return r;
}
void recovery_tests() {
    for(bool mismatch:{false,true}) {
        auto d=std::make_shared<Directory>(); auto j=start(recovery_request(d,mismatch),std::make_shared<Boundary>());
        assert(item(j,0).state==CKFEA_READY); execute(j); assert(item(j,0).state==(mismatch?CKFEA_CHANGED:CKFEA_VERIFIED));
    }
    auto d=std::make_shared<Directory>(); auto r=recovery_request(d); r.recovery->report.has_untrusted_tail=true;
    auto j=start(std::move(r),std::make_shared<Boundary>()); assert(item(j,0).state==CKFEA_REVIEW_REQUIRED); execute(j);
    r=recovery_request(d); r.recovery->artifacts[0].evidence->published_identity.reset();
    j=start(std::move(r),std::make_shared<Boundary>()); assert(item(j,0).state==CKFEA_REVIEW_REQUIRED); execute(j);
    r=recovery_request(d); j=start(std::move(r),std::make_shared<Boundary>()); d->add("published","substitution");
    execute(j); assert(item(j,0).state==CKFEA_CHANGED);
    // Exercise the public recovery adapter and destroy the caller's references
    // before execution. The job must own the copied receipt and held cursor.
    r=recovery_request(d); ckfe_recovery recovery{*r.recovery}; ckfe_directory directory{}; directory.cursor=d;
    ckfea_request in; ckfea_request_init(&in); in.operation=CKFEA_VERIFY_RECOVERY;
    in.recovery=&recovery; in.recovery_destination=&directory; in.max_verify_bytes=1024;
    ckfea_job* job=nullptr; assert(ckfea_job_create(&in,&job)==CKFEA_OK);
    recovery.inspection.artifacts.clear(); directory.cursor.reset(); wait_c(job);
    auto receipt=output<ckfea_receipt>(); assert(ckfea_job_receipt(job,&receipt)==CKFEA_OK);
    assert(ckfea_job_execute(job,&receipt)==CKFEA_OK); wait_c(job);
    auto out=output<ckfea_result>(); assert(ckfea_job_item(job,0,&out)==CKFEA_OK&&out.state==CKFEA_VERIFIED); ckfea_job_destroy(job);
}
ckfea_native_text native_text(const NativeName& n) {
    ckfea_native_text t; ckfea_native_text_init(&t);
    if(auto p=n.posix_bytes()) { t.data=p->data(); t.byte_count=p->size(); }
    else { auto w=n.windows_units(); t.encoding=CKFEA_WINDOWS_UTF16; t.data=w->data(); t.byte_count=w->size()*2; }
    return t;
}
void trash_metadata_tests() {
    std::u16string path=u"V:\\native\\猫-";path+=char16_t(0xd800);path.append(350,u'x');
    auto encoded=windows_trash_metadata(path,0x0102030405060708ULL,123456);assert(encoded.value());
    const auto& b=*encoded.value();assert(b.size()==30+path.size()*2);
    auto get=[&](size_t offset,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;++i)v|=uint64_t(std::to_integer<unsigned char>(b[offset+i]))<<(i*8);return v;};
    assert(get(0,8)==2&&get(8,8)==0x0102030405060708ULL&&get(16,8)==123456&&get(24,4)==path.size()+1);
    for(size_t i=0;i<path.size();++i)assert(get(28+i*2,2)==path[i]);assert(get(28+path.size()*2,2)==0);
    assert(!windows_trash_metadata({},0,0).value());assert(!windows_trash_metadata(std::u16string(32768,u'x'),0,0).value());
    assert(!windows_trash_metadata(std::u16string{u'a',u'\0',u'b'},0,0).value());
    ckfea_restore_request request;ckfea_restore_request_init(&request);ckfea_job* out=nullptr;
    assert(ckfea_restore_job_create(&request,&out)==CKFEA_INVALID_ARGUMENT&&!out);
    ckfea_restore_item row;ckfea_restore_item_init(&row);request.items=&row;request.item_count=1;
    row.reserved[1]=1;assert(ckfea_restore_job_create(&request,&out)==CKFEA_INVALID_ARGUMENT&&!out);
    auto info=output<ckfea_trash_info>();assert(ckfea_trash_receipt_info(nullptr,&info)==CKFEA_INVALID_ARGUMENT);
    uint64_t required=9;assert(ckfea_trash_receipt_copy_name(nullptr,0,nullptr,0,&required)==CKFEA_INVALID_ARGUMENT&&!required);
    ckfea_trash_receipt_destroy(nullptr);
}
void native_gate_test() {
    NativeFileSystem fs; auto opened=fs.open_native_directory(*root); assert(opened.value());
    std::shared_ptr<const DirectoryCursor> cursor(std::move(opened).take_value());
#ifdef _WIN32
    auto source=*NativeName::from_windows(u"native-kept");
    auto target=*NativeName::from_windows(u"native-renamed");
    auto journal_name=*NativeName::from_windows(u"native-gate.journal");
#else
    auto source=name("native-kept"); auto target=name("native-renamed"); auto journal_name=name("native-gate.journal");
#endif
    auto created=cursor->create_child_file(source); assert(created.value());
    auto observed=HeldChild::observe(cursor,source); assert(observed.value());
    ckfe_entry entry{}; entry.child=*observed.value(); ckfea_item i; ckfea_item_init(&i);
    i.source=&entry; i.destination_name=native_text(target);
    ckfea_request r; ckfea_request_init(&r); r.items=&i; r.item_count=1;
    ckfea_native_text_init(&r.journal_directory);
    if(auto p=root->posix_bytes()) { r.journal_directory.data=p->data(); r.journal_directory.byte_count=p->size(); }
    else { auto w=root->windows_units(); r.journal_directory.encoding=CKFEA_WINDOWS_UTF16;
        r.journal_directory.data=w->data(); r.journal_directory.byte_count=w->size()*2; }
    r.journal_name=native_text(journal_name);
    ckfea_job* j=nullptr; assert(ckfea_job_create(&r,&j)==CKFEA_OK);
    entry.child.reset(); wait_c(j); auto result=output<ckfea_result>();
    assert(ckfea_job_item(j,0,&result)==CKFEA_OK);
#ifndef _WIN32
    assert(result.state==CKFEA_UNSUPPORTED&&result.reason==CKFEA_REASON_SOURCE_NOT_BOUND);
    auto source_now=cursor->lookup_child(source,ChildLookupMode::NativeDefault);
    auto target_now=cursor->lookup_child(target,ChildLookupMode::NativeDefault);
    assert(source_now.value()&&source_now.value()->state()==ChildLookupState::Found);
    assert(target_now.value()&&target_now.value()->state()==ChildLookupState::Missing);
#else
    if(result.state==CKFEA_READY) {
        auto receipt=output<ckfea_receipt>(); assert(ckfea_job_receipt(j,&receipt)==CKFEA_OK);
        assert(ckfea_job_execute(j,&receipt)==CKFEA_OK); wait_c(j);
        result=output<ckfea_result>(); assert(ckfea_job_item(j,0,&result)==CKFEA_OK);
        assert(result.state==CKFEA_VERIFIED||result.state==CKFEA_REVIEW_REQUIRED);
    }
#endif
    ckfea_job_destroy(j);
}
#ifdef _WIN32
ckfea_native_text native_path_text(const NativeAbsolutePath& path) {
    ckfea_native_text t;ckfea_native_text_init(&t);t.encoding=CKFEA_WINDOWS_UTF16;
    t.data=path.windows_units()->data();t.byte_count=path.windows_units()->size()*2;return t;
}
void execute_c(ckfea_job* job) {
    auto receipt=output<ckfea_receipt>();assert(ckfea_job_receipt(job,&receipt)==CKFEA_OK);
    assert(ckfea_job_execute(job,&receipt)==CKFEA_OK);wait_c(job);
}
void windows_native_trash_case(std::shared_ptr<const DirectoryCursor> cursor,const NativeName& source,bool collision) {
    static unsigned sequence=0;const auto suffix=std::to_string(++sequence);
    const auto journal=*NativeName::from_windows(std::u16string(u"trash-")+std::u16string(suffix.begin(),suffix.end()));
    auto created=cursor->create_child_file(source);assert(created.value());
    const std::array<std::byte,5> content{std::byte{1},std::byte{0xff},std::byte{3},std::byte{0},std::byte{7}};
    auto write=(*created.value())->write_content(0,content);assert(write.value()&&*write.value()==content.size());
    assert((*created.value())->flush_content().value());created=Observation<std::unique_ptr<OpenedEntry>>{};
    auto observed=HeldChild::observe(cursor,source);assert(observed.value());const auto identity=*(*observed.value())->metadata().identity.value();
    ckfe_entry input{}; input.child=*observed.value();ckfea_item item;ckfea_item_init(&item);item.source=&input;
    ckfea_request request;ckfea_request_init(&request);request.operation=CKFEA_TRASH;request.capabilities=CKFEA_ALLOW_NATIVE_TRASH;
    request.items=&item;request.item_count=1;request.journal_directory=native_path_text(*root);request.journal_name=native_text(journal);
    ckfea_job* job=nullptr;assert(ckfea_job_create(&request,&job)==CKFEA_OK);wait_c(job);
    auto result=output<ckfea_result>();assert(ckfea_job_item(job,0,&result)==CKFEA_OK);
    if(result.state!=CKFEA_READY)std::fprintf(stderr,"native Trash preview state=%u domain=%u code=%lld reason=%u\n",result.state,result.error_domain,(long long)result.error_code,result.reason);
    assert(result.state==CKFEA_READY);execute_c(job);result=output<ckfea_result>();assert(ckfea_job_item(job,0,&result)==CKFEA_OK);
    if(result.state!=CKFEA_VERIFIED)std::fprintf(stderr,"native Trash commit state=%u domain=%u code=%lld\n",result.state,result.error_domain,(long long)result.error_code);
    assert(result.state==CKFEA_VERIFIED);
    ckfea_trash_receipt* trash=nullptr;assert(ckfea_job_trash_receipt(job,0,&trash)==CKFEA_OK&&trash);ckfea_job_destroy(job);
    auto info=output<ckfea_trash_info>();assert(ckfea_trash_receipt_info(trash,&info)==CKFEA_OK);
    assert(info.encoding==CKFEA_WINDOWS_UTF16&&info.original_name_bytes==source.windows_units()->size()*2&&info.object.scheme==2);
    uint64_t required=0;assert(ckfea_trash_receipt_copy_name(trash,CKFEA_TRASH_ORIGINAL_NAME,nullptr,0,&required)==CKFEA_BUFFER_TOO_SMALL);
    std::u16string exact(static_cast<size_t>(required/2),u'\0');
    assert(ckfea_trash_receipt_copy_name(trash,CKFEA_TRASH_ORIGINAL_NAME,exact.data(),required,&required)==CKFEA_OK&&exact==*source.windows_units());
    auto missing=cursor->lookup_child(source,ChildLookupMode::NativeDefault);assert(missing.value()&&missing.value()->state()==ChildLookupState::Missing);
    if(collision) { auto occupied=cursor->create_child_file(source);assert(occupied.value()); }
    ckfe_directory original{}; original.cursor=cursor;ckfea_restore_item restore_item;ckfea_restore_item_init(&restore_item);restore_item.receipt=trash;restore_item.original_parent=&original;
    ckfea_restore_request restore;ckfea_restore_request_init(&restore);restore.capabilities=CKFEA_ALLOW_NATIVE_RESTORE;restore.items=&restore_item;restore.item_count=1;
    auto restore_journal=*NativeName::from_windows(std::u16string(u"restore-")+std::u16string(suffix.begin(),suffix.end()));
    restore.journal_directory=native_path_text(*root);restore.journal_name=native_text(restore_journal);
    assert(ckfea_restore_job_create(&restore,&job)==CKFEA_OK);if(!collision)ckfea_trash_receipt_destroy(trash);wait_c(job);
    result=output<ckfea_result>();assert(ckfea_job_item(job,0,&result)==CKFEA_OK);
    if(collision) {
        assert(result.state==CKFEA_CHANGED||result.state==CKFEA_COLLISION);ckfea_job_destroy(job);
        // Remove only the newly-created occupying TEST fixture via its verified
        // handle boundary, then restore the retained original through the receipt.
        auto occupied=HeldChild::observe(cursor,source);assert(occupied.value());
        const auto occupied_id=*(*occupied.value())->metadata().identity.value();
        assert(compare_identity(occupied_id,identity)==IdentityComparison::Different);
        auto removed=cursor->discard_child(source,occupied_id);assert(removed.value()&&*removed.value());
        occupied=Observation<HeldChild::Pointer>{};
        assert(ckfea_restore_job_create(&restore,&job)==CKFEA_OK);ckfea_trash_receipt_destroy(trash);wait_c(job);
        result=output<ckfea_result>();assert(ckfea_job_item(job,0,&result)==CKFEA_OK);
    }
    if(result.state!=CKFEA_READY)std::fprintf(stderr,"native Restore preview state=%u domain=%u code=%lld\n",result.state,result.error_domain,(long long)result.error_code);
    assert(result.state==CKFEA_READY);execute_c(job);result=output<ckfea_result>();assert(ckfea_job_item(job,0,&result)==CKFEA_OK);
    if(result.state!=CKFEA_VERIFIED)std::fprintf(stderr,"native Restore commit state=%u domain=%u code=%lld\n",result.state,result.error_domain,(long long)result.error_code);
    assert(result.state==CKFEA_VERIFIED);ckfea_job_destroy(job);
    auto restored=HeldChild::observe_with_access(cursor,source,EntryAccess::ContentRead);assert(restored.value());
    assert(compare_identity(identity,*(*restored.value())->metadata().identity.value())==IdentityComparison::Same);
    auto bytes=(*restored.value())->read_content();assert(bytes.value()&&bytes.value()->complete&&bytes.value()->bytes==std::vector<std::byte>(content.begin(),content.end()));
}
struct TestWinClose { void operator()(void* p) const noexcept {if(p&&p!=INVALID_HANDLE_VALUE)CloseHandle(p);} };
using TestWinHandle=std::unique_ptr<void,TestWinClose>;
struct TestLocalClose {void operator()(void* p) const noexcept {if(p)LocalFree(p);}};
using TestLocal=std::unique_ptr<void,TestLocalClose>;
std::wstring test_extended(const NativeAbsolutePath& path) {
    assert(path.windows_units());std::wstring p(path.windows_units()->begin(),path.windows_units()->end());
    if(p.starts_with(L"\\\\?\\"))return p;
    if(p.starts_with(L"\\\\"))return L"\\\\?\\UNC\\"+p.substr(2);
    return L"\\\\?\\"+p;
}
std::wstring test_volume_root(const DirectoryCursor& parent) {
    auto duplicate=duplicate_windows_trash_parent(parent);assert(duplicate.value());
    std::vector<wchar_t> path(32768);const auto n=GetFinalPathNameByHandleW(duplicate.value()->get(),path.data(),static_cast<DWORD>(path.size()),FILE_NAME_OPENED|VOLUME_NAME_GUID);
    assert(n&&n<path.size());std::wstring p(path.data(),n);const auto end=p.find(L'}');assert(end!=p.npos);
    return p.substr(0,end+2);
}
std::wstring test_current_sid() {
    HANDLE raw=nullptr;assert(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw));TestWinHandle token(raw);
    DWORD count=0;GetTokenInformation(token.get(),TokenUser,nullptr,0,&count);assert(count);
    std::vector<std::byte> bytes(count);assert(GetTokenInformation(token.get(),TokenUser,bytes.data(),count,&count));
    LPWSTR text=nullptr;assert(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid,&text));TestLocal local(text);return text;
}
void test_private_acl(HANDLE h,bool public_inheritance) {
    const auto sid=test_current_sid();const auto text=L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+sid+L")"+(public_inheritance?L"(A;OIIO;GR;;;WD)":L"");
    PSECURITY_DESCRIPTOR raw=nullptr;assert(ConvertStringSecurityDescriptorToSecurityDescriptorW(text.c_str(),SDDL_REVISION_1,&raw,nullptr));TestLocal sd(raw);
    PACL acl=nullptr;BOOL present=FALSE,defaulted=FALSE;assert(GetSecurityDescriptorDacl(raw,&present,&acl,&defaulted)&&present);
    assert(SetSecurityInfo(h,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,acl,nullptr)==ERROR_SUCCESS);
}
struct TestTrashJournal {
    OperationJournal::Pointer journal;std::unique_ptr<OperationJournalFile> file;
    TestTrashJournal() {
        OperationJournalId id{};const auto n=++journal_sequence;id.bytes[0]=std::byte{0x74};
        for(unsigned i=0;i<8;++i)id.bytes[i+1]=std::byte(static_cast<unsigned char>(uint64_t(n)>>(i*8)));
        auto j=OperationJournal::create(FileOperation::Move,id);assert(j.value());journal=*j.value();
        auto f=open_native_operation_journal_file(*root,host_name("critical-"+std::to_string(n)+".journal"),true);assert(f.value());file=std::move(f).take_value();
    }
    NativeTrashJournal callback() {return [this](OperationJournalState state,const NativeTrashReceipt& r){
        auto encoded=encode_native_trash_receipt(r);assert(encoded.value());
        return append_operation_journal_file(*file,*journal,{journal->records().size()+1,0,state,std::move(encoded).take_value()});};}
};
void assert_native_result(const Observation<bool>& result,const char* phase) {
    if(!result.value())std::fprintf(stderr,"%s failed state=%u code=%lld op=%s\n",phase,unsigned(result.state()),(long long)result.unavailable_detail()->error.code,result.unavailable_detail()->error.operation.c_str());
    assert(result.value()&&*result.value());
}
void native_bin_critical_tests() {
    NativeFileSystem fs;auto opened=fs.open_native_directory(*root);assert(opened.value());
    std::shared_ptr<const DirectoryCursor> cursor(std::move(opened).take_value());
    auto backend=native_trash_backend();auto file_name=*NativeName::from_windows(u"critical-bin-object");
    auto created=cursor->create_child_file(file_name);assert(created.value());created=Observation<std::unique_ptr<OpenedEntry>>{};
    auto observed=HeldChild::observe(cursor,file_name);assert(observed.value());auto held=*observed.value();
    auto prepared=backend->prepare_trash(held,{});
    if(!prepared.value())std::fprintf(stderr,"prepare critical failed state=%u op=%s code=%lld\n",unsigned(prepared.state()),prepared.unavailable_detail()->error.operation.c_str(),(long long)prepared.unavailable_detail()->error.code);
    assert(prepared.value());auto transaction=std::move(prepared).take_value();
    const auto volume=test_volume_root(*cursor);const auto bin_root=volume+L"$Recycle.Bin";
    const auto sid=test_current_sid();const auto bin_user=bin_root+L"\\"+sid;
    // Native DELETE sharing must prevent both ancestor moves during preview.
    for(const auto& path:{bin_root,bin_user}) {
        assert(!MoveFileExW(path.c_str(),(path+L".critical-moved").c_str(),0));
        assert(GetLastError()==ERROR_SHARING_VIOLATION||GetLastError()==ERROR_ACCESS_DENIED);
    }
    TestWinHandle security(CreateFileW(bin_user.c_str(),READ_CONTROL|WRITE_DAC,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    assert(security.get()!=INVALID_HANDLE_VALUE);
    // A grant that only applies to newly created children must be rejected at
    // preparation AND when it is introduced after a successful preparation.
    test_private_acl(security.get(),true);TestTrashJournal rejected;
    auto refused=transaction->commit(rejected.callback(),{});assert(!refused.value()&&!transaction->mutation_attempted());
    assert(!transaction->receipt().metadata_identity&&rejected.journal->records().empty());transaction.reset();
    prepared=backend->prepare_trash(held,{});assert(!prepared.value());
    test_private_acl(security.get(),false);security.reset();
    prepared=backend->prepare_trash(held,{});assert(prepared.value());transaction=std::move(prepared).take_value();
    TestTrashJournal committed;assert_native_result(transaction->commit(committed.callback(),{}),"critical Trash");
    auto receipt=transaction->receipt();assert(receipt.continuity&&receipt.metadata_identity);transaction.reset();held.reset();observed=Observation<HeldChild::Pointer>{};
    // The $I record must have a protected, explicitly private descriptor.
    const auto metadata_path=bin_user+L"\\"+std::wstring(receipt.metadata_name.windows_units()->begin(),receipt.metadata_name.windows_units()->end());
    TestWinHandle metadata(CreateFileW(metadata_path.c_str(),READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));assert(metadata.get()!=INVALID_HANDLE_VALUE);
    PSECURITY_DESCRIPTOR raw=nullptr;PACL acl=nullptr;assert(GetSecurityInfo(metadata.get(),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&acl,nullptr,&raw)==ERROR_SUCCESS);TestLocal descriptor(raw);
    SECURITY_DESCRIPTOR_CONTROL control{};DWORD revision=0;assert(GetSecurityDescriptorControl(raw,&control,&revision)&&(control&SE_DACL_PROTECTED));
    for(DWORD i=0;i<acl->AceCount;++i){void* item=nullptr;assert(GetAce(acl,i,&item));assert(!(static_cast<ACE_HEADER*>(item)->AceFlags&INHERITED_ACE));}metadata.reset();
    // Read-only receipt pins allow namespace moves but bind their original
    // identities. Replacing either ancestor must make a fresh restore fail.
    for(const auto& path:{bin_user,bin_root}) {
        const auto moved=path+L".critical-moved";
        assert(MoveFileExW(path.c_str(),moved.c_str(),0));assert(CreateDirectoryW(path.c_str(),nullptr));
        auto restore=backend->prepare_restore(receipt,cursor,{});assert(!restore.value());
        assert(RemoveDirectoryW(path.c_str()));assert(MoveFileExW(moved.c_str(),path.c_str(),0));
    }
    auto unbound=receipt;unbound.continuity.reset();assert(!backend->prepare_restore(unbound,cursor,{}).value());
    auto restore=backend->prepare_restore(receipt,cursor,{});assert(restore.value());TestTrashJournal restored;
    assert_native_result((*restore.value())->commit(restored.callback(),{}),"critical Restore");
    std::puts("critical Trash: pinned bin ancestry, inherited-public ACE rejection, protected $I DACL and live-only restore passed");
}
void opaque_parent_critical_test() {
    NativeFileSystem fs;auto opened=fs.open_native_directory(*root);assert(opened.value());std::shared_ptr<const DirectoryCursor> base(std::move(opened).take_value());
    auto directory_name=*NativeName::from_windows(u"critical-original-parent");auto source=*NativeName::from_windows(u"object");
    auto made=base->create_child_directory(directory_name);assert(made.value());std::shared_ptr<const DirectoryCursor> cursor(std::move(made).take_value());
    auto created=cursor->create_child_file(source);assert(created.value());created=Observation<std::unique_ptr<OpenedEntry>>{};
    auto held=HeldChild::observe(cursor,source);assert(held.value());ckfe_entry entry{};entry.child=*held.value();
    ckfea_item item;ckfea_item_init(&item);item.source=&entry;auto journal_name=host_name("opaque-parent-trash.journal");
    ckfea_request request;ckfea_request_init(&request);request.operation=CKFEA_TRASH;request.capabilities=CKFEA_ALLOW_NATIVE_TRASH;request.items=&item;request.item_count=1;
    request.journal_directory=native_path_text(*root);request.journal_name=native_text(journal_name);ckfea_job* job=nullptr;
    assert(ckfea_job_create(&request,&job)==CKFEA_OK);wait_c(job);auto state=output<ckfea_result>();assert(ckfea_job_item(job,0,&state)==CKFEA_OK&&state.state==CKFEA_READY);
    execute_c(job);state=output<ckfea_result>();assert(ckfea_job_item(job,0,&state)==CKFEA_OK&&state.state==CKFEA_VERIFIED);
    ckfea_trash_receipt* receipt=nullptr;assert(ckfea_job_trash_receipt(job,0,&receipt)==CKFEA_OK);ckfea_job_destroy(job);
    auto original_address=root->child_address(directory_name);assert(original_address.value());const auto path=test_extended(*original_address.value());
    entry.child.reset();held=Observation<HeldChild::Pointer>{};cursor.reset();
    // POSIX disposition detaches an empty directory even while the receipt's
    // metadata-only handle pins the old object. Its ID cannot be recycled.
    TestWinHandle removing(CreateFileW(path.c_str(),DELETE|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));assert(removing.get()!=INVALID_HANDLE_VALUE);
    FILE_DISPOSITION_INFO_EX disposition{FILE_DISPOSITION_FLAG_DELETE|FILE_DISPOSITION_FLAG_POSIX_SEMANTICS};
    assert(SetFileInformationByHandle(removing.get(),FileDispositionInfoEx,&disposition,sizeof(disposition)));removing.reset();
    assert(CreateDirectoryW(path.c_str(),nullptr));opened=fs.open_native_directory(*original_address.value());assert(opened.value());cursor=std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
    ckfe_directory replacement{};replacement.cursor=cursor;ckfea_restore_item ri;ckfea_restore_item_init(&ri);ri.receipt=receipt;ri.original_parent=&replacement;
    ckfea_restore_request restore;ckfea_restore_request_init(&restore);restore.capabilities=CKFEA_ALLOW_NATIVE_RESTORE;restore.items=&ri;restore.item_count=1;
    auto restore_name=host_name("opaque-parent-restore.journal");restore.journal_directory=native_path_text(*root);restore.journal_name=native_text(restore_name);
    assert(ckfea_restore_job_create(&restore,&job)==CKFEA_OK);wait_c(job);state=output<ckfea_result>();assert(ckfea_job_item(job,0,&state)==CKFEA_OK);
    assert(state.state==CKFEA_CHANGED||state.state==CKFEA_REVIEW_REQUIRED);ckfea_job_destroy(job);ckfea_trash_receipt_destroy(receipt);
    auto missing=cursor->lookup_child(source,ChildLookupMode::NativeDefault);assert(missing.value()&&missing.value()->state()==ChildLookupState::Missing);
    std::puts("critical Trash: opaque receipt survives job destruction and rejects deleted/recreated original parent");
}
void windows_native_trash_tests() {
    NativeFileSystem fs;auto opened=fs.open_native_directory(*root);assert(opened.value());
    std::shared_ptr<const DirectoryCursor> cursor(std::move(opened).take_value());
    auto qualified=cursor->qualify_identity_bound_rename();
    if(!qualified.value()||!*qualified.value()) {std::puts("native Windows Trash scope unavailable on this fixture volume");return;}
    windows_native_trash_case(cursor,*NativeName::from_windows(u"ordinary-trash.bin"),false);
    windows_native_trash_case(cursor,*NativeName::from_windows(std::u16string(u"猫-ß-")+char16_t(0xd800)),false);
    windows_native_trash_case(cursor,*NativeName::from_windows(u"restore-collision.bin"),true);
    // Held-directory creation keeps every component native and exceeds MAX_PATH.
    for(unsigned i=0;i<5;++i) {
        auto n=*NativeName::from_windows(std::u16string(60,char16_t(u'a'+i)));
        auto child=cursor->create_child_directory(n);assert(child.value());cursor=std::shared_ptr<const DirectoryCursor>(std::move(child).take_value());
    }
    windows_native_trash_case(cursor,*NativeName::from_windows(u"long-path-猫.bin"),false);
}
#endif
void release_test() {
    auto d=std::make_shared<Directory>(); d->add("a"); ckfe_entry entry{}; entry.child=held(d,"a");
    auto block=std::make_shared<Block>(); d->block=block;
    ckfea_item i; ckfea_item_init(&i); i.source=&entry; i.destination_name=text("b");
    ckfea_request r; ckfea_request_init(&r); r.items=&i; r.item_count=1;
    ckfea_job* job=nullptr; assert(ckfea_job_create(&r,&job)==CKFEA_OK);
    { std::unique_lock lock(block->mutex); assert(block->cv.wait_for(lock,std::chrono::seconds(5),[&]{return block->entered;})); }
    std::weak_ptr<Directory> retained=d; entry.child.reset(); d.reset();
    const auto before=std::chrono::steady_clock::now(); ckfea_job_destroy(job);
    assert(std::chrono::steady_clock::now()-before<std::chrono::milliseconds(500));
    assert(!retained.expired());
    { std::lock_guard lock(block->mutex); block->release=true; block->cv.notify_all(); }
    for(unsigned n=0;n<5000&&!retained.expired();++n) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    assert(retained.expired());
}
void bounded_jobs_test() {
    auto d=std::make_shared<Directory>(); d->add("a"); ckfe_entry entry{}; entry.child=held(d,"a");
    ckfea_item item; ckfea_item_init(&item); item.source=&entry; item.destination_name=text("a");
    ckfea_request r; ckfea_request_init(&r); r.items=&item; r.item_count=1;
    std::vector<ckfea_job*> jobs;
    // Nonblocking releases from prior tests may still be finishing cancellation.
    for(unsigned tries=0;tries<1000&&jobs.size()<CKFEA_MAX_JOBS;++tries) {
        ckfea_job* j=nullptr; const auto status=ckfea_job_create(&r,&j);
        if(status==CKFEA_BUSY) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
        assert(status==CKFEA_OK); jobs.push_back(j);
    }
    assert(jobs.size()==CKFEA_MAX_JOBS); ckfea_job* overflow=nullptr;
    assert(ckfea_job_create(&r,&overflow)==CKFEA_BUSY&&!overflow);
    for(auto j:jobs) ckfea_job_destroy(j);
}
}
int main(int argc,char** argv) {
    assert(argc==2||argc==3);
    auto address=NativeAbsolutePath::from_host(std::filesystem::path(argv[1])); assert(address.value());
    root=std::move(address).take_value();
    assert(prepare_native_operation_journal_root(*root).value());
#ifdef _WIN32
    if(argc==3&&std::string_view(argv[2])=="--critical-trash") {
        windows_native_trash_tests();native_bin_critical_tests();opaque_parent_critical_test();
        std::puts("Windows critical Trash regressions passed");return 0;
    }
#endif
    abi_tests(); rename_tests(); exact_names_tests(); journal_failure_test(); retry_tests(); recovery_tests(); trash_metadata_tests(); native_gate_test();
#ifdef _WIN32
    windows_native_trash_tests();
#endif
    release_test(); bounded_jobs_test();
    std::puts("actions: ABI, native gates, chains/cycles/collisions, pinned receipts, retry, journal and recovery passed");
}
