// SPDX-License-Identifier: LGPL-2.0-or-later
#include "verified_copy_retry.hpp"
#include "ck_fs_retry.h"
#include "native_handles.hpp"
#undef NDEBUG
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <thread>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

using namespace ck::files;
extern "C" int retry_c_smoke(void);
namespace {
unsigned sequence=0;
NativeName native(std::string text) {
#ifdef _WIN32
    std::u16string units(text.begin(),text.end());return *NativeName::from_windows(std::move(units));
#else
    return *NativeName::from_posix(std::move(text));
#endif
}
NativeName exact_name(const std::string& prefix) {
#ifdef _WIN32
    std::u16string text(prefix.begin(),prefix.end());text+=u"-猫-";text.push_back(char16_t(0xd800));return *NativeName::from_windows(std::move(text));
#elif defined(__APPLE__)
    // APFS rejects ill-formed UTF-8 at native creation (EILSEQ). Linux below
    // exercises raw bytes; this fixture still uses exact non-ASCII APFS names.
    return *NativeName::from_posix(prefix+"-猫-é");
#else
    return *NativeName::from_posix(prefix+"-猫-"+std::string(1,char(0xff)));
#endif
}
template<class T> T take(Observation<T> result) {
    if(!result.value())std::fprintf(stderr,"native failure %u %lld %s\n",unsigned(result.state()),
        static_cast<long long>(result.unavailable_detail()->error.code),result.unavailable_detail()->error.operation.c_str());
    assert(result.value());return std::move(result).take_value();
}
void yes(Observation<bool> result){assert(take(std::move(result)));}
std::vector<std::byte> read(const DirectoryCursor& directory,const NativeName& name) {
    auto entry=take(directory.open_child(name,EntryAccess::ContentRead));std::vector<std::byte> bytes;
    for(;;){auto part=take(entry->read_content({65536},bytes.size()));bytes.insert(bytes.end(),part.bytes.begin(),part.bytes.end());if(part.complete)break;assert(!part.bytes.empty());}return bytes;
}
void create_file(const DirectoryCursor& directory,const NativeName& name,std::span<const std::byte> bytes) {
    auto entry=take(directory.create_child_file(name));size_t offset=0;
    while(offset<bytes.size()){auto count=take(entry->write_content(offset,bytes.subspan(offset,std::min<size_t>(65536,bytes.size()-offset))));assert(count);offset+=count;}
    yes(entry->finish_content_writes());
}
bool missing(const DirectoryCursor& directory,const NativeName& name) {
    auto lookup=take(directory.lookup_child(name,ChildLookupMode::NativeDefault));return lookup.state()==ChildLookupState::Missing&&lookup.missing_witness();
}
struct Fixture {
    NativeAbsolutePath root;
    std::optional<NativeAbsolutePath> journal_root;
    std::shared_ptr<const DirectoryCursor> journal_directory;
    std::shared_ptr<const DirectoryCursor> directory;
    NativeName source_name,candidate_name,final_name,original_name,attempt_name,hint;
    std::vector<std::byte> bytes,original_journal;
    uint64_t prefix=65536+23;
    HeldChild::Pointer source,candidate;
    OperationJournalId original_id{},attempt_id{};
    Fixture(NativeAbsolutePath path,std::shared_ptr<const DirectoryCursor> cursor)
        :root(std::move(path)),directory(std::move(cursor)),source_name(exact_name("source"+std::to_string(++sequence))),
         candidate_name(exact_name("partial"+std::to_string(sequence))),final_name(exact_name("final"+std::to_string(sequence))),
         original_name(native("origin"+std::to_string(sequence))),attempt_name(native("attempt"+std::to_string(sequence))),
         hint(exact_name("new-stage"+std::to_string(sequence))) {
        const auto child=native("private-journals"+std::to_string(sequence));
        journal_directory=take(directory->create_child_directory(child));
        journal_root=take(root.child_address(child));
        yes(prepare_native_operation_journal_root(*journal_root));
        bytes.resize(5*65536+117);for(size_t i=0;i<bytes.size();++i)bytes[i]=std::byte((i*29+i/251)%253);
        create_file(*directory,source_name,bytes);create_file(*directory,candidate_name,std::span(bytes).first(static_cast<size_t>(prefix)));
        source=take(HeldChild::observe(directory,source_name));candidate=take(HeldChild::observe(directory,candidate_name));
        original_id.bytes[0]=std::byte{7};attempt_id.bytes[0]=std::byte{8};
        for(unsigned i=0;i<4;++i){original_id.bytes[4+i]=std::byte((sequence>>(8*i))&255);attempt_id.bytes[4+i]=original_id.bytes[4+i];}
        write_original(false,false);
    }
    void write_original(bool ambiguous,bool bad_tail) {
        auto file=take(open_native_operation_journal_file(*journal_root,original_name,true));
        auto journal=take(OperationJournal::create(FileOperation::Copy,original_id));
        NativeOperationRecoveryEvidence evidence{candidate_name,final_name,*NativeDurableIdentity::from_live(*source->parent_identity().value()),
            *NativeDurableIdentity::from_live(*source->metadata().identity.value()),*NativeDurableIdentity::from_live(*directory->identity().value()),
            NativeDurableIdentity::from_live(*candidate->metadata().identity.value()),root,{},{}};
        const auto append=[&](OperationJournalState state){auto encoded=take(encode_native_operation_recovery_evidence(evidence));yes(append_operation_journal_file(*file,*journal,{journal->records().size()+1,0,state,std::move(encoded)}));};
        append(OperationJournalState::Planned);append(OperationJournalState::Prepared);
        if(ambiguous){append(OperationJournalState::Copied);append(OperationJournalState::Verified);append(OperationJournalState::CommitIntended);}
        append(OperationJournalState::Failed);
        if(bad_tail){const std::array<std::byte,3> tail{std::byte{7},std::byte{8},std::byte{9}};assert(take(file->write_at(take(file->size()),tail))==tail.size());yes(file->flush());}
        yes(file->finish_io());original_journal=read(*journal_directory,original_name);
    }
    void alternate_original(bool ambiguous,bool tail) {original_name=native("alternate"+std::to_string(sequence));write_original(ambiguous,tail);}
    VerifiedCopyRetryRequest request() const {
        VerifiedCopyRetryRequest result(*journal_root,original_name,*journal_root,attempt_name,hint,final_name);
        result.source=source;result.candidate=candidate;result.candidate_prefix_bytes=prefix;result.destination=directory;result.destination_address=root;
        result.attempt_id=attempt_id;result.metadata_policy.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;
        result.metadata_policy.ownership=MetadataOwnership::CurrentCaller;return result;
    }
    void unchanged(bool candidate_tampered=false) const {
        assert(read(*directory,source_name)==bytes);
        if(!candidate_tampered)assert(read(*directory,candidate_name)==std::vector<std::byte>(bytes.begin(),bytes.begin()+static_cast<ptrdiff_t>(prefix)));
        assert(read(*journal_directory,original_name)==original_journal);
    }
};
VerifiedCopyRetryState review(VerifiedCopyRetryJob& job) {
    for(unsigned n=0;n<10000;++n){const auto state=job.advance();if(state==VerifiedCopyRetryState::AwaitingReview||state==VerifiedCopyRetryState::ReviewRequired)return state;}assert(false);return job.state();
}
void finish(VerifiedCopyRetryJob& job) {
    for(unsigned n=0;n<10000;++n){auto state=job.advance();if(state==VerifiedCopyRetryState::Complete||state==VerifiedCopyRetryState::ReviewRequired||state==VerifiedCopyRetryState::Cancelled)return;}assert(false);
}
void native_positive(Fixture& fixture) {
    auto job=take(VerifiedCopyRetryJob::create(fixture.request()));assert(review(*job)==VerifiedCopyRetryState::AwaitingReview);
    assert(job->prefix_bytes()==fixture.prefix&&job->reviewed_bytes()==fixture.bytes.size()&&job->reviewed_digest()&&job->origin_digest());
    yes(job->approve());assert(!job->approve().value());finish(*job);yes(job->finish_io());
#ifdef __APPLE__
    assert(job->state()==VerifiedCopyRetryState::ReviewRequired&&job->failure()&&job->failure()->state==ObservationState::Unsupported);
    assert(job->failure()->error.operation=="create_staging_file.fd_publication_unqualified");assert(missing(*fixture.directory,fixture.final_name));
    std::puts("Mac native strong publication correctly Unsupported; no positive resume claimed");
#else
    if(job->failure())std::fprintf(stderr,"copy failed %s\n",job->failure()->error.operation.c_str());
    assert(job->state()==VerifiedCopyRetryState::Complete&&job->copied_prefix_bytes()==fixture.prefix);
    assert(read(*fixture.directory,fixture.final_name)==fixture.bytes);
    auto attempt=read(*fixture.journal_directory,fixture.attempt_name);auto journal=take(decode_operation_journal(attempt));assert(!journal.tail&&journal.journal->state(0)==OperationJournalState::Complete);
    assert(journal.journal->records().front().evidence.size()==164);
    std::puts("Actual native prefix resume: prefix 65559 bytes plus suffix, full independent SHA, metadata and publication passed");
#endif
    fixture.unchanged();
}
class WritableMapping {
    void* data_=nullptr;size_t size_=0;
#ifdef _WIN32
    HANDLE mapping_=nullptr;
#endif
public:
    WritableMapping(const NativeAbsolutePath& root,const NativeName& name,size_t size):size_(size) {
        const auto address=take(root.child_address(name));
#ifdef _WIN32
        auto units=*address.windows_units();if(units.rfind(u"\\\\?\\",0)!=0)units=u"\\\\?\\"+units;
        const std::wstring path(units.begin(),units.end());auto file=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);assert(file!=INVALID_HANDLE_VALUE);
        mapping_=CreateFileMappingW(file,nullptr,PAGE_READWRITE,0,0,nullptr);assert(mapping_);data_=MapViewOfFile(mapping_,FILE_MAP_WRITE,0,0,size);assert(data_);assert(CloseHandle(file));
#else
        auto fd=open(address.posix_bytes()->c_str(),O_RDWR|O_NOFOLLOW|O_CLOEXEC);assert(fd>=0);data_=mmap(nullptr,size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);assert(data_!=MAP_FAILED);assert(close(fd)==0);
#endif
    }
    void tamper(){static_cast<std::byte*>(data_)[0]^=std::byte{1};}
    ~WritableMapping(){
#ifdef _WIN32
        assert(UnmapViewOfFile(data_));assert(CloseHandle(mapping_));
#else
        assert(munmap(data_,size_)==0);
#endif
    }
};
ckfer_native_v1 text(const NativeName& value) {
    ckfer_native_v1 out;ckfer_native_init_v1(&out);
    if(auto bytes=value.posix_bytes()){out.data=bytes->data();out.byte_count=bytes->size();}
    else{out.encoding=CKFER_UTF16;out.data=value.windows_units()->data();out.byte_count=value.windows_units()->size()*2;}return out;
}
ckfer_native_v1 text(const NativeAbsolutePath& value) {
    ckfer_native_v1 out;ckfer_native_init_v1(&out);
    if(auto bytes=value.posix_bytes()){out.data=bytes->data();out.byte_count=bytes->size();}
    else{out.encoding=CKFER_UTF16;out.data=value.windows_units()->data();out.byte_count=value.windows_units()->size()*2;}return out;
}
struct CInput {
    ckfe_entry source{},candidate{};ckfe_directory destination{};ckfer_options_v1 options{};
    explicit CInput(const Fixture& fixture) {
        source.child=fixture.source;candidate.child=fixture.candidate;destination.cursor=fixture.directory;destination.address=fixture.root;
        ckfer_options_init_v1(&options);options.source=&source;options.candidate=&candidate;options.destination=&destination;
        options.original_journal_root=text(*fixture.journal_root);options.attempt_journal_root=text(*fixture.journal_root);
        options.original_journal_name=text(fixture.original_name);options.attempt_journal_name=text(fixture.attempt_name);
        options.staging_hint=text(fixture.hint);options.destination_name=text(fixture.final_name);options.prefix_bytes=fixture.prefix;
        options.metadata_scope=CKFER_ORDINARY_METADATA_V1;options.metadata_ownership=CKFER_CURRENT_CALLER_OWNERSHIP;
        std::memcpy(options.attempt_id,fixture.attempt_id.bytes.data(),16);
    }
};
ckfer_snapshot_v1 poll(ckfer_job* job) {ckfer_snapshot_v1 out;ckfer_snapshot_init_v1(&out);assert(ckfer_poll_v1(job,&out)==CKFE_API_OK);return out;}
ckfer_snapshot_v1 await(ckfer_job* job,bool drained) {
    for(unsigned n=0;n<1000;++n){auto out=poll(job);if(drained?out.worker_drained:out.state==CKFER_AWAITING_REVIEW||out.worker_drained)return out;ckfer_wait_v1(job,100);}assert(false);return poll(job);
}
void c_positive(Fixture& fixture) {
    CInput input(fixture);ckfer_job* job=nullptr;assert(ckfer_start_v1(&input.options,&job)==CKFE_API_OK);input.source.child.reset();input.candidate.child.reset();input.destination.cursor.reset();
    fixture.source.reset();fixture.candidate.reset();
    auto before=await(job,false);assert(before.state==CKFER_AWAITING_REVIEW&&before.review_id&&before.has_source_digest&&before.has_origin_digest&&!before.worker_drained);
    assert(before.copied_bytes==0&&before.copied_prefix_bytes==0);
    assert(ckfer_execute_v1(job,before.review_id+1)==CKFE_API_STALE_PLAN);assert(ckfer_execute_v1(job,before.review_id)==CKFE_API_OK);
    assert(ckfer_execute_v1(job,before.review_id)!=CKFE_API_OK);auto after=await(job,true);uint32_t drained=0;assert(ckfer_worker_drained_v1(job,&drained)==CKFE_API_OK&&drained);
#ifdef __APPLE__
    assert(after.state==CKFER_REVIEW_REQUIRED&&after.failure_state==CKFE_OBSERVATION_UNSUPPORTED&&after.recovery_required);
    assert(after.failure_operation[0]);
#else
    if(after.state!=CKFER_COMPLETE)std::fprintf(stderr,"C retry failure %u %lld %s\n",after.failure_state,static_cast<long long>(after.failure_code),after.failure_operation);
    assert(after.state==CKFER_COMPLETE&&after.copied_prefix_bytes==fixture.prefix&&!after.recovery_required);
    assert(read(*fixture.directory,fixture.final_name)==fixture.bytes);
#endif
    ckfer_release(job);fixture.unchanged();
}
void c_validation(Fixture& fixture) {
    CInput input(fixture);ckfer_job* job=reinterpret_cast<ckfer_job*>(uintptr_t(1));
    auto bad=input.options;bad.struct_size--;assert(ckfer_start_v1(&bad,&job)==CKFE_API_INVALID_ARGUMENT&&!job);
    bad=input.options;bad.reserved_words[3]=1;assert(ckfer_start_v1(&bad,&job)==CKFE_API_INVALID_ARGUMENT&&!job);
    bad=input.options;bad.staging_hint.reserved=1;assert(ckfer_start_v1(&bad,&job)==CKFE_API_INVALID_ARGUMENT&&!job);
    bad=input.options;bad.source=nullptr;assert(ckfer_start_v1(&bad,&job)==CKFE_API_INVALID_ARGUMENT&&!job);
    bad=input.options;bad.candidate=nullptr;assert(ckfer_start_v1(&bad,&job)==CKFE_API_INVALID_ARGUMENT&&!job);
    bad=input.options;bad.prefix_bytes=0;assert(ckfer_start_v1(&bad,&job)==CKFE_API_INVALID_ARGUMENT&&!job);
    bad=input.options;bad.original_journal_name.version++;assert(ckfer_start_v1(&bad,&job)==CKFE_API_INVALID_ARGUMENT&&!job);
    assert(ckfer_start_v1(&input.options,&job)==CKFE_API_OK);auto before=await(job,false);assert(before.state==CKFER_AWAITING_REVIEW);
    assert(ckfer_wait_v1(job,1001)==CKFE_API_INVALID_ARGUMENT);
    ckfer_snapshot_v1 out;ckfer_snapshot_init_v1(&out);out.reserved=1;assert(ckfer_poll_v1(job,&out)==CKFE_API_INVALID_ARGUMENT&&out.reserved==1);
    assert(ckfer_cancel_v1(job)==CKFE_API_OK);auto after=await(job,true);assert(after.state==CKFER_CANCELLED&&!after.failure_code);ckfer_release(job);
    assert(missing(*fixture.directory,fixture.attempt_name)&&missing(*fixture.directory,fixture.final_name));fixture.unchanged();
}
ckfjr_snapshot_v1 root_poll(ckfjr_root* root) {
    ckfjr_snapshot_v1 result;ckfjr_snapshot_init_v1(&result);assert(ckfjr_poll_v1(root,&result)==CKFE_API_OK);return result;
}
ckfjr_root* prepare_root(const Fixture& fixture,const NativeName* child=nullptr) {
    ckfe_directory parent{};parent.cursor=fixture.journal_directory; // intentionally no navigation address
    ckfjr_options_v1 options;ckfjr_options_init_v1(&options);options.parent=&parent;
    if(child) {
        options.disposition=CKFJR_PROVISION_CHILD;const auto native=text(*child);
        options.child.encoding=native.encoding;options.child.data=native.data;options.child.byte_count=native.byte_count;
    }
    ckfjr_root* root=nullptr;assert(ckfjr_start_v1(&options,&root)==CKFE_API_OK);parent.cursor.reset();
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(30);
    while(std::chrono::steady_clock::now()<deadline) {
        const auto state=root_poll(root);
        if(state.state==CKFJR_READY)return root;
        if(state.worker_drained)std::fprintf(stderr,"root prep failed %u %lld %s\n",state.failure_state,static_cast<long long>(state.failure_code),state.failure_operation);
        assert(!state.worker_drained);ckfjr_wait_v1(root,100);
    }
    assert(false);return root;
}
void root_drained(ckfjr_root* root) {
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(30);
    while(std::chrono::steady_clock::now()<deadline) {
        const auto state=root_poll(root);
        if(state.worker_drained) {assert(state.state==CKFJR_COMPLETE&&!state.failure_code);ckfjr_release(root);return;}
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(false);
}
void c_prepared_roots(Fixture& fixture,bool finish_before_execution) {
    auto* original=prepare_root(fixture);const auto child=native("prepared-attempts"+std::to_string(sequence));
    auto* attempt=prepare_root(fixture,&child);
    CInput input(fixture);ckfer_native_init_v1(&input.options.original_journal_root);ckfer_native_init_v1(&input.options.attempt_journal_root);
    ckfer_job* job=nullptr;
    auto invalid=input.options;invalid.original_journal_root=text(fixture.root);
    assert(ckfer_start_with_journal_roots_v1(&invalid,original,attempt,&job)==CKFE_API_INVALID_ARGUMENT&&!job);
    assert(ckfer_start_with_journal_roots_v1(&input.options,original,attempt,&job)==CKFE_API_OK);
    // Root shutdown blocks new acquisitions, but must keep this consumer alive.
    if(finish_before_execution) {
        assert(ckfjr_finish_v1(original)==CKFE_API_OK&&ckfjr_finish_v1(attempt)==CKFE_API_OK);
        ckfer_job* refused=nullptr;assert(ckfer_start_with_journal_roots_v1(&input.options,original,attempt,&refused)==CKFE_API_OPERATION_UNAVAILABLE&&!refused);
    }
    const auto before=await(job,false);assert(before.state==CKFER_AWAITING_REVIEW);
    assert(!root_poll(original).worker_drained&&!root_poll(attempt).worker_drained);
    assert(ckfer_execute_v1(job,before.review_id)==CKFE_API_OK);const auto after=await(job,true);
#ifdef __APPLE__
    assert(after.state==CKFER_REVIEW_REQUIRED&&after.failure_state==CKFE_OBSERVATION_UNSUPPORTED);
#else
    assert(after.state==CKFER_COMPLETE&&after.copied_prefix_bytes==fixture.prefix);
    assert(read(*fixture.directory,fixture.final_name)==fixture.bytes);
#endif
    if(!finish_before_execution)
        assert(ckfjr_finish_v1(original)==CKFE_API_OK&&ckfjr_finish_v1(attempt)==CKFE_API_OK);
    // A terminal retry handle owns only cached results. Both native root
    // workers must close while that handle remains alive and pollable.
    root_drained(original);root_drained(attempt);
    const auto cached=poll(job);
    assert(cached.worker_drained&&cached.job_id==after.job_id&&cached.sequence==after.sequence&&
        cached.state==after.state&&cached.copied_prefix_bytes==after.copied_prefix_bytes&&
        cached.failure_code==after.failure_code&&
        std::memcmp(cached.source_digest,after.source_digest,sizeof(cached.source_digest))==0);
    ckfer_release(job);
    assert(missing(*fixture.directory,fixture.attempt_name));
    auto opened=take(fixture.journal_directory->open_directory_child(child));
    assert(!missing(*opened,fixture.attempt_name));fixture.unchanged();
    std::puts("Native C prepared original/attempt roots: pathless identity binding, cached-terminal root drain and independent lifecycle passed");
}
}
int main(int argc,char** argv) {
    assert(argc==2);assert(retry_c_smoke()==0);auto root=take(NativeAbsolutePath::from_host(std::filesystem::path(argv[1])));
    yes(prepare_native_operation_journal_root(root));NativeFileSystem fs;std::shared_ptr<const DirectoryCursor> directory(take(fs.open_native_directory(root)));
    {Fixture fixture(root,directory);native_positive(fixture);}
    {Fixture fixture(root,directory);c_positive(fixture);}
    {Fixture fixture(root,directory);c_validation(fixture);}
    {Fixture fixture(root,directory);c_prepared_roots(fixture,true);}
    {Fixture fixture(root,directory);c_prepared_roots(fixture,false);}
    for(bool tail:{false,true}) {
        Fixture fixture(root,directory);fixture.alternate_original(!tail,tail);auto job=take(VerifiedCopyRetryJob::create(fixture.request()));
        assert(review(*job)==VerifiedCopyRetryState::ReviewRequired);assert(job->failure());yes(job->finish_io());
        assert(missing(*directory,fixture.attempt_name)&&missing(*directory,fixture.final_name));fixture.unchanged();
    }
    {
        Fixture fixture(root,directory);auto job=take(VerifiedCopyRetryJob::create(fixture.request()));
        assert(review(*job)==VerifiedCopyRetryState::AwaitingReview);
        auto writer=open_native_operation_journal_file(*fixture.journal_root,fixture.original_name,false);
        if(writer.value()) {
            // POSIX private storage does not assert writer exclusion. Changed
            // original bytes must invalidate this exact reviewed operation.
            const std::array<std::byte,1> tail{std::byte{1}};
            assert(take((*writer.value())->write_at(take((*writer.value())->size()),tail))==1);
            yes((*writer.value())->finish_io());fixture.original_journal=read(*fixture.journal_directory,fixture.original_name);
            yes(job->approve());finish(*job);assert(job->state()==VerifiedCopyRetryState::ReviewRequired);
            assert(job->failure()->error.operation=="copy_retry.journal_changed");
        } else {
            // Windows keeps the original journal exclusively addressed while
            // reviewed; another writable open must be refused by the OS.
            assert(writer.state()==ObservationState::Denied);
            std::stop_source stop;stop.request_stop();assert(job->advance(stop.get_token())==VerifiedCopyRetryState::Cancelled);
        }
        yes(job->finish_io());assert(missing(*directory,fixture.attempt_name));fixture.unchanged();
    }
    {
        Fixture fixture(root,directory);WritableMapping mapping(root,fixture.candidate_name,static_cast<size_t>(fixture.prefix));
        auto job=take(VerifiedCopyRetryJob::create(fixture.request()));assert(review(*job)==VerifiedCopyRetryState::AwaitingReview);
        mapping.tamper();yes(job->approve());finish(*job);yes(job->finish_io());assert(job->state()==VerifiedCopyRetryState::ReviewRequired);
        assert(job->failure()->error.operation=="copy_retry.prefix_mismatch");assert(missing(*directory,fixture.attempt_name));fixture.unchanged(true);
    }
#ifndef __APPLE__
    {
        Fixture fixture(root,directory);WritableMapping mapping(root,fixture.candidate_name,static_cast<size_t>(fixture.prefix));
        auto job=take(VerifiedCopyRetryJob::create(fixture.request()));assert(review(*job)==VerifiedCopyRetryState::AwaitingReview);yes(job->approve());
        for(unsigned n=0;n<10000&&job->state()!=VerifiedCopyRetryState::Copying;++n)job->advance();
        assert(job->state()==VerifiedCopyRetryState::Copying);
        mapping.tamper();finish(*job);yes(job->finish_io());assert(job->state()==VerifiedCopyRetryState::ReviewRequired);
        assert(job->copied_prefix_bytes()==fixture.prefix&&missing(*directory,fixture.final_name));fixture.unchanged(true);
        std::puts("Post-review writable-mapping candidate substitution refused by frozen whole SHA");
    }
#endif
    {
        Fixture fixture(root,directory);WritableMapping mapping(root,fixture.source_name,fixture.bytes.size());
        auto job=take(VerifiedCopyRetryJob::create(fixture.request()));assert(review(*job)==VerifiedCopyRetryState::AwaitingReview);
        mapping.tamper();yes(job->approve());finish(*job);yes(job->finish_io());assert(job->state()==VerifiedCopyRetryState::ReviewRequired);
        assert(missing(*directory,fixture.attempt_name)&&missing(*directory,fixture.final_name));
        assert(read(*fixture.journal_directory,fixture.original_name)==fixture.original_journal);
        std::puts("Frozen reviewed source tamper refused before a new attempt");
    }
    {
        Fixture fixture(root,directory);auto job=take(VerifiedCopyRetryJob::create(fixture.request()));assert(review(*job)==VerifiedCopyRetryState::AwaitingReview);
        create_file(*directory,fixture.final_name,fixture.bytes);yes(job->approve());finish(*job);yes(job->finish_io());
        assert(job->state()==VerifiedCopyRetryState::ReviewRequired&&missing(*directory,fixture.attempt_name));assert(read(*directory,fixture.final_name)==fixture.bytes);fixture.unchanged();
    }
    std::puts("retry: stable C validation/receipts/drain, exact native names, prefix proof, tamper, ambiguity and no-overwrite regressions passed");
}
