// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_archive_write_job.hpp"
#include "platform/native_archive_file.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "sha256.hpp"
#include "staging_file.hpp"
#include "data_layout.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
namespace ck::files {
namespace {
using Failure=MetadataCaptureCleanupError;
Failure invalid(const char* op){return {ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),op};}
Failure unavailable(const UnavailableObservation& e){return {e.state,e.error.domain,e.error.code,"archive.native"};}
NativeArchiveFailure fixed(Failure f)noexcept{
    NativeArchiveFailure out;out.state=f.state;out.domain=f.domain;out.code=f.code;
    for(std::size_t i=0;i+1<out.operation.size()&&f.operation[i];++i)out.operation[i]=f.operation[i];return out;
}
bool terminal(NativeArchivePhase p){return p==NativeArchivePhase::Complete||p==NativeArchivePhase::Cancelled||p==NativeArchivePhase::NeedsReconciliation;}
void u64(std::vector<std::byte>& out,std::uint64_t n){for(unsigned i=0;i<8;++i)out.push_back(std::byte((n>>(8*i))&255));}
void exact_name(std::vector<std::byte>& out,const NativeName& n){
    out.push_back(std::byte(n.encoding()==NameEncoding::PosixBytes?0:1));
    if(const auto* p=n.posix_bytes()){u64(out,p->size());for(unsigned char c:*p)out.push_back(std::byte(c));}
    else {const auto& w=*n.windows_units();u64(out,w.size()*2);for(auto c:w){out.push_back(std::byte(c&255));out.push_back(std::byte(c>>8));}}
}
}
struct NativeArchiveWriteJob::Impl final:MetadataCaptureFailureLatch {
    NativeArchiveWriteRequest request;
    NativeArchiveProgress progress;
    JournalScopeGuard::Pointer scope;
    OperationJournal::Pointer journal;
    std::unique_ptr<OperationJournalFile> file;
    CreatedStagingFile stage;
    std::vector<std::byte> expected;
    Sha256 hash;
    std::optional<BasicMetadata> verify_before;
    std::size_t extent=0,extent_offset=0;
    NativeArchivePhase outcome=NativeArchivePhase::Cancelled;
    mutable std::optional<Failure> local_failure;
    bool native_drained=false;
    explicit Impl(NativeArchiveWriteRequest r):request(std::move(r)),expected(request.step_bytes){}
    void record_first(Failure f) const noexcept override {
        // Native Root's first-writer slot wins, even if still provisional.
        if(request.journal_root)detail::record_prepared_journal_consumer_failure(*request.journal_root,f.state,f.domain,f.code,f.operation);
        if(!local_failure)local_failure=f;
    }
    void fail(Failure f)noexcept{record_first(f);outcome=NativeArchivePhase::NeedsReconciliation;progress.phase=NativeArchivePhase::Drain;}
    void defer_exception(const char* operation)noexcept{
        if(!local_failure)local_failure=invalid(operation);
        outcome=NativeArchivePhase::NeedsReconciliation;progress.phase=NativeArchivePhase::Drain;
    }
    template<class T>bool accept(const Observation<T>& r,bool cancelled=false){if(r.value())return true;const auto& e=*r.unavailable_detail();
        if(cancelled&&e.error.domain==ErrorDomain::Adapter&&e.error.code==static_cast<std::int64_t>(AdapterError::InterruptedRead)){
            outcome=NativeArchivePhase::Cancelled;progress.phase=NativeArchivePhase::Drain;return false;
        }detail::record_prepared_journal_consumer_failure(*request.journal_root,e.state,e.error.domain,e.error.code,e.error.operation);fail(unavailable(e));return false;}
    bool okay(const Observation<bool>& r){if(!accept(r))return false;if(!*r.value()){fail(invalid("archive.false_success"));return false;}return true;}
    std::vector<std::byte> evidence()const {
        // Adapter evidence is descriptive only. It can never mint restart
        // cleanup authority. No staging hint is encoded as an anonymous name.
        std::vector<std::byte> out{std::byte{'A'},std::byte{'R'},std::byte{'W'},std::byte{2}};
        exact_name(out,request.destination_name);out.push_back(std::byte(progress.staging_namespace));
        out.push_back(std::byte(stage.name?1:0));if(stage.name)exact_name(out,*stage.name);
        u64(out,request.logical_size);out.push_back(std::byte(progress.image_verified?1:0));out.insert(out.end(),progress.digest.begin(),progress.digest.end());
        u64(out,request.application_evidence.size());out.insert(out.end(),request.application_evidence.begin(),request.application_evidence.end());return out;
    }
    bool append(OperationJournalState state){
        return okay(append_operation_journal_file(*file,*journal,{journal->records().size()+1,0,state,evidence()},request.codec_limits));
    }
    void close_stage()noexcept {
        if(!stage.entry)return;
        if(auto e=detail::finish_native_archive_file(*stage.entry))record_first(*e);
        // Includes the creator's held publication parent under this observer.
        stage.entry.reset();
    }
    void drain()noexcept {
        detail::MetadataCaptureCleanupScope observer(this);
        if(!native_drained){
            close_stage();
            if(file){try{auto r=file->finish_io();if(!r.value())record_first(unavailable(*r.unavailable_detail()));else if(!*r.value())record_first(invalid("archive.journal_finish"));}
                catch(...){detail::PreparedJournalConsumerFailure f;if(!detail::read_prepared_journal_consumer_failure(*request.journal_root,f))defer_exception("archive.journal_finish_exception");}}
            file.reset();scope.reset();request.destination.reset();native_drained=true;
        }
        detail::PreparedJournalConsumerFailure root;
        if(detail::read_prepared_journal_consumer_failure(*request.journal_root,root)){
            if(root.pending){progress.failure=fixed(invalid("archive.root_failure_pending"));progress.drained=false;progress.phase=NativeArchivePhase::Drain;return;}
            NativeArchiveFailure published;published.state=root.state;published.domain=root.domain;published.code=root.code;published.operation=root.operation;progress.failure=published;
        }else if(local_failure)progress.failure=fixed(*local_failure);else progress.failure.reset();
        progress.drained=true;progress.phase=progress.failure?NativeArchivePhase::NeedsReconciliation:outcome;
    }
    bool guard(){return okay(scope->check_root());}
    void step(std::stop_token stop){
        if(terminal(progress.phase))return;
        if(progress.phase==NativeArchivePhase::Drain){drain();return;}
        if(stop.stop_requested()&&!progress.published){outcome=NativeArchivePhase::Cancelled;progress.phase=NativeArchivePhase::Drain;drain();return;}
        if(!guard()){drain();return;}
        switch(progress.phase){
        case NativeArchivePhase::Planned: {
            progress.effects=true;auto opened=request.journal_root->open_journal(request.journal_name,true);if(!accept(opened))break;
            file=std::move(opened).take_value();progress.effects=true;
            if(append(OperationJournalState::Planned))progress.phase=NativeArchivePhase::Create;break;}
        case NativeArchivePhase::Create: {
            auto created=request.destination->create_staging_file(request.staging_hint);if(!accept(created))break;
            stage=std::move(created).take_value();progress.staging_namespace=stage.staging_namespace;
            if(!stage.entry||stage.staging_namespace==StagingNamespace::Unknown||
                (stage.staging_namespace==StagingNamespace::Anonymous&&stage.name)) {fail(invalid("archive.creation_result"));break;}
            progress.phase=NativeArchivePhase::Prepare;break;}
        case NativeArchivePhase::Prepare:
            if(okay(detail::prepare_native_archive_file(*stage.entry,request.logical_size,request.sparse))&&append(OperationJournalState::Prepared))progress.phase=NativeArchivePhase::Write;break;
        case NativeArchivePhase::Write: {
            if(extent==request.extents.size()){progress.phase=NativeArchivePhase::Flush;break;}
            const auto& e=request.extents[extent];const auto n=std::min(request.step_bytes,e.bytes.size()-extent_offset);
            auto written=stage.entry->write_content(e.offset+extent_offset,std::span(e.bytes).subspan(extent_offset,n),{request.step_bytes},stop);++progress.content_calls;
            if(!accept(written,stop.stop_requested()))break;
            if(!*written.value()||*written.value()>n){fail(invalid("archive.write_count"));break;}
            extent_offset+=*written.value();progress.written_bytes+=*written.value();
            if(extent_offset==e.bytes.size()){++extent;extent_offset=0;}break;}
        case NativeArchivePhase::Flush: {
            if(!okay(stage.entry->flush_content())||!append(OperationJournalState::Copied))break;
            auto b=stage.entry->inspect_basic();if(!accept(b))break;verify_before=std::move(b).take_value();
            if(!verify_before->logical_size.value()||*verify_before->logical_size.value()!=request.logical_size){fail(invalid("archive.size_after_write"));break;}
            extent=0;progress.phase=NativeArchivePhase::Layout;break;}
        case NativeArchivePhase::Layout: {
            if(request.sparse){
                auto layout=stage.entry->inspect_data_layout();if(!accept(layout))break;
                if(layout.value()->family==DataLayoutFamily::Unknown||layout.value()->logical_size!=request.logical_size||!layout.value()->owner.value()||
                    !verify_before->identity.value()||compare_identity(*layout.value()->owner.value(),*verify_before->identity.value())!=IdentityComparison::Same){fail(invalid("archive.layout_owner"));break;}
                std::uint64_t allocated=0,end=0;
                for(const auto& range:layout.value()->ranges){if(range.offset<end||range.offset>request.logical_size||range.length>request.logical_size-range.offset){fail(invalid("archive.layout_range"));break;}end=range.offset+range.length;allocated+=range.length;}
                if(progress.phase==NativeArchivePhase::Drain)break;
                progress.unallocated_bytes=request.logical_size-allocated;
                if(progress.unallocated_bytes<request.minimum_unallocated_bytes){fail(invalid("archive.sparse_requirement"));break;}
            }
            progress.phase=NativeArchivePhase::Verify;break;}
        case NativeArchivePhase::Verify: {
            if(progress.verified_bytes==request.logical_size){
                auto after=stage.entry->inspect_basic();if(!accept(after))break;
                if(!okay(detail::data_layout_metadata_unchanged(*verify_before,*after.value())))break;
                progress.digest=hash.digest();progress.image_verified=true;if(append(OperationJournalState::Verified))progress.phase=NativeArchivePhase::CommitIntent;break;
            }
            const auto off=progress.verified_bytes;const auto count=static_cast<std::size_t>(std::min<std::uint64_t>(request.step_bytes,request.logical_size-off));
            std::fill(expected.begin(),expected.begin()+count,std::byte{});
            while(extent<request.extents.size()&&request.extents[extent].offset+request.extents[extent].bytes.size()<=off)++extent;
            for(auto i=extent;i<request.extents.size()&&request.extents[i].offset<off+count;++i){const auto& e=request.extents[i];
                const auto lo=std::max(off,e.offset),hi=std::min(off+count,e.offset+e.bytes.size());
                std::copy_n(e.bytes.begin()+(lo-e.offset),hi-lo,expected.begin()+(lo-off));}
            auto read=stage.entry->read_content({count},off,stop);++progress.content_calls;if(!accept(read,stop.stop_requested()))break;
            const auto& bytes=read.value()->bytes;
            if(bytes.empty()||bytes.size()>count||!std::equal(bytes.begin(),bytes.end(),expected.begin())){fail(invalid("archive.verify_image"));break;}
            hash.update(bytes);progress.verified_bytes+=bytes.size();break;}
        case NativeArchivePhase::CommitIntent:
            if(append(OperationJournalState::CommitIntended))progress.phase=NativeArchivePhase::Publish;break;
        case NativeArchivePhase::Publish: {
            auto now=stage.entry->inspect_basic();if(!accept(now)||!okay(detail::data_layout_metadata_unchanged(*verify_before,*now.value())))break;
            progress.publication_attempted=true;progress.publication_uncertain=true;
            auto published=stage.entry->publish_noreplace(*request.destination,request.destination_name);
            // Both concrete native publishers reserve Changed for a proven
            // pre-publication refusal; post-effect ambiguity is Unknown.
            if(!published.value()&&published.state()==ObservationState::Changed)progress.publication_uncertain=false;
            if(okay(published)){progress.published=true;progress.publication_uncertain=false;progress.phase=NativeArchivePhase::Committed;}break;}
        case NativeArchivePhase::Committed:
            if(append(OperationJournalState::DestinationCommitted))progress.phase=NativeArchivePhase::CloseFile;break;
        case NativeArchivePhase::CloseFile:
            close_stage();
            if(local_failure){outcome=NativeArchivePhase::NeedsReconciliation;progress.phase=NativeArchivePhase::Drain;}
            else progress.phase=NativeArchivePhase::CompleteJournal;break;
        case NativeArchivePhase::CompleteJournal:
            if(append(OperationJournalState::Complete)){outcome=NativeArchivePhase::Complete;progress.phase=NativeArchivePhase::Drain;}break;
        default:fail(invalid("archive.phase"));break;
        }
        if(progress.phase==NativeArchivePhase::Drain)drain();
    }
};
NativeArchiveWriteJob::NativeArchiveWriteJob(std::unique_ptr<Impl> p):impl_(std::move(p)){}
NativeArchiveWriteJob::~NativeArchiveWriteJob(){finish_io();}
bool NativeArchiveWriteJob::platform_supports_publication() noexcept {
#if defined(__linux__) || defined(_WIN32)
    return true;
#else
    return false;
#endif
}
Observation<std::unique_ptr<NativeArchiveWriteJob>> NativeArchiveWriteJob::begin(NativeArchiveWriteRequest r){
    using R=Observation<std::unique_ptr<NativeArchiveWriteJob>>;
    const auto bad=[](const char* op){return R::unavailable(ObservationState::Failed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidLimit),op});};
    if(!r.destination||!r.journal_root||!r.step_bytes||r.step_bytes>1024*1024||r.logical_size>r.max_logical_size||r.minimum_unallocated_bytes>r.logical_size||(!r.sparse&&r.minimum_unallocated_bytes)||r.extents.size()>r.max_extents||r.application_evidence.size()>1024*1024||
        !r.destination_name.is_valid()||!r.staging_hint.is_valid()||!r.journal_name.is_valid()||r.destination_name==r.staging_hint||
        r.destination_name.encoding()!=r.journal_root->encoding()||r.destination_name.encoding()!=r.staging_hint.encoding()||r.journal_name.encoding()!=r.journal_root->encoding())return bad("archive.request");
    std::uint64_t end=0,total=0;
    for(const auto& e:r.extents){if(e.bytes.empty()||e.offset<end||e.offset>r.logical_size||e.bytes.size()>r.logical_size-e.offset||
        e.bytes.size()>r.max_recipe_bytes-total)return bad("archive.extents");end=e.offset+e.bytes.size();total+=e.bytes.size();}
    if (!platform_supports_publication())
        return R::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery),
             "create_staging_file.fd_publication_unqualified"});
    auto scope=JournalScopeGuard::create_for_namespace_child(r.journal_root,r.destination);if(!scope.value())return R::unavailable(scope.state(),scope.unavailable_detail()->error);
    auto journal=OperationJournal::create(FileOperation::Copy,r.journal_id,r.journal_limits);if(!journal.value())return R::unavailable(journal.state(),journal.unavailable_detail()->error);
    auto p=std::make_unique<Impl>(std::move(r));p->scope=std::move(scope).take_value();p->journal=std::move(journal).take_value();
    return R::available(std::unique_ptr<NativeArchiveWriteJob>(new NativeArchiveWriteJob(std::move(p))));
}
NativeArchiveProgress NativeArchiveWriteJob::advance(std::stop_token stop)noexcept{
    detail::MetadataCaptureCleanupScope observer(impl_.get());
    try{impl_->step(stop);}catch(...){impl_->defer_exception("archive.worker_exception");impl_->drain();}
    return impl_->progress;
}
NativeArchiveProgress NativeArchiveWriteJob::finish_io()noexcept{
    if(!terminal(impl_->progress.phase)){
        // Explicit finish/destruction only drains: it never appends new commit
        // records. A published/uncertain image with an interrupted protocol is
        // retained for reconciliation, never reported as clean cancellation.
        if(impl_->progress.phase!=NativeArchivePhase::Drain){
            if(impl_->progress.published||impl_->progress.publication_uncertain)
                impl_->outcome=NativeArchivePhase::NeedsReconciliation;
            impl_->progress.phase=NativeArchivePhase::Drain;
        }
        impl_->drain();
    }return impl_->progress;
}
const NativeArchiveProgress& NativeArchiveWriteJob::progress()const noexcept{return impl_->progress;}
}
