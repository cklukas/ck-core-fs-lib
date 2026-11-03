// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Reuse real native fixture setup and its maintained controls; no fake cursor
// or forged snapshot is accepted as native provider/creation evidence.
#define main legacy_directory_main
#define wmain legacy_directory_wmain
#include "native_directory_replay_job_tests.cpp"
#undef main
#undef wmain
#include "directory_execution_source.hpp"
#include "directory_metadata_verify.hpp"
#include "metadata_semantic_digest.hpp"
#include "native_sync_observation.hpp"
#include "sha256.hpp"
namespace {
ComparisonObject object(const BasicMetadata& basic){ComparisonObject out;out.state=ComparisonObjectState::Stable;
 out.identity=*basic.identity.value();out.kind=*basic.kind.value();out.modified=*basic.modified.value();out.timestamp_quantum_ns=1;return out;}
ComparisonMetadataDigest reviewed(const NativeMetadataProof& proof){ComparisonMetadataDigest result;
 result.state=ComparisonDigestState::CompleteStable;result.algorithm=ComparisonDigestAlgorithm::Sha256;
 result.ownership=ComparisonMetadataOwnership::Original;result.bytes=take(detail::metadata_snapshot_semantic_digest(proof.snapshot()));
 result.before=result.after=object(proof.snapshot().basic);Sha256 hash;constexpr char domain[]="ck-core-fs-lib/native-preserved-metadata";
 hash.update(std::as_bytes(std::span(domain,sizeof(domain)-1)));std::array<std::byte,8> version{};
 for(unsigned i=0;i<version.size();++i)version[i]=std::byte((metadata_semantic_digest_version>>(i*8))&255);hash.update(version);result.schema=hash.digest();
 Sha256 app;constexpr char application[]="ck-core-fs-lib/reviewed-tree-preservation";app.update(std::as_bytes(std::span(application,sizeof(application)-1)));
 result.policy_binding=native_sync_policy_binding(app.digest(),proof.snapshot().policy);return result;}
ComparisonMetadataDigest review(HeldChild::Pointer source,MetadataReplayPolicy policy,MetadataCaptureLimits limits){
 auto capture=take(MetadataCaptureJob::begin_held(std::move(source),policy,limits));
 for(unsigned i=0;i<100000&&capture->progress().phase!=MetadataCapturePhase::Complete;++i){auto before=capture->progress();take(capture->advance());
  CHECK(capture->progress().read_calls-before.read_calls<=1);CHECK(capture->progress().read_bytes-before.read_bytes<=limits.read.max_bytes);}
 CHECK(capture->progress().phase==MetadataCapturePhase::Complete);auto proof=take(capture->result());auto result=reviewed(*proof);CHECK(take(capture->finish_io()));return result;}
DirectoryExecutionSourceJob::Pointer execution_source(Fixture& f,HeldChild::Pointer source,std::shared_ptr<MetadataCaptureBudget> budget,MetadataCaptureLimits limits){
 DirectoryExecutionSourceRequest request;request.source=source;request.reviewed=review(source,f.metadata.policy,limits);request.policy=f.metadata.policy;
 request.limits=limits;request.budget=std::move(budget);request.journal_root=f.root;request.verify_review=[](std::stop_token){return Observation<bool>::available(true);};
 auto job=take(DirectoryExecutionSourceJob::create(std::move(request)));
 for(unsigned i=0;i<100000&&job->progress().phase!=DirectorySourcePhase::Ready&&!job->progress().worker_drained;++i){auto before=job->progress();job->advance();
  CHECK(job->progress().read_calls-before.read_calls<=1);CHECK(job->progress().read_bytes-before.read_bytes<=limits.read.max_bytes);}
 if(job->progress().phase!=DirectorySourcePhase::Ready)std::fprintf(stderr,"source failure %s %lld finish%s %lld\n",job->progress().failure.operation.data(),(long long)job->progress().failure.code,job->progress().finish_failure.operation.data(),(long long)job->progress().finish_failure.code);
 CHECK(job->progress().phase==DirectorySourcePhase::Ready&&!job->progress().worker_drained);CHECK(!take(job->proof())->io_finished());return job;}
void bounded_await(NativeDirectoryReplayJob& job,DirectoryReplayPhase wanted){for(unsigned i=0;i<100000&&!terminal(job.progress().phase)&&job.progress().phase!=wanted;++i){auto before=job.progress();job.advance();CHECK(job.progress().content_reads-before.content_reads<=1);CHECK(job.progress().content_bytes-before.content_bytes<=4096);}
 if(job.progress().phase!=wanted)std::fprintf(stderr,"bounded failure phase%u error%s %lld finish%s %lld\n",unsigned(job.progress().phase),job.progress().failure.operation.data(),(long long)job.progress().failure.code,job.progress().finish_failure.operation.data(),(long long)job.progress().finish_failure.code);
 CHECK(job.progress().phase==wanted);}
void bounded_positive(const std::filesystem::path& path,bool existing,bool with_ads=false,bool complete=false){
 Fixture f(path,false,with_ads,complete);bool copied=false;HeldChild::Pointer child_binding;
 MetadataCaptureLimits limits;limits.read.max_bytes=4096;auto budget=std::make_shared<MetadataCaptureBudget>(limits);
 auto source=execution_source(f,f.source_held,budget,limits);auto original=take(source->proof());CHECK(take(source->start_revalidation()));
 for(unsigned i=0;i<100000&&source->progress().phase==DirectorySourcePhase::Rechecking;++i)source->advance();
 CHECK(source->progress().phase==DirectorySourcePhase::Ready&&!original->io_finished());CHECK(take(source->proof()).get()==original.get());
 auto request=f.request(existing,[&](std::stop_token stop){if(!copied)return Observation<bool>::available(false);auto now=child_binding->refresh(stop);
  if(!now.value())return Observation<bool>::unavailable(now.state(),now.unavailable_detail()->error);return Observation<bool>::available((*now.value())->continues(*child_binding));});
 DirectoryExecutionSourceJob::Pointer destination;
 if(existing){destination=execution_source(f,request.existing_destination,budget,limits);request.destination_review_proof=take(destination->proof());}
 request.source_proof=original;request.reviewed_metadata=original->snapshot();request.metadata_limits=limits;request.metadata_budget=budget;
 auto job=take(NativeDirectoryReplayJob::create(std::move(request)));CHECK(!job->verified_target_values());
#ifndef _WIN32
 if(!existing){bounded_await(*job,DirectoryReplayPhase::Unsupported);CHECK(!job->progress().creation_attempted);CHECK(take(source->finish_io()));CHECK(take(f.root->finish_io()));return;}
#endif
 bounded_await(*job,DirectoryReplayPhase::AwaitingChildren);CHECK(!original->io_finished());CHECK(!take(job->children_finished()));
 auto cursor=take(job->child_cursor());copy_payload(f,cursor);child_binding=take(HeldChild::observe_with_access(cursor,name("payload"),EntryAccess::ContentRead));copied=true;
 CHECK(take(job->children_finished()));bounded_await(*job,DirectoryReplayPhase::Complete);
 CHECK(job->progress().worker_drained&&!job->progress().recovery_required&&original->io_finished());CHECK(take(source->finish_io()));if(destination)CHECK(take(destination->finish_io()));
 auto target=take(HeldChild::observe(f.parent,f.target));auto captured=take(target->capture_metadata(f.metadata.policy));
 CHECK(take(detail::metadata_snapshot_semantic_digest(captured))==take(detail::metadata_snapshot_semantic_digest(f.metadata)));
 const auto* verified=job->verified_target_values();CHECK(verified);
 CHECK(verified->basic.identity.value()&&captured.basic.identity.value());
 CHECK(compare_identity(*verified->basic.identity.value(),*captured.basic.identity.value())==IdentityComparison::Same);
 CHECK(compare_identity(*verified->basic.identity.value(),*f.metadata.basic.identity.value())==IdentityComparison::Different);
 CHECK(take(detail::metadata_snapshot_semantic_digest(*verified))==take(detail::metadata_snapshot_semantic_digest(captured)));
 CHECK(!verified->channel_evidence);for(const auto& channel:verified->channels)CHECK(!channel.source);
 if(verified->security_coverage)CHECK(verified->security_coverage->recheck(*verified).state()==ObservationState::Unsupported);
 CHECK(take(directory_metadata_payload_digest_values(*verified))==take(directory_metadata_payload_digest_values(captured)));
 CHECK(take(payload_matches(*child_binding,{})));CHECK(take(f.root->finish_io()));CHECK(job->advance().phase==DirectoryReplayPhase::Complete);
 CHECK(job->verified_target_values()==verified);
 CHECK(take(detail::metadata_snapshot_semantic_digest(*job->verified_target_values()))==take(detail::metadata_snapshot_semantic_digest(captured)));
}
void source_cancel_ready(const std::filesystem::path& path){Fixture f(path);MetadataCaptureLimits limits;auto source=execution_source(f,f.source_held,std::make_shared<MetadataCaptureBudget>(limits),limits);
 auto proof=take(source->proof());std::stop_source stop;stop.request_stop();source->advance(stop.get_token());CHECK(source->progress().phase==DirectorySourcePhase::Cancelled);
 CHECK(source->progress().worker_drained&&proof->io_finished());CHECK(take(f.root->finish_io()));CHECK(source->advance().phase==DirectorySourcePhase::Cancelled);}
void bounded_changed_source(const std::filesystem::path& path){
 Fixture f(path);MetadataCaptureLimits limits;auto budget=std::make_shared<MetadataCaptureBudget>(limits);auto source=execution_source(f,f.source_held,budget,limits);
 auto request=f.request(true,[](std::stop_token){return Observation<bool>::available(true);});
 auto destination=execution_source(f,request.existing_destination,budget,limits);request.destination_review_proof=take(destination->proof());
 request.source_proof=take(source->proof());request.reviewed_metadata=request.source_proof->snapshot();request.metadata_limits=limits;request.metadata_budget=budget;
 auto job=take(NativeDirectoryReplayJob::create(std::move(request)));bounded_await(*job,DirectoryReplayPhase::AwaitingChildren);
#ifdef _WIN32
 directory_permissions(take(f.address.child_address(f.source_held->name())),false);
#else
 auto source_address=take(f.address.child_address(f.source_held->name()));CHECK(::chmod(source_address.host_path().value()->c_str(),0750)==0);
#endif
 auto result=job->children_finished();CHECK(!result.value()&&result.state()==ObservationState::Changed);
 CHECK(job->progress().worker_drained&&!job->progress().metadata_attempted&&!job->verified_target_values());
 CHECK(take(source->finish_io()));CHECK(take(destination->finish_io()));CHECK(take(f.root->finish_io()));
}
void bounded_finish_failure(const std::filesystem::path& path,bool writer_failure,bool oom=false){
 Fixture f(path);MetadataCaptureLimits limits;limits.read.max_bytes=4096;auto budget=std::make_shared<MetadataCaptureBudget>(limits);
 auto source=execution_source(f,f.source_held,budget,limits);auto request=f.request(true,[](std::stop_token){return Observation<bool>::available(true);});
 auto target_source=execution_source(f,request.existing_destination,budget,limits);auto proof=take(source->proof());
 request.source_proof=proof;request.reviewed_metadata=proof->snapshot();request.destination_review_proof=take(target_source->proof());request.metadata_limits=limits;request.metadata_budget=budget;
 auto job=take(NativeDirectoryReplayJob::create(std::move(request)));bounded_await(*job,DirectoryReplayPhase::AwaitingChildren);CHECK(take(job->children_finished()));
 bounded_await(*job,DirectoryReplayPhase::ClosingWriter);
 if(writer_failure){auto held=take(HeldChild::observe(f.parent,f.target));flush_target=*held->metadata().identity.value();injected_flushes=0;inject_writer_flush=true;}
 else {allocation_failures=0;detail::journal_root_test_fault=oom?journal_close_oom:journal_close_fault;}
 for(unsigned i=0;i<100000&&!terminal(job->progress().phase);++i)job->advance();
 inject_writer_flush=false;detail::journal_root_test_fault=nullptr;CHECK(!fail_next_allocation);if(oom)CHECK(allocation_failures==1);
 CHECK(job->progress().phase==DirectoryReplayPhase::ReviewRequired&&job->progress().worker_drained&&job->progress().recovery_required);
 CHECK(job->progress().finish_failure.present&&job->progress().finish_failure.code==5);CHECK(!job->verified_target_values());CHECK(proof->io_finished());
 if(writer_failure)CHECK(injected_flushes==1);source->finish_io();target_source->finish_io();
 auto root_result=f.root->finish_io();CHECK(!root_result.value()&&root_result.unavailable_detail()->error.code==5);
 const auto count=injected_flushes.load();job->advance();job.reset();CHECK(injected_flushes==count);
}
void bounded_run(const std::filesystem::path& path){bounded_positive(path,true);bounded_positive(path,false);source_cancel_ready(path);bounded_changed_source(path);bounded_finish_failure(path,true);bounded_finish_failure(path,false);bounded_finish_failure(path,false,true);
#ifdef _WIN32
 SecurityPrivilege privilege;bounded_positive(path,true,true);bounded_positive(path,false,true);bounded_positive(path,true,true,true);bounded_positive(path,false,true,true);
#endif
 std::printf("postorder worker controls total=%u\n",checks);}
}
#ifndef CKFS_DIRECTORY_WORKER_TEST_SUPPORT
#ifdef _WIN32
int wmain(int argc,wchar_t** argv){CHECK(argc==2);run(std::filesystem::path(argv[1]));bounded_run(std::filesystem::path(argv[1]));}
#else
int main(int argc,char** argv){CHECK(argc==2);run(std::filesystem::path(argv[1]));bounded_run(std::filesystem::path(argv[1]));}
#endif

#endif
