// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#define CKFS_DIRECTORY_WORKER_TEST_SUPPORT
#include "directory_postorder_worker_tests.cpp"
#undef CKFS_DIRECTORY_WORKER_TEST_SUPPORT
#include "platform/native_target_read_seed.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
namespace {
class SeedLatch final:public MetadataCaptureFailureLatch {
public:
 explicit SeedLatch(PreparedJournalRoot::Pointer root):root_(std::move(root)){}
 void record_first(MetadataCaptureCleanupError e)const noexcept override {
  if(!first)first=e;detail::record_prepared_journal_consumer_failure(*root_,e.state,e.domain,e.code,e.operation);
 }
 mutable std::optional<MetadataCaptureCleanupError> first;
private:PreparedJournalRoot::Pointer root_;
};
void directory_seed(const std::filesystem::path& path,bool complete){
 Fixture f(path,false,true,complete);MetadataCaptureLimits limits;limits.read.max_bytes=4096;
 auto budget=std::make_shared<MetadataCaptureBudget>(limits);auto source=execution_source(f,f.source_held,budget,limits);
 auto proof=take(source->proof());auto latch=std::make_shared<SeedLatch>(f.root);
 detail::NativeTargetReadSeed::Pointer seed;HeldChild::Pointer payload_target;bool children_done=false;
 auto request=f.request(false,[&](std::stop_token stop){if(!children_done)return Observation<bool>::available(false);return payload_matches(*payload_target,stop);});
 request.source_proof=proof;request.reviewed_metadata=proof->snapshot();request.metadata_limits=limits;request.metadata_budget=budget;
 request.prepare_target_observation=[&](OpenedEntry& target,std::stop_token stop){
  if(!seed){auto started=detail::begin_native_target_read_seed(target,proof,limits,budget,latch);
   if(!started.value())return Observation<OperationMetadataStep>::unavailable(started.state(),started.unavailable_detail()->error);
   seed=std::move(started).take_value();return Observation<OperationMetadataStep>::available(OperationMetadataStep::Pending);}
  auto step=seed->advance(stop);if(!step.value())return Observation<OperationMetadataStep>::unavailable(step.state(),step.unavailable_detail()->error);
  return Observation<OperationMetadataStep>::available(*step.value()?OperationMetadataStep::Complete:OperationMetadataStep::Pending);
 };
 auto job=take(NativeDirectoryReplayJob::create(std::move(request)));bounded_await(*job,DirectoryReplayPhase::AwaitingChildren);
 auto cursor=take(job->child_cursor());
 auto prepopulation=std::const_pointer_cast<DirectoryCursor>(cursor)->read(64);CHECK(prepopulation.state==DirectoryReadState::End&&prepopulation.names.empty());
 copy_payload(f,cursor);file(cursor,name("late-second"));file(cursor,name("late-third"));payload_target=take(HeldChild::observe_with_access(cursor,name("payload"),EntryAccess::ContentRead));children_done=true;
 CHECK(take(job->children_finished()));bounded_await(*job,DirectoryReplayPhase::Complete);CHECK(seed&&proof->io_finished());
 auto expected=job->verified_target_values();CHECK(expected);const auto expected_digest=take(detail::metadata_snapshot_semantic_digest(*expected));
 auto entry=take(seed->source());auto before=take(entry->inspect_basic());
 auto capture=take(MetadataCaptureJob::begin(entry,f.metadata.policy,limits,budget,latch));
 for(unsigned i=0;i<100000&&capture->progress().phase!=MetadataCapturePhase::Complete;++i){auto old=capture->progress();take(capture->advance());
  CHECK(capture->progress().read_calls-old.read_calls<=1);CHECK(capture->progress().read_bytes-old.read_bytes<=limits.read.max_bytes);}
 CHECK(capture->progress().phase==MetadataCapturePhase::Complete);auto actual=take(capture->result());
 CHECK(take(native_metadata_proof_digest(*actual))==expected_digest);CHECK(take(capture->finish_io()));actual.reset();capture.reset();
 std::vector<Cursor> exhausted_parents;
 for(unsigned pass=0;pass<2;++pass){
  auto enumerator=take(seed->directory_cursor());CHECK(!seed->directory_cursor().value());
  std::vector<NativeName> names;DirectoryReadState state=DirectoryReadState::More;
  for(unsigned n=0;n<20&&state==DirectoryReadState::More;++n){auto list=std::const_pointer_cast<DirectoryCursor>(enumerator)->read(1);CHECK(list.state!=DirectoryReadState::Error);state=list.state;names.insert(names.end(),list.names.begin(),list.names.end());}
  CHECK(state==DirectoryReadState::End);CHECK(names.size()==3);
  for(const auto* wanted_name:{"payload","late-second","late-third"})CHECK(std::find(names.begin(),names.end(),name(wanted_name))!=names.end());
  exhausted_parents.push_back(enumerator);
  for(const auto& previous:exhausted_parents)CHECK(std::const_pointer_cast<DirectoryCursor>(previous)->read(1).state==DirectoryReadState::End);
 }
 exhausted_parents.clear();
 auto after=take(entry->inspect_basic());CHECK(before.accessed.value()&&after.accessed.value()&&*before.accessed.value()==*after.accessed.value());
 CHECK(before.modified.value()&&after.modified.value()&&*before.modified.value()==*after.modified.value());
 entry.reset();CHECK(take(seed->finish_io()));CHECK(!seed->source().value());seed.reset();
 auto closed_target=take(HeldChild::observe(f.parent,f.target));const auto& closed_basic=closed_target->metadata();
 CHECK(closed_basic.accessed.value()&&before.accessed.value()&&*closed_basic.accessed.value()==*before.accessed.value());
 CHECK(closed_basic.modified.value()&&before.modified.value()&&*closed_basic.modified.value()==*before.modified.value());
 closed_target.reset();CHECK(!latch->first);latch.reset();CHECK(take(source->finish_io()));
 proof.reset();cursor.reset();payload_target.reset();CHECK(budget->retained_handle_reservations()==0);CHECK(take(f.root->finish_io()));CHECK(job->progress().worker_drained&&job->verified_target_values());
}
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv){CHECK(argc==2||argc==3);const bool complete=argc==3;CHECK(!complete||std::wstring_view(argv[2])==L"--complete");if(complete){SecurityPrivilege privilege;directory_seed(std::filesystem::path(argv[1]),true);}else directory_seed(std::filesystem::path(argv[1]),false);std::printf("target_read_seed: %u checks passed\n",checks);return 0;}
#else
int main(){return 0;}
#endif
