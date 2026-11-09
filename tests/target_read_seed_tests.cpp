// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#define CKFS_DIRECTORY_WORKER_TEST_SUPPORT
#include "directory_postorder_worker_tests.cpp"
#undef CKFS_DIRECTORY_WORKER_TEST_SUPPORT
#include "platform/native_target_read_seed.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
namespace {
MetadataCaptureBudget* close_budget=nullptr;
std::size_t close_reservations=0;
unsigned budgeted_closes=0;
bool consume_close_failure=false;
BOOL WINAPI seed_budget_close(HANDLE handle){
 using F=BOOL(WINAPI*)(HANDLE);static const auto real=std::bit_cast<F>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CloseHandle"));
 if(close_budget){CHECK(close_budget->retained_handle_reservations()==close_reservations);++budgeted_closes;}
 const auto result=real(handle);
 if(result&&consume_close_failure){consume_close_failure=false;SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 return result;
}
class SeedLatch final:public MetadataCaptureFailureLatch {
public:
 explicit SeedLatch(PreparedJournalRoot::Pointer root):root_(std::move(root)){}
 void record_first(MetadataCaptureCleanupError e)const noexcept override {
  if(!first)first=e;detail::record_prepared_journal_consumer_failure(*root_,e.state,e.domain,e.code,e.operation);
 }
 mutable std::optional<MetadataCaptureCleanupError> first;
private:PreparedJournalRoot::Pointer root_;
};
void directory_clone_budget(const std::filesystem::path& path,bool complete,bool outlive=false){
 Fixture f(path,false,true,complete);MetadataCaptureLimits limits;limits.read.max_bytes=4096;limits.max_retained_handles=32;
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
 auto entry=take(seed->source());
 // This is a chain of actual native capture clones (DuplicateHandle), NOT
 // shared_ptr copies. Each new native owner consumes exactly one reservation.
 const auto baseline=budget->retained_handle_reservations();
 CHECK(!f.metadata.channels.empty());
 auto stream=take(entry->open_metadata_replay_channel_read(f.metadata.channels.front().identifier));
 CHECK(budget->retained_handle_reservations()==baseline+1);
 CHECK(!seed->finish_io().value());
 MetadataReplaySnapshot stream_snapshot;stream_snapshot.channels.push_back(f.metadata.channels.front());
 stream_snapshot.channels.back().source=stream;
 detail::finish_native_metadata_capture(nullptr,stream_snapshot);
 CHECK(budget->retained_handle_reservations()==baseline);stream.reset();stream_snapshot.channels.clear();
 std::vector<std::shared_ptr<const OpenedEntry>> clones;
 while(budget->retained_handle_reservations()<limits.max_retained_handles){
  auto current=clones.empty()?entry:clones.back();const auto old=budget->retained_handle_reservations();
  clones.push_back(take(detail::open_native_metadata_capture_source(std::move(current),f.metadata.policy)));
  CHECK(budget->retained_handle_reservations()==old+1);
 }
 DWORD handles_before=0,handles_after=0;CHECK(GetProcessHandleCount(GetCurrentProcess(),&handles_before));
 auto rejected=detail::open_native_metadata_capture_source(clones.back(),f.metadata.policy);
 CHECK(!rejected.value()&&rejected.state()==ObservationState::Unsupported);
 CHECK(GetProcessHandleCount(GetCurrentProcess(),&handles_after));CHECK(handles_before==handles_after);
 CHECK(budget->retained_handle_reservations()==limits.max_retained_handles);
 CHECK(!seed->finish_io().value());CHECK(take(clones.back()->inspect_basic()).identity.value());
 // Closing the original explicitly must NOT erase the active clone count or
 // release a clone's budget, even when the seed's original manifest detaches.
 detail::finish_native_metadata_capture(entry.get(),{});entry.reset();
 CHECK(!seed->finish_io().value());
 // An active real clone remains a legitimate source after the original closed.
 detail::finish_native_metadata_capture(clones.back().get(),{});clones.pop_back();
 auto replacement=take(detail::open_native_metadata_capture_source(clones.back(),f.metadata.policy));
 CHECK(budget->retained_handle_reservations()==limits.max_retained_handles);
 close_budget=budget.get();close_reservations=limits.max_retained_handles;const auto replaced_closes=budgeted_closes;
 replacement.reset();close_budget=nullptr;CHECK(budgeted_closes==replaced_closes+1);
 while(clones.size()>(outlive?1U:0U)){
  const auto old=budget->retained_handle_reservations();
  close_budget=budget.get();close_reservations=old;const auto closes=budgeted_closes;
  if(clones.size()%2){detail::finish_native_metadata_capture(clones.back().get(),{});
   CHECK(budget->retained_handle_reservations()==old-1);}
  clones.pop_back();close_budget=nullptr;
  CHECK(budgeted_closes==closes+1);CHECK(budget->retained_handle_reservations()==old-1);
 }
 if(outlive){
  // Destroying the seed cannot revoke already returned native readers or lose
  // their budget/latch. The final real clone/ADS remain valid until consumed.
  seed.reset();CHECK(take(clones.back()->inspect_basic()).identity.value());
  auto late_stream=take(clones.back()->open_metadata_replay_channel_read(f.metadata.channels.front().identifier));
  CHECK(take(late_stream->inspect()).logical_size==payload.size());late_stream.reset();
  close_budget=budget.get();close_reservations=budget->retained_handle_reservations();
  consume_close_failure=true;clones.clear();close_budget=nullptr;CHECK(!consume_close_failure);
  CHECK(budget->retained_handle_reservations()==0);CHECK(latch->first&&latch->first->code==ERROR_ACCESS_DENIED);
  (void)source->finish_io();proof.reset();cursor.reset();payload_target.reset();latch.reset();
  auto final=f.root->finish_io();CHECK(!final.value()&&final.unavailable_detail()->error.code==ERROR_ACCESS_DENIED);return;
 }
 CHECK(budget->retained_handle_reservations()==baseline);
 // Original was deliberately consumed. Clone accounting is independent, so
 // finishing the seed now succeeds; a second fixture covers cursor lifetime.
 CHECK(take(seed->finish_io()));seed.reset();
 latch.reset();CHECK(take(source->finish_io()));proof.reset();cursor.reset();payload_target.reset();
 CHECK(budget->retained_handle_reservations()==0);CHECK(take(f.root->finish_io()));
}

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
 CHECK(take(native_metadata_proof_digest(*actual))==expected_digest);CHECK(take(capture->finish_io()));actual.reset();capture.reset();entry.reset();
 std::vector<Cursor> exhausted_parents;
 for(unsigned pass=0;pass<2;++pass){
  auto enumerator=take(seed->directory_cursor());CHECK(!seed->directory_cursor().value());
  CHECK(!seed->finish_io().value());
  std::vector<NativeName> names;DirectoryReadState state=DirectoryReadState::More;
  for(unsigned n=0;n<20&&state==DirectoryReadState::More;++n){auto list=std::const_pointer_cast<DirectoryCursor>(enumerator)->read(1);CHECK(list.state!=DirectoryReadState::Error);state=list.state;names.insert(names.end(),list.names.begin(),list.names.end());}
  CHECK(state==DirectoryReadState::End);CHECK(names.size()==3);
  for(const auto* wanted_name:{"payload","late-second","late-third"})CHECK(std::find(names.begin(),names.end(),name(wanted_name))!=names.end());
  exhausted_parents.push_back(enumerator);
  for(const auto& previous:exhausted_parents)CHECK(std::const_pointer_cast<DirectoryCursor>(previous)->read(1).state==DirectoryReadState::End);
 }
 CHECK(!seed->finish_io().value());
 exhausted_parents.clear();
 entry=take(seed->source());auto after=take(entry->inspect_basic());CHECK(before.accessed.value()&&after.accessed.value()&&*before.accessed.value()==*after.accessed.value());
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
extern "C" {decltype(&CloseHandle) __imp_CloseHandle=&seed_budget_close;}
int wmain(int argc,wchar_t** argv){CHECK(argc==2||argc==3);
 if(argc==3&&std::wstring_view(argv[2])==L"--fixture-address-only") {
  const auto address=fixture_native_address(std::filesystem::path(argv[1]));
  const auto path=extended_address(address);const auto* units=address.windows_units();CHECK(units);
  const auto handle=CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
   nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
  const auto error=handle==INVALID_HANDLE_VALUE?GetLastError():ERROR_SUCCESS;
  std::fprintf(stderr,"fixture-address open_error=%lu normalized_utf16=",static_cast<unsigned long>(error));
  for(const auto unit:*units)std::fprintf(stderr,"%04x",unsigned(unit));std::fputc('\n',stderr);
  CHECK(handle!=INVALID_HANDLE_VALUE);FILE_ID_INFO id{};FILE_ATTRIBUTE_TAG_INFO tag{};
  CHECK(GetFileInformationByHandleEx(handle,FileIdInfo,&id,sizeof(id))&&GetFileInformationByHandleEx(handle,FileAttributeTagInfo,&tag,sizeof(tag)));
  CHECK((tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&!(tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));
  std::fprintf(stderr,"fixture-address volume=%llu file_id=",static_cast<unsigned long long>(id.VolumeSerialNumber));
  for(const auto unit:id.FileId.Identifier)std::fprintf(stderr,"%02x",unsigned(unit));std::fputc('\n',stderr);
  CHECK(CloseHandle(handle));return 0;
 }
 const bool complete=argc==3;CHECK(!complete||std::wstring_view(argv[2])==L"--complete");
 if(complete){SecurityPrivilege privilege;directory_clone_budget(std::filesystem::path(argv[1]),true);directory_clone_budget(std::filesystem::path(argv[1]),true,true);directory_seed(std::filesystem::path(argv[1]),true);}
 else {directory_clone_budget(std::filesystem::path(argv[1]),false);directory_clone_budget(std::filesystem::path(argv[1]),false,true);directory_seed(std::filesystem::path(argv[1]),false);}
 std::printf("target_read_seed: %u checks passed\n",checks);return 0;}

#else
int main(){return 0;}
#endif
