// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#define CKFS_TREE_EXECUTION_TEST_SUPPORT
#include "reviewed_tree_plan_tests.cpp"
#undef CKFS_TREE_EXECUTION_TEST_SUPPORT
#ifdef CreateDirectory
#undef CreateDirectory
#endif
namespace {
ReviewedTreePlanRequest strict_request(Fixture& f) {
 auto r=f.request();r.copy_policy.allow_unhandled_metadata_loss=false;
 MetadataReplayPolicy p;p.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;p.ownership=MetadataOwnership::Original;
 r.copy_policy.metadata_policy=p;r.copy_policy.metadata_scope=p.scope;
 r.digest_chunk_bytes=4096;r.copy_policy.copy_limits.chunk_bytes=4096;
 r.prepared_journal_root=take(acquire_native_journal_root(*r.journal_root));return r;
}
void execute_bounded(ReviewedTreePlanJob& job){
 for(unsigned i=0;i<200000&&active(job.state());++i)bounded_advance(job,4096);
 if(job.state()!=ReviewedTreeState::Complete&&job.progress().failure)std::fprintf(stderr,"execution state=%u op=%s code=%lld\n",unsigned(job.state()),job.progress().failure->error.operation.c_str(),static_cast<long long>(job.progress().failure->error.code));
 CHECK(job.state()==ReviewedTreeState::Complete);
}
void effect_tokens(ReviewedTreePlanJob& job,const ReviewedTreeReceipt& receipt,const ReviewedTreePage& reviewed){
 ReviewedTreeOwnEffectToken empty;CHECK(!empty.is_valid());
 for(const auto& item:reviewed.items)if(item.action==ReviewedTreeAction::Copy||item.action==ReviewedTreeAction::CreateDirectory||item.action==ReviewedTreeAction::MergeDirectory||item.action==ReviewedTreeAction::Replace){
  auto effect=take(job.completed_effect(item.row.token));CHECK(effect.is_valid());CHECK(take(job.verify_completed_effect(effect,receipt,item.row.token)));
  CHECK(!job.verify_completed_effect(empty,receipt,item.row.token).value());
  CHECK(!job.verify_completed_effect(effect,ReviewedTreeReceipt{},item.row.token).value());
  for(const auto& other:reviewed.items)if(other.row.token!=item.row.token)CHECK(!job.verify_completed_effect(effect,receipt,other.row.token).value());
 }
}
void regular_positive(){
 Fixture f;const std::string payload(8193,'r');write_file(f.path("s/a"),payload);attribute(f.path("s/a"),'x');
 auto r=strict_request(f);auto root=r.prepared_journal_root;auto job=take(ReviewedTreePlanJob::create(std::move(r)));bounded_preview(*job,4096);
 auto receipt=take(job->review({}));auto rows=take(job->reviewed_page(receipt,0,128));
 for(const auto& row:rows.items)CHECK(!job->completed_effect(row.row.token).value());
 CHECK(take(job->begin_execution(receipt)));execute_bounded(*job);CHECK(f.read("s/a")==payload&&f.read("d/a")==payload);
 effect_tokens(*job,receipt,rows);CHECK(take(root->finish_io()));effect_tokens(*job,receipt,rows);
 auto other=take(ReviewedTreePlanJob::create(strict_request(f)));bounded_preview(*other,4096);
 auto effect=take(job->completed_effect(rows.items.front().row.token));
 CHECK(!other->verify_completed_effect(effect,receipt,rows.items.front().row.token).value());
 std::printf("strict native regular copy/progressive metadata/targetseed/sealed completion PASS\n");
}
void source_changed_before_staging(){
 Fixture f;write_file(f.path("s/a"),"reviewed main");auto r=strict_request(f);auto root=r.prepared_journal_root;
 auto job=take(ReviewedTreePlanJob::create(std::move(r)));bounded_preview(*job,4096);auto receipt=take(job->review({}));auto rows=take(job->reviewed_page(receipt,0,128));
 CHECK(take(job->begin_execution(receipt)));for(unsigned i=0;i<200000&&job->state()==ReviewedTreeState::Revalidating;++i)bounded_advance(*job,4096);
 CHECK(job->state()==ReviewedTreeState::Executing);write_file(f.path("s/a"),"changed source main",true);
 for(unsigned i=0;i<200000&&active(job->state());++i)bounded_advance(*job,4096);
 CHECK(job->state()!=ReviewedTreeState::Complete&&!f.exists("d/a"));CHECK(f.read("s/a")=="changed source main");
 for(const auto& row:rows.items)CHECK(!job->completed_effect(row.row.token).value());CHECK(take(root->finish_io()));
 std::printf("fresh source changed before staging refuses execution/token PASS\n");
}
void foreign_target_effect(){
 Fixture f;write_file(f.path("s/a"),"reviewed main");auto r=strict_request(f);auto root=r.prepared_journal_root;
 auto job=take(ReviewedTreePlanJob::create(std::move(r)));bounded_preview(*job,4096);auto receipt=take(job->review({}));auto rows=take(job->reviewed_page(receipt,0,128));CHECK(take(job->begin_execution(receipt)));
 for(unsigned i=0;i<200000&&active(job->state())&&!job->progress().completed_items;++i)bounded_advance(*job,4096);
 CHECK(active(job->state())&&job->progress().completed_items==1);write_file(f.path("d/foreign"),"foreign input must never become an own effect");
 for(unsigned i=0;i<200000&&active(job->state());++i)bounded_advance(*job,4096);
 CHECK(job->state()!=ReviewedTreeState::Complete);CHECK(f.read("d/foreign")=="foreign input must never become an own effect");
 for(const auto& row:rows.items)CHECK(!job->completed_effect(row.row.token).value());CHECK(take(root->finish_io()));
 std::printf("foreign namespace mutation cannot mint/rebind own-effect facts PASS\n");
}
void cancel_created_directory(){
 Fixture f;mkdir_new(f.path("s/folder"));write_file(f.path("s/folder/a"),"source remains intact");auto r=strict_request(f);auto root=r.prepared_journal_root;
 auto job=take(ReviewedTreePlanJob::create(std::move(r)));bounded_preview(*job,4096);auto receipt=take(job->review({}));auto rows=take(job->reviewed_page(receipt,0,128));CHECK(take(job->begin_execution(receipt)));
 for(unsigned i=0;i<200000&&active(job->state())&&!f.exists("d/folder");++i)bounded_advance(*job,4096);
 CHECK(active(job->state())&&f.exists("d/folder"));std::stop_source stop;stop.request_stop();bounded_advance(*job,4096,stop.get_token());
 CHECK(job->state()!=ReviewedTreeState::Complete&&job->progress().recovery_required);CHECK(f.read("s/folder/a")=="source remains intact");
 for(const auto& row:rows.items)CHECK(!job->completed_effect(row.row.token).value());CHECK(take(root->finish_io()));
 std::printf("post-create cancellation drains native owners and retains recovery evidence PASS\n");
}
thread_local bool tree_journal_oom=false;thread_local unsigned tree_journal_faults=0;
std::optional<std::int64_t> tree_journal_close_fault(detail::JournalRootFaultPoint point){
 if(point==detail::JournalRootFaultPoint::JournalClose&&!tree_journal_faults){++tree_journal_faults;
  if(tree_journal_oom){tree_capture_test::fail_alloc=true;tree_capture_test::defer_debug_proxy=true;}return 5;}
 return std::nullopt;
}
void close_failure_no_token(bool oom){
 Fixture f;write_file(f.path("s/a"),"reviewed main retained through close failure");auto r=strict_request(f);auto root=r.prepared_journal_root;
 auto job=take(ReviewedTreePlanJob::create(std::move(r)));bounded_preview(*job,4096);auto receipt=take(job->review({}));auto rows=take(job->reviewed_page(receipt,0,128));CHECK(take(job->begin_execution(receipt)));
 tree_journal_faults=0;tree_journal_oom=oom;detail::journal_root_test_fault=tree_journal_close_fault;
 try{for(unsigned i=0;i<200000&&active(job->state());++i)bounded_advance(*job,4096);}catch(const std::bad_alloc&){}
 detail::journal_root_test_fault=nullptr;tree_journal_oom=false;CHECK(!tree_capture_test::fail_alloc);CHECK(tree_journal_faults==1);
 CHECK(job->state()==ReviewedTreeState::NeedsReconciliation&&job->progress().recovery_required);
 CHECK(job->progress().failure&&job->progress().failure->error.code==5);CHECK(f.read("s/a")=="reviewed main retained through close failure");
 for(const auto& row:rows.items)CHECK(!job->completed_effect(row.row.token).value());detail::PreparedJournalConsumerFailure error;
 CHECK(detail::read_prepared_journal_consumer_failure(*root,error)&&error.code==5);CHECK(!root->finish_io().value());
 std::printf("actual journal close%s preserves first error/Root drain/no completion token PASS\n",oom?"+diagnostic OOM":"");
}
void directory_positive(bool existing){
 Fixture f;mkdir_new(f.path("s/folder"));mkdir_new(f.path("s/folder/nested"));
 write_file(f.path("s/folder/a"),"first native payload");write_file(f.path("s/folder/nested/b"),"second native payload");
 attribute(f.path("s/folder"),'d');attribute(f.path("s/folder/nested"),'n');attribute(f.path("s/folder/a"),'a');
 if(existing){mkdir_new(f.path("d/folder"));mkdir_new(f.path("d/folder/nested"));}
 auto r=strict_request(f);auto root=r.prepared_journal_root;auto job=take(ReviewedTreePlanJob::create(std::move(r)));bounded_preview(*job,4096);
 ConflictRule merge;merge.plan=job->preview()->identity();merge.kind=ConflictClass::DirectoryPair;merge.choice=ConflictChoice::MergeFolders;merge.scope=ConflictScope::MatchingClassInJob;
 auto receipt=take(job->review(std::span(&merge,1)));auto rows=take(job->reviewed_page(receipt,0,128));
 CHECK(take(job->begin_execution(receipt)));execute_bounded(*job);
 CHECK(f.read("d/folder/a")=="first native payload"&&f.read("d/folder/nested/b")=="second native payload");
 effect_tokens(*job,receipt,rows);CHECK(take(root->finish_io()));effect_tokens(*job,receipt,rows);
 std::printf("strict native %s directory postorder/children/ADS/targetseed/sealed completion PASS\n",existing?"merged":"created");
}
}
#ifndef CKFS_NATIVE_TREE_TEST_SUPPORT
#ifdef _WIN32
int wmain(int argc,wchar_t** argv){CHECK(argc==2||argc==3);CHECK(SetEnvironmentVariableW(L"TMPDIR",argv[1])&&SetEnvironmentVariableW(L"TEMP",argv[1])&&SetEnvironmentVariableW(L"TMP",argv[1]));
 const bool controls=argc==3&&std::wstring_view(argv[2])==L"--controls";
 if(!controls){regular_positive();directory_positive(false);directory_positive(true);}
 if(controls){source_changed_before_staging();foreign_target_effect();cancel_created_directory();close_failure_no_token(false);close_failure_no_token(true);}
 std::printf("native_tree_execution: %u checks passed\n",checks);return 0;}
#elif defined(__linux__)
int main(){regular_positive();directory_positive(true);source_changed_before_staging();foreign_target_effect();close_failure_no_token(false);close_failure_no_token(true);
 Fixture f;mkdir_new(f.path("s/folder"));write_file(f.path("s/folder/a"),"data");auto job=take(ReviewedTreePlanJob::create(strict_request(f)));bounded_preview(*job,4096);
 auto receipt=take(job->review({}));auto begin=job->begin_execution(receipt);CHECK(!begin.value()&&begin.state()==ObservationState::Unsupported);CHECK(!f.exists("d/folder"));
 std::printf("Linux receipt-bound regular/merged tree positives and unqualified new-directory refusal: %u checks passed\n",checks);return 0;}
#else
int main(){Fixture f;mkdir_new(f.path("s/folder"));write_file(f.path("s/folder/a"),"data");auto job=take(ReviewedTreePlanJob::create(strict_request(f)));bounded_preview(*job,4096);
 auto receipt=take(job->review({}));auto begin=job->begin_execution(receipt);CHECK(!begin.value()&&begin.state()==ObservationState::Unsupported);CHECK(!f.exists("d/folder"));
 std::printf("native tree unqualified POSIX creator refused before effects: %u checks passed\n",checks);return 0;}
#endif

#endif
