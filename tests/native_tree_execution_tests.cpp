// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#define CKFS_TREE_EXECUTION_TEST_SUPPORT
#include "reviewed_tree_plan_tests.cpp"
#undef CKFS_TREE_EXECUTION_TEST_SUPPORT
#ifdef CreateDirectory
#undef CreateDirectory
#endif
#include "ck_fs_tree.h"
#include "ck_fs_diagnostics.h"
#include "ck_fs_session.h"
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
  if(tree_journal_oom)tree_capture_test::fail_alloc=true;return 5;}
 return std::nullopt;
}
void close_failure_no_token(bool oom){
 Fixture f;write_file(f.path("s/a"),"reviewed main retained through close failure");auto r=strict_request(f);auto root=r.prepared_journal_root;
 auto job=take(ReviewedTreePlanJob::create(std::move(r)));bounded_preview(*job,4096);auto receipt=take(job->review({}));auto rows=take(job->reviewed_page(receipt,0,128));CHECK(take(job->begin_execution(receipt)));
 tree_journal_faults=0;tree_capture_test::ordinary_new_denials=0;
 tree_capture_test::ordinary_new_in_job=0;tree_capture_test::ordinary_new_outside_job=0;
 bool armed=false,threw=false;
 {
  struct ResetFault final {
   ~ResetFault()noexcept {
    detail::journal_root_test_fault=nullptr;tree_journal_oom=false;tree_capture_test::fail_alloc=false;
   }
  } reset;
  tree_journal_oom=oom;detail::journal_root_test_fault=tree_journal_close_fault;
  try{for(unsigned i=0;i<200000&&active(job->state());++i)bounded_advance(*job,4096);}catch(const std::bad_alloc&){threw=true;}
  armed=tree_capture_test::fail_alloc;
 }
 check_advance_bounds();
 CHECK(!tree_capture_test::fail_alloc);CHECK(tree_journal_faults==1);
 CHECK(!tree_capture_test::inside_job_advance&&tree_capture_test::ordinary_new_outside_job==0);
 CHECK(tree_capture_test::ordinary_new_denials==tree_capture_test::ordinary_new_in_job);
 CHECK(armed==oom&&(!threw||oom));
 CHECK(oom?tree_capture_test::ordinary_new_in_job>0:tree_capture_test::ordinary_new_in_job==0);
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
#ifdef __linux__
void mirror_and_replace_held_namespace(){
 Fixture f;
 mkdir_new(f.path("s/keepdir"));
 write_file(f.path("s/keepdir/new.txt"),"fresh mirror file");
 write_file(f.path("s/shared.txt"),"updated source content");
 mkdir_new(f.path("d/obsolete_dir"));
 write_file(f.path("d/obsolete_dir/stale.txt"),"to be deleted");
 write_file(f.path("d/extra_root.txt"),"extra root file");
 write_file(f.path("d/shared.txt"),"older target content");

 // Default strict handle-lock namespace policy stays Unsupported on POSIX.
 {
  auto r_strict=strict_request(f);
  r_strict.comparison.profile=ComparisonProfile::Mirror;
  auto strict_root=r_strict.prepared_journal_root;
  auto job_strict=take(ReviewedTreePlanJob::create(std::move(r_strict)));
  bounded_preview(*job_strict,4096);
  auto page0=take(job_strict->page(0,128));
  std::vector<ComparisonDecisionToken> del_tokens;
  for(const auto& item:page0.items)if(item.action==ReviewedTreeAction::RemoveFile||item.action==ReviewedTreeAction::RemoveDirectory)del_tokens.push_back(item.row.token);
  CHECK(del_tokens.size()==3);
  auto del_rec=take(job_strict->review_deletions(del_tokens));
  ConflictRule skip_existing;skip_existing.plan=job_strict->preview()->identity();
  skip_existing.kind=ConflictClass::ExistingRegular;skip_existing.choice=ConflictChoice::KeepTarget;skip_existing.scope=ConflictScope::MatchingClassInJob;
  auto rev=take(job_strict->review(std::span(&skip_existing,1),del_rec));
  auto begin=job_strict->begin_execution(rev);
  CHECK(!begin.value()&&begin.state()==ObservationState::Unsupported);
  job_strict.reset();
  CHECK(take(strict_root->finish_io()));
 }

 // Now execute full Mirror + Replace via ckfet_start_with_journal_root_v2 (CKFET_NAMESPACE_HELD_PARENT_RENAME).
 ckfe_engine* engine=nullptr;ckfe_directory* parent=nullptr;
 ckfe_entry *src_entry=nullptr,*dst_entry=nullptr;
 ckfe_error err{};ckfe_error_init(&err);
 CHECK(ckfe_engine_create(&engine)==CKFE_API_OK);
 const auto top_str=f.work.string();
 CHECK(ckfe_directory_open_utf8(engine,top_str.c_str(),0,&parent,&err)==CKFE_API_OK);
 CHECK(ckfe_entry_open_utf8(parent,"s",&src_entry,&err)==CKFE_API_OK);
 CHECK(ckfe_entry_open_utf8(parent,"d",&dst_entry,&err)==CKFE_API_OK);
 ckfjr_options_v1 jr_opts;ckfjr_options_init_v1(&jr_opts);
 jr_opts.parent=parent;jr_opts.disposition=CKFJR_PROVISION_CHILD;
 jr_opts.child.data="c_journals";jr_opts.child.byte_count=10;
 ckfjr_root* jr_root=nullptr;
 CHECK(ckfjr_start_v1(&jr_opts,&jr_root)==CKFE_API_OK&&jr_root);
 for(unsigned n=0;n<1000;++n){ckfjr_snapshot_v1 js;ckfjr_snapshot_init_v1(&js);CHECK(ckfjr_poll_v1(jr_root,&js)==CKFE_API_OK);if(js.state==CKFJR_READY)break;ckfjr_wait_v1(jr_root,10);}

 ckfet_options_v2 opts;ckfet_options_init_v2(&opts);
 opts.base.profile=CKFSP_MIRROR;
 opts.base.metadata_scope=CKFE_METADATA_ORDINARY_CALLER_VISIBLE_V1;
 opts.base.metadata_ownership=CKFE_OWNERSHIP_CURRENT_CALLER;
 opts.base.operation_id[0]=0x42;
 opts.namespace_policy=CKFET_NAMESPACE_HELD_PARENT_RENAME;
 ckfet_job* cjob=nullptr;
 CHECK(ckfet_start_with_journal_root_v2(src_entry,dst_entry,&opts,jr_root,&cjob,&err)==CKFE_API_OK&&cjob);
 ckfe_entry_destroy(src_entry);ckfe_entry_destroy(dst_entry);ckfe_directory_destroy(parent);ckfe_engine_destroy(engine);

 ckfet_snapshot_v1 snap{};
 for(unsigned n=0;n<5000;++n){CHECK(ckfet_poll_v1(cjob,&snap)==CKFE_API_OK);if(snap.state==CKFET_AWAITING_REVIEW||snap.state>=CKFET_COMPLETE)break;std::this_thread::sleep_for(std::chrono::milliseconds(1));}
 CHECK(snap.state==CKFET_AWAITING_REVIEW&&snap.plan_generation);

 ckfet_row_v1 rows[32]{};ckfet_page_v1 page{};
 CHECK(ckfet_page_v1_get(cjob,snap.plan_generation,0,rows,32,&page)==CKFE_API_OK);
 std::vector<uint64_t> deletions;
 for(uint64_t i=0;i<page.row_count;++i){
  if(rows[i].action==CKFET_REMOVE_FILE||rows[i].action==CKFET_REMOVE_DIRECTORY)
   deletions.push_back(rows[i].row_id);
 }
 CHECK(deletions.size()==3);

 ckfet_rule_v1 rule{};
 rule.version=CKFET_VERSION;rule.struct_size=sizeof(rule);
 rule.kind=CKFET_CONFLICT_EXISTING_REGULAR;rule.choice=CKFET_USE_SOURCE;
 rule.scope=CKFET_SCOPE_JOB;rule.protect_nonempty=1;rule.retain_replaced=1;
 rule.plan_generation=snap.plan_generation;
 uint64_t cmd=0;
 CHECK(ckfet_review_v1(cjob,snap.plan_generation,&rule,1,deletions.data(),deletions.size(),&cmd)==CKFE_API_OK&&cmd);
 for(unsigned n=0;n<5000;++n){CHECK(ckfet_poll_v1(cjob,&snap)==CKFE_API_OK);if(snap.command_id==cmd&&snap.command_state>=CKFET_COMMAND_ACCEPTED)break;std::this_thread::sleep_for(std::chrono::milliseconds(1));}
 CHECK(snap.command_state==CKFET_COMMAND_ACCEPTED&&snap.receipt_id);
 CHECK(ckfet_acknowledge_command_v1(cjob,cmd)==CKFE_API_OK);

 CHECK(ckfet_execute_v1(cjob,snap.plan_generation,snap.receipt_id,&cmd)==CKFE_API_OK&&cmd);
 for(unsigned n=0;n<10000;++n){CHECK(ckfet_poll_v1(cjob,&snap)==CKFE_API_OK);if(snap.state>=CKFET_COMPLETE)break;std::this_thread::sleep_for(std::chrono::milliseconds(1));}
 if(snap.state!=CKFET_COMPLETE||snap.failed_items||snap.recovery_required){
  ckfet_failure_details_v1 det;ckfet_failure_details_init_v1(&det);
  ckfet_get_failure_details_v1(cjob,&det);
  std::fprintf(stderr,"MIRROR_FAIL: state=%u fail=%u/%u/%lld op=%s completed=%llu failed=%llu\n",
   snap.state,snap.failure_state,snap.failure_domain,(long long)snap.failure_code,det.operation,
   (unsigned long long)snap.completed_items,(unsigned long long)snap.failed_items);
 }
 CHECK(snap.state==CKFET_COMPLETE&&!snap.failed_items&&!snap.recovery_required);
 uint32_t drained=0;
 for(unsigned n=0;n<5000&&!drained;++n){CHECK(ckfet_worker_drained_v1(cjob,&drained)==CKFE_API_OK);if(!drained)std::this_thread::sleep_for(std::chrono::milliseconds(1));}
 CHECK(drained==1);
 ckfet_release(cjob);
 CHECK(ckfjr_finish_v1(jr_root)==CKFE_API_OK);
 for(unsigned n=0;n<1000;++n){ckfjr_snapshot_v1 js;ckfjr_snapshot_init_v1(&js);CHECK(ckfjr_poll_v1(jr_root,&js)==CKFE_API_OK);if(js.worker_drained){CHECK(js.state==CKFJR_COMPLETE);break;}ckfjr_wait_v1(jr_root,10);}
 ckfjr_release(jr_root);ckfe_error_free(&err);

 CHECK(f.read("d/keepdir/new.txt")=="fresh mirror file");
 CHECK(f.read("d/shared.txt")=="updated source content");
 CHECK(!f.exists("d/obsolete_dir/stale.txt")&&!f.exists("d/obsolete_dir")&&!f.exists("d/extra_root.txt"));
 bool found_retained=false;
 for(const auto& entry:std::filesystem::directory_iterator(f.path("d"))){
  const auto fname=entry.path().filename().string();
  if(fname.starts_with(".ck-reviewed-retained-")){
   const auto rel=std::string("d/")+fname;
   found_retained=(f.read(rel.c_str())=="older target content");
  }
 }
 CHECK(found_retained);
 std::printf("Linux Mirror + Replace execution via ckfet_start_with_journal_root_v2 PASS\n");
}

void two_way_recursive_tree_held_namespace(){
 Fixture f;
 const auto left_p=f.path("left_tw"),right_p=f.path("right_tw"),coord_p=f.path("coord_tw");
 mkdir_new(left_p);mkdir_new(right_p);mkdir_new(coord_p);
 ::chmod(coord_p.c_str(),0700);
 mkdir_new(left_p/"docs");
 write_file(left_p/"docs/readme.txt","left initial readme");
 write_file(left_p/"root_left.txt","left root");
 mkdir_new(right_p/"notes");
 write_file(right_p/"notes/todo.txt","right initial todo");

 auto open_tw=[&](ckfss_two_way** out,ckfss_error* err){
  const auto ls=left_p.string(),rs=right_p.string(),cs=coord_p.string();
  ckfss_options o;ckfss_options_init(&o);
  o.coordinator={cs.data(),cs.size(),CKFSS_POSIX_BYTES,0};
  o.left={ls.data(),ls.size(),CKFSS_POSIX_BYTES,0};
  o.right={rs.data(),rs.size(),CKFSS_POSIX_BYTES,0};
  o.policy_fingerprint[0]=0x5a;
  ckfss_metadata_policy mp;ckfss_metadata_policy_init(&mp);
  mp.scope=CKFSS_METADATA_ORDINARY_V1;mp.ownership=CKFSS_OWNER_CURRENT_CALLER;
  ckfss_two_way_policy tp;ckfss_two_way_policy_init(&tp);
  tp.max_deletions=64;tp.max_delete_basis_points=10000;
  ckfss_two_way_tree_options_v1 tree;ckfss_two_way_tree_options_init_v1(&tree);
  tree.allow_recursive_trees=1;
  tree.namespace_policy=CKFSS_NAMESPACE_HELD_PARENT_RENAME;
  return ckfss_two_way_open_tree_v1(&o,&mp,&tp,&tree,nullptr,out,err);
 };
 auto run_to_complete=[&](ckfss_two_way* tw,uint32_t first_run,const ckfss_two_way_rule* rules=nullptr,uint64_t rule_count=0){
  ckfss_error err{};
  ckfss_two_way_review* rev=nullptr;
  CHECK(ckfss_two_way_assess_rules(tw,rules,rule_count,1,&rev,&err)==CKFSS_OK&&rev);
  CHECK(ckfss_two_way_approve_review(tw,rev,first_run,&err)==CKFSS_OK);
  ckfss_two_way_review_destroy(rev);
  ckfss_two_way_info info{};
  for(unsigned i=0;i<10000;++i){
   const auto st=ckfss_two_way_advance(tw,&info,&err);
   if(st!=CKFSS_OK)std::fprintf(stderr,"TW_ADVANCE_FAIL: st=%u obs=%u dom=%u code=%lld op=%s state=%u\n",
    st,err.observation,err.domain,(long long)err.code,err.operation,info.state);
   CHECK(st==CKFSS_OK);
   if(info.state==CKFSS_TW_COMPLETE)break;
  }
  CHECK(info.state==CKFSS_TW_COMPLETE&&!info.has_failure);
  CHECK(ckfss_two_way_finish_io(tw,&err)==CKFSS_OK);
 };

 // Gen 0 -> Gen 1: First-run bidirectional merge across nested directories.
 ckfss_two_way* tw=nullptr;ckfss_error err{};
 CHECK(open_tw(&tw,&err)==CKFSS_OK&&tw);
 ckfss_two_way_info info{};
 CHECK(ckfss_two_way_get_info(tw,&info)==CKFSS_OK&&info.generation==0&&info.rows==5);
 run_to_complete(tw,1);
 ckfss_two_way_destroy(tw);
 CHECK(std::filesystem::exists(right_p/"docs/readme.txt")&&std::filesystem::exists(left_p/"notes/todo.txt"));

 // Gen 1 -> Gen 2: Edit on left, new nested file on right, delete notes/todo.txt + notes/ on right!
 write_file(left_p/"docs/readme.txt","left edited gen2",true);
 mkdir_new(right_p/"deep");mkdir_new(right_p/"deep/sub");
 write_file(right_p/"deep/sub/leaf.txt","deep leaf payload");
 CHECK(std::filesystem::remove(right_p/"notes/todo.txt"));
 CHECK(std::filesystem::remove(right_p/"notes"));

 CHECK(open_tw(&tw,&err)==CKFSS_OK&&tw);
 CHECK(ckfss_two_way_get_info(tw,&info)==CKFSS_OK&&info.generation==1);
 run_to_complete(tw,0);
 ckfss_two_way_destroy(tw);
 CHECK(!std::filesystem::exists(left_p/"notes/todo.txt")&&!std::filesystem::exists(left_p/"notes"));
 CHECK(std::filesystem::exists(left_p/"deep/sub/leaf.txt"));
 auto read_posix=[](const std::filesystem::path& p){
  const int fd=::open(p.c_str(),O_RDONLY|O_NOFOLLOW);
  CHECK(fd>=0);
  char buf[256]{};
  const ssize_t n=::read(fd,buf,sizeof(buf));
  ::close(fd);
  CHECK(n>=0);
  return std::string(buf,static_cast<std::size_t>(n));
 };
 CHECK(read_posix(right_p/"docs/readme.txt")=="left edited gen2");
 CHECK(read_posix(left_p/"deep/sub/leaf.txt")=="deep leaf payload");

 // Gen 2 -> Gen 3: BothEdited conflict resolved via KeepRight rule!
 write_file(left_p/"root_left.txt","left conflicting edit",true);
 write_file(right_p/"root_left.txt","right winning edit",true);
 CHECK(open_tw(&tw,&err)==CKFSS_OK&&tw);
 CHECK(ckfss_two_way_get_info(tw,&info)==CKFSS_OK&&info.generation==2);
 ckfss_two_way_rule rule;ckfss_two_way_rule_init(&rule);
 rule.kind=CKFSS_CONFLICT_BOTH_EDITED;
 rule.choice=CKFSS_RULE_KEEP_RIGHT;
 rule.direction=CKFSS_DIRECTION_RIGHT_TO_LEFT;
 rule.expected_generation=info.generation;
 run_to_complete(tw,0,&rule,1);
 ckfss_two_way_destroy(tw);
 CHECK(read_posix(left_p/"root_left.txt")=="right winning edit");
 std::printf("Linux recursive Two-Way Sync (Gen 0->1->2->3, nested dirs, delete+retain, conflicts) PASS\n");
}
#endif
}
#ifndef CKFS_NATIVE_TREE_TEST_SUPPORT
#ifdef _WIN32
int wmain(int argc,wchar_t** argv){CHECK(argc==2||argc==3);CHECK(SetEnvironmentVariableW(L"TMPDIR",argv[1])&&SetEnvironmentVariableW(L"TEMP",argv[1])&&SetEnvironmentVariableW(L"TMP",argv[1]));
 const bool controls=argc==3&&std::wstring_view(argv[2])==L"--controls";
 if(!controls){regular_positive();directory_positive(false);directory_positive(true);}
 if(controls){source_changed_before_staging();foreign_target_effect();cancel_created_directory();close_failure_no_token(false);close_failure_no_token(true);}
 std::printf("native_tree_execution: %u checks passed\n",checks);return 0;}
#elif defined(__linux__)
int main(){regular_positive();directory_positive(false);directory_positive(true);source_changed_before_staging();foreign_target_effect();cancel_created_directory();close_failure_no_token(false);close_failure_no_token(true);
 mirror_and_replace_held_namespace();two_way_recursive_tree_held_namespace();
 std::printf("Linux receipt-bound regular/created/merged/mirror/two-way tree positives: %u checks passed\n",checks);return 0;}
#else
int main(){Fixture f;mkdir_new(f.path("s/folder"));write_file(f.path("s/folder/a"),"data");auto job=take(ReviewedTreePlanJob::create(strict_request(f)));bounded_preview(*job,4096);
 auto receipt=take(job->review({}));auto begin=job->begin_execution(receipt);CHECK(!begin.value()&&begin.state()==ObservationState::Unsupported);CHECK(!f.exists("d/folder"));
 std::printf("native tree unqualified POSIX creator refused before effects: %u checks passed\n",checks);return 0;}
#endif

#endif
