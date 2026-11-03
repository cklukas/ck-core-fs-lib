// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "native_filesystem.hpp"
#include "metadata_replay.hpp"
#include "metadata_capture_job.hpp"
#include "sha256.hpp"
#include "metadata_semantic_digest.hpp"
#include <sys/wait.h>
#include <sched.h>
#include <array>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <bit>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
using namespace ck::files;
namespace {
bool close_fault_armed=false;dev_t close_device{};ino_t close_inode{};unsigned close_fault_hits=0;
void need(bool v,const char*s){if(!v){std::fprintf(stderr,"probe failure %s errno%d\n",s,errno);std::exit(1);}}
template<class T>T get(Observation<T>o){if(!o.value()){auto&e=*o.unavailable_detail();std::fprintf(stderr,"probe %s state%u code%lld\n",e.error.operation.c_str(),unsigned(e.state),(long long)e.error.code);std::exit(1);}return std::move(o).take_value();}
NativeName name(const char*s){return *NativeName::from_posix(s);}
std::string text(const char*p){int fd=open(p,O_RDONLY|O_CLOEXEC);if(fd<0)return "UNAVAILABLE";std::string out;char b[4096];for(;;){auto n=read(fd,b,sizeof(b));if(n<=0)break;out.append(b,std::size_t(n));}need(!close(fd),"text close");return out;}
void credential(const char*phase){uid_t r,e,s;gid_t gr,ge,gs;need(!getresuid(&r,&e,&s)&&!getresgid(&gr,&ge,&gs),"ids");__user_cap_header_struct h{};h.version=_LINUX_CAPABILITY_VERSION_3;__user_cap_data_struct c[2]{};need(!syscall(SYS_capget,&h,c),"capget");std::printf("CREDENTIAL %s uid=%u/%u/%u gid=%u/%u/%u eff=%08x%08x prm=%08x%08x inh=%08x%08x groups=%d nnp=%d\n",phase,r,e,s,gr,ge,gs,c[1].effective,c[0].effective,c[1].permitted,c[0].permitted,c[1].inheritable,c[0].inheritable,getgroups(0,nullptr),prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0));std::printf("PROC_STATUS %s\n%sUID_MAP\n%sLSM\n%s\n",phase,text("/proc/self/status").c_str(),text("/proc/self/uid_map").c_str(),text("/sys/kernel/security/lsm").c_str());}
void reduce(bool original){need(!setgroups(0,nullptr),"clear groups");need(!prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0),"ambient clear");const unsigned allowed=(1U<<CAP_SYS_ADMIN)|(1U<<CAP_SETFCAP)|(original?((1U<<CAP_CHOWN)|(1U<<CAP_FOWNER)):0U);for(unsigned n=0;n<=40;++n)if(n>=32||!(allowed&(1U<<n)))need(!prctl(PR_CAPBSET_DROP,n,0,0,0),"bound drop");__user_cap_header_struct h{};h.version=_LINUX_CAPABILITY_VERSION_3;__user_cap_data_struct c[2]{};c[0].effective=c[0].permitted=allowed;need(!syscall(SYS_capset,&h,c),"capset");need(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0),"nnp");}
std::vector<std::byte> attr(int fd,const char*n){errno=0;auto size=fgetxattr(fd,n,nullptr,0);if(size<0){std::printf("ATTRIBUTE name=%s unavailable_errno=%d\n",n,errno);return{};}std::vector<std::byte>b(std::size_t(size),std::byte{});need(fgetxattr(fd,n,b.data(),b.size())==size,"getattr");std::printf("ATTRIBUTE name=%s bytes=%zu hex=",n,b.size());for(auto v:b)std::printf("%02x",std::to_integer<unsigned>(v));std::puts("");return b;}
std::array<std::byte,32> contents(int fd,const char*label){Sha256 hash;std::array<std::byte,65536>b{};std::uint64_t at=0;for(;;){auto n=pread(fd,b.data(),b.size(),off_t(at));need(n>=0,"independent data read");if(!n)break;hash.update(std::span(b.data(),std::size_t(n)));at+=std::size_t(n);}auto digest=hash.digest();std::printf("CONTENTS %s size=%llu sha256=",label,(unsigned long long)at);for(auto v:digest)std::printf("%02x",std::to_integer<unsigned>(v));std::puts("");return digest;}
struct Values{struct stat st{};struct statx sx{};std::array<std::vector<std::byte>,4> attrs;};
Values values(int fd,const char*label){Values v;need(!fstat(fd,&v.st)&&!statx(fd,"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,STATX_BASIC_STATS|STATX_BTIME,&v.sx),"native values");std::printf("NATIVE %s uid=%u gid=%u mode=%o dev=%llu ino=%llu nlink=%llu btime=%lld.%09u btime_known=%u atime=%lld.%09u mtime=%lld.%09u\n",label,v.st.st_uid,v.st.st_gid,unsigned(v.st.st_mode&07777),(unsigned long long)v.st.st_dev,(unsigned long long)v.st.st_ino,(unsigned long long)v.st.st_nlink,(long long)v.sx.stx_btime.tv_sec,v.sx.stx_btime.tv_nsec,unsigned((v.sx.stx_mask&STATX_BTIME)!=0),(long long)v.sx.stx_atime.tv_sec,v.sx.stx_atime.tv_nsec,(long long)v.sx.stx_mtime.tv_sec,v.sx.stx_mtime.tv_nsec);unsigned i=0;for(auto n:{"system.posix_acl_access","user.ck.full","trusted.ck.full","security.capability"})v.attrs[i++]=attr(fd,n);for(auto n:{"security.selinux","security.SMACK64","security.SMACK64EXEC","security.SMACK64MMAP","security.SMACK64TRANSMUTE","security.SMACK64IPIN","security.SMACK64IPOUT","security.ima","security.evm"})(void)attr(fd,n);return v;}
struct ReadCloseLatch final:MetadataCaptureFailureLatch {
 mutable std::optional<MetadataCaptureCleanupError> first;
 void record_first(MetadataCaptureCleanupError e)const noexcept override{if(!first)first=e;}
};
void drain_snapshot(const MetadataReplaySnapshot& snapshot){ReadCloseLatch latch;detail::MetadataCaptureCleanupScope scope(&latch);detail::finish_native_metadata_capture(nullptr,snapshot);need(!latch.first,"legacy proof read-owner close");}
struct ForgedCoverage final:MetadataSecurityCoverageEvidence {
 MetadataSecurityCoverage family()const noexcept override{return MetadataSecurityCoverage::LinuxPersistentSecurityV1;}
 Observation<bool> recheck(const MetadataReplaySnapshot&)const override{return Observation<bool>::available(true);}
};
void denied_apply(OpenedEntry& target,const MetadataReplaySnapshot& snapshot,int targetfd,const Values& initial,const char* label){
 auto attempt=apply_metadata_replay(target,snapshot);need(!attempt.value(),label);auto actual=values(targetfd,label);
 need(actual.attrs==initial.attrs&&actual.st.st_uid==initial.st.st_uid&&actual.st.st_gid==initial.st.st_gid&&(actual.st.st_mode&07777)==(initial.st.st_mode&07777),"preflight refusal had metadata effects");
 const auto&e=*attempt.unavailable_detail();std::printf("PASS negative %s state=%u code=%lld op=%s\n",label,unsigned(e.state),(long long)e.error.code,e.error.operation.c_str());
}
void sgid_control(const DirectoryCursor& directory,OpenedEntry& target,int sourcefd,int targetfd,const void* capability,std::size_t capability_size){
 struct statx sx{};need(!statx(sourcefd,"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,STATX_BTIME,&sx),"SGID btime query");if(sx.stx_mask&STATX_BTIME)return;
 need(!fchown(sourcefd,0,1)&&!fchmod(sourcefd,02660),"SGID actual source fixture");
 for(bool allowed:{false,true}){std::fflush(nullptr);pid_t pid=fork();need(pid>=0,"SGID fork");if(!pid){
  if(setgroups(0,nullptr))_exit(100);__user_cap_header_struct h{};h.version=_LINUX_CAPABILITY_VERSION_3;__user_cap_data_struct c[2]{};
  c[0].effective=c[0].permitted=allowed?0x00200011U:0x80200009U;if(syscall(SYS_capset,&h,c)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))_exit(101);
  MetadataReplayPolicy policy;policy.scope=RegularMetadataScope::CompleteMetadataV1;policy.ownership=MetadataOwnership::Original;policy.allow_privilege_metadata=true;
  auto source=get(directory.open_child(name("source"),EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));auto snapshot=get(capture_metadata_replay(*source,policy));auto applied=apply_metadata_replay(target,snapshot);bool correct=false;
  if(allowed){if(applied.value()&&*applied.value()){auto basic=get(target.inspect_basic());auto verified=verify_metadata_replay(target,snapshot,basic);struct stat actual{};correct=verified.value()&&*verified.value()&&!fstat(targetfd,&actual)&&actual.st_uid==0&&actual.st_gid==1&&(actual.st_mode&07777)==02660;}}
  else{struct stat actual{};correct=!applied.value()&&applied.state()==ObservationState::Denied&&applied.unavailable_detail()->error.operation=="metadata_replay.full_target_fsetid_required"&&!fstat(targetfd,&actual)&&actual.st_uid==0&&actual.st_gid==0&&(actual.st_mode&07777)==0600;}
  drain_snapshot(snapshot);ReadCloseLatch latch;{detail::MetadataCaptureCleanupScope scope(&latch);detail::finish_native_metadata_capture(source.get(),{});}if(latch.first)correct=false;
  std::printf("SGID native %s capmask=%08x result=%u\n",allowed?"roundtrip":"before-effect-denial",c[0].effective,unsigned(correct));std::fflush(nullptr);_exit(correct?0:102);
 }int status=0;need(waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"SGID privilege preflight/roundtrip");}
 // Restore only the task-owned data/metadata fixtures, before the two main
 // qualified workers drop their credentials. No host policy changes.
 for(const char*n:{"system.posix_acl_access","user.ck.full","trusted.ck.full"})need(!fremovexattr(targetfd,n),"SGID target fixture attr cleanup");
 need(!fchown(targetfd,0,0)&&!fchmod(targetfd,0600),"SGID target fixture restore");
 need(!fchown(sourcefd,1000,0)&&!fchmod(sourcefd,0660)&&!fsetxattr(sourcefd,"security.capability",capability,capability_size,0),"SGID source fixture restore");
 std::puts("PASS native SGID denies without group membership/CAP_FSETID before effects; explicit optin+CAP_FSETID preserves exact mode/group/ACL/xattrs");
}
void mapped_child_namespace_control(const OpenedEntry&source){
 int ready[2],go[2];need(!pipe2(ready,O_CLOEXEC)&&!pipe2(go,O_CLOEXEC),"userns pipes");std::fflush(nullptr);pid_t pid=fork();need(pid>=0,"userns fork");
 if(!pid){close(ready[0]);close(go[1]);if(unshare(CLONE_NEWUSER))_exit(90);if(write(ready[1],"R",1)!=1)_exit(91);char byte=0;if(read(go[0],&byte,1)!=1)_exit(92);close(ready[1]);close(go[0]);
  __user_cap_header_struct h{};h.version=_LINUX_CAPABILITY_VERSION_3;__user_cap_data_struct c[2]{};c[0].effective=c[0].permitted=0x80200009U;if(syscall(SYS_capset,&h,c))_exit(93);if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))_exit(94);
  std::printf("NEGATIVE child userns UID_MAP=%s",text("/proc/self/uid_map").c_str());MetadataReplayPolicy policy;policy.scope=RegularMetadataScope::CompleteMetadataV1;policy.ownership=MetadataOwnership::Original;policy.allow_privilege_metadata=true;auto result=capture_metadata_replay(source,policy);
  bool rejected=!result.value()&&result.state()==ObservationState::Unsupported&&result.unavailable_detail()->error.operation=="metadata_replay.initial_user_namespace_unqualified";
  if(!result.value())std::printf("NEGATIVE full-identity-map child native op=%s state=%u\n",result.unavailable_detail()->error.operation.c_str(),unsigned(result.state()));std::fflush(nullptr);_exit(rejected?0:95);
 }
 close(ready[1]);close(go[0]);char byte=0;need(read(ready[0],&byte,1)==1,"child namespace created");
 auto put=[&](const char*leaf,const char*value){std::string path="/proc/"+std::to_string(pid)+"/"+leaf;int fd=open(path.c_str(),O_WRONLY|O_CLOEXEC|O_NOFOLLOW);need(fd>=0,"userns map open");need(write(fd,value,strlen(value))==ssize_t(strlen(value))&&!close(fd),"userns map write");};
 put("setgroups","deny\n");put("uid_map","0 0 4294967295\n");put("gid_map","0 0 4294967295\n");need(write(go[1],"G",1)==1,"child map release");close(ready[0]);close(go[1]);int status=0;need(waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"mapped child userns impersonated initial");
 std::puts("PASS actual full-identity-mapped child namespace with CAP_SYS_ADMIN refuses; not counted as initial-userns positive");
}
void child_capability_control(const OpenedEntry&source,OpenedEntry&target,const MetadataReplaySnapshot&snapshot,unsigned capability,bool capture){
 std::fflush(nullptr);pid_t pid=fork();need(pid>=0,"negative fork");if(!pid){
  __user_cap_header_struct h{};h.version=_LINUX_CAPABILITY_VERSION_3;__user_cap_data_struct c[2]{};
  if(syscall(SYS_capget,&h,c))_exit(80);c[capability/32].effective&=~(1U<<(capability%32));c[capability/32].permitted&=~(1U<<(capability%32));if(syscall(SYS_capset,&h,c))_exit(81);
  bool refused;if(capture){auto result=capture_metadata_replay(source,snapshot.policy);refused=!result.value()&&result.state()==ObservationState::Unsupported;}
  else{auto result=apply_metadata_replay(target,snapshot);refused=!result.value()&&result.state()==ObservationState::Denied;}
  _exit(refused?0:82);
 }int status=0;need(waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"actual missing capability accepted");std::printf("PASS actual missing capability=%u %s refuses\n",capability,capture?"capture":"preflight");
}

}
int main(int argc,char**argv){need((argc==2||argc==3)&&getuid()==0&&geteuid()==0&&getgid()==0,"root setup only");static_assert(std::endian::native==std::endian::little);struct stat self{},init{};need(!stat("/proc/self/ns/user",&self)&&!stat("/proc/1/ns/user",&init)&&self.st_dev==init.st_dev&&self.st_ino==init.st_ino,"initial userns identity");std::printf("INITIAL_USERNS dev=%llu ino=%llu pid1match=1\n",(unsigned long long)self.st_dev,(unsigned long long)self.st_ino);credential("setup");
 need(!mkdir(argv[1],0700),"private fixture mkdir");int rootfd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);need(rootfd>=0,"root open");NativeFileSystem fs;auto directory=get(fs.open_directory(argv[1]));auto target=get(directory->create_child_file(name("target")));int sourcefd=openat(rootfd,"source",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC|O_NOATIME,0660);need(sourcefd>=0,"source create");int targetfd=openat(rootfd,"target",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NOATIME);need(targetfd>=0,"target readview");std::vector<std::byte> data(4097);for(std::size_t n=0;n<data.size();++n)data[n]=std::byte(n%251);need(write(sourcefd,data.data(),data.size())==ssize_t(data.size()),"source write");need(get(target->write_content(0,data))==data.size(),"target write");
 need(!fchown(sourcefd,1000,0)&&!fchmod(sourcefd,0660),"source owner/mode");
 const std::array<unsigned char,44> acl{2,0,0,0, 1,0,6,0,255,255,255,255, 2,0,4,0,233,3,0,0, 4,0,6,0,255,255,255,255, 16,0,6,0,255,255,255,255, 32,0,0,0,255,255,255,255};
 need(!fsetxattr(sourcefd,"system.posix_acl_access",acl.data(),acl.size(),0),"acl write");const unsigned char bytes[]{0,255,7,0,19};for(auto n:{"user.ck.full","trusted.ck.full"})need(!fsetxattr(sourcefd,n,bytes,sizeof(bytes),0),"xattr write");const std::array<std::uint32_t,5> caps{VFS_CAP_REVISION_2|VFS_CAP_FLAGS_EFFECTIVE,1U<<CAP_NET_BIND_SERVICE,0,0,0};need(!fsetxattr(sourcefd,"security.capability",caps.data(),sizeof(caps),0),"real filecap write");need(!fsync(sourcefd),"source flush");
 sgid_control(*directory,*target,sourcefd,targetfd,caps.data(),sizeof(caps));
 {auto negative_source=get(directory->open_child(name("source"),EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));mapped_child_namespace_control(*negative_source);ReadCloseLatch latch;detail::MetadataCaptureCleanupScope scope(&latch);detail::finish_native_metadata_capture(negative_source.get(),{});need(!latch.first,"negative source read close");}
 reduce(!(argc==3&&std::strcmp(argv[2],"caller")==0));credential("qualified-worker");auto main_before=contents(sourcefd,"source-before");need(main_before==contents(targetfd,"target-before"),"independent initial main content");auto before=values(sourcefd,"source-before");auto target_before=values(targetfd,"target-before");need(before.st.st_uid==1000&&before.st.st_gid==0&&before.attrs[0].size()==acl.size()&&before.attrs[2].size()==sizeof(bytes)&&before.attrs[3].size()==sizeof(caps),"native fixture class values");
 MetadataReplayPolicy p;p.scope=RegularMetadataScope::CompleteMetadataV1;p.ownership=(argc==3&&std::strcmp(argv[2],"caller")==0)?MetadataOwnership::CurrentCaller:MetadataOwnership::Original;p.allow_privilege_metadata=true;auto source=std::shared_ptr<const OpenedEntry>(get(directory->open_child(name("source"),EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity)));auto captured=capture_metadata_replay(*source,p);bool positive=false;
 if(captured.value()){
  need(captured.value()->security_coverage&&captured.value()->security_coverage->family()==MetadataSecurityCoverage::LinuxPersistentSecurityV1,"Complete genuine native Linux proof missing");
  const unsigned char integrity[]{1,2,3};need(!fsetxattr(targetfd,"security.ima",integrity,sizeof(integrity),0),"protected target fixture");denied_apply(*target,*captured.value(),targetfd,target_before,"target-protected-integrity-class");need(attr(targetfd,"security.ima")==std::vector<std::byte>{std::byte{1},std::byte{2},std::byte{3}},"protected target metadata silently removed");need(!fremovexattr(targetfd,"security.ima"),"protected target fixture cleanup");
  need(!fsetxattr(sourcefd,"security.ima",integrity,sizeof(integrity),0),"protected source fixture");auto integrity_source=capture_metadata_replay(*source,p);need(!integrity_source.value()&&integrity_source.state()==ObservationState::Unsupported,"protected source granted Complete evidence");need(!fremovexattr(sourcefd,"security.ima"),"protected source fixture cleanup");drain_snapshot(*captured.value());captured=capture_metadata_replay(*source,p);need(captured.value()!=nullptr,"authoritative post-integrity recapture");std::puts("PASS actual protected security.ima source/target refuse, target bytes retained before effects");
  auto no_optin=p;no_optin.allow_privilege_metadata=false;auto refused=capture_metadata_replay(*source,no_optin);need(!refused.value()&&refused.state()==ObservationState::Unsupported,"privilege optin omitted");
  auto false_time=*captured.value();false_time.basic.accessed=Observation<FileTimestamp>::available(*FileTimestamp::from_unix(false_time.basic.accessed.value()->seconds()+86400,false_time.basic.accessed.value()->nanoseconds()));false_time.security_coverage.reset();auto issued=source->issue_metadata_security_coverage(false_time);need(!issued.value()&&issued.state()==ObservationState::Changed,"public issuer endorsed forged access time");std::puts("PASS public legacy issuer rejects forged access time; progressive initial timestamp remains privately bound");
  auto forged=*captured.value();forged.security_coverage=std::make_shared<ForgedCoverage>();denied_apply(*target,forged,targetfd,target_before,"caller-subclass-evidence");
  forged=*captured.value();forged.basic.posix_uid=Observation<std::uint64_t>::available(1002);denied_apply(*target,forged,targetfd,target_before,"forged-owner");
  forged=*captured.value();forged.attributes.front().bytes.push_back(std::byte{1});denied_apply(*target,forged,targetfd,target_before,"forged-attribute-bytes");
  forged=*captured.value();forged.security.clear();denied_apply(*target,forged,targetfd,target_before,"omitted-acl");
  forged=*captured.value();forged.policy.ownership=p.ownership==MetadataOwnership::Original?MetadataOwnership::CurrentCaller:MetadataOwnership::Original;denied_apply(*target,forged,targetfd,target_before,"forged-policy");
  child_capability_control(*source,*target,*captured.value(),CAP_SYS_ADMIN,true);child_capability_control(*source,*target,*captured.value(),CAP_SETFCAP,false);
  if(p.ownership==MetadataOwnership::Original){child_capability_control(*source,*target,*captured.value(),CAP_CHOWN,false);child_capability_control(*source,*target,*captured.value(),CAP_FOWNER,false);}
  const unsigned char changed[]{9,8,7};need(!fsetxattr(sourcefd,"user.ck.full",changed,sizeof(changed),0),"source mutation");denied_apply(*target,*captured.value(),targetfd,target_before,"source-version-changed");
  need(!fsetxattr(sourcefd,"user.ck.full",bytes,sizeof(bytes),0),"source restore");drain_snapshot(*captured.value());captured=capture_metadata_replay(*source,p);need(captured.value()!=nullptr,"fresh authoritative recapture");
  auto applied=apply_metadata_replay(*target,*captured.value());if(!applied.value()){auto&e=*applied.unavailable_detail();std::printf("FULL_APPLY_REFUSAL state=%u domain=%u code=%lld operation=%s\n",unsigned(e.state),unsigned(e.error.domain),(long long)e.error.code,e.error.operation.c_str());}
  else if(*applied.value()){auto applied_basic=get(target->inspect_basic());auto verified=verify_metadata_replay(*target,*captured.value(),applied_basic);positive=verified.value()&&*verified.value();if(!verified.value()){const auto&e=*verified.unavailable_detail();std::printf("FULL_VERIFY_REFUSAL state=%u code=%lld operation=%s\n",unsigned(e.state),(long long)e.error.code,e.error.operation.c_str());}}
  if(positive){
   MetadataCaptureLimits limits;limits.read.max_bytes=1024;auto budget=std::make_shared<MetadataCaptureBudget>(limits);auto job=get(MetadataCaptureJob::begin(source,p,limits,budget));unsigned advances=0;
   while(job->progress().phase!=MetadataCapturePhase::Complete){auto step=get(job->advance());need(step.content_reads<=1&&step.content_bytes<=1024,"bounded progressive read");need(++advances<1000,"progressive completion");}
   auto proof=get(job->result());need(proof->main_digest()&&*proof->main_digest()==main_before&&proof->snapshot().security_coverage&&proof->snapshot().security_coverage->family()==MetadataSecurityCoverage::LinuxPersistentSecurityV1,"progressive actual Full source proof");
   auto digest=get(native_metadata_proof_digest(*proof));get(job->finish_io());need(proof->io_finished()&&budget->retained_handle_reservations()==0,"explicit progressive read/source/proof cleanup");need(digest==get(native_metadata_proof_digest(*proof)),"closed no-I/O V3 digest changed");need(!proof->snapshot().security_coverage->recheck(proof->snapshot()).value(),"closed proof retained replay authority");
   std::printf("PASS progressive Full capture advances=%u reads=%llu closed-V3=1\n",advances,(unsigned long long)proof->progress().read_calls);
   auto failure_budget=std::make_shared<MetadataCaptureBudget>(limits);auto failure_latch=std::make_shared<ReadCloseLatch>();auto failed_job=get(MetadataCaptureJob::begin(source,p,limits,failure_budget,failure_latch));
   while(failed_job->progress().phase!=MetadataCapturePhase::Complete)get(failed_job->advance());
   struct stat selected{};need(!fstat(sourcefd,&selected),"close error identity");close_device=selected.st_dev;close_inode=selected.st_ino;close_fault_armed=true;
   auto closed=failed_job->finish_io();close_fault_armed=false;need(!closed.value()&&closed.unavailable_detail()->error.code==EIO&&close_fault_hits==1,"extra native security proof reader close EIO lost");
   need(failure_latch->first&&failure_latch->first->code==EIO&&failure_budget->first_cleanup_error()&&failure_budget->first_cleanup_error()->code==EIO,"proof close first POD forwarding lost");
   need(!failed_job->finish_io().value()&&close_fault_hits==1&&!failed_job->result().value()&&failure_budget->retained_handle_reservations()==0,"failed finish idempotence/authority/consumption");need(source->inspect_basic().value()!=nullptr,"borrowed original source closed");
   std::puts("PASS actual consumed extra security-proof reader close EIO, cached all-terminal finish and first-POD forwarding; borrowed source retained");
  }
  drain_snapshot(*captured.value());
 }
 else{auto&e=*captured.unavailable_detail();std::printf("FULL_CAPTURE_REFUSAL state=%u domain=%u code=%lld operation=%s proof=NONE\n",unsigned(e.state),unsigned(e.error.domain),(long long)e.error.code,e.error.operation.c_str());}
 need(main_before==contents(sourcefd,"source-after")&&main_before==contents(targetfd,"target-after"),"independent final main content");auto after=values(sourcefd,"source-after");auto target_after=values(targetfd,"target-after");if(positive)need(target_after.attrs==before.attrs&&target_after.st.st_uid==(p.ownership==MetadataOwnership::Original?1000U:0U)&&target_after.st.st_gid==0&&(target_after.st.st_mode&07777)==0660,"independent native target ACL/xattrs/capability/owner/mode equality");need(before.attrs==after.attrs&&before.st.st_uid==after.st.st_uid&&before.st.st_gid==after.st.st_gid,"source independent values changed");if(!captured.value())need(target_before.attrs==target_after.attrs&&target_before.st.st_uid==target_after.st.st_uid,"refusal changed target metadata");get(target->finish_content_writes());target.reset();{ReadCloseLatch latch;detail::MetadataCaptureCleanupScope scope(&latch);detail::finish_native_metadata_capture(source.get(),{});need(!latch.first,"original native source final read close");}source.reset();directory.reset();need(!close(sourcefd)&&!close(targetfd),"read owner close");need(!unlinkat(rootfd,"source",0)&&!unlinkat(rootfd,"target",0)&&!close(rootfd),"own fixture cleanup");std::printf("COMPLETE_NATIVE_POSITIVE=%u no_ordinary_fallback=1 files_executed=0\n",unsigned(positive));return positive?0:2;
}

extern "C" int close(int fd){struct stat s{};const bool selected=close_fault_armed&&!fstat(fd,&s)&&S_ISREG(s.st_mode)&&s.st_dev==close_device&&s.st_ino==close_inode;const int result=static_cast<int>(syscall(SYS_close,fd));if(result==0&&selected){close_fault_armed=false;++close_fault_hits;errno=EIO;return -1;}return result;}
