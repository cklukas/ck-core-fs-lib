// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_capture_job.hpp"
#include "metadata_replay.hpp"
#include "native_filesystem.hpp"
#include "mac_capability_fixture.hpp"
#include "native_operation_copy_job.hpp"
#include "private_journal_scope.hpp"
#include "prepared_journal_root.hpp"
#include "windows_name.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string_view>
#include <optional>
#include <filesystem>
#include <stdexcept>
#include <vector>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif
using namespace ck::files;
namespace {
unsigned checks=0,failures=0;
void check(bool ok,const char* text){++checks;if(!ok)throw std::runtime_error(text);}
template<class T>T take(Observation<T> o){if(!o.value()){auto e=o.unavailable_detail();std::fprintf(stderr,"OBS state=%u domain=%u code=%lld op=%s\n",unsigned(e->state),unsigned(e->error.domain),(long long)e->error.code,e->error.operation.c_str());throw std::runtime_error(e->error.operation);}return std::move(o).take_value();}
void yes(Observation<bool> o){check(take(std::move(o)),"false native result");}
NativeName name(const char* s){
#ifdef _WIN32
 return *NativeName::from_windows(std::u16string(s,s+std::strlen(s)));
#else
 return *NativeName::from_posix(s);
#endif
}
MetadataReplayPolicy policy(){MetadataReplayPolicy p;p.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;p.ownership=MetadataOwnership::CurrentCaller;return p;}
using Cursor=std::shared_ptr<const DirectoryCursor>;
std::filesystem::path normalized(std::filesystem::path p){
#ifdef _WIN32
 auto result=windows_extended_path(p.native());check(bool(result),"absolute modern Windows boundary");return std::filesystem::path(*result);
#else
 return p;
#endif
}
#ifdef _WIN32
std::filesystem::path windows_temp_boundary(std::wstring_view text,bool require_v) {
 auto p=normalized(std::filesystem::path(text));
 if(require_v) {
  constexpr std::wstring_view prefix=L"\\\\?\\V:\\tmp\\";
  const auto& value=p.native();
  check(value.size()>=prefix.size()&&CompareStringOrdinal(value.data(),int(prefix.size()),prefix.data(),int(prefix.size()),TRUE)==CSTR_EQUAL,"workstation requires TEMP in the V development tmp tree when CK_FS_REQUIRE_V_DEV_DRIVE=1");
 }
 return p;
}
std::optional<std::wstring> wide_environment(const wchar_t* name) {
 SetLastError(ERROR_SUCCESS);const DWORD size=GetEnvironmentVariableW(name,nullptr,0);
 if(!size) {
  check(GetLastError()==ERROR_SUCCESS||GetLastError()==ERROR_ENVVAR_NOT_FOUND,"environment size query");
  return std::nullopt;
 }
 check(size<=32768,"environment value exceeds native bound");
 std::wstring value(size,L'\0');const DWORD count=GetEnvironmentVariableW(name,value.data(),size);
 check(count>0&&count<size,"environment changed during capture");value.resize(count);return value;
}
std::filesystem::path windows_temp_root() {
 auto temp=wide_environment(L"TEMP");
 if(!temp)temp=wide_environment(L"TMP");
 if(!temp)temp=wide_environment(L"TMPDIR");
 check(temp.has_value(),"explicit wide Windows TEMP/TMP/TMPDIR required");
 const auto require=wide_environment(L"CK_FS_REQUIRE_V_DEV_DRIVE");
 return windows_temp_boundary(*temp,require&&*require==L"1");
}
void path_policy() {
 // Pure path validation: these synthetic C: addresses cause no filesystem I/O.
 auto c=windows_temp_boundary(L"C:/runner-temp/hardlink-case",false);
 check(c.native()==L"\\\\?\\C:\\runner-temp\\hardlink-case","hosted Windows C: TEMP accepted without workstation policy");
 bool refused=false;try{(void)windows_temp_boundary(L"C:/runner-temp/hardlink-case",true);}catch(const std::runtime_error&){refused=true;}
 check(refused,"workstation flag rejects C: before any filesystem operation");
 auto v=windows_temp_boundary(L"V:/tmp/hardlink-case",true);
 check(v.native()==L"\\\\?\\V:\\tmp\\hardlink-case","workstation V: TEMP accepted through central wide boundary");
 std::puts("PATH_POLICY_VALIDATION C: synthetic path only; no C: filesystem I/O");
}
#endif
void make_dir(const std::filesystem::path& p){
#ifdef _WIN32
 check(CreateDirectoryW(normalized(p).c_str(),nullptr),"CreateDirectoryW fixture");
#else
 check(::mkdir(p.c_str(),0700)==0,"mkdir fixture");
#endif
}
void unlink_name(const std::filesystem::path& p){
#ifdef _WIN32
 check(DeleteFileW(normalized(p).c_str()),"DeleteFileW fixture");
#else
 check(::unlink(p.c_str())==0,"unlink fixture");
#endif
}
struct Fixture{
 NativeFileSystem fs;std::filesystem::path root;std::vector<std::filesystem::path> directories;Cursor base,source,target,journals;NativeName original=name("ordinary"),alias=name("alias");std::vector<std::byte> bytes;
 Fixture(){
#ifdef _WIN32
 const auto temp=windows_temp_root();static unsigned sequence=0;
 root=normalized(temp/(L"hardlink-source-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(++sequence)));
 make_dir(root);directories.push_back(root);
 for(unsigned i=0;i<4;++i){root/=std::wstring(72,wchar_t(L'a'+i));make_dir(root);directories.push_back(root);}
 auto units=std::u16string(u"ordinary-");units.push_back(char16_t(0xd800));units+=u". ";original=*NativeName::from_windows(units);alias=*NativeName::from_windows(u"alias. ");
#else
 const auto* temp=std::getenv("TMPDIR");check(temp&&*temp,"explicit TMPDIR");std::string pattern=std::string(temp)+"/hardlink-source.XXXXXX";check(::mkdtemp(pattern.data()),"mkdtemp fixture");root=pattern;directories.push_back(root);
#endif
 for(auto n:{"source","target","journals"}){auto p=normalized(root/n);make_dir(p);directories.push_back(p);}base=Cursor(take(fs.open_directory(root)));source=Cursor(take(base->open_directory_child(name("source"))));target=Cursor(take(base->open_directory_child(name("target"))));journals=Cursor(take(base->open_directory_child(name("journals"))));bytes.resize(8193);for(size_t i=0;i<bytes.size();++i)bytes[i]=std::byte(i%251);auto file=take(source->create_child_file(original));check(take(file->write_content(0,bytes))==bytes.size(),"actual source bytes written");yes(file->finish_content_writes());auto basic=take(source->lookup_child(original,ChildLookupMode::NativeDefault));check(basic.state()==ChildLookupState::Found,"source lookup");auto e=read_source();yes(source->create_hard_link(original,*take(e->inspect_basic()).identity.value(),*source,alias));check(*take(e->inspect_basic()).link_count.value()==2,"actual hardlink source count2");}
 std::shared_ptr<const OpenedEntry> read_source(){return std::shared_ptr<const OpenedEntry>(take(source->open_child(original,EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity)));}
 NativeAbsolutePath journal_address(){return take(NativeAbsolutePath::from_host(normalized(root/"journals")));}
 std::vector<std::byte> read(Cursor dir,const NativeName& n){auto e=take(dir->open_child(n,EntryAccess::ContentRead));std::vector<std::byte> out;for(unsigned i=0;i<10000;++i){auto b=take(e->read_content({1024},out.size()));out.insert(out.end(),b.bytes.begin(),b.bytes.end());if(b.complete)return out;}throw std::runtime_error("finite native read budget");}
 ~Fixture(){source.reset();target.reset();journals.reset();base.reset();
#ifdef _WIN32
 for(const auto& d:{root/L"source",root/L"target",root/L"journals"}){WIN32_FIND_DATAW f{};auto pattern=normalized(d/L"*");HANDLE h=FindFirstFileW(pattern.c_str(),&f);if(h!=INVALID_HANDLE_VALUE){do{if(!(f.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))DeleteFileW(normalized(d/f.cFileName).c_str());}while(FindNextFileW(h,&f));FindClose(h);}}for(auto p=directories.rbegin();p!=directories.rend();++p)RemoveDirectoryW(normalized(*p).c_str());
#else
 std::error_code ec;std::filesystem::remove_all(directories.front(),ec);
#endif
 }
};
std::shared_ptr<const NativeMetadataProof> drain(MetadataCaptureJob& job){for(unsigned i=0;i<10000;++i){take(job.advance());if(job.progress().phase==MetadataCapturePhase::Complete)return take(job.result());}throw std::runtime_error("finite metadata capture budget");}
void source_capture(){Fixture f;auto source=f.read_source();auto legacy=take(capture_metadata_replay(*source,policy()));check(*legacy.basic.link_count.value()==2,"legacy count2 observation");auto job=take(MetadataCaptureJob::begin(source,policy()));auto proof=drain(*job);check(*proof->snapshot().basic.link_count.value()==2,"progressive count2 observation");check(proof->main_digest().has_value(),"actual source digest");yes(verify_metadata_replay_source(*source,legacy));auto fresh=take(MetadataCaptureJob::verify(proof));drain(*fresh);yes(fresh->finish_io());yes(job->finish_io());check(f.read(f.source,f.original)==f.bytes&&f.read(f.source,f.alias)==f.bytes,"both real source names survive capture unchanged");}
// ChangeTime is an observation, not a unique link-event counter. This negative
// uses an actual, durable content/size change through the third hardlink, then
// restores nlink=2. It makes no claim that a pure 2->3->2 ABA is always detected.
void append_through_third(Fixture& f,const BasicMetadata& expected) {
 const auto path=normalized(f.root/"source"/"third");
 const std::byte extra{0x21};
#ifdef _WIN32
 struct Owner {HANDLE value=INVALID_HANDLE_VALUE;~Owner(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}} owner;
 owner.value=CreateFileW(path.c_str(),FILE_APPEND_DATA|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
 check(owner.value!=INVALID_HANDLE_VALUE,"open actual third hardlink with append rights");
 FILE_ID_INFO id{};FILE_STANDARD_INFO standard{};
 check(GetFileInformationByHandleEx(owner.value,FileIdInfo,&id,sizeof(id)),"third alias held FileIdInfo");
 NativeIdentifier object;std::memcpy(object.bytes.data(),id.FileId.Identifier,16);
 const auto& observed=*expected.identity.value();
 check(observed.scheme==IdentityScheme::WindowsFileId128&&observed.volume==NativeIdentifier::from_u64(id.VolumeSerialNumber)&&observed.object==object,"third writable alias matches genuine held source identity");
 check(GetFileInformationByHandleEx(owner.value,FileStandardInfo,&standard,sizeof(standard))&&standard.NumberOfLinks==3&&!standard.Directory&&!standard.DeletePending&&standard.EndOfFile.QuadPart==static_cast<LONGLONG>(f.bytes.size()),"third held alias begins count3 and original actual size");
 DWORD count=0;check(WriteFile(owner.value,&extra,1,&count,nullptr)&&count==1,"append real byte through held third alias");
 check(FlushFileBuffers(owner.value),"flush actual alias content change");
 check(GetFileInformationByHandleEx(owner.value,FileStandardInfo,&standard,sizeof(standard))&&standard.EndOfFile.QuadPart==static_cast<LONGLONG>(f.bytes.size()+1),"held alias actual size increased by one");
 const HANDLE consumed=owner.value;owner.value=INVALID_HANDLE_VALUE;check(CloseHandle(consumed),"consume actual writable third alias close exactly once");
#else
 struct Owner {int value=-1;~Owner(){if(value>=0)::close(value);}} owner;
 owner.value=::open(path.c_str(),O_WRONLY|O_APPEND|O_NOFOLLOW|O_CLOEXEC);check(owner.value>=0,"open actual third hardlink with append rights");
 struct stat st{};check(::fstat(owner.value,&st)==0,"third alias held fstat");const auto& observed=*expected.identity.value();
 check(observed.scheme==IdentityScheme::PosixDeviceInode&&observed.volume==NativeIdentifier::from_u64(st.st_dev)&&observed.object==NativeIdentifier::from_u64(st.st_ino),"third writable alias matches genuine held source identity");
 check(S_ISREG(st.st_mode)&&st.st_nlink==3&&st.st_size==static_cast<off_t>(f.bytes.size()),"third held alias begins count3 and original actual size");
 check(::write(owner.value,&extra,1)==1&&::fsync(owner.value)==0,"append and flush actual third alias byte");
 check(::fstat(owner.value,&st)==0&&st.st_size==static_cast<off_t>(f.bytes.size()+1),"held alias actual size increased by one");
 const int consumed=owner.value;owner.value=-1;check(::close(consumed)==0,"consume actual writable third alias close exactly once");
#endif
}
void progressive_changed(const std::shared_ptr<const NativeMetadataProof>& proof,const char* reason) {
 auto verifier=take(MetadataCaptureJob::verify(proof));
 auto step=Observation<MetadataCaptureAdvance>::available({MetadataCapturePhase::Basic});
 for(unsigned i=0;i<10000&&step.value()&&verifier->progress().phase!=MetadataCapturePhase::Complete;++i)step=verifier->advance();
 check(!step.value()&&step.state()==ObservationState::Changed,reason);yes(verifier->finish_io());
}
void source_version(){
 Fixture f;auto source=f.read_source();auto legacy=take(capture_metadata_replay(*source,policy()));auto job=take(MetadataCaptureJob::begin(source,policy()));auto proof=drain(*job);
 const auto id=*legacy.basic.identity.value();yes(f.source->create_hard_link(f.original,id,*f.source,name("third")));
 check(*take(source->inspect_basic()).link_count.value()==3,"real third source link count3");
 auto changed=verify_metadata_replay_source(*source,legacy);check(!changed.value()&&changed.state()==ObservationState::Changed,"legacy exact linkcount change rejected");
 progressive_changed(proof,"progressive exact linkcount change rejected");
 append_through_third(f,take(source->inspect_basic()));
 auto actual=take(source->inspect_basic());check(actual.logical_size.value()&&*actual.logical_size.value()==f.bytes.size()+1,"genuine held source observes real appended size after flush+close");
 unlink_name(normalized(f.root/"source"/"third"));auto now=take(source->inspect_basic());check(*now.link_count.value()==2,"restored source count2");
 check(now.logical_size.value()&&*now.logical_size.value()==f.bytes.size()+1,"restored linkcount retains deterministic changed content size");
 changed=verify_metadata_replay_source(*source,legacy);check(!changed.value()&&changed.state()==ObservationState::Changed,"legacy real content-version change rejected after restored linkcount");
 progressive_changed(proof,"progressive real content-version change rejected after restored linkcount");
 f.bytes.push_back(std::byte{0x21});check(f.read(f.source,f.original)==f.bytes&&f.read(f.source,f.alias)==f.bytes,"both surviving aliases contain exactly original data plus real appended byte");
 yes(job->finish_io());
}
void native_copy(){Fixture f;yes(prepare_native_operation_journal_root(f.journal_address()));
#if defined(__APPLE__)
 const auto source_before=mac_capability_fixture::observe(f.root/"source");
 const auto target_before=mac_capability_fixture::observe(f.root/"target");
#endif
 NativeOperationCopyBatchRequest r;r.sources={take(HeldChild::observe_with_access(f.source,f.original,EntryAccess::ContentRead))};r.destination=f.target;r.destination_names={name("copy")};r.journal_root=f.journal_address();r.journal_id.bytes[0]=std::byte{71};r.policy.metadata_scope=RegularMetadataScope::OrdinaryCallerVisibleV1;r.policy.metadata_policy=policy();r.open_journal=open_native_operation_journal_file;auto job=take(create_native_operation_copy_batch(std::move(r)));for(unsigned i=0;i<10000&&job->state()!=OperationBatchState::Complete&&job->state()!=OperationBatchState::NeedsReconciliation&&job->state()!=OperationBatchState::Failed&&job->state()!=OperationBatchState::Cancelled;++i)job->advance();
#if defined(__APPLE__)
 check(job->state()==OperationBatchState::NeedsReconciliation,"Mac hardlink copy refuses publication");
 check(job->progress().observed_bytes==0&&job->result().items.size()==1,"refusal has no copied bytes");
 const auto failure=job->result().items.front().failure;
 check(failure&&failure->state==ObservationState::Unsupported&&failure->error.domain==ErrorDomain::Adapter&&
   failure->error.code==4&&failure->error.operation=="create_staging_file.fd_publication_unqualified","exact Mac publication capability refusal");
 check(mac_capability_fixture::observe(f.root/"source")==source_before,"both source aliases unchanged");
 check(mac_capability_fixture::observe(f.root/"target")==target_before,"no target or staging published");
 const auto journal_before=mac_capability_fixture::observe(f.root/"journals");
 for(unsigned poll=0;poll<3;++poll)check(job->advance()==OperationBatchState::NeedsReconciliation,"stable refusal poll");
 check(mac_capability_fixture::observe(f.root/"journals")==journal_before,"terminal poll cannot replay journal");
 job.reset();
 for(const auto& file:std::filesystem::directory_iterator(f.root/"journals")){
  if(!file.path().filename().native().starts_with(".ck-copy-journal-"))continue;
  auto handle=take(open_native_operation_journal_file(f.journal_address(),name(file.path().filename().native().c_str()),false));
  auto parsed=take(load_operation_journal(*handle));yes(handle->finish_io());
  check(!parsed.tail&&parsed.journal->records().size()==2&&parsed.journal->records()[0].state==OperationJournalState::Planned&&
    parsed.journal->records()[1].state==OperationJournalState::Prepared,"Mac hardlink journal stops before copy");
 }
#else
check(job->state()==OperationBatchState::Complete,"native hardlink source copy Complete");check(f.read(f.target,name("copy"))==f.bytes,"actual copied destination bytes");check(f.read(f.source,f.original)==f.bytes&&f.read(f.source,f.alias)==f.bytes,"copy preserves both source aliases");auto target=take(f.target->open_child(name("copy")));check(*take(target->inspect_basic()).link_count.value()==1,"copied destination has own single link");
#endif
}
void target_alias(){Fixture f;auto seed=take(f.source->create_child_file(name("single-source")));check(take(seed->write_content(0,f.bytes))==f.bytes.size(),"single-link reference bytes");yes(seed->finish_content_writes());auto source=take(f.source->open_child(name("single-source"),EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));auto snapshot=take(capture_metadata_replay(*source,policy()));auto unique=take(f.target->create_child_file(name("writer")));check(take(unique->write_content(0,f.bytes))==f.bytes.size(),"target setup bytes");auto writer=std::shared_ptr<OpenedEntry>(std::move(unique));auto basic=take(writer->inspect_basic());auto alias=f.target->create_hard_link(name("writer"),*basic.identity.value(),*f.target,name("writer-alias"));
yes(std::move(alias));check(*take(writer->inspect_basic()).link_count.value()==2,"actual writable target count2");auto qualified=writer->qualify_metadata_replay(policy());if(qualified.unavailable_detail()){const auto&e=*qualified.unavailable_detail();std::printf("TARGET_ALIAS_QUALIFY state=%u domain=%u code=%lld op=%s\n",unsigned(e.state),unsigned(e.error.domain),(long long)e.error.code,e.error.operation.c_str());}check(!qualified.value()&&qualified.state()==ObservationState::Unsupported&&qualified.unavailable_detail()->error.domain==ErrorDomain::Adapter&&qualified.unavailable_detail()->error.code==14,"native writable target count2 qualification denied");auto before=take(writer->inspect_basic());auto applied=apply_metadata_replay(*writer,snapshot);check(!applied.value()&&applied.state()==ObservationState::Unsupported&&applied.unavailable_detail()->error.domain==ErrorDomain::Adapter&&applied.unavailable_detail()->error.code==14,"target alias denied before metadata replay");auto after=take(writer->inspect_basic());check(*before.modified.value()==*after.modified.value()&&*before.changed.value()==*after.changed.value(),"aliased target timestamps unchanged");
#ifdef _WIN32
check(*before.windows_attributes.value()==*after.windows_attributes.value(),"aliased target attributes unchanged");
#else
check(*before.posix_permissions.value()==*after.posix_permissions.value(),"aliased target mode unchanged");
#endif
 auto capture=MetadataCaptureJob::begin(writer,policy());check(!capture.value()&&capture.state()==ObservationState::Denied,"actual native writable owner cannot masquerade as read-only capture source");yes(writer->finish_content_writes());check(f.read(f.target,name("writer"))==f.bytes,"writable target data unchanged");
check(f.read(f.target,name("writer-alias"))==f.bytes,"aliased target data unchanged");
}
void private_alias(){Fixture f;yes(prepare_native_operation_journal_root(f.journal_address()));auto root=take(acquire_native_journal_root(f.journal_address()));auto file=take(root->open_journal(name("private-state"),true));check(take(file->write_at(0,std::span(f.bytes).first(17)))==17,"private state actual bytes");yes(file->finish_io());file.reset();auto guard=take(JournalScopeGuard::create(root,f.source));auto entry=take(f.journals->open_child(name("private-state")));auto id=*take(entry->inspect_basic()).identity.value();entry.reset();yes(f.journals->create_hard_link(name("private-state"),id,*f.source,name("private-alias")));auto selected=take(HeldChild::observe(f.source,name("private-alias")));auto refused=guard->check_entry(*selected);check(!refused.value()&&refused.state()==ObservationState::Unsupported&&refused.unavailable_detail()->error.domain==ErrorDomain::Adapter&&refused.unavailable_detail()->error.code==18,"private journal hardlink refused by actual Root scope");std::printf("PRIVATE_ALIAS_REFUSAL %s\n",refused.unavailable_detail()->error.operation.c_str());selected.reset();unlink_name(normalized(f.root/"source"/"private-alias"));guard.reset();yes(root->finish_io());}
void complete_context(){
#ifdef __linux__
 Fixture f;auto source=f.read_source();auto p=policy();p.scope=RegularMetadataScope::CompleteMetadataV1;auto q=source->qualify_metadata_replay(p);check(!q.value()&&q.state()==ObservationState::Unsupported&&q.unavailable_detail()->error.domain==ErrorDomain::Adapter&&q.unavailable_detail()->error.code==14&&q.unavailable_detail()->error.operation=="metadata_replay.complete_requires_initial_sys_admin","Complete has actual cap0 capability gate, distinct from ordinary hardlinks");
#endif
}
}
#ifdef _WIN32
struct Unqualified final:std::runtime_error {using std::runtime_error::runtime_error;};
template<class T>T unc_setup(Observation<T> value,const char* label) {
 if(!value.value()) {const auto& e=*value.unavailable_detail();std::fprintf(stderr,"UNC_SETUP %s state=%u domain=%u code=%lld op=%s\n",label,unsigned(e.state),unsigned(e.error.domain),(long long)e.error.code,e.error.operation.c_str());throw Unqualified(label);}
 return std::move(value).take_value();
}
void unc_refusal(const std::filesystem::path& configured_parent) {
 // The argument is the actual UNC alias of TEMP, not an inferred admin share.
 auto parent_path=windows_extended_path(configured_parent.native());
 if(!parent_path||!parent_path->starts_with(L"\\\\?\\UNC\\"))throw Unqualified("--unc requires an absolute configured UNC alias of TEMP");
 const auto local_temp=windows_temp_root();NativeFileSystem fs;
 auto local_base=unc_setup(fs.open_directory(local_temp),"local TEMP unavailable");
 auto remote_base=unc_setup(fs.open_directory(std::filesystem::path(*parent_path)),"configured UNC parent unreachable");
 auto local_id=unc_setup(local_base->identity(),"local TEMP identity unavailable");
 auto remote_id=unc_setup(remote_base->identity(),"configured UNC identity unavailable");
 if(compare_identity(local_id,remote_id)!=IdentityComparison::Same)throw Unqualified("configured UNC parent does not identify this local TEMP");
 Fixture f;auto suffix=f.root.lexically_relative(local_temp);
 if(suffix.empty()||suffix.is_absolute()||*suffix.begin()==L"..")throw Unqualified("fixture cannot be bound to configured TEMP alias");
 const auto remote_source=normalized(std::filesystem::path(*parent_path)/suffix/L"source");
 auto parent=unc_setup(f.fs.open_directory(remote_source),"configured UNC fixture unreachable");
 auto entry=unc_setup(parent->open_child(f.original,EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity),"configured UNC hardlink source unreachable");
 auto local=take(f.read_source()->inspect_basic());auto remote=unc_setup(entry->inspect_basic(),"UNC source identity unavailable");
 if(!remote.identity.value()||compare_identity(*local.identity.value(),*remote.identity.value())!=IdentityComparison::Same)throw Unqualified("UNC source is not the actual local hardlinked object");
 check(*remote.link_count.value()==2,"actual configured UNC source has two links");
 auto q=entry->qualify_metadata_replay(policy());
 if(auto e=q.unavailable_detail())std::printf("ACTUAL_UNC_TUPLE state=%u domain=%u code=%lld op=%s\n",unsigned(e->state),unsigned(e->error.domain),(long long)e->error.code,e->error.operation.c_str());
 check(!q.value()&&q.state()==ObservationState::Unsupported&&q.unavailable_detail()->error.domain==ErrorDomain::Adapter&&q.unavailable_detail()->error.code==14&&q.unavailable_detail()->error.operation=="metadata_provider.windows_driver_unqualified","actual configured UNC metadata provider remains refused");
 std::printf("ACTUAL_UNC_REFUSAL %s\n",q.unavailable_detail()->error.operation.c_str());
}
#endif
void run_case(const char* label,void(*test)()){try{test();std::printf("PASS %s\n",label);}catch(const std::exception& e){++failures;std::fprintf(stderr,"FAIL %s: %s\n",label,e.what());}}
int run_local_cases(){
#ifdef _WIN32
run_case("local TEMP path policy",path_policy);
#endif
run_case("ordinary-hardlink progressive+legacy capture",source_capture);run_case("linkcount/content-version revalidation",source_version);
#ifdef __APPLE__
run_case("ordinary hardlink Mac publication refusal",native_copy);
#else
run_case("actual ordinary hardlink native copy",native_copy);
#endif
run_case("aliased writable target denied",target_alias);run_case("private journal alias refused",private_alias);
#ifdef __linux__
run_case("Complete SYS_ADMIN context",complete_context);
#endif
std::printf("HARDLINK_SOURCE_CAPTURE_LOCAL checks=%u failures=%u unc=not_requested\n",checks,failures);return failures?1:0;}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv){
 if(argc==1||(argc==2&&std::wcscmp(argv[1],L"--local")==0))return run_local_cases();
 if(argc>=2&&std::wcscmp(argv[1],L"--unc")==0){
  if(argc!=3){std::fprintf(stderr,"UNQUALIFIED hardlink_source_unc: --unc needs the configured UNC alias of TEMP; unc=unqualified coverage=0\n");return 77;}
  try{unc_refusal(std::filesystem::path(argv[2]));std::printf("HARDLINK_SOURCE_CAPTURE_UNC checks=%u failures=0 unc=passed\n",checks);return 0;}
  catch(const Unqualified&e){std::fprintf(stderr,"UNQUALIFIED hardlink_source_unc: %s; unc=unqualified coverage=0\n",e.what());return 77;}
  catch(const std::exception&e){std::fprintf(stderr,"FAIL hardlink_source_unc: %s; unc=failed\n",e.what());return 1;}
 }
 std::fprintf(stderr,"usage: hardlink_source_capture_tests [--local | --unc UNC_ALIAS_OF_TEMP]\n");return 2;
}
#else
int main(int argc,char** argv){
 if(argc==1||(argc==2&&std::strcmp(argv[1],"--local")==0))return run_local_cases();
 if(argc>=2&&std::strcmp(argv[1],"--unc")==0){std::fprintf(stderr,"UNQUALIFIED hardlink_source_unc: Windows native UNC supplement required; unc=unqualified coverage=0\n");return 77;}
 std::fprintf(stderr,"usage: hardlink_source_capture_tests [--local | --unc UNC_ALIAS_OF_TEMP]\n");return 2;
}
#endif
