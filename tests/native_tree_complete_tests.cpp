// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#define CKFS_NATIVE_TREE_TEST_SUPPORT
#include "native_tree_execution_tests.cpp"
#undef CKFS_NATIVE_TREE_TEST_SUPPORT
#ifdef _WIN32
#include <aclapi.h>
namespace {
class CompleteSecurityPrivilege final {
public:
 CompleteSecurityPrivilege(){CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&token_.value));
  TOKEN_PRIVILEGES next{};next.PrivilegeCount=1;next.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
  CHECK(LookupPrivilegeValueW(nullptr,L"SeSecurityPrivilege",&next.Privileges[0].Luid));DWORD size=sizeof(previous_);SetLastError(ERROR_SUCCESS);
  CHECK(AdjustTokenPrivileges(token_.value,FALSE,&next,sizeof(previous_),&previous_,&size)&&GetLastError()==ERROR_SUCCESS);
  DWORD count=0;GetTokenInformation(token_.value,TokenPrivileges,nullptr,0,&count);std::vector<std::byte> data(count);
  CHECK(GetTokenInformation(token_.value,TokenPrivileges,data.data(),count,&count));const auto* entries=reinterpret_cast<const TOKEN_PRIVILEGES*>(data.data());bool found=false;
  for(DWORD i=0;i<entries->PrivilegeCount;++i)if(entries->Privileges[i].Luid.LowPart==next.Privileges[0].Luid.LowPart&&entries->Privileges[i].Luid.HighPart==next.Privileges[0].Luid.HighPart)
   found=(entries->Privileges[i].Attributes&SE_PRIVILEGE_ENABLED)!=0;CHECK(found);
 }
 ~CompleteSecurityPrivilege(){CHECK(AdjustTokenPrivileges(token_.value,FALSE,&previous_,0,nullptr,nullptr));token_.close();}
private:FixtureHandle token_;TOKEN_PRIVILEGES previous_{};
};
std::wstring current_user_sid(){FixtureHandle token;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value));DWORD count=0;
 GetTokenInformation(token.value,TokenUser,nullptr,0,&count);std::vector<std::byte> data(count);CHECK(GetTokenInformation(token.value,TokenUser,data.data(),count,&count));
 wchar_t* raw=nullptr;CHECK(ConvertSidToStringSidW(reinterpret_cast<const TOKEN_USER*>(data.data())->User.Sid,&raw));std::wstring sid(raw);LocalFree(raw);token.close();return sid;}
constexpr SECURITY_INFORMATION all_security_classes=OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|
 SACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION|ATTRIBUTE_SECURITY_INFORMATION|SCOPE_SECURITY_INFORMATION|PROCESS_TRUST_LABEL_SECURITY_INFORMATION|ACCESS_FILTER_SECURITY_INFORMATION;
void native_ea(const std::filesystem::path& path){FixtureHandle handle{CreateFileW(extended(path).c_str(),FILE_WRITE_EA|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
 FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};CHECK(handle.value!=INVALID_HANDLE_VALUE);
 const std::string key="CK_TREE_FULL_EA";const std::array<std::byte,5> data{std::byte{'x'},std::byte{0},std::byte{0xff},std::byte{'z'},std::byte{0}};
 std::vector<std::byte> bytes(8+key.size()+1+data.size());bytes[5]=std::byte(key.size());bytes[6]=std::byte(data.size());
 std::memcpy(bytes.data()+8,key.data(),key.size());std::copy(data.begin(),data.end(),bytes.begin()+static_cast<std::ptrdiff_t>(9+key.size()));
 using SetEA=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG);auto address=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetEaFile");CHECK(address);IO_STATUS_BLOCK io{};
 CHECK(std::bit_cast<SetEA>(address)(handle.value,&io,bytes.data(),static_cast<ULONG>(bytes.size()))==0);handle.close();}
std::vector<std::byte> token_query(HANDLE token,TOKEN_INFORMATION_CLASS kind){
 DWORD count=0;GetTokenInformation(token,kind,nullptr,0,&count);CHECK(GetLastError()==ERROR_INSUFFICIENT_BUFFER&&count>0&&count<65536);
 std::vector<std::byte> data(count);CHECK(GetTokenInformation(token,kind,data.data(),count,&count));return data;
}
void alternate_source_owner(HANDLE target){
 FixtureHandle token;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value));
 auto owner=token_query(token.value,TokenOwner),user=token_query(token.value,TokenUser),groups=token_query(token.value,TokenGroups);
 const auto current=reinterpret_cast<const TOKEN_OWNER*>(owner.data())->Owner;
 PSID alternate=reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid;
 if(EqualSid(current,alternate)){alternate=nullptr;const auto* list=reinterpret_cast<const TOKEN_GROUPS*>(groups.data());
  for(DWORD i=0;i<list->GroupCount;++i)if((list->Groups[i].Attributes&SE_GROUP_OWNER)&&!EqualSid(current,list->Groups[i].Sid)){
   alternate=list->Groups[i].Sid;break;}}
 CHECK(alternate&&IsValidSid(alternate)&&!EqualSid(current,alternate));
 CHECK(SetSecurityInfo(target,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,alternate,nullptr,nullptr,nullptr)==ERROR_SUCCESS);token.close();
}
void caller_owner_query(HANDLE target,bool expected_equal){
 FixtureHandle token;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value));auto expected=token_query(token.value,TokenOwner);
 DWORD count=0;constexpr SECURITY_INFORMATION owner_classes=OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION;CHECK(!GetKernelObjectSecurity(target,owner_classes,nullptr,0,&count)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER&&count>=20&&count<65536);
 std::vector<std::byte> actual(count);CHECK(GetKernelObjectSecurity(target,owner_classes,actual.data(),count,&count));
 PSID owner=nullptr;BOOL defaulted=FALSE;CHECK(GetSecurityDescriptorOwner(actual.data(),&owner,&defaulted)&&owner&&IsValidSid(owner));
 CHECK((EqualSid(owner,reinterpret_cast<const TOKEN_OWNER*>(expected.data())->Owner)!=FALSE)==expected_equal);
 if(expected_equal){auto group=token_query(token.value,TokenPrimaryGroup);PSID actual_group=nullptr;
  CHECK(GetSecurityDescriptorGroup(actual.data(),&actual_group,&defaulted)&&actual_group&&IsValidSid(actual_group));
  CHECK(EqualSid(actual_group,reinterpret_cast<const TOKEN_PRIMARY_GROUP*>(group.data())->PrimaryGroup));}
 token.close();
}
void source_security(const std::filesystem::path& path,bool caller=false){FixtureHandle handle{CreateFileW(extended(path).c_str(),WRITE_DAC|WRITE_OWNER|READ_CONTROL|ACCESS_SYSTEM_SECURITY,
 FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};CHECK(handle.value!=INVALID_HANDLE_VALUE);
 if(caller){alternate_source_owner(handle.value);caller_owner_query(handle.value,false);}
 const auto sddl=L"D:P(A;;FRFX;;;"+current_user_sid()+L")(A;;FA;;;SY)S:P(AU;SAFA;FR;;;WD)(ML;;NW;;;ME)";
 PSECURITY_DESCRIPTOR descriptor=nullptr;CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr));FixtureLocal owned{descriptor};
 CHECK(SetKernelObjectSecurity(handle.value,DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION,descriptor));handle.close();}
void restore_setup_acl(const std::filesystem::path& path){FixtureHandle handle{CreateFileW(extended(path).c_str(),WRITE_DAC,
 FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};CHECK(handle.value!=INVALID_HANDLE_VALUE);
 FixtureSecurity security;CHECK(SetKernelObjectSecurity(handle.value,DACL_SECURITY_INFORMATION,security.descriptor.value));handle.close();}
void security_queries(const std::filesystem::path& path,unsigned owner_expectation=0){FixtureHandle handle{CreateFileW(extended(path).c_str(),READ_CONTROL|ACCESS_SYSTEM_SECURITY,
 FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};CHECK(handle.value!=INVALID_HANDLE_VALUE);
 if(owner_expectation)caller_owner_query(handle.value,owner_expectation==1);
 unsigned audit=0,label=0;for(const auto mask:std::array<SECURITY_INFORMATION,10>{OWNER_SECURITY_INFORMATION,GROUP_SECURITY_INFORMATION,DACL_SECURITY_INFORMATION,SACL_SECURITY_INFORMATION,
  LABEL_SECURITY_INFORMATION,ATTRIBUTE_SECURITY_INFORMATION,SCOPE_SECURITY_INFORMATION,PROCESS_TRUST_LABEL_SECURITY_INFORMATION,ACCESS_FILTER_SECURITY_INFORMATION,all_security_classes}){
  DWORD count=0;CHECK(!GetKernelObjectSecurity(handle.value,mask,nullptr,0,&count)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER&&count>=20&&count<65536);
  std::vector<std::byte> bytes(count);CHECK(GetKernelObjectSecurity(handle.value,mask,reinterpret_cast<PSECURITY_DESCRIPTOR>(bytes.data()),count,&count));
  CHECK(IsValidSecurityDescriptor(bytes.data()));if(mask==all_security_classes){PACL acl=nullptr;BOOL present=FALSE,defaulted=FALSE;
   CHECK(GetSecurityDescriptorSacl(bytes.data(),&present,&acl,&defaulted)&&present&&acl);
   for(DWORD i=0;i<acl->AceCount;++i){void* raw=nullptr;CHECK(GetAce(acl,i,&raw));const auto kind=static_cast<const ACE_HEADER*>(raw)->AceType;
    audit+=kind==SYSTEM_AUDIT_ACE_TYPE;label+=kind==SYSTEM_MANDATORY_LABEL_ACE_TYPE;}}
 }
 CHECK(audit>0&&label>0);handle.close();
}
ReviewedTreePlanRequest complete_request(Fixture& f,bool caller){auto r=strict_request(f);auto p=*r.copy_policy.metadata_policy;
 p.scope=RegularMetadataScope::CompleteMetadataV1;p.allow_privilege_metadata=true;p.ownership=caller?MetadataOwnership::CurrentCaller:MetadataOwnership::Original;
 r.copy_policy.metadata_policy=p;r.copy_policy.metadata_scope=p.scope;return r;}
void complete_regular(bool caller){Fixture f;write_file(f.path("s/a"),std::string(4097,'c'));attribute(f.path("s/a"),'a');native_ea(f.path("s/a"));source_security(f.path("s/a"));security_queries(f.path("s/a"));
 auto r=complete_request(f,caller);auto root=r.prepared_journal_root;auto job=take(ReviewedTreePlanJob::create(std::move(r)));bounded_preview(*job,4096);
 auto receipt=take(job->review({}));auto rows=take(job->reviewed_page(receipt,0,128));CHECK(take(job->begin_execution(receipt)));execute_bounded(*job);
 security_queries(f.path("d/a"));effect_tokens(*job,receipt,rows);CHECK(take(root->finish_io()));effect_tokens(*job,receipt,rows);
 restore_setup_acl(f.path("s/a"));restore_setup_acl(f.path("d/a"));
 std::printf("Complete %s regular native EA/ADS/audit-SACL/mandatory-label/read-only-DACL PASS\n",caller?"CurrentCaller":"Original");std::fflush(stdout);}
void complete_directory(bool existing,bool caller){Fixture f;mkdir_new(f.path("s/folder"));mkdir_new(f.path("s/folder/nested"));
 write_file(f.path("s/folder/a"),"first full data");write_file(f.path("s/folder/nested/b"),"second full data");
 const std::array<const char*,4> inputs{"s/folder/a","s/folder/nested/b","s/folder/nested","s/folder"};
 for(const auto* n:inputs){attribute(f.path(n),'d');native_ea(f.path(n));source_security(f.path(n));security_queries(f.path(n));}
 if(existing){mkdir_new(f.path("d/folder"));mkdir_new(f.path("d/folder/nested"));}
 auto r=complete_request(f,caller);auto root=r.prepared_journal_root;auto job=take(ReviewedTreePlanJob::create(std::move(r)));bounded_preview(*job,4096);
 ConflictRule merge;merge.plan=job->preview()->identity();merge.kind=ConflictClass::DirectoryPair;merge.choice=ConflictChoice::MergeFolders;merge.scope=ConflictScope::MatchingClassInJob;
 auto receipt=take(job->review(std::span(&merge,1)));auto rows=take(job->reviewed_page(receipt,0,128));CHECK(take(job->begin_execution(receipt)));execute_bounded(*job);
 const std::array<const char*,4> outputs{"d/folder/a","d/folder/nested/b","d/folder/nested","d/folder"};for(const auto* n:outputs)security_queries(f.path(n));
 effect_tokens(*job,receipt,rows);CHECK(take(root->finish_io()));effect_tokens(*job,receipt,rows);
 for(const auto* n:inputs)restore_setup_acl(f.path(n));for(const auto* n:outputs)restore_setup_acl(f.path(n));
 std::printf("Complete %s %s directory postorder native EA/ADS/audit-SACL/mandatory-label/read-only-DACL PASS\n",caller?"CurrentCaller":"Original",existing?"merged":"created");std::fflush(stdout);}
std::vector<std::byte> full_security_bytes(const std::filesystem::path& path){
 FixtureHandle handle{CreateFileW(extended(path).c_str(),READ_CONTROL|ACCESS_SYSTEM_SECURITY,
  FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};CHECK(handle.value!=INVALID_HANDLE_VALUE);
 DWORD count=0;CHECK(!GetKernelObjectSecurity(handle.value,all_security_classes,nullptr,0,&count)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER&&count>=20&&count<65536);
 std::vector<std::byte> data(count);CHECK(GetKernelObjectSecurity(handle.value,all_security_classes,data.data(),count,&count));data.resize(count);handle.close();return data;
}
void focused_caller_owner(){
 Fixture f;mkdir_new(f.path("s/folder"));write_file(f.path("s/folder/a"),"source retained across genuine caller ownership remap");
 for(const auto* n:{"s/folder/a","s/folder"}){attribute(f.path(n),'x');native_ea(f.path(n));source_security(f.path(n),true);security_queries(f.path(n),2);}
 mkdir_new(f.path("d/folder"));
 {FixtureHandle target{CreateFileW(extended(f.path("d/folder")).c_str(),WRITE_OWNER|READ_CONTROL,
  FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
  CHECK(target.value!=INVALID_HANDLE_VALUE);alternate_source_owner(target.value);caller_owner_query(target.value,false);target.close();}
 const auto source_dir_before=full_security_bytes(f.path("s/folder")),source_file_before=full_security_bytes(f.path("s/folder/a"));
 auto r=complete_request(f,true);auto root=r.prepared_journal_root;auto job=take(ReviewedTreePlanJob::create(std::move(r)));bounded_preview(*job,4096);
 ConflictRule merge;merge.plan=job->preview()->identity();merge.kind=ConflictClass::DirectoryPair;merge.choice=ConflictChoice::MergeFolders;merge.scope=ConflictScope::MatchingClassInJob;
 auto receipt=take(job->review(std::span(&merge,1)));auto rows=take(job->reviewed_page(receipt,0,128));CHECK(take(job->begin_execution(receipt)));execute_bounded(*job);
 security_queries(f.path("d/folder"),1);security_queries(f.path("d/folder/a"),1);
 CHECK(full_security_bytes(f.path("s/folder"))==source_dir_before);CHECK(full_security_bytes(f.path("s/folder/a"))==source_file_before);
 effect_tokens(*job,receipt,rows);CHECK(take(root->finish_io()));effect_tokens(*job,receipt,rows);
 CHECK(f.read("s/folder/a")=="source retained across genuine caller ownership remap");CHECK(f.read("d/folder/a")==f.read("s/folder/a"));
 for(const auto* n:{"s/folder/a","s/folder","d/folder/a","d/folder"})restore_setup_acl(f.path(n));
 std::printf("CurrentCaller native different source AND preexisting target owner -> actual TokenOwner/PrimaryGroup; source security+data retained; Full EA/ADS/audit-SACL/label/restrictive ACL PASS\n");std::fflush(stdout);
}
}
int wmain(int argc,wchar_t** argv){try{CHECK(argc==2||argc==3);CHECK(SetEnvironmentVariableW(L"TMPDIR",argv[1])&&SetEnvironmentVariableW(L"TEMP",argv[1])&&SetEnvironmentVariableW(L"TMP",argv[1]));
 CompleteSecurityPrivilege privilege;if(argc==3&&std::wstring_view(argv[2])==L"--caller-owner-only"){
  focused_caller_owner();std::printf("native_tree_caller_owner: %u checks passed\n",checks);return 0;}
 const bool caller=argc==3&&std::wstring_view(argv[2])==L"--caller";
 complete_regular(caller);complete_directory(false,caller);complete_directory(true,caller);std::printf("native_tree_complete: %u checks passed\n",checks);return 0;
 }catch(const std::exception& e){std::fprintf(stderr,"native_tree_complete: %s\n",e.what());return 1;}}
#else
int main(){return 0;}
#endif
