// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
// The Root cancellation executable needs only this real native fixture. It
// must not import another executable's allocator/I/O overrides or tests.
#include "mac_capability_fixture.hpp"
#include "reviewed_tree_plan.hpp"
#include "native_filesystem.hpp"
#include "operation_journal_file.hpp"
#include "private_journal_scope.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <cstdio>
#include <cwchar>
#include <stop_token>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include "windows_name.hpp"
#else
#include <sys/stat.h>
#include <unistd.h>
#endif
using namespace ck::files;
namespace {
unsigned checks=0;
void check(bool value,const char* text,int line){++checks;if(!value)throw std::runtime_error(std::string("line ")+std::to_string(line)+": "+text);}
#define CHECK(x) check(bool(x),#x,__LINE__)
template<class T>T take(Observation<T> result){if(!result.value())throw std::runtime_error(result.unavailable_detail()->error.operation+" state="+std::to_string(int(result.state())));return std::move(result).take_value();}
NativeName name(std::string value){
#ifdef _WIN32
 return *NativeName::from_windows(std::u16string(value.begin(),value.end()));
#else
 return *NativeName::from_posix(std::move(value));
#endif
}
#ifdef _WIN32
std::wstring environment(const wchar_t* key){
 const auto size=GetEnvironmentVariableW(key,nullptr,0);CHECK(size>1&&size<=32768);
 std::wstring value(size,L'\0');CHECK(GetEnvironmentVariableW(key,value.data(),size)==size-1);value.resize(size-1);return value;
}
std::wstring extended(const std::filesystem::path& path){auto value=windows_extended_path(path.native());CHECK(value);return std::move(*value);}
struct FixtureHandle{HANDLE value=INVALID_HANDLE_VALUE;~FixtureHandle(){if(value!=INVALID_HANDLE_VALUE&&value&&!CloseHandle(value))std::abort();}void close(){const auto h=value;value=INVALID_HANDLE_VALUE;CHECK(CloseHandle(h));}};
struct FixtureLocal{HLOCAL value=nullptr;~FixtureLocal(){if(value&&LocalFree(value))std::abort();}};
struct FixtureSecurity {
 FixtureLocal descriptor;
 FixtureSecurity(){
  FixtureHandle token;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value));
  DWORD size=0;CHECK(!GetTokenInformation(token.value,TokenUser,nullptr,0,&size)&&GetLastError()==ERROR_INSUFFICIENT_BUFFER&&size>=sizeof(TOKEN_USER));
  std::vector<std::byte> bytes(size);CHECK(GetTokenInformation(token.value,TokenUser,bytes.data(),size,&size));
  const auto user=reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid;CHECK(IsValidSid(user));
  wchar_t* text=nullptr;CHECK(ConvertSidToStringSidW(user,&text));FixtureLocal sid{text};
  const auto sddl=L"O:"+std::wstring(text)+L"D:P(A;;FA;;;"+text+L")(A;;FA;;;SY)";
  PSECURITY_DESCRIPTOR sd=nullptr;CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr));descriptor.value=sd;token.close();
 }
 SECURITY_ATTRIBUTES attributes()const{return {sizeof(SECURITY_ATTRIBUTES),descriptor.value,FALSE};}
};
void mkdir_new(const std::filesystem::path& path){FixtureSecurity security;auto attributes=security.attributes();CHECK(CreateDirectoryW(extended(path).c_str(),&attributes));}
void cleanup(const std::filesystem::path& path){
 WIN32_FIND_DATAW data{};const auto h=FindFirstFileW((extended(path)+L"\\*").c_str(),&data);
 if(h==INVALID_HANDLE_VALUE)CHECK(GetLastError()==ERROR_FILE_NOT_FOUND);
 else {
  DWORD error=ERROR_SUCCESS;
  do {
   const std::wstring_view leaf(data.cFileName);if(leaf==L"."||leaf==L"..")continue;
   const auto child=path/data.cFileName;
   if((data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&!(data.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))cleanup(child);
   else if(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)CHECK(RemoveDirectoryW(extended(child).c_str()));
   else CHECK(DeleteFileW(extended(child).c_str()));
  }while(FindNextFileW(h,&data));
  error=GetLastError();CHECK(FindClose(h));CHECK(error==ERROR_NO_MORE_FILES);
 }
 CHECK(RemoveDirectoryW(extended(path).c_str()));
}
#else
void mkdir_new(const std::filesystem::path& path){CHECK(::mkdir(path.c_str(),0700)==0);}
void cleanup(const std::filesystem::path& path){std::filesystem::remove_all(path);}
#endif
struct Fixture {
 std::filesystem::path root,work;
 NativeFileSystem fs;
 std::shared_ptr<const DirectoryCursor> parent;
 static inline unsigned sequence=0;
 Fixture(){
#ifdef _WIN32
  const auto temp=environment(L"TMPDIR");(void)environment(L"TEMP");(void)environment(L"TMP");
  root=extended(std::filesystem::path(temp));
  wchar_t required[3]{};const auto size=GetEnvironmentVariableW(L"CK_FS_REQUIRE_V_DEV_DRIVE",required,3);
  if(size){CHECK(size==1&&(required[0]==L'0'||required[0]==L'1'));if(required[0]==L'1'){
   const auto path=extended(root);constexpr std::wstring_view prefix=L"\\\\?\\V:\\tmp\\";
   CHECK(GetFileAttributesW(L"V:\\")!=INVALID_FILE_ATTRIBUTES&&path.size()>=prefix.size());
   CHECK(CompareStringOrdinal(path.data(),int(prefix.size()),prefix.data(),int(prefix.size()),TRUE)==CSTR_EQUAL);
  }}
  root/=L"reviewed-root-cancel-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(++sequence);mkdir_new(root);
#else
  const char* tmp=std::getenv("TMPDIR");CHECK(tmp&&*tmp);
#ifdef __APPLE__
  CHECK(std::string(tmp).starts_with("/Volumes/S8T/tmp/")||std::string(tmp).starts_with("/Volumes/PRO-BLADE/tmp/"));
#endif
  std::string pattern=std::string(tmp)+"/reviewed-root-cancel.XXXXXX";CHECK(mkdtemp(pattern.data()));root=pattern;
#endif
  work=root;parent=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(work)));
  mkdir_new(path("s"));mkdir_new(path("d"));mkdir_new(path("journals"));
  CHECK(take(prepare_native_operation_journal_root(take(NativeAbsolutePath::from_host(path("journals"))))));
 }
 ~Fixture()noexcept{parent.reset();try{cleanup(root);}catch(const std::exception& e){
#ifdef _WIN32
  std::fwprintf(stderr,L"Root cancel fixture cleanup failed path=%ls\n",root.c_str());
#else
  std::fprintf(stderr,"Root cancel fixture cleanup failed path=%s\n",root.c_str());
#endif
  std::fprintf(stderr,"%s\n",e.what());std::abort();
 }}
 std::filesystem::path path(const char* leaf)const{return work/leaf;}
 ReviewedTreePlanRequest request(){
  ReviewedTreePlanRequest r;
  r.source_root=take(HeldChild::observe(parent,name("s")));r.destination_root=take(HeldChild::observe(parent,name("d")));
  r.destination_address=take(NativeAbsolutePath::from_host(path("d")));
  r.comparison.profile=ComparisonProfile::Copy;r.comparison.mode=ComparisonMode::CompleteDigest;
  r.copy_policy.allow_unhandled_metadata_loss=true;r.copy_policy.metadata_scope=RegularMetadataScope::OrdinaryCallerVisibleV1;
  r.journal_root=take(NativeAbsolutePath::from_host(path("journals")));r.open_journal=open_native_operation_journal_file;
  r.digest_chunk_bytes=7;r.journal_id.bytes[0]=std::byte(static_cast<unsigned char>(++sequence));return r;
 }
 bool exists(const char* leaf)const{return fs.inspect_basic(path(leaf)).value()!=nullptr;}
};
} // namespace
