// SPDX-License-Identifier: LGPL-2.0-or-later
// Genuine native Root, actual temporary directory handle, real close failure.
#ifndef CK_FS_NATIVE_CLOSE_TEST_HOOKS
#error All SDK TUs and this fixture require matching safe native-close hooks.
#endif
#include "native_filesystem.hpp"
#include "prepared_journal_root.hpp"
#include "metadata_capture_job.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "platform/native_close_test_faults.hpp"
#include "windows_name.hpp"
#include <windows.h>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <new>
#include <string_view>
#include <string>
#include <malloc.h>
using namespace ck::files;using namespace ck::files::detail;
namespace fault{thread_local bool oom=false;}
void* operator new(std::size_t n){if(fault::oom)throw std::bad_alloc();if(auto p=std::malloc(n?n:1))return p;throw std::bad_alloc();}void* operator new[](std::size_t n){return ::operator new(n);}void operator delete(void*p)noexcept{std::free(p);}void operator delete[](void*p)noexcept{std::free(p);}void operator delete(void*p,std::size_t)noexcept{std::free(p);}void operator delete[](void*p,std::size_t)noexcept{std::free(p);}
void* operator new(std::size_t n,std::align_val_t a){if(fault::oom)throw std::bad_alloc();if(auto p=_aligned_malloc(n?n:1,std::size_t(a)))return p;throw std::bad_alloc();}void* operator new[](std::size_t n,std::align_val_t a){return ::operator new(n,a);}void operator delete(void*p,std::align_val_t)noexcept{_aligned_free(p);}void operator delete[](void*p,std::align_val_t)noexcept{_aligned_free(p);}void operator delete(void*p,std::size_t,std::align_val_t)noexcept{_aligned_free(p);}void operator delete[](void*p,std::size_t,std::align_val_t)noexcept{_aligned_free(p);}
namespace{
unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x)){std::fprintf(stderr,"FAIL line=%u expr=%s oom=%d\n",unsigned(__LINE__),#x,fault::oom);std::abort();}}while(false)
template<class T>T get(Observation<T> o){CHECK(o.value());return std::move(o).take_value();} // never under OOM
struct Latch final:MetadataCaptureFailureLatch {PreparedJournalRoot::Pointer root;std::optional<MetadataCaptureCleanupError> first;explicit Latch(PreparedJournalRoot::Pointer r):root(std::move(r)){}void record_first(MetadataCaptureCleanupError e)const noexcept override{auto* self=const_cast<Latch*>(this);if(!self->first)self->first=e;record_prepared_journal_consumer_failure(*root,e.state,e.domain,e.code,e.operation);}};
constexpr char tag[]="journal_file.temporary_CloseHandle";
FILE_ID_INFO expected{},seen{};bool protect=false,arm_oom=false,control=false;HANDLE selected=nullptr,reused=nullptr;unsigned selected_calls=0;BOOL native_ok=FALSE;DWORD native_error=0;bool typed_directory=false;
void before(void* h,const char* op,const char*)noexcept{
 if(std::strcmp(op,tag))return;FILE_ID_INFO id{};FILE_STANDARD_INFO info{};
 if(!GetFileInformationByHandleEx(h,FileIdInfo,&id,sizeof(id))||!GetFileInformationByHandleEx(h,FileStandardInfo,&info,sizeof(info)))return;
 if(!info.Directory||id.VolumeSerialNumber!=expected.VolumeSerialNumber||std::memcmp(id.FileId.Identifier,expected.FileId.Identifier,16))return;
 selected=h;seen=id;typed_directory=true;++selected_calls;if(protect)CHECK(SetHandleInformation(h,HANDLE_FLAG_PROTECT_FROM_CLOSE,HANDLE_FLAG_PROTECT_FROM_CLOSE));
}
std::uint32_t after(void* h,const char* op,bool okay,std::uint32_t error)noexcept{
 if(std::strcmp(op,tag)||h!=selected)return 0;native_ok=okay;native_error=error;
 if(!protect&&!control&&okay){for(unsigned n=0;n<256;++n){auto e=CreateEventW(nullptr,TRUE,FALSE,nullptr);CHECK(e);if(e==h){reused=e;break;}CHECK(CloseHandle(e));}CHECK(reused);}
 if(arm_oom)fault::oom=true;return control?0:ERROR_WRITE_FAULT; // real failure must win over this later error.
}
NativeName name(const char16_t* p){return *NativeName::from_windows(std::u16string(p));}
std::filesystem::path ext(std::filesystem::path p){auto n=windows_extended_path(p.native());CHECK(n);return std::filesystem::path(*n);}
void log_environment(const wchar_t* key){
 std::array<wchar_t,32768> value{};const auto size=GetEnvironmentVariableW(key,value.data(),static_cast<DWORD>(value.size()));CHECK(size&&size<value.size());
 std::printf("JOURNAL_ENV %ls=%ls UTF16=%lu\n",key,value.data(),size);
}
}
int wmain(int argc,wchar_t** argv){CHECK(argc==5);CHECK(!IsDebuggerPresent());auto base=ext(argv[1]);const auto mode=std::wstring_view(argv[2]);const auto provider=std::wstring_view(argv[3]);CHECK(provider==L"NTFS"||provider==L"ReFS");wchar_t require_v[4]{};const auto count=GetEnvironmentVariableW(L"CK_FS_REQUIRE_V_DEV_DRIVE",require_v,4);if(count==1&&require_v[0]==L'1')CHECK(base.native().starts_with(LR"(\\?\V:\tmp\)"));
 const auto variant=std::wstring_view(argv[4]);CHECK(variant==L"ordinary"||variant==L"long");
 if(variant==L"long"){
  // Data-only nesting under the launcher's unique root, after the V policy.
  // Extended paths stay intact through native creation and Python cleanup.
  for(unsigned depth=0;depth<8&&base.native().size()<=340;++depth){base/=std::wstring(72,static_cast<wchar_t>(L'a'+depth));CHECK(CreateDirectoryW(base.c_str(),nullptr));}
  CHECK(base.native().size()>340);
 }else CHECK(base.native().size()+sizeof(L"\\private-root")/sizeof(wchar_t)-1<=260);
 std::printf("JOURNAL_PATH input=%ls data=%ls provider=%ls variant=%ls dataUTF16=%zu\n",argv[1],base.c_str(),argv[3],argv[4],base.native().size());
 log_environment(L"TEMP");log_environment(L"TMP");log_environment(L"TMPDIR");std::fflush(stdout);
 control=mode==L"control";protect=mode==L"native"||mode==L"native-oom";arm_oom=mode==L"native-oom"||mode==L"consumed-oom";CHECK(control||protect||mode==L"consumed"||mode==L"consumed-oom");
 NativeFileSystem fs;auto parent=std::shared_ptr<const DirectoryCursor>(get(fs.open_directory(base)));PreparedJournalRootRequest request;request.parent=parent;request.child=name(u"private-root");request.disposition=JournalRootDisposition::ProvisionChild;JournalRootPreparationProgress progress;auto root=get(prepare_native_journal_root(std::move(request),progress));Latch latch(root);
 // Query the actual held Root through an owning duplicate, never a path reopen.
 auto duplicate=get(duplicate_prepared_journal_directory(*root));HANDLE reference=static_cast<HANDLE>(duplicate);wchar_t filesystem[32]{};CHECK(GetFileInformationByHandleEx(reference,FileIdInfo,&expected,sizeof(expected)));CHECK(GetVolumeInformationByHandleW(reference,nullptr,0,nullptr,nullptr,nullptr,filesystem,32));CHECK(provider==filesystem);CHECK(CloseHandle(reference));
 native_close_test_before.store(before);native_close_test_after.store(after);bool caught=false,unavailable=false;
 {MetadataCaptureCleanupScope cleanup(&latch);try{auto result=root->open_journal(name(u"not-created"),false);unavailable=!result.value();}catch(const std::bad_alloc&){caught=true;}}
 CHECK(selected_calls==1&&typed_directory&&selected);CHECK(unavailable||caught);PreparedJournalConsumerFailure first{};const bool failed=read_prepared_journal_consumer_failure(*root,first);
 if(control){CHECK(native_ok&&!native_error&&!failed&&!latch.first);}
 else{CHECK(latch.first&&failed&&!first.pending&&first.domain==ErrorDomain::Win32&&first.code==(protect?ERROR_INVALID_HANDLE:ERROR_WRITE_FAULT)&&!std::strcmp(first.operation.data(),tag));if(protect)CHECK(!native_ok&&native_error==ERROR_INVALID_HANDLE);else CHECK(native_ok&&!native_error&&reused);}
 if(arm_oom){CHECK(fault::oom);bool denied=false;try{auto* p=new char[8];delete[]p;}catch(const std::bad_alloc&){denied=true;}CHECK(denied);PreparedJournalConsumerFailure repeated;CHECK(read_prepared_journal_consumer_failure(*root,repeated)&&repeated.code==first.code);}
 fault::oom=false;native_close_test_before.store(nullptr);native_close_test_after.store(nullptr);
 if(protect){DWORD flags=0;CHECK(GetHandleInformation(selected,&flags)&&(flags&HANDLE_FLAG_PROTECT_FROM_CLOSE));CHECK(SetHandleInformation(selected,HANDLE_FLAG_PROTECT_FROM_CLOSE,0));CHECK(CloseHandle(selected));}
 latch.root.reset();CHECK(root.use_count()==1);const auto attempts=selected_calls;auto finished=root->finish_io();if(control)CHECK(finished.value()&&*finished.value());else CHECK(!finished.value()&&finished.unavailable_detail()->error.code==first.code);auto again=root->finish_io();CHECK(bool(again.value())==control&&selected_calls==attempts);if(reused){DWORD flags=0;CHECK(GetHandleInformation(reused,&flags));CHECK(CloseHandle(reused));}
 std::printf("JOURNAL_TEMP mode=%ls provider=%ls variant=%ls parentUTF16=%zu checks=%u actualDirectory=1 volume=%llu FileID=",argv[2],filesystem,argv[4],base.native().size(),checks,static_cast<unsigned long long>(seen.VolumeSerialNumber));for(auto b:seen.FileId.Identifier)std::printf("%02x",unsigned(b));std::printf(" nativeCloseOkay=%d nativeError=%lu RootError=%lld caughtOOM=%d PASS\n",native_ok,native_error,static_cast<long long>(first.code),caught);return 0;}
