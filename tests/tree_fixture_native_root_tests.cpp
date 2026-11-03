// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#define CKFS_NATIVE_TREE_TEST_SUPPORT
#include "native_tree_execution_tests.cpp"
#undef CKFS_NATIVE_TREE_TEST_SUPPORT
#ifdef _WIN32
namespace {
std::wstring bounded_env(const wchar_t* name){const auto count=GetEnvironmentVariableW(name,nullptr,0);CHECK(count>1&&count<=32768);
 std::wstring value(count,L'\0');const auto n=GetEnvironmentVariableW(name,value.data(),count);CHECK(n>0&&n<count);value.resize(n);return value;}
void native_environment(const std::wstring& value){CHECK(value.size()<32768);for(const auto* key:{L"TMPDIR",L"TEMP",L"TMP"}){
 CHECK(SetEnvironmentVariableW(key,value.c_str()));CHECK(bounded_env(key)==value);}}
void root_control(const std::filesystem::path& parent,bool long_path){const auto original=bounded_env(L"TMPDIR");
 std::wstring component=L"fixture-root-猫-";component.push_back(static_cast<wchar_t>(0xd800));component+=L"-"+std::to_wstring(GetCurrentProcessId())+(long_path?L"-long":L"-short");
 auto root=parent/component;mkdir_new(root);if(long_path)for(unsigned i=0;i<10;++i){root/=L"wide-native-root-component-0123456789";mkdir_new(root);}
 const auto exact=extended(root);CHECK(fixture_on_canonical_v_tmp(root));native_environment(exact);
 {
  Fixture fixture;CHECK(fixture.root.native().starts_with(exact+L"\\"));CHECK(!long_path||fixture.root.native().size()>260);
  auto actual=take(NativeAbsolutePath::from_host(fixture.root));const auto* units=actual.windows_units();CHECK(units);
  CHECK(std::find(units->begin(),units->end(),char16_t(0xd800))!=units->end());
  write_file(fixture.path("s/raw-root-file"),"exact UTF16 root data");CHECK(fixture.read("s/raw-root-file")=="exact UTF16 root data");
  auto identity=fixture.parent->identity();CHECK(identity.value()&&identity.value()->scheme==IdentityScheme::WindowsFileId128);
 }
 native_environment(original);
 // Restore/cleanup only this exact fixture-owned branch, using wide APIs.
 auto top=parent/component;cleanup(top);
}
}
int wmain(int argc,wchar_t** argv){try{CHECK(argc==2);native_environment(argv[1]);CHECK(SetEnvironmentVariableW(L"CK_FS_REQUIRE_V_DEV_DRIVE",L"1"));
 CHECK(fixture_on_canonical_v_tmp(std::filesystem::path(argv[1])));CHECK(!fixture_on_canonical_v_tmp(std::filesystem::path(L"C:\\tmp\\foreign")));
 root_control(std::filesystem::path(argv[1]),false);root_control(std::filesystem::path(argv[1]),true);
 std::printf("tree_fixture_native_root: %u checks passed; Unicode+rawUTF16+extended long V-root\n",checks);return 0;
 }catch(const std::exception& error){std::fprintf(stderr,"tree_fixture_native_root: %s\n",error.what());return 1;}}
#else
int main(){return 0;}
#endif
