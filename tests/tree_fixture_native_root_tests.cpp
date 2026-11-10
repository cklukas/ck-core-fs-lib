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
bool requires_workstation_drive() {
 wchar_t value[2]{};
 return GetEnvironmentVariableW(L"CK_FS_REQUIRE_V_DEV_DRIVE",value,2)==1&&value[0]==L'1';
}
FILE_ID_INFO open_fixture_root(const std::filesystem::path& path,FixtureHandle& owner) {
 CHECK(path.is_absolute());
 const auto native=extended(path);
 CHECK(NativeAbsolutePath::from_host(std::filesystem::path(native)).value());
 owner.value=CreateFileW(native.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
  nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
 CHECK(owner.value!=INVALID_HANDLE_VALUE);
 FILE_ATTRIBUTE_TAG_INFO attributes{};FILE_ID_INFO identity{};
 CHECK(GetFileInformationByHandleEx(owner.value,FileAttributeTagInfo,&attributes,sizeof(attributes)));
 CHECK((attributes.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&!(attributes.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT));
 CHECK(GetFileInformationByHandleEx(owner.value,FileIdInfo,&identity,sizeof(identity)));
 return identity;
}
void root_control(const std::filesystem::path& parent,bool long_path,bool workstation,
                  const FILE_ID_INFO& parent_identity){const auto original=bounded_env(L"TMPDIR");
 std::wstring component=L"fixture-root-猫-";component.push_back(static_cast<wchar_t>(0xd800));component+=L"-"+std::to_wstring(GetCurrentProcessId())+(long_path?L"-long":L"-short");
 auto root=parent/component;mkdir_new(root);if(long_path)for(unsigned i=0;i<10;++i){root/=L"wide-native-root-component-0123456789";mkdir_new(root);}
 if(workstation)CHECK(fixture_on_canonical_v_tmp(root));
 const auto exact=extended(root);native_environment(exact);
 {
  FixtureHandle root_owner;
  const auto root_identity=open_fixture_root(root,root_owner);
  CHECK(root_identity.VolumeSerialNumber==parent_identity.VolumeSerialNumber);
  Fixture fixture;CHECK(fixture.root.native().starts_with(exact+L"\\"));CHECK(!long_path||fixture.root.native().size()>260);
  auto actual=take(NativeAbsolutePath::from_host(fixture.root));const auto* units=actual.windows_units();CHECK(units);
  CHECK(std::find(units->begin(),units->end(),char16_t(0xd800))!=units->end());
  write_file(fixture.path("s/raw-root-file"),"exact UTF16 root data");CHECK(fixture.read("s/raw-root-file")=="exact UTF16 root data");
  const auto fixture_identity=fixture.parent->identity();
  CHECK(fixture_identity.value()&&fixture_identity.value()->scheme==IdentityScheme::WindowsFileId128);
 }
 native_environment(original);
 // Restore/cleanup only this exact fixture-owned branch, using wide APIs.
 auto top=parent/component;cleanup(top);
}
}
int wmain(int argc,wchar_t** argv){try{CHECK(argc==2);
 const std::filesystem::path parent(argv[1]);
 const bool workstation=requires_workstation_drive();
 if(workstation)CHECK(fixture_on_canonical_v_tmp(parent));
 CHECK(!fixture_on_canonical_v_tmp(std::filesystem::path(L"C:\\tmp\\foreign")));
 // CTest supplies the admitted scratch root on both workstation and hosted CI.
 // Validate the actual directory before creating either test branch.
 FixtureHandle parent_owner;
 const auto parent_identity=open_fixture_root(parent,parent_owner);
 wchar_t provider[32]{};
 CHECK(GetVolumeInformationByHandleW(parent_owner.value,nullptr,0,nullptr,nullptr,nullptr,provider,32));
 const std::wstring_view filesystem(provider);
 CHECK(filesystem==L"NTFS"||filesystem==L"ReFS");
 native_environment(argv[1]);
 root_control(parent,false,workstation,parent_identity);
 root_control(parent,true,workstation,parent_identity);
 parent_owner.close();
 std::printf("tree_fixture_native_root: %u checks passed; Unicode+rawUTF16+extended long root\n",checks);return 0;
 }catch(const std::exception& error){std::fprintf(stderr,"tree_fixture_native_root: %s\n",error.what());return 1;}}
#else
int main(){return 0;}
#endif
