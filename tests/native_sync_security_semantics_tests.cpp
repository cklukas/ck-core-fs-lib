// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_observation.hpp"
#include "native_filesystem.hpp"
#include "windows_acl_semantics.hpp"
#include "windows_name.hpp"
#include <algorithm>
#include <bit>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#ifdef _WIN32
#include "platform/native_windows_native_fsd.hpp"
#include "platform/native_windows_journal_volume.hpp"
#include <sddl.h>
#endif
using namespace ck::files;
namespace {
using Bytes=std::vector<std::byte>;
void check(bool b,const char* m){if(!b)throw std::runtime_error(m);}
template<class T>T take(Observation<T> o){if(!o.value()){const auto&e=*o.unavailable_detail();throw std::runtime_error(e.error.operation+":"+std::to_string(e.error.code));}return std::move(o).take_value();}
#ifdef _WIN32
void success(Observation<bool> o){check(take(std::move(o)),"false result");}
#endif
void set(Bytes& b,std::size_t at,std::uint64_t n,unsigned width){for(unsigned i=0;i<width;++i)b.at(at+i)=std::byte((n>>(8*i))&255);}
Bytes sid(){return {std::byte{1},std::byte{1},std::byte{},std::byte{},std::byte{},std::byte{},std::byte{},std::byte{1},std::byte{},std::byte{},std::byte{},std::byte{}};}
Bytes ace(unsigned type,Bytes tail={}){Bytes b(8);b[0]=std::byte(type);set(b,4,1,4);auto s=sid();b.insert(b.end(),s.begin(),s.end());b.insert(b.end(),tail.begin(),tail.end());while(b.size()%4)b.push_back(std::byte{});set(b,2,b.size(),2);return b;}
Bytes acl(std::vector<Bytes> entries,unsigned revision=4,unsigned spare=0){Bytes b(8);b[0]=std::byte(revision);set(b,4,entries.size(),2);for(const auto& e:entries)b.insert(b.end(),e.begin(),e.end());b.resize(b.size()+spare,std::byte{0xad});set(b,2,b.size(),2);return b;}
Bytes canon(const Bytes& b){return take(detail::canonical_windows_acl(b));}
void corpus(){
    auto basic=ace(0),padded=basic;padded.resize(padded.size()+8,std::byte{0xaa});set(padded,2,padded.size(),2);
    check(canon(acl({basic}))==canon(acl({padded},4,32)),"ignored ACE/ACL padding leaked into digest");
    check(canon(acl({basic},2))!=canon(acl({basic},4)),"ACL revision omitted");
    auto denied=ace(1);check(canon(acl({basic,denied}))!=canon(acl({denied,basic})),"ACE order omitted");
    Bytes opaque{std::byte{0x77},std::byte{},std::byte{},std::byte{}};auto callback=ace(9,opaque),altered=callback;altered.back()=std::byte{1};
    check(canon(acl({callback}))!=canon(acl({altered})),"opaque application data omitted");
    Bytes condition{std::byte{'a'},std::byte{'r'},std::byte{'t'},std::byte{'x'},std::byte{0x10},std::byte{2},std::byte{},std::byte{},std::byte{},std::byte{'X'},std::byte{}};
    auto conditional=ace(9,condition);auto extra=conditional;extra.insert(extra.end(),4,std::byte{});set(extra,2,extra.size(),2);
    check(!detail::canonical_windows_acl(acl({extra})).value(),"excess conditional padding accepted");
    auto missing=conditional;missing.resize(missing.size()-4);set(missing,2,missing.size(),2);check(!detail::canonical_windows_acl(acl({missing})).value(),"truncated callback literal accepted");
    // Claim offsets and unreferenced bytes can change without changing values.
    const auto claim=[](unsigned gap){Bytes c(28+gap);set(c,0,20+gap,4);set(c,4,2,2);set(c,12,1,4);set(c,16,24+gap,4);c[20+gap]=std::byte{'N'};set(c,24+gap,17,4);c.resize(32+gap);return c;};
    check(canon(acl({ace(18,claim(0))}))==canon(acl({ace(18,claim(4))})),"claim-relative offsets/padding leaked into digest");
    auto changed=claim(0);set(changed,24,18,4);check(canon(acl({ace(18,claim(0))}))!=canon(acl({ace(18,changed)})),"resource attribute value omitted");
    for(unsigned type: {1U,2U,3U,5U,6U,16U}){
        Bytes c(40);set(c,0,20,4);set(c,4,type,2);set(c,12,1,4);set(c,16,24,4);c[20]=std::byte{'N'};
        if(type==3){c[24]=std::byte{'V'};}else if(type==5||type==16){set(c,24,4,4);c[28]=std::byte{'X'};}
        else set(c,24,1,8);
        const auto original=canon(acl({ace(18,c)}));
        if(type==3)c[24]=std::byte{'W'};else if(type==5||type==16)c[29]=std::byte{1};else set(c,24,0,8);
        check(original!=canon(acl({ace(18,c)})),"relative claim value family omitted");
    }
    for(unsigned type=0;type<=21;++type){Bytes a;
        if((type>=5&&type<=8)||type==11||type==12||type==15||type==16){a=Bytes(12+32);a[0]=std::byte(type);set(a,4,1,4);set(a,8,3,4);for(std::size_t i=12;i<44;++i)a[i]=std::byte(i);auto s=sid();a.insert(a.end(),s.begin(),s.end());set(a,2,a.size(),2);}
        else if(type==4){a=Bytes(12);a[0]=std::byte(type);set(a,8,1,2);auto s=sid();a.insert(a.end(),s.begin(),s.end());a.insert(a.end(),s.begin(),s.end());set(a,2,a.size(),2);}
        else a=ace(type,type==18?claim(0):Bytes{});
        check(detail::canonical_windows_acl(acl({a})).value()!=nullptr,"known ACE form blanket-refused");
        if(type==4){auto unknown=a;set(unknown,8,2,2);check(detail::canonical_windows_acl(acl({unknown})).state()==ObservationState::Unsupported,"unknown compound ACE subtype accepted");}
        if(!a.empty()){auto x=a;x[4]^=std::byte{2};check(canon(acl({a}))!=canon(acl({x})),"ACE mask omitted");}
    }
    auto bad=acl({basic});set(bad,4,2,2);check(!detail::canonical_windows_acl(bad).value(),"truncated ACL accepted");
    bad=acl({basic});bad[17]=std::byte{255};check(!detail::canonical_windows_acl(bad).value(),"malformed SID accepted");
    bad=acl({basic});bad[8]=std::byte{22};check(!detail::canonical_windows_acl(bad).value(),"unknown ACE accepted");
    std::cout<<"bounded ACE0..21, object GUID/SIDs, opaque application bytes, claim values, order/revision and padding regressions PASS\n";
}
#ifdef _WIN32
struct Handle{HANDLE value=nullptr;explicit Handle(HANDLE h=nullptr):value(h){}~Handle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);}Handle(const Handle&)=delete;Handle&operator=(const Handle&)=delete;};
struct Privilege{Handle token;TOKEN_PRIVILEGES old{};Privilege(){HANDLE h=nullptr;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&h)!=0,"privilege token");token.value=h;TOKEN_PRIVILEGES p{};p.PrivilegeCount=1;p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;check(LookupPrivilegeValueW(nullptr,L"SeSecurityPrivilege",&p.Privileges[0].Luid)!=0,"security privilege LUID");DWORD n=sizeof(old);SetLastError(0);check(AdjustTokenPrivileges(h,FALSE,&p,sizeof(old),&old,&n)&&GetLastError()==0,"security privilege unavailable");}~Privilege(){AdjustTokenPrivileges(token.value,FALSE,&old,0,nullptr,nullptr);}};
struct Descriptor{PSECURITY_DESCRIPTOR value=nullptr;explicit Descriptor(const std::wstring& s){check(ConvertStringSecurityDescriptorToSecurityDescriptorW(s.c_str(),1,&value,nullptr)!=0,"fixture SDDL invalid");}~Descriptor(){LocalFree(value);}Descriptor(const Descriptor&)=delete;};
std::wstring user_sid(){Handle token;check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value)!=0,"user token");DWORD n=0;GetTokenInformation(token.value,TokenUser,nullptr,0,&n);Bytes b(n);check(GetTokenInformation(token.value,TokenUser,b.data(),n,&n)!=0,"user SID query");LPWSTR text=nullptr;check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(b.data())->User.Sid,&text)!=0,"SID text");std::wstring result(text);LocalFree(text);return result;}
NativeName name(const char16_t* n){return *NativeName::from_windows(n);}
struct Fixture{
    std::wstring path;std::vector<std::wstring> parents;std::shared_ptr<const DirectoryCursor> directory;std::unique_ptr<OpenedEntry> source,target;
    Fixture(){const auto* p=_wgetenv(L"TEMP"),*q=_wgetenv(L"TMP");check(p&&q,"explicit Windows TEMP/TMP required");path=*windows_extended_path(p);const auto tmp=*windows_extended_path(q);if(const auto* v=_wgetenv(L"CK_FS_REQUIRE_V_DEV_DRIVE");v&&std::wstring_view(v)==L"1")check(path.starts_with(L"\\\\?\\V:\\tmp\\")&&tmp.starts_with(L"\\\\?\\V:\\tmp\\"),"V temp required");
        path+=L"\\security-semantics-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());Descriptor private_sd(L"O:"+user_sid()+L"D:P(A;;FA;;;"+user_sid()+L")(A;;FA;;;SY)");SECURITY_ATTRIBUTES sa{sizeof(sa),private_sd.value,FALSE};
        for(unsigned i=0;i<5;++i){if(i)path+=L"\\"+std::wstring(70,wchar_t(L'a'+i));check(CreateDirectoryW(path.c_str(),&sa)!=0,"fixture directory");parents.push_back(path);}
        NativeFileSystem fs;directory=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(path)));source=take(directory->create_child_file(name(u"s")));target=take(directory->create_child_file(name(u"t")));
        const std::byte data[]{std::byte{'b'},std::byte{'a'},std::byte{'s'},std::byte{'e'}};check(take(source->write_content(0,data))==4&&take(target->write_content(0,data))==4,"fixture write");success(source->flush_content());success(target->flush_content());
        Handle h(open());WCHAR fsname[32]{};check(GetVolumeInformationByHandleW(h.value,nullptr,0,nullptr,nullptr,nullptr,fsname,32),"fixture filesystem");const auto* expected=_wgetenv(L"CK_SECURITY_SEMANTICS_EXPECT_FS");check(expected&&std::wstring_view(expected)==fsname,"actual fixture filesystem mismatch");
        check(detail::prove_windows_native_fsd(h.value).qualified,"generic genuine FSD proof file refused");
        Handle dir(CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));
        check(dir.value!=INVALID_HANDLE_VALUE&&detail::prove_windows_native_fsd(dir.value).qualified,"generic genuine FSD directory proof refused");check(!detail::prove_windows_journal_volume(h.value).qualified,"frozen DIR-only helper admitted file");
        std::cout<<"native actual provider=";for(auto* c=fsname;*c;++c)std::cout<<char(*c);std::cout<<" longpath="<<path.size()<<'\n';
    }
    HANDLE open(){const HANDLE h=CreateFileW((path+L"\\s").c_str(),FILE_READ_ATTRIBUTES|READ_CONTROL|WRITE_DAC|WRITE_OWNER|ACCESS_SYSTEM_SECURITY,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE,"held fixture security handle");return h;}
    ~Fixture(){target.reset();source.reset();directory.reset();DeleteFileW((path+L"\\s").c_str());DeleteFileW((path+L"\\t").c_str());for(auto p=parents.rbegin();p!=parents.rend();++p)RemoveDirectoryW(p->c_str());}
};
NTSTATUS assign(HANDLE h,PSECURITY_DESCRIPTOR sd,SECURITY_INFORMATION mask){using Set=NTSTATUS(NTAPI*)(HANDLE,SECURITY_INFORMATION,PSECURITY_DESCRIPTOR);const auto p=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetSecurityObject");check(p!=nullptr,"NtSetSecurityObject resolve");return std::bit_cast<Set>(p)(h,mask,sd);}
MetadataReplayPolicy full(){MetadataReplayPolicy p;p.scope=RegularMetadataScope::CompleteMetadataV1;p.ownership=MetadataOwnership::Original;p.allow_privilege_metadata=true;return p;}
void native_case(const wchar_t* label,const std::wstring& dacl,const std::wstring& sacl,SECURITY_INFORMATION mask,bool required){
    Fixture f;Descriptor requested(L"D:P(A;;FA;;;"+user_sid()+L")(A;;FA;;;SY)"+dacl+L"S:P"+sacl);Handle security(f.open());
    auto status=assign(security.value,requested.value,mask);if(status!=0){std::cout<<"native class setup DENIED/UNSUPPORTED label=";for(auto*p=label;*p;++p)std::cout<<char(*p);std::cout<<" NTSTATUS="<<std::hex<<std::uint32_t(status)<<std::dec<<'\n';check(!required,"required native complex ACE setup failed");return;}
    const auto captured=take(capture_metadata_replay(*f.source,full()));check(captured.security_coverage!=nullptr,"Full native security proof missing");check(captured.security.size()==1&&captured.security[0].native_query_mask==0x1ff,"Full query omitted a logical class");
    auto* sd=const_cast<std::byte*>(captured.security[0].bytes.data());PACL native_lists[2]{};BOOL exists=FALSE,defaulted=FALSE;
    check(GetSecurityDescriptorDacl(sd,&exists,&native_lists[0],&defaulted)&&GetSecurityDescriptorSacl(sd,&exists,&native_lists[1],&defaulted),"native stored ACLs");
    std::vector<unsigned> stored;
    std::cout<<"stored native ACE types:";
    for(auto* list:native_lists)if(list)for(DWORD i=0;i<list->AceCount;++i){void* entry=nullptr;check(GetAce(list,i,&entry)!=0,"native stored ACE");const auto type=static_cast<ACE_HEADER*>(entry)->AceType;stored.push_back(type);std::cout<<' '<<unsigned(type);}
    std::cout<<'\n';const auto has=[&](unsigned type){return std::find(stored.begin(),stored.end(),type)!=stored.end();};
    check(has(SYSTEM_AUDIT_ACE_TYPE)&&has(SYSTEM_MANDATORY_LABEL_ACE_TYPE),"fixture did not actually persist audit AND label");
    const std::wstring_view kind(label);
    if(kind==L"conditional-and-object")check(has(ACCESS_ALLOWED_OBJECT_ACE_TYPE)&&has(ACCESS_ALLOWED_CALLBACK_ACE_TYPE),"native object/callback ACE omitted");
    if(kind==L"resource")check(has(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE),"native resource ACE omitted");
    if(kind==L"scoped-policy")check(has(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE),"native scoped-policy ACE omitted");
    if(kind==L"access-filter")check(has(SYSTEM_ACCESS_FILTER_ACE_TYPE),"native access-filter ACE omitted");
    const auto before=take(native_sync_metadata_digest(*f.source,captured));success(apply_metadata_replay(*f.target,captured));const auto applied=take(f.target->inspect_basic());success(verify_metadata_replay(*f.target,captured,applied));
    const auto replayed=take(capture_metadata_replay(*f.target,full()));const auto target=take(native_sync_metadata_digest(*f.target,replayed));check(before==target,"equal replayed Full descriptor has unequal semantic digest");
    // Mutation of exactly one stored ACE mask; the base payload/creation time
    // remain unchanged, so the digest difference must include security values.
    auto changed=captured.security[0].bytes;PACL native_acl=nullptr;BOOL present=FALSE,def=FALSE;check(GetSecurityDescriptorDacl(changed.data(),&present,&native_acl,&def)&&present&&native_acl,"captured DACL missing");void* raw=nullptr;check(GetAce(native_acl,native_acl->AceCount-1,&raw)!=0,"mutate one native ACE");bool application_changed=false;
    PACL candidates[]{native_acl,nullptr};BOOL sacl_present=FALSE;
    check(GetSecurityDescriptorSacl(changed.data(),&sacl_present,&candidates[1],&def)!=0,"captured SACL query");
    SECURITY_INFORMATION mutation=DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION;
    const std::byte pattern[]{std::byte{'W'},std::byte{},std::byte{'i'},std::byte{},std::byte{'n'},std::byte{},std::byte{'d'},std::byte{},std::byte{'o'},std::byte{},std::byte{'w'},std::byte{},std::byte{'s'},std::byte{}};
    for(unsigned k=0;k<2&&!application_changed;++k)if(candidates[k])for(DWORD i=0;i<candidates[k]->AceCount&&!application_changed;++i){
        void* entry=nullptr;check(GetAce(candidates[k],i,&entry)!=0,"application ACE query");auto* h=static_cast<ACE_HEADER*>(entry);
        auto bytes=std::span(static_cast<std::byte*>(entry),h->AceSize);auto it=std::search(bytes.begin(),bytes.end(),std::begin(pattern),std::end(pattern));
        if(it!=bytes.end()){*it=std::byte{'L'};application_changed=true;if(k)mutation=h->AceType==SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE?ATTRIBUTE_SECURITY_INFORMATION:(h->AceType==SYSTEM_ACCESS_FILTER_ACE_TYPE?ACCESS_FILTER_SECURITY_INFORMATION:SACL_SECURITY_INFORMATION);}
    }
    if(kind==L"conditional-and-object"||kind==L"resource"||kind==L"access-filter")
        check(application_changed,"required native application payload mutation missing");
    if(!application_changed)reinterpret_cast<ACCESS_ALLOWED_ACE*>(raw)->Mask^=FILE_READ_EA;
    std::cout<<"single stored ACE mutation="<<(application_changed?"application-data":"mask")<<'\n';
    check(assign(security.value,changed.data(),mutation)==0,"assign one changed native ACE");
    const auto fresh=take(capture_metadata_replay(*f.source,full()));check(before!=take(native_sync_metadata_digest(*f.source,fresh)),"single stored ACE change falsely converged");check(!native_sync_metadata_digest(*f.source,captured).value(),"stale native security evidence accepted");
    success(f.target->finish_content_writes());success(f.source->finish_content_writes());
    std::cout<<"native Full all-nine-class query, exact replay/equal digest and one-ACE conflict PASS label=";for(auto*p=label;*p;++p)std::cout<<char(*p);std::cout<<'\n';
}
unsigned driver_stub_mode=0,driver_stub_calls=0;
NTSTATUS NTAPI driver_stub(HANDLE,PIO_STATUS_BLOCK io,PVOID raw,ULONG size,ULONG info){
    check(info==9&&size==40&&reinterpret_cast<std::uintptr_t>(raw)%8==0,"generic proof used wrong information family/alignment");
    ++driver_stub_calls;auto* bytes=static_cast<std::byte*>(raw);check(std::to_integer<unsigned>(bytes[4])==32,"generic driver path input length");
    io->Status=0;io->Information=driver_stub_mode==1?4:12;bytes[0]=std::byte{};
    return driver_stub_mode==2?NTSTATUS(0x103):0;
}
void provider_negatives(){
    driver_stub_mode=0;driver_stub_calls=0;const auto unknown=detail::query_windows_native_fsd(nullptr,&driver_stub);
    check(!unknown.qualified&&unknown.state==ObservationState::Unsupported&&driver_stub_calls==2,"unknown FSD admitted or ReFS not checked");
    driver_stub_mode=1;check(!detail::query_windows_native_fsd(nullptr,&driver_stub).qualified,"malformed driver proof admitted");
    driver_stub_mode=2;check(!detail::query_windows_native_fsd(nullptr,&driver_stub).qualified,"pending/unqualified driver proof admitted");
    std::cout<<"Query9-only generic file/directory FSD proof refuses unknown, malformed and unexpected status fixtures PASS\n";
}
void native_tests(){Privilege privilege;provider_negatives();
    constexpr auto base=DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION|PROTECTED_SACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION;
    const std::wstring audit=L"(AU;SA;FR;;;WD)(ML;;NW;;;ME)";
    native_case(L"conditional-and-object",L"(OA;;0x8;00112233-4455-6677-8899-aabbccddeeff;;WD)(XA;;0x8;;;WD;(@Resource.Project == \"Windows\"))",audit,base,true);
    native_case(L"resource",L"",audit+L"(RA;;;;;WD;(\"Project\",TS,0,\"Windows\",\"SQL\"))",base|ATTRIBUTE_SECURITY_INFORMATION,true);
    native_case(L"scoped-policy",L"",audit+L"(SP;;;;;S-1-17-1)",base|SCOPE_SECURITY_INFORMATION,false);
    native_case(L"process-trust",L"",audit+L"(TL;;0x1;;;S-1-19-0-0)",base|PROCESS_TRUST_LABEL_SECURITY_INFORMATION,false);
    native_case(L"access-filter",L"",audit+L"(FL;;0x1;;;WD;(@Resource.Project == \"Windows\"))",base|ACCESS_FILTER_SECURITY_INFORMATION,false);
}
#endif
}
int main(int argc,char** argv){try{
const bool codec_only=argc==2&&std::strcmp(argv[1],"--codec")==0;
check(argc==1||codec_only,"expected no arguments or --codec");corpus();
#ifdef _WIN32
if(!codec_only)native_tests();
#endif
std::cout<<"native_sync_security_semantics_tests passed\n";return 0;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
