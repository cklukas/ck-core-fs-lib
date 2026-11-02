// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_replay.hpp"
#include "regular_metadata_preservation.hpp"
#include "native_filesystem.hpp"
#include "windows_name.hpp"
#include <cstdlib>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#ifdef __APPLE__
#include <sys/acl.h>
#include <membership.h>
#include <sys/mount.h>
#endif
#endif
using namespace ck::files;
namespace {
void require(bool value,const char* message) {if(!value) throw std::runtime_error(message);}
template<class T> const T& need(const Observation<T>& value,const char* message) {
    if(!value.value()) {
        std::cerr<<message<<": "<<value.unavailable_detail()->error.operation<<" state="<<static_cast<int>(value.state())
                 <<" code="<<value.unavailable_detail()->error.code<<'\n';
        throw std::runtime_error(message);
    }
    return *value.value();
}
void success(const Observation<bool>& value,const char* message) {require(need(value,message),message);}
NativeName name(const char* raw) {
#ifdef _WIN32
    std::u16string units;for(;*raw;++raw)units.push_back(static_cast<unsigned char>(*raw));
    return *NativeName::from_windows(std::move(units));
#else
    return *NativeName::from_posix(raw);
#endif
}
class UnsupportedEntry final:public OpenedEntry {
public:Observation<BasicMetadata> inspect_basic() const override {return {};}
};
struct Fixture {
    NativeFileSystem filesystem;
    std::shared_ptr<const DirectoryCursor> directory;
    std::unique_ptr<OpenedEntry> source;
    std::unique_ptr<OpenedEntry> target;
#ifdef _WIN32
    std::wstring root;
    std::vector<std::wstring> directories;
#else
    std::string root;
#endif
    explicit Fixture(const char* fixture_root=nullptr) {
#ifdef _WIN32
        (void)fixture_root;
        const auto* temp=_wgetenv(L"TEMP");const auto* tmp=_wgetenv(L"TMP");
        require(temp&&*temp&&tmp&&*tmp,"Windows tests require explicit TEMP/TMP");
        const auto native_temp=windows_extended_path(temp);const auto native_tmp=windows_extended_path(tmp);
        require(native_temp&&native_tmp,"Windows tests require absolute TEMP/TMP");
        const auto* require_v=_wgetenv(L"CK_FS_REQUIRE_V_DEV_DRIVE");
        if (require_v&&std::wstring_view(require_v)==L"1")
            require(native_temp->starts_with(L"\\\\?\\V:\\tmp\\")&&native_tmp->starts_with(L"\\\\?\\V:\\tmp\\"),"workstation tests require V:\\tmp TEMP/TMP");
        root=*native_temp+L"\\metadata-replay-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
        require(CreateDirectoryW(root.c_str(),nullptr)!=0,"create root");directories.push_back(root);
        // Exact wide/native calls exercise an extended path longer than MAX_PATH.
        for(int i=0;i<4;++i) {root+=L"\\"+std::wstring(72,L'a'+i);require(CreateDirectoryW(root.c_str(),nullptr)!=0,"create long root");directories.push_back(root);}
#else
        const auto* temp=fixture_root?fixture_root:std::getenv("TMPDIR");require(temp&&*temp,"explicit TMPDIR required");
#ifdef __APPLE__
        require(std::string(temp).starts_with("/Volumes/S8T/tmp/")||std::string(temp).starts_with("/Volumes/PRO-BLADE/tmp/"),"approved Mac temporary volume required");
#endif
        root=std::string(temp)+"/metadata-replay-tests.XXXXXX";require(mkdtemp(root.data())!=nullptr,"mkdtemp");
#endif
        auto opened=filesystem.open_directory(root);need(opened,"open directory");
        directory=std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
        auto from=directory->create_child_file(name("source"));need(from,"create source");source=std::move(from).take_value();
        auto to=directory->create_child_file(name("target"));need(to,"create target");target=std::move(to).take_value();
        const std::byte data[]{std::byte{'t'},std::byte{'e'},std::byte{'s'},std::byte{'t'}};
        require(need(source->write_content(0,data),"write source")==4,"source write count");
        require(need(target->write_content(0,data),"write target")==4,"target write count");
        success(source->flush_content(),"flush source");success(target->flush_content(),"flush target");
    }
    ~Fixture() {
        source.reset();target.reset();directory.reset();
#ifdef _WIN32
        for(const auto* n:{L"source",L"target",L"renamed",L"moved",L"held-renamed",L"staging",L"published",L"exact_\u00e9. "}) DeleteFileW((root+L"\\"+n).c_str());
        for(auto it=directories.rbegin();it!=directories.rend();++it) RemoveDirectoryW(it->c_str());
#else
        for(const auto* n:{"source","target","renamed"}) unlink((root+"/"+n).c_str());
        rmdir(root.c_str());
#endif
    }
    MetadataReplayPolicy policy(RegularMetadataScope scope=RegularMetadataScope::OrdinaryCallerVisibleV1) {
        MetadataReplayPolicy result;result.scope=scope;result.ownership=MetadataOwnership::CurrentCaller;return result;
    }
    AttributeValue attribute(const char* key,std::vector<std::byte> bytes) {
#ifdef _WIN32
        auto id=*NativeFeatureIdentifier::from_windows_ea(key);
        auto flags=Observation<std::uint32_t>::available(0);
#else
        auto id=*NativeFeatureIdentifier::from_posix(key);Observation<std::uint32_t> flags;
#endif
        return {std::move(id),std::move(bytes),need(source->inspect_basic(),"source identity").identity,std::move(flags)};
    }
    void add_attribute(const char* key,std::vector<std::byte> value) {success(source->apply_nonsecurity_attribute(attribute(key,std::move(value))),"set source attribute");}
    MetadataReplaySnapshot capture(MetadataReplayPolicy p) {return need(capture_metadata_replay(*source,p),"capture");}
    BasicMetadata replay(const MetadataReplaySnapshot& snapshot) {
        success(apply_metadata_replay(*target,snapshot),"apply replay");
        const auto applied=need(target->inspect_basic(),"applied identity");
        success(verify_metadata_replay(*target,snapshot,applied),"verify replay");return applied;
    }
};
class DeniedInventory final : public OpenedEntry {
public:
    DeniedInventory(const OpenedEntry& entry,bool attributes):entry_(entry),attributes_(attributes) {}
    Observation<BasicMetadata> inspect_basic() const override {return entry_.inspect_basic();}
    Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy& p) const override {return entry_.qualify_metadata_replay(p);}
    Observation<AttributeCatalog> inspect_attributes(InventoryLimits limits) const override {
        return attributes_ ? Observation<AttributeCatalog>::unavailable(ObservationState::Denied,{ErrorDomain::Posix,13,"fixture.attribute_denied"}) : entry_.inspect_attributes(limits);
    }
    Observation<AttributeValue> read_attribute(const NativeFeatureIdentifier& id,InventoryLimits limits) const override {return entry_.read_attribute(id,limits);}
    Observation<StorageInfo> inspect_storage() const override {return entry_.inspect_storage();}
    Observation<NativeSecurityValue> read_security(SecurityPart,InventoryLimits) const override {
        return Observation<NativeSecurityValue>::unavailable(ObservationState::Denied,{ErrorDomain::Posix,13,"fixture.security_denied"});
    }
private:const OpenedEntry& entry_;bool attributes_;
};
class DeniedOwnership final : public OpenedEntry {
public:
    explicit DeniedOwnership(const OpenedEntry& entry):entry_(entry) {}
    Observation<BasicMetadata> inspect_basic() const override {return entry_.inspect_basic();}
    Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy& p) const override {return entry_.qualify_metadata_replay(p);}
    Observation<bool> apply_replay_ownership(const BasicMetadata&,const MetadataReplayPolicy&) override {
        return Observation<bool>::unavailable(ObservationState::Denied,{ErrorDomain::Posix,1,"fixture.ownership_denied"});
    }
private:const OpenedEntry& entry_;
};
void policy_tests() {
    MetadataReplayPolicy p;require(p.valid(),"default policy invalid");p.version=2;require(!p.valid(),"unknown version accepted");
    UnsupportedEntry unsupported;
    require(unsupported.qualify_stable_content().state()==ObservationState::Unsupported,"unqualified content freeze accepted");
    require(capture_metadata_replay(unsupported,p).state()==ObservationState::Failed,"invalid policy not typed Failed");
    require(!valid_entry_access(EntryAccess::RenameSource|EntryAccess::MoveSource),"contradictory guards accepted");
    require(valid_entry_access(EntryAccess::RenameSource|EntryAccess::ContentRead),"rename read guard rejected");
}
void writer_finalization_tests() {
    Fixture f;
    // Capture live qualified evidence before fully closing the writer. The
    // receipt can retain this value, never a post-close reinspection claim.
    const auto before=need(f.target->inspect_basic(),"writer identity before finish");
    success(f.target->finish_content_writes(),"native writer finish");
    success(f.target->finish_content_writes(),"native writer finish idempotent");
    require(!f.target->inspect_basic().value(),"closed writer remained inspectable");
    require(!f.target->read_content().value(),"closed writer remained readable");
    const std::byte bytes[]{std::byte{'x'}};
    require(!f.target->write_content(0,bytes).value(),"closed writer remained writable");
    require(!f.target->flush_content().value(),"closed writer flush accepted");
    auto opened=f.directory->open_child(name("target"),EntryAccess::ContentRead);
    need(opened,"independent final destination read");
    const auto after=need((*opened.value())->inspect_basic(),"independent final identity");
    require(before.identity.value()&&after.identity.value()&&
        compare_identity(*before.identity.value(),*after.identity.value())==IdentityComparison::Same,
        "finalized writer identity changed");
    const auto data=need((*opened.value())->read_content(),"finalized data");
    require(data.bytes==std::vector<std::byte>{std::byte{'t'},std::byte{'e'},std::byte{'s'},std::byte{'t'}},
        "finalized bytes changed");
#ifdef _WIN32
    HANDLE writer=CreateFileW((f.root+L"\\target").c_str(),GENERIC_WRITE|DELETE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(writer!=INVALID_HANDLE_VALUE,"finalization retained WRITE/DELETE share exclusion");
    require(CloseHandle(writer)!=0,"independent writer close");
#endif
    std::cout<<"native writer finalization closes handle, disables live access and caches success\n";
}
#ifdef _WIN32
void strong_staging_tests() {
    Fixture f;
    auto created=f.directory->create_staging_file(name("staging"));need(created,"strong Windows staging");
    require(created.value()->staging_namespace==StagingNamespace::Named&&created.value()->name&&
        *created.value()->name==name("staging"),"Windows staging namespace evidence");
    auto staging=std::move(created).take_value().entry;
    const auto before=need(staging->inspect_basic(),"staging held identity");
    const std::byte bytes[]{std::byte{'x'}};
    require(need(staging->write_content(0,bytes),"staging content")==1,"staging write length");
    const auto excluded=[&](const wchar_t* leaf) {
        for(const DWORD rights:{DWORD(GENERIC_WRITE),DWORD(DELETE)}) {
            HANDLE outsider=CreateFileW((f.root+L"\\"+leaf).c_str(),rights,
                FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
            const DWORD code=GetLastError();if(outsider!=INVALID_HANDLE_VALUE) CloseHandle(outsider);
            require(outsider==INVALID_HANDLE_VALUE&&code==ERROR_SHARING_VIOLATION,"strong staging lost WRITE/DELETE exclusion");
        }
    };
    excluded(L"staging");
    success(staging->publish_noreplace(*f.directory,name("published")),"same held staging publication");
    excluded(L"published");
    const auto published=need(staging->inspect_basic(),"published held identity");
    require(before.identity.value()&&published.identity.value()&&
        compare_identity(*before.identity.value(),*published.identity.value())==IdentityComparison::Same,
        "publication changed held staging identity");
    success(staging->finish_content_writes(),"published writer finish");
    success(staging->finish_content_writes(),"published writer cached finish");
    auto reopened=f.directory->open_child(name("published"),EntryAccess::ContentRead);need(reopened,"published independent reader");
    const auto observed=need((*reopened.value())->inspect_basic(),"published independent identity");
    require(observed.identity.value()&&compare_identity(*published.identity.value(),*observed.identity.value())==IdentityComparison::Same,
        "finalized published identity mismatch");
    require(need((*reopened.value())->read_content(),"published bytes").bytes==std::vector<std::byte>{std::byte{'x'}},
        "published content mismatch");
    std::cout<<"strong Windows staging retains WRITE/DELETE exclusion through held-object publication, then finalizes\n";
}
#endif
#ifdef __APPLE__
void noowners_tests() {
    const auto* negative_root=std::getenv("CK_FS_NOOWNERS_TEST_ROOT");
    if (!negative_root) negative_root="/Volumes/S8T/tmp/";
    struct statfs filesystem{};
    if (statfs(negative_root,&filesystem)!=0 || !(filesystem.f_flags&MNT_IGNORE_OWNERSHIP)) {
        require(!std::getenv("CK_METADATA_REPLAY_REQUIRE_NOOWNERS"),"mandatory noowners fixture mount unavailable");
        std::cout<<"noowners negative mount unavailable\n";return;
    }
    Fixture ignored(negative_root),enforced;
    struct statfs positive{};
    require(statfs(enforced.root.c_str(),&positive)==0 && !(positive.f_flags&MNT_IGNORE_OWNERSHIP),
        "positive metadata fixtures require ownership enforcement");
    const auto refused=[](const auto& observed) {
        require(observed.state()==ObservationState::Unsupported,"noowners metadata was qualified");
        require(observed.unavailable_detail()->error.domain==ErrorDomain::Adapter &&
            observed.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::ProviderReviewRequired) &&
            observed.unavailable_detail()->error.operation=="metadata_replay.ignored_ownership_mount",
            "noowners refusal lost its mount-specific evidence");
    };
    refused(ignored.source->qualify_ordinary_regular_metadata());
    for (const auto scope:{RegularMetadataScope::OrdinaryCallerVisibleV1,RegularMetadataScope::CompleteMetadataV1})
        for (const auto owner:{MetadataOwnership::CurrentCaller,MetadataOwnership::Original}) {
            auto policy=ignored.policy(scope);policy.ownership=owner;
            refused(ignored.source->qualify_metadata_replay(policy));
            refused(capture_metadata_replay(*ignored.source,policy));
        }
    const auto policy=enforced.policy();
    const auto snapshot=enforced.capture(policy);
    const auto before=need(ignored.target->inspect_basic(),"noowners target before");
    refused(apply_metadata_replay(*ignored.target,snapshot));
    const auto after=need(ignored.target->inspect_basic(),"noowners target after");
    require(before.changed.value() && after.changed.value() && *before.changed.value()==*after.changed.value(),
        "noowners target mutated before refusal");
    refused(ignored.target->apply_current_caller_ownership());
    refused(ignored.target->apply_replay_ownership(snapshot.basic,policy));
    refused(ignored.target->apply_replay_security(snapshot.security.front(),policy));
    refused(ignored.target->verify_replay_security(snapshot.security.front(),policy));
    auto held=HeldChild::observe(ignored.directory,name("source"));need(held,"held noowners source");
    refused(RegularMetadataPreservation::create_with_policy(*held.value(),false,policy));
    std::cout<<"mounted noowners source/target capture, ownership, ACL apply/verify refusal passed\n";
}
#endif
void native_tests() {
    Fixture f;
    auto p=f.policy();
    const auto qualified=f.source->qualify_metadata_replay(p);
    if(!qualified.value()) {
        std::cout<<"native provider unsupported: "<<qualified.unavailable_detail()->error.operation<<'\n';
        require(!std::getenv("CK_METADATA_REPLAY_REQUIRE_NATIVE_SUCCESS"),"mandatory native replay unavailable");return;
    }
#ifdef _WIN32
    const char* key="CK.REPLAY";
#else
    const char* key="user.ck_replay";
#endif
    f.add_attribute(key,{std::byte{0},std::byte{0xff},std::byte{7}});
#ifndef _WIN32
    f.add_attribute("user.ck_empty",{});
#endif
#ifdef _WIN32
    // Opting into label replay must not materialize a present null SACL for
    // an already-exact implicit label. This is the C v2 Original-owner path.
    {
        Fixture original;
        auto explicit_policy=original.policy();explicit_policy.ownership=MetadataOwnership::Original;
        explicit_policy.allow_privilege_metadata=true;
        const auto captured=original.capture(explicit_policy);
        original.replay(captured);
        success(original.target->finish_content_writes(),"security-bearing writer finish");
        require(!original.target->inspect_basic().value(),"security-bearing writer still live");
    }
    {
        Fixture labelled;
        auto explicit_policy=labelled.policy();explicit_policy.ownership=MetadataOwnership::Original;
        explicit_policy.allow_privilege_metadata=true;
        PSECURITY_DESCRIPTOR descriptor=nullptr;ULONG size=0;
        require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;LW)",SDDL_REVISION_1,&descriptor,&size)!=0,
            "construct explicit low integrity label");
        const auto* first=static_cast<const std::byte*>(descriptor);
        NativeSecurityValue label{SecurityPart::WindowsIntegrity,SecurityEncoding::WindowsRelativeDescriptor,
            SecurityPresence::Present,NativeBytes(first,first+size),
            need(labelled.source->inspect_basic(),"label source identity").identity,LABEL_SECURITY_INFORMATION};
        LocalFree(descriptor);
        success(labelled.source->apply_replay_security(label,explicit_policy),"install actual mandatory integrity label");
        const auto captured=labelled.capture(explicit_policy);
        auto no_optin=explicit_policy;no_optin.allow_privilege_metadata=false;
        const auto refused=labelled.target->apply_replay_security(captured.security.back(),no_optin);
        require(refused.state()==ObservationState::Changed,"different integrity label silently accepted without optin");
        labelled.replay(captured);
        std::cout<<"explicit mandatory integrity ACE replayed and exactly verified with optin\n";
    }
    // Match the C API/tree leaf access: data read without EA/READ_CONTROL.
    auto minimal=HeldChild::observe_with_access(f.directory,name("source"),EntryAccess::ContentRead);
    need(minimal,"minimal source handle");
    const auto through_identity=(*minimal.value())->capture_metadata(p);
    need(through_identity,"policy-specific held identity query rights");
    require(!through_identity.value()->attributes.empty(),"identity query lost source EAs");
    auto full_policy=p;full_policy.scope=RegularMetadataScope::CompleteMetadataV1;full_policy.allow_privilege_metadata=true;
    auto full=(*minimal.value())->capture_metadata(full_policy);
    if (full.value()) require(full.value()->security.size()==1&&full.value()->security.front().part==SecurityPart::WindowsFullDescriptor,
        "full security query silently weakened");
    else require(full.state()==ObservationState::Denied||full.state()==ObservationState::Unsupported,"full security denial not retained");
    for (const DWORD rights:{DWORD(GENERIC_WRITE),DWORD(DELETE)}) {
        HANDLE outsider=CreateFileW((f.root+L"\\source").c_str(),rights,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        const DWORD code=GetLastError();
        if (outsider!=INVALID_HANDLE_VALUE) CloseHandle(outsider);
        require(outsider==INVALID_HANDLE_VALUE&&code==ERROR_SHARING_VIOLATION,"staging permits external WRITE/DELETE handle");
    }
    require(!MoveFileExW((f.root+L"\\source").c_str(),(f.root+L"\\moved").c_str(),0)&&
        GetLastError()==ERROR_SHARING_VIOLATION,"staging basename can be renamed externally");
#endif
    auto snapshot=f.capture(p);
    require(!snapshot.attributes.empty(),"missing attribute inventory");
#ifdef __APPLE__
    const auto provenance=std::find_if(snapshot.attributes.begin(),snapshot.attributes.end(),[](const auto& a){return a.identifier.posix_bytes()&&*a.identifier.posix_bytes()=="com.apple.provenance";});
    require(provenance!=snapshot.attributes.end(),"provenance regression fixture unavailable");
#endif
    DeniedInventory denied_attributes(*f.source,true),denied_security(*f.source,false);
    require(capture_metadata_replay(denied_attributes,p).state()==ObservationState::Denied,"attribute denial weakened");
    require(capture_metadata_replay(denied_security,p).state()==ObservationState::Denied,"security denial weakened");
    DeniedOwnership denied_owner(*f.target);
    require(apply_metadata_replay(denied_owner,snapshot).state()==ObservationState::Denied,"ownership denial weakened");
    const auto applied=f.replay(snapshot);
    auto mutation=f.attribute(key,{std::byte{8}});mutation.owner=applied.identity;
    success(f.target->apply_nonsecurity_attribute(mutation),"tamper target attribute");
    require(verify_metadata_replay(*f.target,snapshot,applied).state()==ObservationState::Changed,"target tampering accepted");
    f.add_attribute(key,{std::byte{9}});
    require(verify_metadata_replay_source(*f.source,snapshot).state()==ObservationState::Changed,"source tampering accepted");
    std::stop_source cancelled;cancelled.request_stop();
    require(!capture_metadata_replay(*f.source,p,cancelled.get_token()).value(),"cancelled capture accepted");
    auto bounded=p;bounded.limits.max_native_bytes=1;
    require(!capture_metadata_replay(*f.source,bounded).value(),"inventory byte bound ignored");

    Fixture inherited;
    auto extra=inherited.attribute("user.ck_inherited",{std::byte{6}});
#ifdef _WIN32
    extra.identifier=*NativeFeatureIdentifier::from_windows_ea("CK.INHERITED");
    extra.native_flags=Observation<std::uint32_t>::available(0);
#endif
    extra.owner=need(inherited.target->inspect_basic(),"target owner").identity;
    success(inherited.target->apply_nonsecurity_attribute(extra),"install inherited attribute");
    auto clean=inherited.capture(p);inherited.replay(clean);
    require(!inherited.target->read_attribute(extra.identifier).value(),"inherited extra attribute retained");

    Fixture held;
    const auto access=EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity;
    auto source=HeldChild::observe_with_access(held.directory,name("source"),access);need(source,"held source");
    auto preserving=RegularMetadataPreservation::create_with_policy(*source.value(),false,p);need(preserving,"regular preserving capture");
    auto prepared=(*preserving.value())->prepare(*held.target);need(prepared,"regular metadata job");
    auto& job=**prepared.value();
    for(int i=0;i<12&&job.state()!=OperationMetadataState::Complete&&job.state()!=OperationMetadataState::Failed;++i)job.advance();
    if(job.failure())std::cerr<<"job failure: "<<job.failure()->error.operation<<'\n';
    require(job.state()==OperationMetadataState::Complete,"regular metadata job failed");
    success((*preserving.value())->verify(*held.target),"regular final verification");
    auto smaller=held.attribute(key,{std::byte{3}});success(held.source->apply_nonsecurity_attribute(smaller),"held mutate source");
    require(!(*preserving.value())->verify(*held.target).value(),"regular prepublish source mutation accepted");

#ifndef _WIN32
    Fixture mode;
    // Darwin can clear setgid when an inherited directory group is not one
    // of the caller's groups. Establish the fixture's intended group first.
    success(mode.source->apply_current_caller_ownership(),"special-bit source ownership");
    require(chmod((mode.root+"/source").c_str(),06754)==0,"install special bits");
    require(*need(mode.source->inspect_basic(),"special source mode").posix_permissions.value()==06754,"fixture special bits not installed");
    require(!capture_metadata_replay(*mode.source,p).value(),"special bits silently accepted");
    auto opted=p;opted.allow_privilege_metadata=true;
    auto special=mode.capture(opted);mode.replay(special);
    require(*need(mode.target->inspect_basic(),"special mode").posix_permissions.value()==06754,"explicit special bits not preserved");
    // Captured metadata belongs to the retained inode after a name replacement.
    Fixture renamed;
    const auto before=renamed.capture(p);
    require(rename((renamed.root+"/source").c_str(),(renamed.root+"/renamed").c_str())==0,"rename source");
    const int replacement=open((renamed.root+"/source").c_str(),O_CREAT|O_EXCL|O_WRONLY,0600);
    require(replacement>=0,"replace source name");close(replacement);
    // Rename changes ctime: a new capture is needed, but it must still name
    // the original held inode, not the replacement basename.
    const auto held_snapshot=renamed.capture(p);
    require(compare_identity(*before.basic.identity.value(),*held_snapshot.basic.identity.value())==IdentityComparison::Same,"capture reopened replacement name");
#endif
#ifdef __APPLE__
    Fixture acl;
    acl_t native=acl_init(1);require(native!=nullptr,"acl_init");acl_entry_t entry{};
    require(acl_create_entry(&native,&entry)==0&&acl_set_tag_type(entry,ACL_EXTENDED_ALLOW)==0,"create ACE");
    uuid_t uuid{};require(mbr_uid_to_uuid(geteuid(),uuid)==0&&acl_set_qualifier(entry,uuid)==0,"ACE qualifier");
    acl_permset_t perms{};require(acl_get_permset(entry,&perms)==0&&acl_add_perm(perms,ACL_READ_DATA)==0&&acl_set_permset(entry,perms)==0,"ACE permissions");
    const int fd=open((acl.root+"/source").c_str(),O_RDONLY);require(fd>=0&&acl_set_fd_np(fd,native,ACL_TYPE_EXTENDED)==0,"install ACL");close(fd);acl_free(native);
    auto with_acl=acl.capture(p);require(with_acl.security.front().presence==SecurityPresence::Present,"ACL not captured");acl.replay(with_acl);
    // An inherited ACL must also be removed when the source has none.
    auto malformed=with_acl.security.front();malformed.bytes.resize(8);
    require(!acl.target->apply_replay_security(malformed,p).value(),"truncated Darwin ACL accepted");
    auto empty=acl.capture(p);empty.security.front().presence=SecurityPresence::Absent;empty.security.front().bytes.clear();
    success(acl.target->apply_replay_security(empty.security.front(),p),"remove inherited Darwin ACL");
    require(need(acl.target->read_security(SecurityPart::DarwinExtendedAcl),"removed ACL query").presence==SecurityPresence::Absent,"inherited ACL not removed");
    Fixture complete;
    auto full=complete.policy(RegularMetadataScope::CompleteMetadataV1);full.ownership=MetadataOwnership::Original;
    const auto unproved=capture_metadata_replay(*complete.source,full);
    require(unproved.state()==ObservationState::Unsupported&&
        unproved.unavailable_detail()->error.operation=="metadata_replay.complete_security_coverage_unproved",
        "Darwin complete security coverage overclaimed");
    auto forged=complete.capture(p);forged.policy=full;
    const auto untouched=need(complete.target->inspect_basic(),"complete target before refusal");
    require(apply_metadata_replay(*complete.target,forged).state()==ObservationState::Unsupported,
        "caller-constructed complete snapshot bypassed coverage proof");
    const auto after_refusal=need(complete.target->inspect_basic(),"complete target after refusal");
    require(untouched.changed.value()&&after_refusal.changed.value()&&*untouched.changed.value()==*after_refusal.changed.value(),
        "complete target mutated before coverage refusal");
#endif
#ifdef __linux__
    Fixture acl;
    const unsigned char bytes[]={2,0,0,0,1,0,6,0,255,255,255,255,2,0,4,0,210,4,0,0,4,0,4,0,255,255,255,255,16,0,4,0,255,255,255,255,32,0,0,0,255,255,255,255};
    const int fd=open((acl.root+"/source").c_str(),O_RDONLY);require(fd>=0&&fsetxattr(fd,"system.posix_acl_access",bytes,sizeof(bytes),0)==0,"install Linux ACL");close(fd);
    auto with_acl=acl.capture(p);require(with_acl.security.front().presence==SecurityPresence::Present,"Linux ACL not captured");acl.replay(with_acl);
    auto malformed=with_acl.security.front();malformed.bytes.resize(5);
    require(!acl.target->apply_replay_security(malformed,p).value(),"truncated Linux ACL accepted");
    require(!capture_metadata_replay(*acl.source,acl.policy(RegularMetadataScope::CompleteMetadataV1)).value(),"Linux complete coverage overclaimed");
    if (geteuid()==0) {
        Fixture ownership;
        require(chown((ownership.root+"/source").c_str(),1234,2345)==0,"distinct source ownership fixture");
        auto original=p;original.ownership=MetadataOwnership::Original;
        ownership.replay(ownership.capture(original));
        struct stat owner{};require(stat((ownership.root+"/target").c_str(),&owner)==0&&owner.st_uid==1234&&owner.st_gid==2345,
            "explicit original ownership not replayed");
        ownership.replay(ownership.capture(p));
        require(stat((ownership.root+"/target").c_str(),&owner)==0&&owner.st_uid==geteuid()&&owner.st_gid==getegid(),
            "explicit caller ownership not replayed");
        Fixture capabilities;
        const unsigned char capability[]={1,0,0,2,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        const int cap_fd=open((capabilities.root+"/source").c_str(),O_RDONLY|O_CLOEXEC);
        require(cap_fd>=0&&fsetxattr(cap_fd,"security.capability",capability,sizeof(capability),0)==0,"install real capability fixture");close(cap_fd);
        require(!capture_metadata_replay(*capabilities.source,p).value(),"capability replay without optin accepted");
        auto explicit_policy=p;explicit_policy.allow_privilege_metadata=true;
        auto captured=capabilities.capture(explicit_policy);const auto applied=capabilities.replay(captured);
        // Exercise the regular final-times callback again after capabilities.
        success(capabilities.target->apply_replay_basic(captured.basic,explicit_policy),"final times after capabilities");
        success(verify_metadata_replay(*capabilities.target,captured,applied),"capabilities survive final metadata phase");
        unsigned char copied[sizeof(capability)]{};
        const int target_fd=open((capabilities.root+"/target").c_str(),O_RDONLY|O_CLOEXEC);
        require(target_fd>=0&&fgetxattr(target_fd,"security.capability",copied,sizeof(copied))==sizeof(capability)&&
            std::equal(std::begin(copied),std::end(copied),std::begin(capability)),"opted-in capability bytes changed");close(target_fd);
        std::cout<<"real privileged capability replay and final-phase verification passed\n";
    }

#endif
#ifdef _WIN32
    if (f.root.size()>6 && f.root[5]==L':') {
    const auto unc_root=std::wstring(L"\\\\?\\UNC\\localhost\\")+f.root[4]+L"$"+f.root.substr(6);
    auto unc_directory=f.filesystem.open_directory(unc_root);
    if (unc_directory.value()) {
        auto unc_source=(*unc_directory.value())->open_child(name("source"),EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity);
        if (unc_source.value()) require(capture_metadata_replay(**unc_source.value(),p).state()==ObservationState::Unsupported,"UNC provider metadata coverage overclaimed");
        else std::cout<<"UNC source query unavailable: "<<unc_source.unavailable_detail()->error.operation<<'\n';
    } else std::cout<<"UNC administrative share unavailable: "<<unc_directory.unavailable_detail()->error.operation<<'\n';
    }
    f.source.reset();
    auto held_guard=HeldChild::observe_with_access(f.directory,name("source"),EntryAccess::RenameSource|EntryAccess::ContentRead|EntryAccess::MetadataAndLayout);
    need(held_guard,"held rename guard");
    for (const DWORD rights:{DWORD(GENERIC_WRITE),DWORD(DELETE)}) {
        HANDLE outsider=CreateFileW((f.root+L"\\source").c_str(),rights,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        const DWORD code=GetLastError();
        if (outsider!=INVALID_HANDLE_VALUE) CloseHandle(outsider);
        require(outsider==INVALID_HANDLE_VALUE&&code==ERROR_SHARING_VIOLATION,"rename guard permits WRITE/DELETE opener");
    }
    require(!MoveFileExW((f.root+L"\\source").c_str(),(f.root+L"\\moved").c_str(),0)&&
        GetLastError()==ERROR_SHARING_VIOLATION,"rename guard permits external basename replacement");
    require((*held_guard.value())->qualify_stable_content().state()==ObservationState::Unsupported,
        "share exclusion masquerades as mapping freeze");
    success(f.directory->qualify_identity_bound_rename(),"qualified Windows rename");
    const auto original_id=need((*held_guard.value())->inspect_basic(),"held rename identity").identity;
    success((*held_guard.value())->rename_noreplace(*f.directory,name("held-renamed")),"same held DELETE handle rename");
    const auto published=f.directory->open_child(name("held-renamed"));need(published,"held published entry");
    require(compare_identity(*need((*published.value())->inspect_basic(),"held published identity").identity.value(),*original_id.value())==IdentityComparison::Same,
        "held rename changed object identity");
    Fixture mapped;
    mapped.source.reset();
    struct NativeHandle { HANDLE value=INVALID_HANDLE_VALUE;~NativeHandle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);} };
    NativeHandle writer{CreateFileW((mapped.root+L"\\source").c_str(),GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
    require(writer.value!=INVALID_HANDLE_VALUE,"open writable mapping fixture");
    NativeHandle section{CreateFileMappingW(writer.value,nullptr,PAGE_READWRITE,0,0,nullptr)};
    require(section.value!=nullptr,"create existing writable section");
    struct View {void* value=nullptr;~View(){if(value)UnmapViewOfFile(value);}} view{MapViewOfFile(section.value,FILE_MAP_WRITE,0,0,0)};
    require(view.value!=nullptr,"map existing writable section");
    CloseHandle(writer.value);writer.value=INVALID_HANDLE_VALUE;
    auto mapped_guard=HeldChild::observe_with_access(mapped.directory,name("source"),EntryAccess::RenameSource|EntryAccess::ContentRead);
    if (mapped_guard.value()) {
        require((*mapped_guard.value())->qualify_stable_content().state()==ObservationState::Unsupported,
            "existing writable mapping qualified for old-target retention");
        static_cast<char*>(view.value)[0]='M';require(FlushViewOfFile(view.value,1)!=0,"flush mapped write");
        const auto changed=(*mapped_guard.value())->read_content();need(changed,"read under share-only guard");
        require(changed.value()->bytes.front()==std::byte{'M'},"mapped write regression fixture did not change held data");
    } else require(mapped_guard.state()==ObservationState::Denied||mapped_guard.state()==ObservationState::Changed,
        "mapped section guard failure not typed");
    auto exact=f.directory->create_child_file(*NativeName::from_windows(u"exact_\u00e9. "));need(exact,"exact UTF16/trailing spelling");
    require(need((*exact.value())->inspect_basic(),"exact spelling identity").identity.value()!=nullptr,"wide identity");
#endif
    std::cout<<"native capture/apply/verify, ACL/xattr, identity, limits and mutation regressions passed\n";
}
}
int main() {try {policy_tests();writer_finalization_tests();
#ifdef _WIN32
    strong_staging_tests();
#endif
#ifdef __APPLE__
    noowners_tests();
#endif
    native_tests();return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
