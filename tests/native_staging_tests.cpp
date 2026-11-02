// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "directory_cursor.hpp"
#include "native_filesystem.hpp"
#include "regular_metadata_preservation.hpp"
#include "staging_file.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef __linux__
#include <cerrno>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>
#endif

using namespace ck::files;
namespace {
NativeName name(const char* text) { return *NativeName::from_posix(text); }
template<class T> T take(Observation<T> observation) {
    if (!observation.value()) {
        std::fprintf(stderr,"native staging: state=%d code=%lld operation=%s\n",int(observation.state()),
            static_cast<long long>(observation.unavailable_detail()->error.code),observation.unavailable_detail()->error.operation.c_str());
        std::abort();
    }
    return std::move(observation).take_value();
}
[[maybe_unused]] void write(OpenedEntry& entry,const std::string& text) {
    auto bytes=std::span(reinterpret_cast<const std::byte*>(text.data()),text.size());
    assert(take(entry.write_content(0,bytes))==bytes.size());
    assert(take(entry.flush_content()));
}
[[maybe_unused]] std::string read(const DirectoryCursor& directory,const char* text) {
    auto entry=take(directory.open_child(name(text),EntryAccess::ContentRead));
    auto bytes=take(entry->read_content({4096})); assert(bytes.complete);
    return {reinterpret_cast<const char*>(bytes.bytes.data()),bytes.bytes.size()};
}
[[maybe_unused]] bool missing(const DirectoryCursor& directory,const char* text) {
    auto lookup=take(directory.lookup_child(name(text),ChildLookupMode::NativeDefault));
    return lookup.state()==ChildLookupState::Missing;
}
class DefaultCursor final : public DirectoryCursor {
    Observation<DirectoryStep> next_step() override { return Observation<DirectoryStep>::available(DirectoryEnd{}); }
};
#ifdef __linux__
CreatedStagingFile stage(const DirectoryCursor& directory,const char* hint) {
    auto result=take(directory.create_staging_file(name(hint)));
    assert(result.entry && result.staging_namespace==StagingNamespace::Anonymous && !result.name);
    const auto metadata=take(result.entry->inspect_basic());
    assert(metadata.kind.value() && *metadata.kind.value()==ObjectKind::RegularFile);
    assert(metadata.link_count.value() && *metadata.link_count.value()==0);
    return result;
}
void unshared_thread_publication(const std::shared_ptr<const DirectoryCursor>& directory) {
    std::thread worker([&] {
        if (::unshare(CLONE_FILES) != 0) {
            // Some hosted sandboxes deny unshare even without a namespace or
            // privilege change. Qualification hosts must explicitly require it.
            assert(!std::getenv("CK_FS_REQUIRE_THREAD_FD_STAGING"));
            std::fprintf(stderr,"native staging: unshared-thread coverage unavailable: %s\n",std::strerror(errno));
            return;
        }
        auto created=stage(*directory,"thread-hint");
        write(*created.entry,"worker-owned descriptor table");
        assert(take(created.entry->publish_noreplace(*directory,name("thread-published"))));
        assert(read(*directory,"thread-published")=="worker-owned descriptor table");
        assert(missing(*directory,"thread-hint"));
    });
    worker.join();
}
void publication_and_source_substitution(const std::shared_ptr<const DirectoryCursor>& directory,const NativeAbsolutePath& root) {
    {
        auto sentinel=take(directory->create_child_file(name("hint"))); write(*sentinel,"original sentinel");
    }
    auto created=stage(*directory,"hint");
    const auto before=take(created.entry->inspect_basic());
    write(*created.entry,"verified anonymous bytes");
    assert(read(*directory,"hint")=="original sentinel");
    assert(missing(*directory,"published"));
    // Replace every name an old stat-then-rename publisher might use. The
    // anonymous publisher must neither move nor unlink either sentinel.
    const auto hint=take(take(root.child_address(name("hint"))).host_path());
    const auto saved=take(take(root.child_address(name("saved-hint"))).host_path());
    assert(::rename(hint.c_str(),saved.c_str())==0);
    {
        auto unrelated=take(directory->create_child_file(name("hint"))); write(*unrelated,"unrelated replacement");
    }
    assert(take(created.entry->publish_noreplace(*directory,name("published"))));
    assert(created.staging_namespace==StagingNamespace::Anonymous && !created.name);
    const auto after=take(created.entry->inspect_basic());
    assert(compare_identity(*before.identity.value(),*after.identity.value())==IdentityComparison::Same);
    assert(after.link_count.value() && *after.link_count.value()==1);
    assert(read(*directory,"published")=="verified anonymous bytes");
    assert(read(*directory,"hint")=="unrelated replacement");
    assert(read(*directory,"saved-hint")=="original sentinel");
    // Publication cannot be repeated to synthesize unreviewed hard links.
    assert(!created.entry->publish_noreplace(*directory,name("second-publication")).value());
    assert(missing(*directory,"second-publication"));
}
void occupied_and_unpublished_disposal(const std::shared_ptr<const DirectoryCursor>& directory) {
    { auto occupant=take(directory->create_child_file(name("occupied"))); write(*occupant,"do not replace"); }
    auto created=stage(*directory,"never-created-hint"); write(*created.entry,"unpublished data");
    const auto refused=created.entry->publish_noreplace(*directory,name("occupied"));
    assert(!refused.value() && refused.state()==ObservationState::Changed);
    const auto still_anonymous=take(created.entry->inspect_basic());
    assert(still_anonymous.link_count.value() && *still_anonymous.link_count.value()==0);
    created.entry.reset(); // disposal is close, never unlink(recovery_hint)
    assert(read(*directory,"occupied")=="do not replace");
    assert(missing(*directory,"never-created-hint"));
}
void named_publication_refused(const std::shared_ptr<const DirectoryCursor>& directory) {
    auto ordinary=take(directory->create_child_file(name("ordinary-fixture"))); write(*ordinary,"ordinary fixture data");
    auto metadata=take(ordinary->inspect_basic()); assert(*metadata.link_count.value()==1);
    assert(ordinary->publish_noreplace(*directory,name("unsafe-named-publication")).state()==ObservationState::Unsupported);
    assert(read(*directory,"ordinary-fixture")=="ordinary fixture data");
    assert(missing(*directory,"unsafe-named-publication"));
}
void anonymous_metadata(const std::shared_ptr<const DirectoryCursor>& directory) {
    auto created=stage(*directory,"metadata-hint"); write(*created.entry,"metadata bytes");
    assert(take(created.entry->apply_current_caller_ownership()));
    auto desired=take(created.entry->inspect_basic());
    desired.posix_permissions=Observation<std::uint32_t>::available(04750);
    MetadataReplayPolicy policy; policy.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;
    policy.ownership=MetadataOwnership::CurrentCaller; policy.allow_privilege_metadata=true;
    // Exact same inode publication must preserve explicitly requested mode,
    // including SUID, and owner. A clone is not an equivalent implementation.
    assert(take(created.entry->apply_replay_basic(desired,policy)));
    const auto prepared=take(created.entry->inspect_basic()); assert(*prepared.posix_permissions.value()==04750);
    assert(take(created.entry->publish_noreplace(*directory,name("metadata-published"))));
    const auto published=take(created.entry->inspect_basic());
    assert(*published.posix_permissions.value()==04750);
    assert(*prepared.posix_uid.value()==*published.posix_uid.value() && *prepared.posix_gid.value()==*published.posix_gid.value());
    assert(compare_identity(*prepared.identity.value(),*published.identity.value())==IdentityComparison::Same);
}
void strict_zero_link_target(const std::shared_ptr<const DirectoryCursor>& directory) {
    { auto source=take(directory->create_child_file(name("metadata-source"))); write(*source,"strict metadata source"); }
    auto source=take(HeldChild::observe(directory,name("metadata-source")));
    auto preservation=take(RegularMetadataPreservation::create(source,false,RegularMetadataScope::OrdinaryCallerVisibleV1));
    auto created=stage(*directory,"strict-target-hint"); write(*created.entry,"strict metadata source");
    auto metadata=take(preservation->prepare(*created.entry));
    for(unsigned n=0;n<16 && metadata->state()!=OperationMetadataState::Complete && metadata->state()!=OperationMetadataState::Failed;++n) metadata->advance();
    assert(metadata->state()==OperationMetadataState::Complete);
    assert(take(preservation->verify(*created.entry)));
    assert(*take(created.entry->inspect_basic()).link_count.value()==0);
    assert(take(created.entry->publish_noreplace(*directory,name("strict-target"))));
    assert(read(*directory,"strict-target")=="strict metadata source");
    assert(missing(*directory,"strict-target-hint"));
}
void readonly_successor(const std::shared_ptr<const DirectoryCursor>& directory,const NativeAbsolutePath& root) {
    auto created=stage(*directory,"readonly-hint"); write(*created.entry,"readonly linked bytes");
    assert(take(created.entry->publish_noreplace(*directory,name("readonly-published"))));
    const auto expected=take(created.entry->inspect_basic());
    // The copy-job finalizer closes the writer AFTER publication. Validate
    // that the link persists and creation namespace never becomes a fake name.
    assert(take(created.entry->finish_content_writes()));
    assert(created.staging_namespace==StagingNamespace::Anonymous && !created.name);
    auto current=take(directory->open_child(name("readonly-published"),EntryAccess::ContentRead));
    assert(compare_identity(*expected.identity.value(),*take(current->inspect_basic()).identity.value())==IdentityComparison::Same);
    assert(read(*directory,"readonly-published")=="readonly linked bytes");
    (void)root;
}
#endif
} // namespace

int main(int argc,char** argv) {
    assert(argc==2);
    DefaultCursor default_cursor;
    assert(default_cursor.create_staging_file(name("hint")).state()==ObservationState::Unsupported);
    const auto root=take(NativeAbsolutePath::from_host(std::filesystem::path(argv[1])));
#ifdef __APPLE__
    assert(root.posix_bytes() && (root.posix_bytes()->starts_with("/Volumes/PRO-BLADE/tmp/") || root.posix_bytes()->starts_with("/Volumes/S8T/tmp/")));
#endif
    NativeFileSystem filesystem;
    auto directory=std::shared_ptr<const DirectoryCursor>(take(filesystem.open_native_directory(root)));
#ifdef __linux__
    if(const auto* required=std::getenv("CK_FS_REQUIRE_UNPRIVILEGED_STAGING"); required && std::string(required)=="1") {
        struct __user_cap_header_struct header{}; header.version=_LINUX_CAPABILITY_VERSION_3;
        struct __user_cap_data_struct caps[2]{}; assert(::syscall(SYS_capget,&header,caps)==0);
        assert((caps[CAP_DAC_READ_SEARCH/32].effective & (1U<<(CAP_DAC_READ_SEARCH%32)))==0);
    }
    auto probe=directory->create_staging_file(name("probe-hint"));
    if (!probe.value()) {
        std::fprintf(stderr,"native staging unavailable: state=%d operation=%s\n",int(probe.state()),probe.unavailable_detail()->error.operation.c_str());
        if (std::getenv("CK_FS_REQUIRE_NATIVE_STAGING")) return 1;
        return 77; // explicitly incomplete native coverage, never a pass
    }
    probe=Observation<CreatedStagingFile>::unavailable(ObservationState::Unknown);
    unshared_thread_publication(directory);
    publication_and_source_substitution(directory,root);
    occupied_and_unpublished_disposal(directory);
    named_publication_refused(directory);
    anonymous_metadata(directory);
    strict_zero_link_target(directory);
    readonly_successor(directory,root);
    std::puts("native staging: Linux anonymous fd publication, adversarial hints, metadata and disposal passed");
#else
    (void)directory;
    std::puts("native staging: Linux positive suite not run on this host");
    return 77;
#endif
}
