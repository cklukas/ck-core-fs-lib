// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "regular_metadata_preservation.hpp"
#include "native_operation_copy_job.hpp"
#include "native_filesystem.hpp"
#include "object_inventory_job.hpp"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#ifndef _WIN32
#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/fs.h>
#endif
#endif

using namespace ck::files;
namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
template<class T> void require_review(const Observation<T>& observation) {
    require(!observation.value(), "unexpected strict success");
    require(observation.unavailable_detail()->error.domain == ErrorDomain::Adapter &&
        observation.unavailable_detail()->error.code == static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),
        "expected typed ProviderReviewRequired");
}
class UnqualifiedEntry final : public OpenedEntry {
    Observation<BasicMetadata> inspect_basic() const override { return {}; }
};
#ifndef _WIN32
struct Fixture {
    std::string root;
    std::shared_ptr<const DirectoryCursor> directory;
    Fixture() {
        const auto* temporary = std::getenv("TMPDIR");
        require(temporary && *temporary, "TMPDIR must be explicitly configured");
#ifdef __APPLE__
        const std::string base(temporary);
        require(base.starts_with("/Volumes/S8T/tmp/") || base.starts_with("/Volumes/PRO-BLADE/tmp/"),
                "Mac test data must use an approved temporary volume");
#endif
        root = std::string(temporary) + "/regular-metadata-tests.XXXXXX";
        require(mkdtemp(root.data()) != nullptr, "mkdtemp failed");
        NativeFileSystem filesystem;
        auto opened = filesystem.open_directory(root);
        require(opened.value() != nullptr, "open test directory");
        directory = std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
    }
    ~Fixture() { directory.reset(); std::filesystem::remove_all(root); }
    std::string path(const char* name) { return root + "/" + name; }
    void source() {
        const int fd = open(path("source").c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0640);
        require(fd >= 0, "create source");
        const std::string bytes = "ordinary held regular file\n";
        require(write(fd, bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()), "write source");
        const timespec times[2]{{1600000000, 123456789}, {1600000100, 987654321}};
        require(fchmod(fd, 0640) == 0 && futimens(fd, times) == 0, "source mode/times");
        close(fd);
    }
    HeldChild::Pointer held() {
        auto source = HeldChild::observe(directory, *NativeName::from_posix("source"));
        require(source.value() != nullptr, "hold source");
        return *source.value();
    }
    Observation<OperationBatchJob::Pointer> batch(bool allow_loss, const char* target, unsigned id,
        RegularMetadataScope scope = RegularMetadataScope::OrdinaryCallerVisibleV1) {
        NativeOperationCopyBatchRequest request;
        request.sources = {held()};
        request.destination = directory;
        request.destination_names = {*NativeName::from_posix(target)};
        request.journal_root = std::move(NativeAbsolutePath::from_posix(root)).take_value();
        request.journal_id.bytes[0] = std::byte{static_cast<unsigned char>(id)};
        request.policy.allow_unhandled_metadata_loss = allow_loss;
        request.policy.metadata_scope = scope;
        request.open_journal = open_native_operation_journal_file;
        return create_native_operation_copy_batch(std::move(request));
    }
    static void complete(OperationBatchJob& job) {
        for (unsigned i = 0; i != 10000 && (job.state() == OperationBatchState::Ready ||
            job.state() == OperationBatchState::Running); ++i) job.advance();
        if (job.state() != OperationBatchState::Complete && !job.result().items.empty() &&
            job.result().items.front().failure)
            std::cerr << job.result().items.front().failure->error.operation << '\n';
        require(job.state() == OperationBatchState::Complete, "copy failed");
    }
    void xattr() {
        const char value[] = "metadata";
#ifdef __APPLE__
        require(setxattr(path("source").c_str(), "user.ck_metadata_test", value, sizeof(value), 0, 0) == 0, "set xattr");
#else
        require(setxattr(path("source").c_str(), "user.ck_metadata_test", value, sizeof(value), 0) == 0, "set xattr");
#endif
    }
};
void native_tests() {
    Fixture ordinary;
    ordinary.source();
    auto strict = ordinary.batch(false, "strict", 1);
    const bool native_qualified = strict.value() != nullptr;
    if (native_qualified) {
        Fixture::complete(**strict.value());
        struct stat destination{};
        require(stat(ordinary.path("strict").c_str(), &destination) == 0, "published strict file missing");
        require((destination.st_mode & 07777) == 0640, "strict mode mismatch");
        require(destination.st_uid == geteuid() && destination.st_gid == getegid(), "current caller ownership mismatch");
#ifdef __APPLE__
        require(destination.st_atimespec.tv_sec == 1600000000 && destination.st_atimespec.tv_nsec == 123456789 &&
                destination.st_mtimespec.tv_sec == 1600000100 && destination.st_mtimespec.tv_nsec == 987654321, "strict times mismatch");
#else
        require(destination.st_atim.tv_sec == 1600000000 && destination.st_atim.tv_nsec == 123456789 &&
                destination.st_mtim.tv_sec == 1600000100 && destination.st_mtim.tv_nsec == 987654321, "strict times mismatch");
#endif
        std::cout << "strict native ordinary copy verified\n";
        // The held source changes after review but before metadata application.
        auto pending = ordinary.batch(false, "mutated", 2);
        require(pending.value() != nullptr, "second strict preflight");
        ordinary.xattr();
        for (unsigned i = 0; i != 10000 && ((*pending.value())->state() == OperationBatchState::Ready ||
            (*pending.value())->state() == OperationBatchState::Running); ++i) (*pending.value())->advance();
        require((*pending.value())->state() != OperationBatchState::Complete, "mutated source accepted");
        require(access(ordinary.path("mutated").c_str(), F_OK) != 0, "mutated source published");
    } else {
        require_review(strict);
        std::cout << "scope-1 native ordinary success UNQUALIFIED: " << strict.unavailable_detail()->error.operation << '\n';
        auto diagnostic = ObjectInventoryJob::for_held_source(ordinary.held());
        while (diagnostic->state() == ObjectInventoryJobState::Collecting ||
               diagnostic->state() == ObjectInventoryJobState::Paused) diagnostic->advance();
        const auto collected = diagnostic->completed();
        if (collected.value() && (*collected.value())->data().attributes.value())
            for (const auto& attribute : (*collected.value())->data().attributes.value()->attributes)
                std::cout << "visible attribute name=" << attribute.identifier.display_name()
                          << " role=" << static_cast<int>(attribute.role) << " (name/role only)\n";
        require(!std::getenv("CK_REGULAR_REQUIRE_NATIVE_SUCCESS"), "mandatory scope-1 preserving gate FAILED");
    }
    auto complete_scope=ordinary.batch(false,"complete",42,RegularMetadataScope::CompleteMetadataV1);
#ifdef __APPLE__
    require(complete_scope.value()!=nullptr,"Darwin complete metadata preflight refused");
    Fixture::complete(**complete_scope.value());
    struct stat complete_source{},complete_target{};
    require(stat(ordinary.path("source").c_str(),&complete_source)==0&&stat(ordinary.path("complete").c_str(),&complete_target)==0,"complete stat");
    require(complete_source.st_uid==complete_target.st_uid&&complete_source.st_gid==complete_target.st_gid&&
        complete_source.st_birthtimespec.tv_sec==complete_target.st_birthtimespec.tv_sec&&
        complete_source.st_birthtimespec.tv_nsec==complete_target.st_birthtimespec.tv_nsec,"complete ownership/birthtime mismatch");
#else
    require_review(complete_scope);
#endif
    Fixture attributes;
    attributes.source();
    attributes.xattr();
    auto preserved_attributes=attributes.batch(false,"preserved",3);
    require(preserved_attributes.value()!=nullptr,"xattr-bearing source refused");
    Fixture::complete(**preserved_attributes.value());
    char source_value[128]{},target_value[128]{};
#ifdef __APPLE__
    const auto source_size=getxattr(attributes.path("source").c_str(),"user.ck_metadata_test",source_value,sizeof(source_value),0,0);
    const auto target_size=getxattr(attributes.path("preserved").c_str(),"user.ck_metadata_test",target_value,sizeof(target_value),0,0);
    char source_provenance[128]{},target_provenance[128]{};
    const auto source_provenance_size=getxattr(attributes.path("source").c_str(),"com.apple.provenance",source_provenance,sizeof(source_provenance),0,0);
    const auto target_provenance_size=getxattr(attributes.path("preserved").c_str(),"com.apple.provenance",target_provenance,sizeof(target_provenance),0,0);
    require(source_provenance_size>=0&&source_provenance_size==target_provenance_size&&
        std::memcmp(source_provenance,target_provenance,source_provenance_size)==0,"opaque provenance not preserved exactly");
#else
    const auto source_size=getxattr(attributes.path("source").c_str(),"user.ck_metadata_test",source_value,sizeof(source_value));
    const auto target_size=getxattr(attributes.path("preserved").c_str(),"user.ck_metadata_test",target_value,sizeof(target_value));
#endif
    require(source_size>=0&&source_size==target_size&&std::memcmp(source_value,target_value,source_size)==0,"xattr bytes not preserved exactly");
    auto consent = attributes.batch(true, "consented", 4);
    require(consent.value() != nullptr, "explicit loss consent refused");
    Fixture::complete(**consent.value());

    Fixture privileged;
    privileged.source();
    require(chmod(privileged.path("source").c_str(), 06754) == 0, "set special bits");
    require_review(privileged.batch(false, "denied", 5));
    auto stripped = privileged.batch(true, "stripped", 6);
    require(stripped.value() != nullptr, "loss consent for special bits refused");
    Fixture::complete(**stripped.value());
    struct stat safe{};
    require(stat(privileged.path("stripped").c_str(), &safe) == 0 && (safe.st_mode & 07777) == 0754,
            "privilege bits were replayed");

    Fixture sparse;
    sparse.source();
    const int sparse_fd = open(sparse.path("source").c_str(), O_RDWR | O_CLOEXEC);
    require(sparse_fd >= 0 && ftruncate(sparse_fd, 1024 * 1024) == 0, "make sparse source");
    close(sparse_fd);
    require_review(sparse.batch(false, "denied", 7));
#ifdef __linux__
    Fixture acl;
    acl.source();
    // POSIX ACL xattr v2: owner, named user, owning group, mask, other.
    const unsigned char acl_value[] = {
        2,0,0,0,
        1,0,6,0,255,255,255,255, 2,0,4,0,210,4,0,0,
        4,0,4,0,255,255,255,255, 16,0,4,0,255,255,255,255,
        32,0,0,0,255,255,255,255};
    require(setxattr(acl.path("source").c_str(), "system.posix_acl_access", acl_value, sizeof(acl_value), 0) == 0,
            "install access ACL fixture");
    auto preserved_acl=acl.batch(false,"preserved",9);
    require(preserved_acl.value()!=nullptr,"ACL-bearing source refused");Fixture::complete(**preserved_acl.value());
    unsigned char copied_acl[sizeof(acl_value)]{};
    require(getxattr(acl.path("preserved").c_str(),"system.posix_acl_access",copied_acl,sizeof(copied_acl))==sizeof(acl_value)&&
        std::memcmp(copied_acl,acl_value,sizeof(acl_value))==0,"ACL bytes not preserved exactly");
    if (geteuid() == 0 && native_qualified) {
        Fixture ownership;
        ownership.source();
        require(chown(ownership.path("source").c_str(), 1234, 1234) == 0, "set distinct source ownership");
        auto owned_copy = ownership.batch(false, "owned", 10);
        require(owned_copy.value() != nullptr, "current-caller policy rejected source owner difference");
        Fixture::complete(**owned_copy.value());
        struct stat owned{};
        require(stat(ownership.path("owned").c_str(), &owned) == 0 &&
                owned.st_uid == geteuid() && owned.st_gid == getegid(), "source owner was replayed");
        Fixture capabilities;
        capabilities.source();
        // v2 VFS capabilities: CAP_CHOWN permitted + effective.
        const unsigned char capability[] = {1,0,0,2, 1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
        require(setxattr(capabilities.path("source").c_str(), "security.capability", capability, sizeof(capability), 0) == 0,
                "install capability fixture");
        require_review(capabilities.batch(false, "denied", 11));
        auto capability_loss = capabilities.batch(true, "safe", 12);
        require(capability_loss.value() != nullptr, "capability loss consent refused");
        Fixture::complete(**capability_loss.value());
        require(getxattr(capabilities.path("safe").c_str(), "security.capability", nullptr, 0) < 0 && errno == ENODATA,
                "capabilities replayed");
    }
    Fixture flags;
    flags.source();
    const int flags_fd = open(flags.path("source").c_str(), O_RDONLY | O_CLOEXEC);
    int native_flags = 0;
    require(flags_fd >= 0 && ioctl(flags_fd, FS_IOC_GETFLAGS, &native_flags) == 0, "read inode flags");
    native_flags |= FS_NODUMP_FL;
    require(ioctl(flags_fd, FS_IOC_SETFLAGS, &native_flags) == 0, "set nodump flag");
    close(flags_fd);
    require_review(flags.batch(false, "denied", 8));
#endif
    // Unsupported metadata classes retain typed strict refusal.
    std::cout << "versioned metadata scope, ACL/xattr replay and explicit-consent checks passed\n";
    if (native_qualified) std::cout << "scope-1 native ordinary preservation and source-mutation checks passed\n";
    else std::cout << "scope-1 preserving gate NOT PASSED; mutation/ownership cases requiring native success not run\n";
}
#endif
}
int main() {
    try {
        UnqualifiedEntry unqualified;
        require_review(unqualified.qualify_ordinary_regular_metadata());
        require_review(unqualified.apply_current_caller_ownership());
#ifndef _WIN32
        native_tests();
#endif
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
