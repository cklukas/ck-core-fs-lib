// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Linux only. Run through run_private_scope_mounts.py, never in the host mount namespace.
#include "private_journal_scope.hpp"
#include "reviewed_tree_plan.hpp"
#include "native_filesystem.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace ck::files;
namespace {
struct Unqualified : std::runtime_error { using std::runtime_error::runtime_error; };
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
template<class T> T take(Observation<T> result, const char* context, bool environment = false) {
    if (result.value()) return std::move(result).take_value();
    const auto& e = *result.unavailable_detail();
    const auto message = std::string(context) + ": state=" + std::to_string(int(e.state)) +
        " domain=" + std::to_string(int(e.error.domain)) + " code=" + std::to_string(e.error.code) +
        " operation=" + e.error.operation;
    if (environment && e.state == ObservationState::Unsupported) throw Unqualified(message);
    throw std::runtime_error(message);
}
template<class T> void refused(const char* label, Observation<T> result) {
    require(!result.value(), "private state was accepted as disjoint");
    const auto& e = *result.unavailable_detail();
    require(e.state == ObservationState::Unsupported && e.error.domain == ErrorDomain::Adapter &&
        e.error.code == 18 && e.error.code == static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe),
        "scope refusal must be typed Unsupported/Adapter/PlanTopologyUnsafe(18)");
    std::printf("CASE %s PASS Unsupported Adapter 18 (%s)\n", label, e.error.operation.c_str());
}
NativeName name(const char* text) { return *NativeName::from_posix(text); }
using Cursor = std::shared_ptr<const DirectoryCursor>;
Cursor child(const Cursor& parent, const char* text) {
    return Cursor(take(parent->create_child_directory(name(text)), "create fixture directory"));
}
NativeAbsolutePath address(const NativeAbsolutePath& parent, const char* text) {
    return take(parent.child_address(name(text)), "fixture child address");
}
std::string bytes(const NativeAbsolutePath& path) { return *path.posix_bytes(); }
std::string namespace_id(const char* path) {
    struct stat value{};
    if (::stat(path, &value)) throw Unqualified(std::string("namespace identity unavailable: ") + path);
    return std::to_string(value.st_dev) + ":" + std::to_string(value.st_ino);
}
class Mounts {
public:
    ~Mounts() { for (auto at = paths_.rbegin(); at != paths_.rend(); ++at) ::umount2(at->c_str(), MNT_DETACH); }
    void add(const std::string& source, const std::string& target, const char* type,
             unsigned long flags, const char* options = nullptr) {
        // Allocate bookkeeping before the native effect, including on allocation failure.
        paths_.push_back(target);
        if (::mount(source.c_str(), target.c_str(), type, flags, options)) {
            const int error = errno;
            paths_.pop_back();
            const auto message = std::string("mount ") + (type ? type : "bind") + ": " + std::strerror(error);
            if (error == EPERM || error == EACCES || error == ENODEV || error == ENOSYS ||
                error == EOPNOTSUPP || error == EINVAL) throw Unqualified(message);
            throw std::runtime_error(message);
        }
    }
    void finish() {
        while (!paths_.empty()) {
            if (::umount2(paths_.back().c_str(), 0)) throw std::runtime_error("fixture unmount failed");
            paths_.pop_back();
        }
    }
private:
    std::vector<std::string> paths_;
};
constexpr std::array<std::byte, 8> sentinel{
    std::byte{0x42}, std::byte{0}, std::byte{0xff}, std::byte{3},
    std::byte{9}, std::byte{8}, std::byte{7}, std::byte{6}};
void check_sentinel(PreparedJournalRoot& root, const ObjectIdentity& expected, const Cursor& state) {
    auto held = take(HeldChild::observe(state, name("private-state")), "observe protected sentinel");
    require(held->metadata().identity.value() &&
        compare_identity(expected, *held->metadata().identity.value()) == IdentityComparison::Same,
        "scope checks replaced the protected sentinel");
    auto file = take(root.open_journal(name("private-state"), false), "reopen protected journal through capability");
    require(take(file->size(), "protected journal size") == sentinel.size(), "protected journal size changed");
    std::array<std::byte, sentinel.size()> current{};
    require(take(file->read_at(0, current), "protected journal read") == current.size() && current == sentinel,
        "protected journal content changed");
    require(take(file->finish_io(), "protected journal close"), "protected journal close returned false");
}
int run(const NativeAbsolutePath& scratch) {
    NativeFileSystem fs;
    auto parent = Cursor(take(fs.open_native_directory(scratch), "native scratch cursor", true));
    auto source = child(parent, "source");
    auto upper = child(parent, "upper");
    auto work = child(parent, "work");
    auto whole = child(source, "whole");
    auto inside = child(source, "inside");
    auto view = child(source, "view");
    auto unrelated = child(source, "journals"); // Same basename is not private identity.
    (void)upper; (void)work; (void)whole; (void)inside; (void)view;
    PreparedJournalRootRequest request;
    request.parent = parent;
    request.child = name("journals");
    request.disposition = JournalRootDisposition::ProvisionChild;
    JournalRootPreparationProgress progress;
    auto root = take(prepare_native_journal_root(std::move(request), progress), "prepare native private Root", true);
    require(progress.directory_creates == 1, "fixture did not provision one private Root");
    auto state = Cursor(take(parent->open_directory_child(name("journals")), "private Root cursor"));
    auto nested = child(state, "nested");
    (void)nested;
    {
        auto file = take(root->open_journal(name("private-state"), true), "create protected journal");
        require(take(file->write_at(0, sentinel), "write sentinel") == sentinel.size(), "short sentinel write");
        require(take(file->finish_io(), "durable sentinel finish"), "sentinel finish returned false");
    }
    auto protected_entry = take(HeldChild::observe(state, name("private-state")), "protected identity");
    require(protected_entry->metadata().identity.value() != nullptr, "protected identity unavailable");
    const auto protected_id = *protected_entry->metadata().identity.value();
    protected_entry.reset();
    {
        auto writer = take(parent->create_child_file(name("ordinary")), "create unrelated selected file");
        require(take(writer->finish_content_writes(), "finish ordinary fixture"), "ordinary finish false");
        writer = take(source->create_child_file(name("file-alias")), "create bind mount target");
        require(take(writer->finish_content_writes(), "finish bind target"), "bind target finish false");
    }
    auto guard = take(JournalScopeGuard::create(root, source), "unrelated scan root");
    {
        auto positive = take(JournalScopeGuard::create(root, unrelated), "unrelated same-name directory");
        require(take(positive->check_root(), "unrelated root check"), "positive root check false");
        auto entry = take(HeldChild::observe(source, name("journals")), "unrelated directory entry");
        require(take(guard->check_entry(*entry), "unrelated entry check"), "positive entry check false");
        auto ordinary = take(HeldChild::observe(parent, name("ordinary")), "ordinary sibling file");
        auto selected = take(JournalScopeGuard::create_for_entry(root, *ordinary), "ordinary file beside private Root");
        require(take(selected->check_entry(*ordinary), "ordinary selected entry check"), "positive selected check false");
        std::puts("CASE unrelated_directory_and_selected_file PASS");
    }
    // A hardlink preserves mount ID, so mount-boundary checks alone cannot
    // distinguish a private-state alias from an ordinary external hardlink.
    {
        auto ordinary = take(HeldChild::observe(parent, name("ordinary")), "ordinary hardlink original");
        require(take(parent->create_hard_link(name("ordinary"), *ordinary->metadata().identity.value(),
            *source, name("ordinary-hardlink")), "create ordinary hardlink"), "ordinary link false");
        auto selected = take(HeldChild::observe(source, name("ordinary-hardlink")), "refresh ordinary hardlink");
        require(take(guard->check_entry(*selected), "ordinary external hardlink check"), "ordinary hardlink refused");
        auto selected_guard = take(JournalScopeGuard::create_for_entry(root, *selected), "ordinary hardlink selection");
        require(take(selected_guard->check_entry(*selected), "ordinary hardlink selected check"), "ordinary selection refused");
        require(take(state->create_hard_link(name("private-state"), protected_id, *source,
            name("private-hardlink")), "create private hardlink"), "private link false");
        auto alias = take(HeldChild::observe(source, name("private-hardlink")), "refresh private hardlink");
        require(alias->metadata().identity.value() && alias->metadata().link_count.value() &&
            *alias->metadata().link_count.value() == 2 &&
            compare_identity(protected_id, *alias->metadata().identity.value()) == IdentityComparison::Same,
            "hardlink fixture did not preserve private identity");
        refused("private_hardlink_per_entry", guard->check_entry(*alias));
        refused("private_hardlink_selected", JournalScopeGuard::create_for_entry(root, *alias));
        std::puts("CASE ordinary_external_hardlink PASS");
    }
    {
        auto tree_source = child(parent, "tree-source");
        auto tree_target = child(parent, "tree-target");
        (void)tree_target;
        auto ordinary = take(HeldChild::observe(parent, name("ordinary")), "tree ordinary original");
        require(take(parent->create_hard_link(name("ordinary"), *ordinary->metadata().identity.value(),
            *tree_source, name("ordinary-hardlink")), "tree ordinary hardlink"), "tree ordinary link false");
        auto preview = [&](unsigned id) {
            ReviewedTreePlanRequest plan;
            plan.source_root = take(HeldChild::observe(parent, name("tree-source")), "tree source Root");
            plan.destination_root = take(HeldChild::observe(parent, name("tree-target")), "tree destination Root");
            plan.destination_address = address(scratch, "tree-target");
            plan.comparison.profile = ComparisonProfile::Copy;
            plan.comparison.mode = ComparisonMode::CompleteDigest;
            plan.copy_policy.allow_unhandled_metadata_loss = true;
            plan.copy_policy.metadata_scope = RegularMetadataScope::OrdinaryCallerVisibleV1;
            plan.journal_root = address(scratch, "journals");
            plan.prepared_journal_root = root;
            plan.journal_id.bytes[0] = std::byte(id);
            auto job = take(ReviewedTreePlanJob::create(std::move(plan)), "tree membership plan");
            for (unsigned n = 0; n < 10000 && job->state() == ReviewedTreeState::Inventory; ++n) job->advance();
            return job;
        };
        {
            auto ordinary_plan = preview(1);
            require(ordinary_plan->state() == ReviewedTreeState::AwaitingReview && bool(ordinary_plan->preview()),
                "ordinary external hardlink did not produce a frozen Tree proposal");
            auto receipt = take(ordinary_plan->review({}), "ordinary hardlink review receipt");
            require(receipt.is_valid(), "ordinary hardlink receipt invalid");
            std::stop_source stop; stop.request_stop(); ordinary_plan->advance(stop.get_token());
            std::puts("CASE ordinary_external_hardlink_tree_receipt PASS");
        }
        require(take(state->create_hard_link(name("private-state"), protected_id, *tree_source,
            name("private-hardlink")), "tree private hardlink"), "tree private link false");
        auto private_plan = preview(2);
        require(private_plan->state() == ReviewedTreeState::Failed && !private_plan->preview() &&
            bool(private_plan->progress().failure), "private alias exposed a Tree mutation proposal");
        const auto& error = *private_plan->progress().failure;
        require(error.state == ObservationState::Unsupported && error.error.domain == ErrorDomain::Adapter &&
            error.error.code == static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe),
            "Tree private alias refusal lost typed Unsupported Adapter18");
        require(take(tree_target->lookup_child(name("private-hardlink"), ChildLookupMode::NativeDefault),
            "Tree no publication check").state() == ChildLookupState::Missing, "Tree alias published before refusal");
        std::puts("CASE private_hardlink_tree_before_preview PASS Unsupported Adapter 18");
    }
    const auto source_path = address(scratch, "source"), private_path = address(scratch, "journals");
    // Remove only our two hostile fixture links before the journal provider's
    // independent unique-link privacy check reopens the protected sentinel.
    require(::unlink(bytes(address(source_path, "private-hardlink")).c_str()) == 0,
        "remove private hardlink fixture");
    require(::unlink(bytes(address(address(scratch, "tree-source"), "private-hardlink")).c_str()) == 0,
        "remove Tree private hardlink fixture");
    Mounts mounts;
    mounts.add(bytes(private_path), bytes(address(source_path, "whole")), nullptr, MS_BIND);
    mounts.add(bytes(address(private_path, "nested")), bytes(address(source_path, "inside")), nullptr, MS_BIND);
    mounts.add(bytes(address(private_path, "private-state")), bytes(address(source_path, "file-alias")), nullptr, MS_BIND);
    const auto options = "lowerdir=" + bytes(private_path) + ",upperdir=" + bytes(address(scratch, "upper")) +
        ",workdir=" + bytes(address(scratch, "work")) + ",userxattr";
    mounts.add("overlay", bytes(address(source_path, "view")), "overlay", 0, options.c_str());
    for (const auto* component : {"whole", "inside"}) {
        auto cursor = Cursor(take(fs.open_native_directory(address(source_path, component)), "native directory alias"));
        refused(component, JournalScopeGuard::create(root, cursor));
        auto entry = take(HeldChild::observe(source, name(component)), "held directory alias");
        refused("directory_alias_per_entry", guard->check_entry(*entry));
        refused("directory_alias_selected", JournalScopeGuard::create_for_entry(root, *entry));
    }
    {
        auto cursor = Cursor(take(fs.open_native_directory(address(source_path, "view")), "native overlay view"));
        refused("overlay_private_root", JournalScopeGuard::create(root, cursor));
        auto entry = take(HeldChild::observe(cursor, name("private-state")), "overlay private journal");
        refused("overlay_private_file_per_entry", guard->check_entry(*entry));
        refused("overlay_private_file_selected", JournalScopeGuard::create_for_entry(root, *entry));
        // Inverse alias: a translating filesystem must not mint a private
        // Root capability whose IDs could appear disjoint from its direct
        // backing scan. Test provider admission, not only scan certification.
        for (const auto disposition : {JournalRootDisposition::AdoptHeld, JournalRootDisposition::ProvisionChild}) {
            PreparedJournalRootRequest inverse;
            inverse.parent = cursor;
            inverse.disposition = disposition;
            if (disposition == JournalRootDisposition::ProvisionChild) inverse.child = name("must-not-create");
            JournalRootPreparationProgress inverse_progress;
            auto admission = prepare_native_journal_root(std::move(inverse), inverse_progress);
            require(!admission.value(), "OverlayFS minted a private Root capability");
            const auto& failure = *admission.unavailable_detail();
            require(failure.state == ObservationState::Unsupported && failure.error.domain == ErrorDomain::Adapter &&
                failure.error.code == static_cast<std::int64_t>(AdapterError::UnsupportedQuery),
                "OverlayFS Root must be refused by typed native filesystem qualification");
            require(inverse_progress.directory_creates == 0 && inverse_progress.flushed_directories == 0,
                "OverlayFS Root refusal occurred after provisioning effects");
            require(take(cursor->lookup_child(name("must-not-create"), ChildLookupMode::NativeDefault),
                "inverse Root create absence").state() == ChildLookupState::Missing,
                "OverlayFS Root refusal created a child");
            std::printf("CASE inverse_overlay_root_%s PASS Unsupported Adapter 4 before effects\n",
                disposition == JournalRootDisposition::AdoptHeld ? "adoption" : "provisioning");
        }
    }
    {
        auto entry = take(HeldChild::observe(source, name("file-alias")), "held private file bind alias");
        require(entry->metadata().identity.value() &&
            compare_identity(protected_id, *entry->metadata().identity.value()) == IdentityComparison::Same,
            "file bind fixture did not alias the exact private journal");
        const auto parent_info = take(source->inspect_basic(), "file bind parent mount");
        require(entry->metadata().mount_id.value() && parent_info.mount_id.value() &&
            *entry->metadata().mount_id.value() != *parent_info.mount_id.value(), "file bind mount IDs not distinct");
        refused("private_file_bind_per_entry", guard->check_entry(*entry));
        refused("private_file_bind_selected", JournalScopeGuard::create_for_entry(root, *entry));
    }
    // Assessment only: no copy/action executor receives authority. Verify the
    // exact protected object and bytes before removing the namespace fixtures.
    check_sentinel(*root, protected_id, state);
    mounts.finish();
    check_sentinel(*root, protected_id, state);
    require(take(guard->check_root(), "source after unmount"), "source scope changed after unmount");
    guard.reset();
    require(take(root->finish_io(), "private Root explicit close"), "private Root close false");
    std::puts("PRIVATE_SCOPE_MOUNTS_PASS");
    return 0;
}
}
int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    try {
        require(argc == 5 && std::string(argv[1]) == "--isolated", "use run_private_scope_mounts.py");
        if (namespace_id("/proc/self/ns/user") == argv[3] || namespace_id("/proc/self/ns/mnt") == argv[4])
            throw Unqualified("both a new user namespace and a new mount namespace are required");
        if (::geteuid() != 0) throw Unqualified("namespace uid mapping did not provide namespace-local uid 0");
        std::puts("PRIVATE_SCOPE_MOUNTS_STARTED");
        return run(take(NativeAbsolutePath::from_posix(argv[2]), "scratch address"));
    } catch (const Unqualified& error) {
        std::fprintf(stderr, "UNQUALIFIED private_scope_mounts: %s\n", error.what());
        return 77;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL private_scope_mounts: %s\n", error.what());
        return 1;
    }
}
