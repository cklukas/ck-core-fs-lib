// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#if !defined(__linux__)
#error "native_target_read_seed_linux_tests.cpp must be registered only for Linux"
#else
#include "metadata_capture_job.hpp"
#include "native_filesystem.hpp"
#include "platform/native_target_read_seed.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace ck::files;

namespace {
class Latch final : public MetadataCaptureFailureLatch {
public:
    void record_first(MetadataCaptureCleanupError error) const noexcept override { if (!first) first = error; }
    mutable std::optional<MetadataCaptureCleanupError> first;
};

template<class T> T take(Observation<T> value) {
    if (!value.value()) {
        std::fprintf(stderr, "observation failed state=%u op=%s\n", static_cast<unsigned>(value.state()),
            value.unavailable_detail()->error.operation.c_str());
        std::abort();
    }
    return std::move(value).take_value();
}

NativeName name(const char* text) { return *NativeName::from_posix(text); }

bool expected_full_gate(const std::string& operation) {
    return operation=="metadata_replay.complete_requires_initial_sys_admin"||
        operation=="metadata_replay.initial_user_namespace_unqualified"||
        operation=="metadata_replay.ext4_birthtime_setter_unavailable"||
        operation=="metadata_replay.full_active_lsm_unimplemented"||
        operation=="metadata_replay.full_native_policy_unimplemented"||
        operation=="metadata_replay.full_attribute_class_unimplemented"||
        operation=="metadata_replay.full_capability_encoding_unimplemented"||
        operation=="metadata_replay.full_acl_coverage";
}

MetadataReplayPolicy policy() {
    MetadataReplayPolicy value;
    value.scope = RegularMetadataScope::OrdinaryCallerVisibleV1;
    value.limits.max_records = 256;
    value.limits.max_native_bytes = 64 * 1024;
    return value;
}

std::shared_ptr<const NativeMetadataProof> capture_directory(
    std::shared_ptr<const DirectoryCursor> directory, const MetadataReplayPolicy& replay,
    const std::shared_ptr<MetadataCaptureBudget>& budget, const std::shared_ptr<const Latch>& latch) {
    auto job = take(MetadataCaptureJob::begin_directory(directory, replay, budget->limits(), budget, latch));
    for (unsigned step = 0; step != 10000 && job->progress().phase != MetadataCapturePhase::Complete; ++step)
        take(job->advance());
    assert(job->progress().phase == MetadataCapturePhase::Complete);
    auto proof = take(job->result());
    job.reset(); // The proof remains open for the target-read seed.
    return proof;
}

std::shared_ptr<const NativeMetadataProof> capture_file(
    std::shared_ptr<const OpenedEntry> entry, const MetadataReplayPolicy& replay,
    const std::shared_ptr<MetadataCaptureBudget>& budget, const std::shared_ptr<const Latch>& latch) {
    auto job = take(MetadataCaptureJob::begin(entry, replay, budget->limits(), budget, latch));
    for (unsigned step = 0; step != 10000 && job->progress().phase != MetadataCapturePhase::Complete; ++step)
        take(job->advance());
    assert(job->progress().phase == MetadataCapturePhase::Complete);
    auto proof = take(job->result());
    job.reset(); // The proof remains open for the target-read seed.
    return proof;
}

class ForeignCursor final : public DirectoryCursor {
public:
    ForeignCursor() : DirectoryCursor() {}
protected:
    Observation<DirectoryStep> next_step() override { return Observation<DirectoryStep>::available(DirectoryEnd{}); }
};

void directory_case(const std::filesystem::path& path) {
    NativeFileSystem filesystem;
    auto directory = std::shared_ptr<const DirectoryCursor>(take(filesystem.open_directory(path)));
    auto late = take(directory->create_child_file(name("late")));
    assert(take(late->write_content(0, std::span<const std::byte>{})) == 0);
    assert(take(late->finish_content_writes()));
    late.reset();
    MetadataCaptureLimits limits;
    limits.read.max_bytes = 4096;
    auto budget = std::make_shared<MetadataCaptureBudget>(limits);
    auto latch = std::make_shared<Latch>();
    auto proof = capture_directory(directory, policy(), budget, latch);

    MetadataCaptureLimits denied_limits = limits;
    denied_limits.max_metadata_bytes = 1;
    auto denied_budget = std::make_shared<MetadataCaptureBudget>(denied_limits);
    auto denied_seed = take(detail::begin_native_directory_read_seed(directory, proof, denied_limits, denied_budget, latch));
    auto denied = denied_seed->advance();
    assert(!denied.value() && denied.state() == ObservationState::Unsupported);
    auto denied_again = denied_seed->advance();
    assert(!denied_again.value() && denied_again.state() == denied.state());
    assert(take(denied_seed->finish_io()));

    const auto baseline_handles = budget->retained_handle_reservations();
    auto cancelled_seed = take(detail::begin_native_directory_read_seed(directory, proof, limits, budget, latch));
    auto pending = cancelled_seed->advance();
    assert(pending.value() && !*pending.value());
    assert(budget->retained_handle_reservations() > baseline_handles);
    std::stop_source stop;
    stop.request_stop();
    auto cancelled = cancelled_seed->advance(stop.get_token());
    assert(!cancelled.value() && cancelled.state() == ObservationState::Unknown);
    assert(take(cancelled_seed->finish_io()));
    assert(budget->retained_handle_reservations() == baseline_handles);

    auto seed = take(detail::begin_native_directory_read_seed(directory, proof, limits, budget, latch));
    auto directory_pending = seed->advance();
    assert(directory_pending.value() && !*directory_pending.value());
    assert(take(seed->advance()));
    auto source = take(seed->source());
    auto before = take(source->inspect_basic());
    auto first = take(seed->directory_cursor());
    assert(!seed->directory_cursor().value());
    std::vector<NativeName> names;
    for (;;) {
        auto batch = std::const_pointer_cast<DirectoryCursor>(first)->read(1);
        assert(batch.state != DirectoryReadState::Error);
        names.insert(names.end(), batch.names.begin(), batch.names.end());
        if (batch.state == DirectoryReadState::End) break;
    }
    assert(std::find(names.begin(), names.end(), name("late")) != names.end());
    // EOF releases only the position lease; the exhausted cursor may remain
    // pinned while a subsequent independent cursor is opened.
    auto second = take(seed->directory_cursor());
    auto restarted = std::const_pointer_cast<DirectoryCursor>(second)->read(1);
    assert(restarted.state != DirectoryReadState::Error);
    assert(std::find(restarted.names.begin(), restarted.names.end(), name("late")) != restarted.names.end());
    second.reset();
    first.reset();
    auto after = take(source->inspect_basic());
    assert(before.accessed.value() && after.accessed.value() && *before.accessed.value() == *after.accessed.value());
    assert(before.modified.value() && after.modified.value() && *before.modified.value() == *after.modified.value());
    auto active_finish = seed->finish_io();
    assert(!active_finish.value() && active_finish.unavailable_detail()->error.operation == "seed.consumers_active");
    source.reset();
    assert(take(seed->finish_io()));
    assert(take(proof->finish_io()));
    assert(!latch->first);

    auto foreign = std::make_shared<ForeignCursor>();
    auto rejected = detail::begin_native_directory_read_seed(foreign, proof, limits, budget, latch);
    assert(!rejected.value() && rejected.state() == ObservationState::Unsupported);
}

void regular_case(const std::filesystem::path& path) {
    NativeFileSystem filesystem;
    auto directory = std::shared_ptr<const DirectoryCursor>(take(filesystem.open_directory(path)));
    const std::array<std::byte, 4> bytes{std::byte{'r'}, std::byte{'e'}, std::byte{'a'}, std::byte{'d'}};
    auto source_writer = take(directory->create_child_file(name("source")));
    assert(take(source_writer->write_content(0, bytes)) == bytes.size());
    assert(take(source_writer->finish_content_writes()));
    source_writer.reset();
    auto reader = std::shared_ptr<const OpenedEntry>(take(directory->open_child(name("source"), EntryAccess::ContentRead)));
    auto target = take(directory->create_child_file(name("target")));
    assert(take(target->write_content(0, bytes)) == bytes.size());
    MetadataCaptureLimits limits;
    limits.read.max_bytes = 4096;
    auto budget = std::make_shared<MetadataCaptureBudget>(limits);
    auto latch = std::make_shared<Latch>();
    auto proof = capture_file(reader, policy(), budget, latch);
    const auto proof_handles = budget->retained_handle_reservations();
    auto seed = take(detail::begin_native_target_read_seed(*target, proof, limits, budget, latch));
    assert(take(seed->advance()));
    auto source = take(seed->source());
    auto before = take(source->inspect_basic());
    auto content = take(source->read_content({bytes.size()}, 0));
    assert(content.bytes == std::vector<std::byte>(bytes.begin(), bytes.end()));
    auto after = take(source->inspect_basic());
    assert(before.accessed.value() && after.accessed.value() && *before.accessed.value() == *after.accessed.value());
    const auto seed_handles = budget->retained_handle_reservations();
    auto capture_clone = take(detail::open_native_metadata_capture_source(source, policy()));
    {
        detail::MetadataCaptureCleanupScope cleanup(latch.get());
        detail::finish_native_metadata_capture(source.get(), proof->snapshot());
    }
    source.reset();
    auto active_finish = seed->finish_io();
    assert(!active_finish.value() && active_finish.unavailable_detail()->error.operation == "seed.consumers_active");
    // The original source may finish first, but the independent clone still
    // owns its own native-handle reservation.
    assert(budget->retained_handle_reservations() == seed_handles + 1);
    {
        detail::MetadataCaptureCleanupScope cleanup(latch.get());
        detail::finish_native_metadata_capture(capture_clone.get(), proof->snapshot());
    }
    capture_clone.reset();
    assert(take(seed->finish_io()));
    assert(budget->retained_handle_reservations() == proof_handles);
    NativeFileSystem foreign_filesystem;
    auto foreign_directory = std::shared_ptr<const DirectoryCursor>(take(foreign_filesystem.open_directory(path)));
    auto foreign_target = take(foreign_directory->create_child_file(name("foreign-target")));
    assert(take(foreign_target->write_content(0, bytes)) == bytes.size());
    auto foreign_seed = take(detail::begin_native_target_read_seed(*foreign_target, proof, limits, budget, latch));
    auto foreign_advance = foreign_seed->advance();
    assert(!foreign_advance.value() && foreign_advance.state() == ObservationState::Unsupported);
    auto foreign_finish = foreign_seed->finish_io();
    assert(foreign_finish.value() && *foreign_finish.value());
    assert(take(foreign_target->finish_content_writes()));
    foreign_target.reset();
    foreign_directory.reset();
    assert(take(proof->finish_io()));
    assert(take(target->finish_content_writes()));
    reader.reset();
    target.reset();
    std::filesystem::remove(path / "source");
    std::filesystem::remove(path / "target");
    std::filesystem::remove(path / "foreign-target");
    assert(!latch->first);
}

void anonymous_target_capture_case(const std::filesystem::path& path) {
    NativeFileSystem filesystem;
    auto directory=std::shared_ptr<const DirectoryCursor>(take(filesystem.open_directory(path)));
    const std::array<std::byte,4> bytes{std::byte{'a'},std::byte{'n'},std::byte{'o'},std::byte{'n'}};
    auto source_writer=take(directory->create_child_file(name("anonymous-source")));
    assert(take(source_writer->write_content(0,bytes))==bytes.size());
    assert(take(source_writer->finish_content_writes()));
    source_writer.reset();
    auto source=std::shared_ptr<const OpenedEntry>(take(directory->open_child(name("anonymous-source"),EntryAccess::ContentRead)));
    MetadataCaptureLimits limits;limits.read.max_bytes=4096;
    auto budget=std::make_shared<MetadataCaptureBudget>(limits);
    auto latch=std::make_shared<Latch>();
    auto proof=capture_file(source,policy(),budget,latch);

    auto created=take(directory->create_staging_file(name("anonymous-target")));
    assert(created.staging_namespace==StagingNamespace::Anonymous&&!created.name);
    assert(take(created.entry->write_content(0,bytes))==bytes.size());
    auto seed=take(detail::begin_native_target_read_seed(*created.entry,proof,limits,budget,latch));
    assert(take(seed->advance()));
    auto anonymous_source=take(seed->source());
    const auto anonymous_basic=take(anonymous_source->inspect_basic());
    MetadataReplayPolicy wrong_version=policy();wrong_version.version=2;
    auto wrong_version_check=detail::qualify_native_anonymous_target_capture(*anonymous_source,anonymous_basic,wrong_version);
    assert(!wrong_version_check.value()&&wrong_version_check.unavailable_detail()->error.operation=="metadata_capture.anonymous_policy_version");
    auto stale_basic=anonymous_basic;
    assert(stale_basic.logical_size.value());
    stale_basic.logical_size=Observation<std::uint64_t>::available(*stale_basic.logical_size.value()+1);
    auto live_basic=take(anonymous_source->inspect_basic());
    std::printf("anonymous bookend supplied_size=%llu live_size=%llu\n",
        static_cast<unsigned long long>(*stale_basic.logical_size.value()),
        static_cast<unsigned long long>(*live_basic.logical_size.value()));
    auto stale_bookend=detail::qualify_native_anonymous_target_capture(*anonymous_source,stale_basic,policy());
    if(stale_bookend.value())std::fprintf(stderr,"stale anonymous target unexpectedly accepted\n");
    else std::printf("PASS stale anonymous target refused state=%u operation=%s\n",unsigned(stale_bookend.state()),stale_bookend.unavailable_detail()->error.operation.c_str());
    assert(!stale_bookend.value());
    auto anonymous_job=take(MetadataCaptureJob::begin(anonymous_source,policy(),limits,budget,latch));
    for(unsigned i=0;i<10000&&anonymous_job->progress().phase!=MetadataCapturePhase::Complete;++i)
        take(anonymous_job->advance());
    assert(anonymous_job->progress().phase==MetadataCapturePhase::Complete);
    auto anonymous_proof=take(anonymous_job->result());
    assert(anonymous_proof->snapshot().basic.link_count.value()&&*anonymous_proof->snapshot().basic.link_count.value()==0);
    assert(take(anonymous_job->finish_io()));
    anonymous_proof.reset();anonymous_job.reset();

    // CompleteMetadataV1 is an independent policy qualification. On a
    // normal unprivileged runner it is a precise pending gate; a fixture
    // launcher may require it with CK_FS_REQUIRE_FULL_ANONYMOUS_CAPTURE=1.
    auto full_policy=policy();
    full_policy.scope=RegularMetadataScope::CompleteMetadataV1;
    full_policy.allow_privilege_metadata=true;
    const char* require_full_value=std::getenv("CK_FS_REQUIRE_FULL_ANONYMOUS_CAPTURE");
    const bool require_full=require_full_value!=nullptr;
    assert(!require_full||std::strcmp(require_full_value,"1")==0);
    auto full_job=MetadataCaptureJob::begin(anonymous_source,full_policy,limits,budget,latch);
    if(!full_job.value()) {
        const auto&e=*full_job.unavailable_detail();
        std::printf("FULL_ANONYMOUS_CAPTURE_PENDING state=%u operation=%s\n",unsigned(e.state),e.error.operation.c_str());
        assert(expected_full_gate(e.error.operation)&&!require_full);
    } else {
        auto full_capture=std::move(full_job).take_value();
        bool pending=false;
        for(unsigned i=0;i<10000&&full_capture->progress().phase!=MetadataCapturePhase::Complete;++i) {
            auto step=full_capture->advance();
            if(!step.value()) {
                const auto&e=*step.unavailable_detail();
                std::printf("FULL_ANONYMOUS_CAPTURE_PENDING state=%u operation=%s\n",unsigned(e.state),e.error.operation.c_str());
                assert(expected_full_gate(e.error.operation));
                pending=true;
                break;
            }
        }
        if(pending) {
            const auto drained=full_capture->finish_io();
            if(!drained.value()) {
                const auto&e=*drained.unavailable_detail();
                std::fprintf(stderr,"FULL_ANONYMOUS_CAPTURE_DRAIN_FAILURE state=%u operation=%s\n",unsigned(e.state),e.error.operation.c_str());
            }
            assert(drained.value()&&*drained.value());
            assert(!require_full);
        } else {
            assert(full_capture->progress().phase==MetadataCapturePhase::Complete);
            auto full_proof=take(full_capture->result());
            assert(full_proof->snapshot().basic.link_count.value()&&*full_proof->snapshot().basic.link_count.value()==0);
            assert(take(full_capture->finish_io()));
            full_proof.reset();
            std::puts("FULL_ANONYMOUS_CAPTURE_PASS zero-link native capability");
        }
        full_capture.reset();
    }
    anonymous_source.reset();
    assert(take(seed->finish_io()));
    assert(take(created.entry->finish_content_writes()));
    created.entry.reset();

    NativeFileSystem foreign_filesystem;
    auto foreign_directory=std::shared_ptr<const DirectoryCursor>(take(foreign_filesystem.open_directory(path)));
    auto foreign_created=take(foreign_directory->create_staging_file(name("foreign-anonymous-target")));
    assert(take(foreign_created.entry->write_content(0,bytes))==bytes.size());
    auto foreign_seed=take(detail::begin_native_target_read_seed(*foreign_created.entry,proof,limits,budget,latch));
    auto foreign_step=foreign_seed->advance();
    assert(!foreign_step.value()&&foreign_step.unavailable_detail()->error.operation=="seed.source_target_scope");
    assert(take(foreign_seed->finish_io()));
    assert(take(foreign_created.entry->finish_content_writes()));
    foreign_created.entry.reset();foreign_directory.reset();

    auto unlinked_writer=take(directory->create_child_file(name("ordinary-unlinked")));
    assert(take(unlinked_writer->write_content(0,bytes))==bytes.size());
    assert(take(unlinked_writer->finish_content_writes()));
    unlinked_writer.reset();
    auto unlinked=std::shared_ptr<const OpenedEntry>(take(directory->open_child(name("ordinary-unlinked"),EntryAccess::ContentRead)));
    assert(::unlink((path/"ordinary-unlinked").c_str())==0);
    auto rejected=take(MetadataCaptureJob::begin(unlinked,policy(),limits,budget,latch));
    auto rejected_step=rejected->advance();
    assert(!rejected_step.value()&&rejected_step.unavailable_detail()->error.operation=="metadata_capture.anonymous_capability_required");
    assert(take(rejected->finish_io()));
    rejected.reset();unlinked.reset();

    assert(!MetadataCaptureJob::begin(source,wrong_version,limits,budget,latch).value());
    source.reset();
    assert(take(proof->finish_io()));proof.reset();
    assert(!latch->first);
    std::filesystem::remove(path/"anonymous-source");
    std::puts("native anonymous target capability: genuine zero-link clone accepted; ordinary unlinked, foreign-policy and version fakes refused");
}

void different_directory_target_case(const std::filesystem::path& path) {
    const auto source_path=path/"source-dir";
    const auto target_path=path/"target-dir";
    std::filesystem::create_directory(source_path);
    std::filesystem::create_directory(target_path);
    NativeFileSystem filesystem;
    auto source_directory=std::shared_ptr<const DirectoryCursor>(take(filesystem.open_directory(source_path)));
    auto target_directory=std::shared_ptr<const DirectoryCursor>(take(filesystem.open_directory(target_path)));
    auto child=take(target_directory->create_child_file(name("target-child")));
    assert(take(child->finish_content_writes()));
    child.reset();
    MetadataCaptureLimits limits;
    limits.read.max_bytes=4096;
    auto budget=std::make_shared<MetadataCaptureBudget>(limits);
    auto latch=std::make_shared<Latch>();
    auto proof=capture_directory(source_directory,policy(),budget,latch);
    auto target_view=take(detail::open_native_directory_capture_source(target_directory,policy()));
    auto writer=take(target_view->open_directory_metadata_target(policy()));
    auto seed=take(detail::begin_native_target_read_seed(*writer,proof,limits,budget,latch));
    auto pending=seed->advance();
    assert(pending.value()&&!*pending.value());
    assert(take(seed->advance()));
    auto source=take(seed->source());
    // Authorized target metadata work can change directory ctime before the
    // late fresh enumeration. The seed retains native identity/mount/kind
    // continuity; the tree layer owns validation of the fresh values.
    auto late_child=take(target_directory->create_child_file(name("late-target-child")));
    assert(take(late_child->finish_content_writes()));
    late_child.reset();
    assert(::chmod(target_path.c_str(),0)==0);
    auto cursor=take(seed->directory_cursor());
    auto batch=std::const_pointer_cast<DirectoryCursor>(cursor)->read(1);
    assert(batch.state!=DirectoryReadState::Error);
    auto active_finish=seed->finish_io();
    assert(!active_finish.value() && active_finish.unavailable_detail()->error.operation=="seed.consumers_active");
    cursor.reset();
    active_finish=seed->finish_io();
    assert(!active_finish.value() && active_finish.unavailable_detail()->error.operation=="seed.consumers_active");
    source.reset();
    assert(take(seed->finish_io()));
    assert(::chmod(target_path.c_str(),0700)==0);
    source.reset();
    assert(take(writer->finish_content_writes()));
    writer.reset();
    target_view.reset();
    assert(take(proof->finish_io()));
    assert(!latch->first);
    std::filesystem::remove_all(source_path);
    std::filesystem::remove_all(target_path);
}

void clone_budget_case(const std::filesystem::path& path) {
    NativeFileSystem filesystem;
    auto directory=std::shared_ptr<const DirectoryCursor>(take(filesystem.open_directory(path)));
    const std::array<std::byte,4> bytes{std::byte{'b'},std::byte{'u'},std::byte{'d'},std::byte{'g'}};
    auto writer=take(directory->create_child_file(name("budget-source")));
    assert(take(writer->write_content(0,bytes))==bytes.size());
    assert(take(writer->finish_content_writes()));
    writer.reset();
    auto reader=std::shared_ptr<const OpenedEntry>(take(directory->open_child(name("budget-source"),EntryAccess::ContentRead)));
    auto target=take(directory->create_child_file(name("budget-target")));
    assert(take(target->write_content(0,bytes))==bytes.size());
    MetadataCaptureLimits limits;
    limits.read.max_bytes=4096;
    limits.max_retained_handles=10; // proof=8, seed=1, one real clone=1
    auto budget=std::make_shared<MetadataCaptureBudget>(limits);
    auto latch=std::make_shared<Latch>();
    auto proof=capture_file(reader,policy(),budget,latch);
    const auto proof_handles=budget->retained_handle_reservations();
    auto seed=take(detail::begin_native_target_read_seed(*target,proof,limits,budget,latch));
    assert(take(seed->advance()));
    auto source=take(seed->source());
    auto clone=take(detail::open_native_metadata_capture_source(source,policy()));
    source.reset();
    assert(budget->retained_handle_reservations()==limits.max_retained_handles);
    auto exhausted=detail::open_native_metadata_capture_source(clone,policy());
    assert(!exhausted.value()&&exhausted.state()==ObservationState::Unsupported);
    assert(budget->retained_handle_reservations()==limits.max_retained_handles);
    {
        detail::MetadataCaptureCleanupScope cleanup(latch.get());
        detail::finish_native_metadata_capture(clone.get(),proof->snapshot());
    }
    clone.reset();
    assert(budget->retained_handle_reservations()==proof_handles+1);
    auto source_again=take(seed->source());
    auto clone_again=take(detail::open_native_metadata_capture_source(source_again,policy()));
    source_again.reset();
    assert(budget->retained_handle_reservations()==limits.max_retained_handles);
    {
        detail::MetadataCaptureCleanupScope cleanup(latch.get());
        detail::finish_native_metadata_capture(clone_again.get(),proof->snapshot());
    }
    clone_again.reset();
    assert(take(seed->finish_io()));
    assert(budget->retained_handle_reservations()==proof_handles);
    assert(take(proof->finish_io()));
    assert(take(target->finish_content_writes()));
    reader.reset();
    target.reset();
    std::filesystem::remove(path/"budget-source");
    std::filesystem::remove(path/"budget-target");
    assert(!latch->first);
}
}

int main(int argc, char** argv) {
    assert(argc == 2);
    std::filesystem::path base(argv[1]);
    std::filesystem::create_directories(base);
    std::string raw = (base / "native-target-read-seed-XXXXXX").string();
    char* created = ::mkdtemp(raw.data());
    assert(created);
    std::filesystem::path fixture(created);
    std::puts("directory-case");
    directory_case(fixture);
    std::puts("regular-case");
    regular_case(fixture);
    std::puts("anonymous-target-capture-case");
    anonymous_target_capture_case(fixture);
    std::puts("different-directory-target-case");
    different_directory_target_case(fixture);
    std::puts("clone-budget-case");
    clone_budget_case(fixture);
    std::filesystem::remove_all(fixture);
    std::puts("native_target_read_seed_linux: passed");
}
#endif
