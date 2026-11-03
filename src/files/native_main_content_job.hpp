// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "metadata_capture_job.hpp"
#include "private_journal_scope.hpp"

namespace ck::files {
// Main DATA observation only. This schema is distinct from the V3 preserved
// metadata digest and carries no stream-catalog, security or replay authority.
inline constexpr std::uint32_t native_main_content_schema = 1;
struct NativeMainContentLimits final {
    ContentReadLimits read{};
    std::uint64_t max_main_bytes=std::numeric_limits<std::uint64_t>::max();
    bool valid()const noexcept{return read.valid();}
};
enum class NativeMainContentPhase { Basic, ReadData, Boundary, FinalBasic, DataReady, Closed, Cancelled, Failed };
struct NativeMainContentProgress final {
    NativeMainContentPhase phase=NativeMainContentPhase::Basic;
    unsigned pass=0;
    std::uint64_t read_calls=0,read_bytes=0,pass_bytes=0;
    std::optional<std::uint64_t> main_bytes;
};
struct NativeMainContentAdvance final {
    NativeMainContentPhase phase;
    std::size_t content_reads=0,content_bytes=0;
};
// Native-issued immutable values only. A two-pass source observation, not a
// freeze or a target atime verifier. Read-induced access times are retained in
// the raw bookends but excluded from version equality. No native owners.
class NativeMainContentProof final {
public:
    const BasicMetadata& before()const noexcept{return before_;}
    const BasicMetadata& after()const noexcept{return after_;}
    const std::array<std::byte,32>& main_digest()const noexcept{return digest_;}
    std::uint64_t main_bytes()const noexcept{return size_;}
    std::uint32_t schema()const noexcept{return native_main_content_schema;}
private:
    friend class NativeMainContentJob;
    NativeMainContentProof(BasicMetadata a,BasicMetadata b,std::array<std::byte,32> h,std::uint64_t n)
        :before_(std::move(a)),after_(std::move(b)),digest_(h),size_(n){}
    const BasicMetadata before_,after_;
    const std::array<std::byte,32> digest_;
    const std::uint64_t size_;
};
class NativeMainContentJob final {
public:
    ~NativeMainContentJob();
    NativeMainContentJob(const NativeMainContentJob&)=delete;
    NativeMainContentJob&operator=(const NativeMainContentJob&)=delete;
    // Requires genuine native HeldChild ContentRead access. A genuine scope
    // guard is required by Root consumers; descriptive Compare may pass null.
    // Membership and optional Root scope are checked around every advance.
    static Observation<std::unique_ptr<NativeMainContentJob>> begin_held(
        HeldChild::Pointer,NativeMainContentLimits={},JournalScopeGuard::Pointer={},
        std::shared_ptr<const MetadataCaptureFailureLatch> = {},std::stop_token={});
    // At most one read_content call, <= limits.read bytes, per advance.
    Observation<NativeMainContentAdvance> advance(std::stop_token={});
    const NativeMainContentProgress& progress()const noexcept;
    // Mandatory on ALL paths on the native worker. Consumes the actual clone
    // once; releases operation-owned held/scope refs under the close observer.
    // Idempotent, drains before formatting errors. A close error latches the
    // first Root consumer failure even when formatting subsequently throws.
    Observation<bool> finish_read();
    std::optional<MetadataCaptureCleanupError> cleanup_error()const noexcept;
    // Available only after DataReady followed by successful finish_read.
    // A closed early/failed/cancelled job never exports a proof.
    Observation<std::shared_ptr<const NativeMainContentProof>> result()const;
private:
    struct Impl;
    explicit NativeMainContentJob(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
} // namespace ck::files
