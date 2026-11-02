// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "ck_fs_actions.h"
#include "held_child.hpp"
#include "native_operation_recovery.hpp"
#include "native_trash.hpp"
#include <condition_variable>
#include <mutex>
#include <thread>

namespace ck::files {
// Private qualification boundary. Production POSIX name-based adapters cannot
// satisfy this contract. Tests may inject an atomic object-bound implementation.
class ActionNativeBoundary {
public:
    virtual ~ActionNativeBoundary() = default;
    virtual bool source_bound_rename() const noexcept = 0;
    virtual Observation<bool> qualify(const HeldChild&) const;
    virtual Observation<bool> distinct_targets(const HeldChild&, const NativeName&, const NativeName&) const;
    virtual Observation<bool> rename(const HeldChild&, const NativeName&, bool case_only) const = 0;
};
std::shared_ptr<const ActionNativeBoundary> native_action_boundary();
struct ActionItem {
    HeldChild::Pointer source;
    std::optional<NativeName> destination;
    bool case_only = false;
};
struct ActionRestoreItem {
    std::shared_ptr<const NativeTrashReceipt> receipt;
    std::shared_ptr<const DirectoryCursor> original_parent;
};
struct ActionRequest {
    uint32_t operation = CKFEA_RENAME, capabilities = 0, retry_limit = 0;
    std::vector<ActionItem> items;
    std::vector<ActionRestoreItem> restore_items;
    std::optional<NativeAbsolutePath> journal_directory;
    std::optional<NativeName> journal_name;
    std::optional<NativeOperationRecoveryInspection> recovery;
    std::shared_ptr<const DirectoryCursor> recovery_destination;
    uint64_t recovery_item = 0, max_verify_bytes = 0;
};
class ActionJob final : public std::enable_shared_from_this<ActionJob> {
public:
    explicit ActionJob(ActionRequest, std::shared_ptr<const ActionNativeBoundary> = native_action_boundary(),
        std::shared_ptr<const NativeTrashBackend> = native_trash_backend());
    ~ActionJob() = default;
    ActionJob(const ActionJob&) = delete;
    ActionJob& operator=(const ActionJob&) = delete;
    void start();
    ckfea_summary summary() const;
    ckfea_status item(uint32_t, ckfea_result&) const;
    ckfea_status evidence(uint64_t, ckfea_evidence&) const;
    ckfea_status receipt(ckfea_receipt&) const;
    ckfea_status trash_receipt(uint32_t, std::shared_ptr<const NativeTrashReceipt>&) const;
    ckfea_status execute(const ckfea_receipt&);
    void cancel();
    ckfea_status wait(uint32_t);
private:
    void run() noexcept;
    void preview();
    void perform();
    void preview_trash();
    void perform_trash();
    void release_native_inputs() noexcept;
    void preview_rename();
    bool revalidate(size_t);
    bool destination_clear(size_t);
    bool append_journal(size_t, OperationJournalState);
    void event(size_t, uint32_t);
    void set(size_t, uint32_t, uint32_t = CKFEA_REASON_NONE);
    ckfea_result row(size_t) const;
    void unavailable(size_t, const UnavailableObservation&, bool mutation_started = false);
    bool cancelled() const noexcept { return stop_.stop_requested(); }
    ActionRequest request_;
    std::shared_ptr<const ActionNativeBoundary> native_;
    std::shared_ptr<const NativeTrashBackend> trash_backend_;
    std::vector<std::unique_ptr<NativeTrashTransaction>> trash_transactions_;
    std::vector<std::shared_ptr<const NativeTrashReceipt>> trash_receipts_;
    uint64_t id_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    uint32_t phase_ = CKFEA_PREVIEWING;
    bool approved_ = false;
    std::stop_source stop_;
    std::vector<ckfea_result> results_;
    std::vector<ckfea_evidence> events_;
    std::vector<size_t> order_;
    std::vector<int> dependencies_;
    OperationJournal::Pointer journal_;
    std::unique_ptr<OperationJournalFile> journal_file_;
    std::optional<NativeOperationRecoveryArtifact> artifact_;

};
} // namespace ck::files
