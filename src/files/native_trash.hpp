// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "held_child.hpp"
#include "native_operation_recovery_evidence.hpp"
#include "operation_journal.hpp"
#include <functional>

namespace ck::files {
// Process-local native evidence; never reconstructed from an untrusted $I path.
// Live receipts retain native identity owners. Their final disposal is queued
// on a cleanup worker, never a UI-thread handle-close or a durable replay token.
class NativeTrashIdentityOwner {
public:
    virtual ~NativeTrashIdentityOwner() = default;
};
struct NativeTrashReceipt final {
    NativeName original_name, data_name, metadata_name, user_sid;
    NativeDurableIdentity original_parent, object, recycle_parent;
    std::optional<NativeDurableIdentity> metadata_identity;
    std::vector<std::byte> metadata_bytes;
    std::shared_ptr<const NativeTrashIdentityOwner> continuity;
};
using NativeTrashJournal = std::function<Observation<bool>(OperationJournalState, const NativeTrashReceipt&)>;
class NativeTrashTransaction {
public:
    virtual ~NativeTrashTransaction() = default;
    virtual const NativeTrashReceipt& receipt() const noexcept = 0;
    // One-shot worker operation. Journal callback must durably flush each fact.
    // After any ambiguous mutation, retain all objects/evidence; never replay.
    virtual Observation<bool> commit(const NativeTrashJournal&, std::stop_token) = 0;
    virtual bool mutation_attempted() const noexcept = 0;
};
class NativeTrashBackend {
public:
    virtual ~NativeTrashBackend() = default;
    // May provision the native per-user bin, but never moves the source or
    // creates a metadata record until commit. Only qualified ordinary files.
    virtual Observation<std::unique_ptr<NativeTrashTransaction>> prepare_trash(HeldChild::Pointer, std::stop_token) const = 0;
    virtual Observation<std::unique_ptr<NativeTrashTransaction>> prepare_restore(const NativeTrashReceipt&,
        std::shared_ptr<const DirectoryCursor> original_parent, std::stop_token) const = 0;
};
std::shared_ptr<const NativeTrashBackend> native_trash_backend();
// Bounded opaque journal evidence. No decoder grants execution authority.
Observation<std::vector<std::byte>> encode_native_trash_receipt(const NativeTrashReceipt&);
// Correct variable-length Windows v2 $I record, exact UTF-16LE including raw
// surrogate units. No legacy fixed 260-unit field. Bounded to 32767 path units.
Observation<std::vector<std::byte>> windows_trash_metadata(std::u16string_view original_path,
    std::uint64_t size, std::uint64_t deletion_filetime);
#ifdef _WIN32
class WindowsTrashHandle final {
public:
    explicit WindowsTrashHandle(void* p = nullptr) noexcept : value_(p) {}
    ~WindowsTrashHandle();
    WindowsTrashHandle(WindowsTrashHandle&&) noexcept;
    WindowsTrashHandle& operator=(WindowsTrashHandle&&) noexcept;
    WindowsTrashHandle(const WindowsTrashHandle&) = delete;
    WindowsTrashHandle& operator=(const WindowsTrashHandle&) = delete;
    void* get() const noexcept { return value_; }
private:
    void* value_;
};
// Minimal bridge implemented beside WindowsDirectoryCursor; duplicates an
// existing held parent handle, never reopens its pathname or changes a vtable.
Observation<WindowsTrashHandle> duplicate_windows_trash_parent(const DirectoryCursor&);
#endif
} // namespace ck::files
