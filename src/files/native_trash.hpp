// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "held_child.hpp"
#include "native_operation_recovery_evidence.hpp"
#include "operation_journal.hpp"
#include <functional>
#include <utility>

namespace ck::files {
class PreparedJournalRoot;
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
    ObjectKind object_kind = ObjectKind::RegularFile;
    bool metadata_retired = false;
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
    // The scoped factory binds live native source and destination owners to
    // one exact private Root. A receipt's value IDs cannot satisfy this check.
    // Call before opening a journal and again immediately before commit.
    virtual Observation<bool> revalidate_private_scope(std::stop_token) const;
    // Explicit completion on all terminal paths. Native providers close and
    // report errors once; the default owns no native I/O (memory test models).
    virtual Observation<bool> finish_io();
};
class NativeTrashBackend {
public:
    virtual ~NativeTrashBackend() = default;
    // May provision the native per-user bin, but never moves the source or
    // creates a metadata record until commit. Only qualified ordinary files
    // and directories; directory Trash moves the entire held object, never a
    // recursive permanent-delete fallback.
    virtual Observation<std::unique_ptr<NativeTrashTransaction>> prepare_trash(HeldChild::Pointer, std::stop_token) const = 0;
    virtual Observation<std::unique_ptr<NativeTrashTransaction>> prepare_restore(const NativeTrashReceipt&,
        std::shared_ptr<const DirectoryCursor> original_parent, std::stop_token) const = 0;
    // No fallback to the unscoped methods. Providers must check every possible
    // provisioning parent before creation, then retain/recheck actual native
    // source/destination projections through commit. This is local protection
    // of the passed owner, not a global operation/namespace lease.
    virtual Observation<std::unique_ptr<NativeTrashTransaction>> prepare_trash_scoped(HeldChild::Pointer,
        std::shared_ptr<PreparedJournalRoot>, std::stop_token) const;
    virtual Observation<std::unique_ptr<NativeTrashTransaction>> prepare_restore_scoped(const NativeTrashReceipt&,
        std::shared_ptr<const DirectoryCursor>, std::shared_ptr<PreparedJournalRoot>, std::stop_token) const;
};
std::shared_ptr<const NativeTrashBackend> native_trash_backend();
// Bounded opaque journal evidence. No decoder grants execution authority.
Observation<std::vector<std::byte>> encode_native_trash_receipt(const NativeTrashReceipt&);
// Correct variable-length Windows v2 $I record, exact UTF-16LE including raw
// surrogate units. No legacy fixed 260-unit field. Bounded to 32767 path units.
Observation<std::vector<std::byte>> windows_trash_metadata(std::u16string_view original_path,
    std::uint64_t size, std::uint64_t deletion_filetime);
#ifdef _WIN32
namespace detail { class WindowsTrashScopeIssuer; }
class WindowsTrashHandle final {
public:
    explicit WindowsTrashHandle(void* p = nullptr) noexcept : value_(p) {}
    ~WindowsTrashHandle();
    WindowsTrashHandle(WindowsTrashHandle&&) noexcept;
    WindowsTrashHandle& operator=(WindowsTrashHandle&&) noexcept;
    WindowsTrashHandle(const WindowsTrashHandle&) = delete;
    WindowsTrashHandle& operator=(const WindowsTrashHandle&) = delete;
    void* get() const noexcept { return value_; }
    void* release() noexcept;
private:
    void* value_;
};
// Minimal bridge implemented beside WindowsDirectoryCursor; duplicates an
// existing held parent handle, never reopens its pathname or changes a vtable.
Observation<WindowsTrashHandle> duplicate_windows_trash_parent(const DirectoryCursor&);
// Query-only provider projection. Its cursor and entries expose no mutation,
// content/write access, or rights-upgrade path. Explicitly finish after guards
// release their cursor references, including failure and cancellation paths.
class NativeTrashDirectoryProjection {
public:
    virtual ~NativeTrashDirectoryProjection() = default;
    virtual const std::shared_ptr<const DirectoryCursor>& cursor() const noexcept = 0;
    virtual Observation<bool> finish_io() = 0;
};
class WindowsTrashScopeHandle final {
public:
    ~WindowsTrashScopeHandle();
    WindowsTrashScopeHandle(WindowsTrashScopeHandle&&) noexcept = default;
    WindowsTrashScopeHandle& operator=(WindowsTrashScopeHandle&&) = delete;
    WindowsTrashScopeHandle(const WindowsTrashScopeHandle&) = delete;
    WindowsTrashScopeHandle& operator=(const WindowsTrashScopeHandle&) = delete;
private:
    explicit WindowsTrashScopeHandle(WindowsTrashHandle handle,std::shared_ptr<PreparedJournalRoot> root)
        :handle_(std::move(handle)),root_(std::move(root)) {}
    WindowsTrashHandle handle_;
    std::shared_ptr<PreparedJournalRoot> root_;
    friend class detail::WindowsTrashScopeIssuer;
    friend Observation<std::unique_ptr<NativeTrashDirectoryProjection>> project_windows_trash_directory(WindowsTrashScopeHandle);
};
// Consumes a token minted only by the native Trash backend from a duplicate of
// its actual held directory. No caller HANDLE/identity/path factory exists.
Observation<std::unique_ptr<NativeTrashDirectoryProjection>> project_windows_trash_directory(WindowsTrashScopeHandle);
namespace detail {
// Scope inspector bridge: accepts only the genuine private read-only native
// Trash projection class and transfers a query-only owning duplicate.
Observation<void*> duplicate_windows_trash_scope_directory(const DirectoryCursor&);
}
#endif
} // namespace ck::files
