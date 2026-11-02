// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../operation_journal_file.hpp"
#include "posix_private_storage.hpp"

#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

namespace ck::files {
namespace {
class Fd final {
public:
    explicit Fd(int value) noexcept : value_(value) {}
    ~Fd() { if (value_ >= 0) ::close(value_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int value() const noexcept { return value_; }
    int release() noexcept { const int value = value_; value_ = -1; return value; }
private:
    int value_;
};

ObservationState state(int code) {
    if (code == ENOENT || code == ENOTDIR) return ObservationState::Gone;
    if (code == EACCES || code == EPERM) return ObservationState::Denied;
    if (code == ENOSYS || code == ENOTSUP) return ObservationState::Unsupported;
    return ObservationState::Failed;
}

template <class T>
Observation<T> failure(int code, const char* operation) {
    return Observation<T>::unavailable(state(code), {ErrorDomain::Posix, code, operation});
}

template <class T>
Observation<T> rejected(AdapterError code, const char* operation,
                        ObservationState state = ObservationState::Failed) {
    return Observation<T>::unavailable(state,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(code), operation});
}

bool valid_io(std::uint64_t offset, std::size_t count) {
    const auto max = static_cast<std::uint64_t>(std::numeric_limits<off_t>::max());
    return offset <= max && count <= max - offset;
}

Observation<bool> private_directory(int fd) {
    return detail::qualify_posix_private_storage(fd,detail::PosixPrivateStorageKind::Directory);
}

Observation<bool> private_regular(int fd,bool newly_created) {
    auto private_check=detail::qualify_posix_private_storage(fd,detail::PosixPrivateStorageKind::RegularFile);
    if(!private_check.value()) return private_check;
    if(newly_created) {
        struct stat info{};
        if(fstat(fd,&info)) return failure<bool>(errno,"journal_file.created_stat");
        if(info.st_size!=0) return rejected<bool>(AdapterError::InvalidAccess,"journal_file.created_nonempty",ObservationState::Denied);
    }
    return Observation<bool>::available(true);
}

class PosixOperationJournalFile final : public OperationJournalFile {
public:
    PosixOperationJournalFile(int fd,int directory) noexcept : fd_(fd),directory_(directory) {}
    Observation<std::uint64_t> size() override {
        auto checked=revalidate();
        if(!checked.value()) return Observation<std::uint64_t>::unavailable(checked.state(),checked.unavailable_detail()->error);
        struct stat info{};
        if (fstat(fd_.value(), &info) != 0) return failure<std::uint64_t>(errno, "journal_file.fstat");
        if (!S_ISREG(info.st_mode) || info.st_size < 0 || info.st_nlink != 1)
            return rejected<std::uint64_t>(AdapterError::InvalidNativeResult, "journal_file.size");
        return Observation<std::uint64_t>::available(static_cast<std::uint64_t>(info.st_size));
    }
    Observation<std::size_t> read_at(std::uint64_t offset, std::span<std::byte> bytes) override {
        if (!valid_io(offset, bytes.size())) return rejected<std::size_t>(AdapterError::InvalidLimit, "journal_file.read_range");
        auto checked=revalidate();
        if(!checked.value()) return Observation<std::size_t>::unavailable(checked.state(),checked.unavailable_detail()->error);
        const auto count = std::min(bytes.size(), static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
        const auto result = pread(fd_.value(), bytes.data(), count, static_cast<off_t>(offset));
        if (result < 0) return failure<std::size_t>(errno, "journal_file.pread");
        checked=revalidate();
        if(!checked.value()) return Observation<std::size_t>::unavailable(checked.state(),checked.unavailable_detail()->error);
        return Observation<std::size_t>::available(static_cast<std::size_t>(result));
    }
    Observation<std::size_t> write_at(std::uint64_t offset, std::span<const std::byte> bytes) override {
        if (!valid_io(offset, bytes.size())) return rejected<std::size_t>(AdapterError::InvalidLimit, "journal_file.write_range");
        auto checked=revalidate();
        if(!checked.value()) return Observation<std::size_t>::unavailable(checked.state(),checked.unavailable_detail()->error);
        const auto count = std::min(bytes.size(), static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
        const auto result = pwrite(fd_.value(), bytes.data(), count, static_cast<off_t>(offset));
        if (result < 0) return failure<std::size_t>(errno, "journal_file.pwrite");
        checked=revalidate();
        if(!checked.value()) return Observation<std::size_t>::unavailable(checked.state(),checked.unavailable_detail()->error);
        return Observation<std::size_t>::available(static_cast<std::size_t>(result));
    }
    Observation<bool> flush() override {
        auto checked=revalidate();if(!checked.value()) return checked;
        if (fsync(fd_.value()) != 0) return failure<bool>(errno, "journal_file.fsync");
        if (fsync(directory_.value()) != 0) return failure<bool>(errno,"journal_file.parent_fsync");
#ifdef __APPLE__
        if (fcntl(fd_.value(),F_FULLFSYNC) != 0) return failure<bool>(errno,"journal_file.fullsync");
#endif
        return revalidate();
    }
    Observation<bool> finish_io() override {
        if (finished_) return finish_failure_ ? Observation<bool>::unavailable(finish_failure_->state,finish_failure_->error)
                                             : Observation<bool>::available(true);
        auto flushed=flush();
        if (!flushed.value() || !*flushed.value()) {
            finish_failure_=flushed.value() ? UnavailableObservation{ObservationState::Failed,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.finish_flush"}}
                : *flushed.unavailable_detail();
        }
        // Release ownership before close: EINTR/EIO must never cause a second
        // close on a descriptor that another thread could already have reused.
        const int fd=fd_.release();
        if (::close(fd)!=0 && !finish_failure_)
            finish_failure_=*failure<bool>(errno,"journal_file.close").unavailable_detail();
        const int directory=directory_.release();
        if (::close(directory)!=0 && !finish_failure_)
            finish_failure_=*failure<bool>(errno,"journal_file.parent_close").unavailable_detail();
        finished_=true;
        return finish_failure_ ? Observation<bool>::unavailable(finish_failure_->state,finish_failure_->error)
                               : Observation<bool>::available(true);
    }
private:
    Observation<bool> revalidate() {
        auto root=private_directory(directory_.value());if(!root.value()) return root;
        return private_regular(fd_.value(),false);
    }
    Fd fd_,directory_;
    bool finished_=false;
    std::optional<UnavailableObservation> finish_failure_;
};
}

Observation<bool> prepare_native_operation_journal_root(const NativeAbsolutePath& private_root) {
    using Result = Observation<bool>;
    auto host = private_root.host_path();
    if (!host.value())
        return Result::unavailable(host.unavailable_detail()->state, host.unavailable_detail()->error);
    Fd directory(open(host.value()->c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (directory.value() < 0)
        return failure<bool>(errno, "journal_file.prepare_root.open");
    auto preflight=detail::qualify_posix_private_storage(directory.value(),detail::PosixPrivateStorageKind::Directory,false);
    if(!preflight.value()) return preflight;
    if (fchmod(directory.value(), 0700) != 0)
        return failure<bool>(errno, "journal_file.prepare_root.mode");
    return private_directory(directory.value());
}

Observation<std::unique_ptr<OperationJournalFile>> open_native_operation_journal_file(
    const NativeAbsolutePath& private_root, const NativeName& basename, bool create_new) {
    using Pointer = std::unique_ptr<OperationJournalFile>;
    if (!basename.is_valid() || !basename.posix_bytes())
        return rejected<Pointer>(AdapterError::InvalidIdentifier, "journal_file.basename");
    auto host = private_root.host_path();
    if (!host.value()) {
        const auto& detail = *host.unavailable_detail();
        return Observation<Pointer>::unavailable(detail.state, detail.error);
    }
    const auto& root = *host.value();
    if (root.native().empty() || root.filename() == "." || root.filename() == "..")
        return rejected<Pointer>(AdapterError::InvalidPath, "journal_file.root_address");
    Fd directory(open(root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (directory.value() < 0) return failure<Pointer>(errno, "journal_file.open_root");
    auto private_check = private_directory(directory.value());
    if (!private_check.value()) {
        const auto& detail = *private_check.unavailable_detail();
        return Observation<Pointer>::unavailable(detail.state, detail.error);
    }
    int flags = O_RDWR | O_NOFOLLOW | O_CLOEXEC;
    if (create_new) flags |= O_CREAT | O_EXCL;
    Fd file(openat(directory.value(), basename.posix_bytes()->c_str(), flags, 0600));
    if (file.value() < 0) return failure<Pointer>(errno, "journal_file.open");
    auto private_file = private_regular(file.value(), create_new);
    if (!private_file.value()) {
        const auto& detail = *private_file.unavailable_detail();
        return Observation<Pointer>::unavailable(detail.state, detail.error);
    }
    auto final_root=private_directory(directory.value());
    if(!final_root.value()) return Observation<Pointer>::unavailable(final_root.state(),final_root.unavailable_detail()->error);
    // Allocate before relinquishing either native owner, including bad_alloc.
    auto result = std::make_unique<PosixOperationJournalFile>(file.value(),directory.value());
    file.release();directory.release();
    return Observation<Pointer>::available(std::move(result));
}
} // namespace ck::files
