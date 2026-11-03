// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../operation_journal_file.hpp"
#include "../prepared_journal_root.hpp"
#include "../prepared_journal_directory.hpp"
#include "prepared_journal_root_bridge.hpp"
#include "prepared_journal_failure_latch.hpp"
#include "../directory_cursor.hpp"
#include "posix_private_storage.hpp"
#include "native_journal_directory_bridge.hpp"
#include "journal_root_test_faults.hpp"

#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <vector>
#include <utility>
#include <cstring>
#include <array>
#include <dirent.h>
#include <sys/param.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#else
#include <sys/mount.h>
#endif
#include <unistd.h>

namespace ck::files {
namespace {
class Fd final {
public:
    explicit Fd(int value) noexcept : value_(value) {}
    ~Fd() { if (value_ >= 0) ::close(value_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept : value_(other.release()) {}
    Fd& operator=(Fd&& other) noexcept {
        if(this!=&other) { if(value_>=0)::close(value_);value_=other.release(); }
        return *this;
    }
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
    PosixOperationJournalFile(int fd,int directory, std::optional<NativeName> name = {},
        PreparedJournalRoot::Pointer root = {}) noexcept
        : fd_(fd),directory_(directory),name_(std::move(name)),root_(std::move(root)) {}
    ~PosixOperationJournalFile() override {
        if(!finished_) {
            try {(void)finish_io();}catch(...) {
                record_failure(ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.finalizer_exception");
                close_handles();finished_=true;
            }
        }
    }
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
        if(finished_)return finish_result();
        if(finish_started_) {
            record_failure(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.finalizer_incomplete");
            if(!close_operation_) {close_exception_=true;close_error_=static_cast<std::int64_t>(AdapterError::InvalidNativeResult);
                close_operation_="journal_file.finalizer_incomplete";}
            close_handles();finished_=true;return finish_result();
        }
        finish_started_=true;
        auto flushed=flush();
        if(!flushed.value()) {
            const auto& error=*flushed.unavailable_detail();
            record_failure(error.state,error.error.domain,error.error.code,error.error.operation);
            finish_failure_=error;
        } else if(!*flushed.value()) {
            record_failure(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.finish_flush_false");
            finish_failure_=UnavailableObservation{ObservationState::Unknown,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.finish_flush_false"}};
        }
        close_handles();finished_=true;return finish_result();
    }
private:

    void record_failure(ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view operation) noexcept {
        if(root_)detail::record_prepared_journal_consumer_failure(*root_,state,domain,code,operation);
    }
    void remember_close(std::int64_t code,const char* operation) noexcept {
        record_failure(state(static_cast<int>(code)),ErrorDomain::Posix,code,operation);
        if(!close_operation_) {close_error_=code;close_operation_=operation;}
    }
    void observe_close_fault() noexcept {
        try {
            if(const auto fault=detail::journal_root_fault(detail::JournalRootFaultPoint::JournalClose))
                remember_close(*fault,"journal_file.close_fault");
        } catch(...) {
            record_failure(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.close_fault_exception");
            if(!close_operation_) {close_error_=static_cast<std::int64_t>(AdapterError::InvalidNativeResult);
                close_operation_="journal_file.close_fault_exception";close_exception_=true;}
        }
    }
    void close_handles() noexcept {
        const int file=fd_.release();
        if(file>=0) {if(::close(file))remember_close(errno,"journal_file.close");observe_close_fault();}
        const int directory=directory_.release();
        if(directory>=0&&::close(directory))remember_close(errno,"journal_file.parent_close");
    }
    Observation<bool> finish_result() const {
        if(finish_failure_)return Observation<bool>::unavailable(finish_failure_->state,finish_failure_->error);
        if(close_operation_)return close_exception_?Observation<bool>::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter,close_error_,close_operation_}):failure<bool>(static_cast<int>(close_error_),close_operation_);
        return Observation<bool>::available(true);
    }
    Observation<bool> revalidate() {
        if(root_) {auto checked=root_->revalidate();if(!checked.value())return checked;}
        auto root=private_directory(directory_.value());if(!root.value()) return root;
        auto file=private_regular(fd_.value(),false);if(!file.value())return file;
        if(name_) {
            struct stat held{},named{};
            if(fstat(fd_.value(),&held) || fstatat(directory_.value(),name_->posix_bytes()->c_str(),&named,AT_SYMLINK_NOFOLLOW))
                return failure<bool>(errno,"journal_file.membership");
            if(held.st_dev!=named.st_dev || held.st_ino!=named.st_ino || !S_ISREG(named.st_mode))
                return rejected<bool>(AdapterError::MetadataChanged,"journal_file.membership_changed",ObservationState::Changed);
        }
        return Observation<bool>::available(true);
    }
    Fd fd_,directory_;
    std::optional<NativeName> name_;
    PreparedJournalRoot::Pointer root_;
    bool finished_=false,finish_started_=false;
    std::int64_t close_error_=0;const char* close_operation_=nullptr;bool close_exception_=false;
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
    auto result = std::make_unique<PosixOperationJournalFile>(file.value(),directory.value(),basename);
    file.release();directory.release();
    return Observation<Pointer>::available(std::move(result));
}

namespace {
struct JournalDirectory final {
    Fd fd;
    dev_t device;
    ino_t object;
    std::uint64_t mount;
    bool read_only;
};
#ifdef __linux__
// One kernel observation supplies the same held/parent inode, directory,
// live-link and mount facts formerly obtained by separate fstat + statx calls.
// Keep the available path scalar-only: no per-ancestor string or variant is
// constructed. A failed observation is formatted by the caller exactly once.
struct JournalNodeFailure final {
    ObservationState state=ObservationState::Available;
    ErrorDomain domain=ErrorDomain::None;
    std::int64_t code=0;
    const char* operation="";
    Observation<bool> result() const {
        return Observation<bool>::unavailable(state,{domain,code,operation});
    }
};
bool journal_node_matches(int fd,const char* name,int flags,const JournalDirectory& expected,
    bool ancestor,JournalNodeFailure& error) {
    struct statx value{};
    constexpr auto required=STATX_TYPE|STATX_INO|STATX_NLINK|STATX_MNT_ID;
    if(statx(fd,name,flags|AT_NO_AUTOMOUNT,required,&value)) {
        const int code=errno;
        error={state(code),ErrorDomain::Posix,code,ancestor?"journal_root.ancestor_edge":"journal_root.held_identity"};
        return false;
    }
    if((value.stx_mask&required)!=required) {
        error={ObservationState::Unsupported,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::UnsupportedQuery),"journal_root.identity_or_mount_unqualified"};
        return false;
    }
    if(!S_ISDIR(value.stx_mode)||!value.stx_nlink||
        makedev(value.stx_dev_major,value.stx_dev_minor)!=expected.device||value.stx_ino!=expected.object) {
        error={ObservationState::Changed,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::MetadataChanged),
            ancestor?"journal_root.ancestor_changed":"journal_root.held_identity_changed"};
        return false;
    }
    if(value.stx_mnt_id!=expected.mount) {
        error={ObservationState::Changed,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::MetadataChanged),
            ancestor?"journal_root.ancestor_mount_changed":"journal_root.held_mount_changed"};
        return false;
    }
    return true;
}
#endif
Observation<std::uint64_t> journal_mount(int fd,const char* component,int flags) {
#if defined(__linux__) && defined(STATX_MNT_ID)
    struct statx info{};
    if(statx(fd,component,flags|AT_NO_AUTOMOUNT,STATX_MNT_ID,&info))return failure<std::uint64_t>(errno,"journal_root.mount_id");
    if(!(info.stx_mask&STATX_MNT_ID))return rejected<std::uint64_t>(AdapterError::UnsupportedQuery,"journal_root.mount_id_unqualified",ObservationState::Unsupported);
    return Observation<std::uint64_t>::available(info.stx_mnt_id);
#elif defined(__APPLE__)
    (void)fd;(void)component;(void)flags;
    return Observation<std::uint64_t>::available(0); // Darwin uses retained native volume identity, not a Linux mount-ID claim.
#else
    (void)fd;(void)component;(void)flags;
    return rejected<std::uint64_t>(AdapterError::UnsupportedQuery,"journal_root.mount_id_unavailable",ObservationState::Unsupported);
#endif
}
Observation<bool> journal_storage(int fd,bool writable) {
    struct statfs fs{};
    if(fstatfs(fd,&fs))return failure<bool>(errno,"journal_root.filesystem");
#ifdef __APPLE__
    if(!(fs.f_flags&MNT_LOCAL) || (fs.f_flags&MNT_IGNORE_OWNERSHIP) ||
        (std::strcmp(fs.f_fstypename,"apfs") && std::strcmp(fs.f_fstypename,"hfs")))
        return rejected<bool>(AdapterError::UnsupportedQuery,"journal_root.durable_private_filesystem",ObservationState::Unsupported);
    const bool read_only=(fs.f_flags&MNT_RDONLY)!=0;
#else
    if(fs.f_type!=0xef53 && fs.f_type!=0x58465342 && fs.f_type!=0x9123683e)
        return rejected<bool>(AdapterError::UnsupportedQuery,"journal_root.durable_private_filesystem",ObservationState::Unsupported);
    const bool read_only=(fs.f_flags&ST_RDONLY)!=0;
#endif
    if(writable && read_only)return failure<bool>(EROFS,"journal_root.read_only");
    return Observation<bool>::available(true);
}
Observation<JournalDirectory> journal_directory(Fd fd) {
    if(fd.value()<0)return failure<JournalDirectory>(errno,"journal_root.open_ancestor");
    struct stat s{};struct statfs fs{};
    if(fstat(fd.value(),&s) || fstatfs(fd.value(),&fs))return failure<JournalDirectory>(errno,"journal_root.directory_identity");
    if(!S_ISDIR(s.st_mode) || !s.st_nlink)
        return rejected<JournalDirectory>(AdapterError::MetadataChanged,"journal_root.directory_kind",ObservationState::Changed);
#ifdef __APPLE__
    const bool read_only=(fs.f_flags&MNT_RDONLY)!=0;
#else
    const bool read_only=(fs.f_flags&ST_RDONLY)!=0;
#endif
#ifdef __linux__
    auto mount=journal_mount(fd.value(),"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW);
#else
    auto mount=journal_mount(fd.value(),"",0);
#endif
    if(!mount.value())return Observation<JournalDirectory>::unavailable(mount.state(),mount.unavailable_detail()->error);
    return Observation<JournalDirectory>::available({std::move(fd),s.st_dev,s.st_ino,*mount.value(),read_only});
}
Observation<bool> journal_edge(int parent,const NativeName& component,const JournalDirectory& expected) {
    struct stat current{};
    if(fstatat(parent,component.posix_bytes()->c_str(),&current,AT_SYMLINK_NOFOLLOW)) {
        const int code=errno;
        if(code==ENOENT||code==ENOTDIR)return Observation<bool>::unavailable(ObservationState::Changed,
            {ErrorDomain::Posix,code,"journal_root.membership"});
        return failure<bool>(code,"journal_root.membership");
    }
    auto mount=journal_mount(parent,component.posix_bytes()->c_str(),AT_SYMLINK_NOFOLLOW);
    if(!mount.value())return Observation<bool>::unavailable(mount.state(),mount.unavailable_detail()->error);
    if(!S_ISDIR(current.st_mode)||current.st_dev!=expected.device||current.st_ino!=expected.object||*mount.value()!=expected.mount)
        return rejected<bool>(AdapterError::MetadataChanged,"journal_root.membership_changed",ObservationState::Changed);
    return Observation<bool>::available(true);
}
Observation<NativeName> discover_journal_component(int parent,const JournalDirectory& root,std::stop_token stop) {
    using R=Observation<NativeName>;
    // An independent directory stream starts at offset zero. dup alone would
    // share enumeration position with another owner; openat('.') is relative
    // to this held parent and never reopens the root's former address.
    Fd scan(openat(parent,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    if(scan.value()<0)return failure<NativeName>(errno,"journal_root.scan_parent");
    DIR* stream=fdopendir(scan.value());if(!stream)return failure<NativeName>(errno,"journal_root.scan_stream");
    scan.release();
    std::optional<NativeName> found;std::optional<UnavailableObservation> failure_detail;
    for(std::uint32_t step=0;step<1048576;++step) {
        if(stop.stop_requested()) {failure_detail=*rejected<bool>(AdapterError::InterruptedRead,"journal_root.cancelled",ObservationState::Changed).unavailable_detail();break;}
        errno=0;const auto* entry=readdir(stream);const int code=errno;
        if(!entry){if(code)failure_detail=*failure<bool>(code,"journal_root.readdir").unavailable_detail();break;}
        if(!std::strcmp(entry->d_name,".")||!std::strcmp(entry->d_name,".."))continue;
        if(entry->d_type!=DT_DIR&&entry->d_type!=DT_UNKNOWN)continue;
        auto name=NativeName::from_posix(entry->d_name);if(!name)continue;
        auto same=journal_edge(parent,*name,root);
        if(same.value()) {found=std::move(name);break;}
        if(same.state()!=ObservationState::Changed&&same.state()!=ObservationState::Gone) {failure_detail=*same.unavailable_detail();break;}
    }
    const int closed=closedir(stream);const int close_error=errno;
    if(failure_detail)return R::unavailable(failure_detail->state,failure_detail->error);
    if(closed)return failure<NativeName>(close_error,"journal_root.scan_close");
    if(!found)return rejected<NativeName>(AdapterError::UnqualifiedIdentity,"journal_root.membership_unqualified",ObservationState::Unsupported);
    return R::available(std::move(*found));
}
bool flush_journal_directory(const JournalDirectory& node,detail::PreparedJournalFailureLatch& failure) noexcept {
    if(node.read_only)return true;
    auto record=[&](int code,const char* operation){failure.record(state(code),ErrorDomain::Posix,code,operation);};
    if(fsync(node.fd.value())) {record(errno,"journal_root.directory_fsync");return false;}
#ifdef __APPLE__
    if(fcntl(node.fd.value(),F_FULLFSYNC)) {record(errno,"journal_root.directory_fullsync");return false;}
#endif
    try {
        if(const auto fault=detail::journal_root_fault(detail::JournalRootFaultPoint::DirectoryFlush)) {
            record(static_cast<int>(*fault),"journal_root.directory_fsync");return false;
        }
    } catch(...) {
        failure.record(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.flush_fault_exception");return false;
    }
    return true;
}
class PosixPreparedJournalRoot final : public PreparedJournalRoot,
    public std::enable_shared_from_this<PosixPreparedJournalRoot> {
public:
    PosixPreparedJournalRoot(std::vector<JournalDirectory> chain,ObjectIdentity identity,
        std::optional<NativeAbsolutePath> navigation,NativeName component)
        : chain_(std::move(chain)),identity_(std::move(identity)),navigation_(std::move(navigation)),component_(std::move(component)) {}
    ~PosixPreparedJournalRoot() override {if(!finished_)try {(void)finish_io();}catch(...) {}}
    const ObjectIdentity& identity() const noexcept override {return identity_;}
    NameEncoding encoding() const noexcept override {return NameEncoding::PosixBytes;}
    const std::optional<NativeAbsolutePath>& navigation_address() const noexcept override {return navigation_;}
    void record_consumer_failure(ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view operation) noexcept {
        consumer_failure_.record(state,domain,code,operation);
    }
    bool read_consumer_failure(detail::PreparedJournalConsumerFailure& out) const noexcept {return consumer_failure_.read(out);}
    Observation<std::vector<ObjectIdentity>> inspect_ancestry() const {
        using R=Observation<std::vector<ObjectIdentity>>;std::lock_guard lock(mutex_);
        auto checked=check();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        std::vector<ObjectIdentity> ids;ids.reserve(chain_.size());
        for(const auto& node:chain_) {
            struct stat value{};
            if(fstat(node.fd.value(),&value))return failure<std::vector<ObjectIdentity>>(errno,"journal_root.ancestry_identity");
            std::optional<std::uint64_t> generation;
#ifdef __APPLE__
            generation=static_cast<std::uint64_t>(value.st_gen);
#endif
            ids.push_back({identity_.scope,IdentityScheme::PosixDeviceInode,
                NativeIdentifier::from_u64(value.st_dev),NativeIdentifier::from_u64(value.st_ino),generation});
        }
        checked=check();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        return R::available(std::move(ids));
    }
    Observation<bool> revalidate() const override {std::lock_guard lock(mutex_);return check();}
    Observation<int> duplicate_native_directory() const {
        std::lock_guard lock(mutex_);auto checked=check();
        if(!checked.value())return Observation<int>::unavailable(checked.state(),checked.unavailable_detail()->error);
        const int fd=fcntl(chain_.front().fd.value(),F_DUPFD_CLOEXEC,0);
        if(fd<0)return failure<int>(errno,"journal_root.duplicate_directory");
        return Observation<int>::available(fd);
    }

    Observation<std::unique_ptr<OperationJournalFile>> open_journal(const NativeName& name,bool create) override {
        using R=Observation<std::unique_ptr<OperationJournalFile>>;
        if(!name.is_valid() || !name.posix_bytes())
            return rejected<std::unique_ptr<OperationJournalFile>>(AdapterError::InvalidIdentifier,"journal_root.basename");
        std::lock_guard lock(mutex_);
        auto checked=check();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        Fd directory(fcntl(chain_.front().fd.value(),F_DUPFD_CLOEXEC,0));
        if(directory.value()<0)return failure<std::unique_ptr<OperationJournalFile>>(errno,"journal_root.duplicate_root");
        int flags=O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK;
        if(create)flags|=O_CREAT|O_EXCL;
        Fd file(openat(directory.value(),name.posix_bytes()->c_str(),flags,0600));
        if(file.value()<0)return failure<std::unique_ptr<OperationJournalFile>>(errno,"journal_root.openat");
        checked=private_regular(file.value(),create);
        if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        checked=check();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        auto result=std::make_unique<PosixOperationJournalFile>(file.value(),directory.value(),name,shared_from_this());
        file.release();directory.release();
        return R::available(std::move(result));
    }
    Observation<bool> sync() override {
        JournalRootPreparationProgress progress;
        return flush_prepared(progress,{},{});
    }
    Observation<bool> flush_prepared(JournalRootPreparationProgress& progress,std::stop_token stop,
        const std::function<void(const JournalRootPreparationProgress&)>& observer) {
        std::lock_guard lock(mutex_);
        auto checked=check();if(!checked.value())return checked;
        for(const auto& node:chain_) {
            if(stop.stop_requested())return rejected<bool>(AdapterError::InterruptedRead,"journal_root.cancelled",ObservationState::Changed);
            if(!flush_journal_directory(node,consumer_failure_))return consumer_failure_.result();
            if(!node.read_only)++progress.flushed_directories;
            if(observer)observer(progress);
        }
        return check();
    }
    Observation<bool> finish_io() override {
        std::lock_guard lock(mutex_);if(finished_)return consumer_failure_.result();
        if(weak_from_this().use_count()>1)return rejected<bool>(AdapterError::InvalidAccess,"journal_root.consumers_active",ObservationState::Changed);
        bool qualified=false;
        try {
            auto checked=check(false);qualified=checked.value()&&*checked.value();
            if(!checked.value()) {const auto& e=*checked.unavailable_detail();consumer_failure_.record(e.state,e.error.domain,e.error.code,e.error.operation);}
            else if(!qualified)consumer_failure_.record(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.check_false");
        } catch(...) {
            consumer_failure_.record(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.finalizer_exception");
        }
        if(qualified)for(const auto& node:chain_)(void)flush_journal_directory(node,consumer_failure_);
        for(auto& node:chain_) {
            const int fd=node.fd.release();if(fd<0)continue;
            if(::close(fd)) {const int code=errno;consumer_failure_.record(state(code),ErrorDomain::Posix,code,"journal_root.directory_close");}
            try {
                if(const auto fault=detail::journal_root_fault(detail::JournalRootFaultPoint::DirectoryClose))
                    consumer_failure_.record(state(static_cast<int>(*fault)),ErrorDomain::Posix,*fault,"journal_root.directory_close");
            } catch(...) {
                consumer_failure_.record(ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.close_fault_exception");
            }
        }
        finished_=true;return consumer_failure_.result();
    }
private:
    Observation<bool> check(bool include_consumer=true) const {
        if(finished_ || chain_.empty())return rejected<bool>(AdapterError::InvalidAccess,"journal_root.finished",ObservationState::Changed);
        if(include_consumer) {auto failure=consumer_failure_.result();if(!failure.value())return failure;}
        auto privacy=private_directory(chain_.front().fd.value());if(!privacy.value())return privacy;
        if(chain_.size()<2)return rejected<bool>(AdapterError::UnqualifiedIdentity,"journal_root.membership_unqualified",ObservationState::Unsupported);
        auto edge=journal_edge(chain_[1].fd.value(),component_,chain_.front());if(!edge.value())return edge;
        for(std::size_t i=0;i<chain_.size();++i) {
#ifdef __linux__
            JournalNodeFailure failure;
            if(!journal_node_matches(chain_[i].fd.value(),"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,chain_[i],false,failure))
                return failure.result();
            if(i+1<chain_.size()&&!journal_node_matches(chain_[i].fd.value(),"..",AT_SYMLINK_NOFOLLOW,chain_[i+1],true,failure))
                return failure.result();
#else
            struct stat s{};
            if(fstat(chain_[i].fd.value(),&s))return failure<bool>(errno,"journal_root.held_identity");
            if(!S_ISDIR(s.st_mode) || !s.st_nlink || s.st_dev!=chain_[i].device || s.st_ino!=chain_[i].object)
                return rejected<bool>(AdapterError::MetadataChanged,"journal_root.held_identity_changed",ObservationState::Changed);
            if(i+1<chain_.size()) {
                if(fstatat(chain_[i].fd.value(),"..",&s,AT_SYMLINK_NOFOLLOW))return failure<bool>(errno,"journal_root.ancestor_edge");
                if(s.st_dev!=chain_[i+1].device || s.st_ino!=chain_[i+1].object)
                    return rejected<bool>(AdapterError::MetadataChanged,"journal_root.ancestor_changed",ObservationState::Changed);
                auto mount=journal_mount(chain_[i].fd.value(),"..",AT_SYMLINK_NOFOLLOW);
                if(!mount.value())return Observation<bool>::unavailable(mount.state(),mount.unavailable_detail()->error);
                if(*mount.value()!=chain_[i+1].mount)return rejected<bool>(AdapterError::MetadataChanged,"journal_root.ancestor_mount_changed",ObservationState::Changed);
            }
#endif
        }
        return Observation<bool>::available(true);
    }
    mutable std::mutex mutex_;
    std::vector<JournalDirectory> chain_;
    ObjectIdentity identity_;
    std::optional<NativeAbsolutePath> navigation_;
    NativeName component_;
    bool finished_=false;
    detail::PreparedJournalFailureLatch consumer_failure_;
};
class PosixPreparedJournalDirectory final : public PreparedJournalDirectory {
public:
    PosixPreparedJournalDirectory(DIR* directory,PreparedJournalRoot::Pointer root)
        :PreparedJournalDirectory(root->identity()),directory_(directory),root_(std::move(root)){}
    ~PosixPreparedJournalDirectory() override {try {(void)finish_io();}catch(...) {}}
    Observation<AdapterScope> source_scope() const override {
        return root_?Observation<AdapterScope>::available(root_->identity().scope):
            rejected<AdapterScope>(AdapterError::InvalidAccess,"journal_root.enumeration_finished",ObservationState::Changed);
    }
    Observation<bool> finish_io() override {
        if(directory_) {
            DIR* directory=std::exchange(directory_,nullptr);
            if(closedir(directory))close_error_=errno;
            if(close_error_)detail::record_prepared_journal_consumer_failure(*root_,
                state(close_error_),ErrorDomain::Posix,close_error_,"journal_root.enumeration_close");
            try {
                const auto fault=detail::journal_root_fault(detail::JournalRootFaultPoint::DirectoryClose);
                if(!close_error_&&fault)close_error_=static_cast<int>(*fault);
            } catch(...) {
                detail::record_prepared_journal_consumer_failure(*root_,ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.enumeration_close_exception");
                if(!close_error_)close_exception_=true;
            }
            if(close_error_)detail::record_prepared_journal_consumer_failure(*root_,
                state(close_error_),ErrorDomain::Posix,close_error_,"journal_root.enumeration_close");
            root_.reset();
        }
        if(close_exception_)return Observation<bool>::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.enumeration_close_exception"});
        return close_error_?failure<bool>(close_error_,"journal_root.enumeration_close"):Observation<bool>::available(true);
    }
private:
    Observation<DirectoryStep> next_step() override {
        using R=Observation<DirectoryStep>;
        if(!directory_||!root_)return rejected<DirectoryStep>(AdapterError::InvalidAccess,"journal_root.enumeration_finished",ObservationState::Changed);
        auto checked=root_->revalidate();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        errno=0;const auto* entry=readdir(directory_);const int code=errno;
        checked=root_->revalidate();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        if(!entry) return code?failure<DirectoryStep>(code,"journal_root.readdir"):R::available(DirectoryEnd{});
        if(!std::strcmp(entry->d_name,".")||!std::strcmp(entry->d_name,".."))return R::available(DirectorySkip{});
        auto name=NativeName::from_posix(entry->d_name);
        if(!name)return rejected<DirectoryStep>(AdapterError::InvalidNativeResult,"journal_root.readdir_name");
        return R::available(std::move(*name));
    }
    DIR* directory_;PreparedJournalRoot::Pointer root_;int close_error_=0;bool close_exception_=false;
};
}
namespace detail {
Observation<std::vector<ObjectIdentity>> inspect_prepared_journal_ancestry(PreparedJournalRoot& root) {
    const auto* native=dynamic_cast<const PosixPreparedJournalRoot*>(&root);
    if(!native)return rejected<std::vector<ObjectIdentity>>(AdapterError::UnqualifiedIdentity,"journal_root.foreign_provider",ObservationState::Unsupported);
    return native->inspect_ancestry();
}
bool record_prepared_journal_consumer_failure(PreparedJournalRoot& root,ObservationState state,
    ErrorDomain domain,std::int64_t code,std::string_view operation) noexcept {
    auto* native=dynamic_cast<PosixPreparedJournalRoot*>(&root);if(!native)return false;
    native->record_consumer_failure(state,domain,code,operation);return true;
}
bool read_prepared_journal_consumer_failure(const PreparedJournalRoot& root,PreparedJournalConsumerFailure& out) noexcept {
    out={};const auto* native=dynamic_cast<const PosixPreparedJournalRoot*>(&root);
    return native&&native->read_consumer_failure(out);
}
Observation<int> duplicate_prepared_journal_directory(PreparedJournalRoot& root) {
    const auto* native=dynamic_cast<const PosixPreparedJournalRoot*>(&root);
    if(!native)return rejected<int>(AdapterError::UnqualifiedIdentity,"journal_root.foreign_provider",ObservationState::Unsupported);
    return native->duplicate_native_directory();
}
}
Observation<std::unique_ptr<PreparedJournalDirectory>> open_prepared_journal_directory(PreparedJournalRoot::Pointer root) {
    using R=Observation<std::unique_ptr<PreparedJournalDirectory>>;
    if(!root)return rejected<std::unique_ptr<PreparedJournalDirectory>>(AdapterError::InvalidAccess,"journal_root.null");
    auto duplicate=detail::duplicate_prepared_journal_directory(*root);
    if(!duplicate.value())return R::unavailable(duplicate.state(),duplicate.unavailable_detail()->error);
    Fd original(std::move(duplicate).take_value());
    // Kernel-resolved self below the held object: independent enumeration
    // position, no original namespace address, procfd or navigation hint.
    Fd directory(openat(original.value(),".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    if(directory.value()<0)return failure<std::unique_ptr<PreparedJournalDirectory>>(errno,"journal_root.enumeration_open");
    const int old=original.release();if(close(old))return failure<std::unique_ptr<PreparedJournalDirectory>>(errno,"journal_root.enumeration_duplicate_close");
    auto checked=root->revalidate();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
    DIR* raw=fdopendir(directory.value());
    if(!raw)return failure<std::unique_ptr<PreparedJournalDirectory>>(errno,"journal_root.fdopendir");
    directory.release();
    const auto close_directory=[owner=root.get()](DIR* value) noexcept {
        if(closedir(value)) {const int code=errno;detail::record_prepared_journal_consumer_failure(
            *owner,state(code),ErrorDomain::Posix,code,"journal_root.enumeration_cleanup_close");}
    };
    std::unique_ptr<DIR,decltype(close_directory)> owned(raw,close_directory);
    auto result=std::make_unique<PosixPreparedJournalDirectory>(raw,std::move(root));owned.release();
    return R::available(std::move(result));
}

Observation<PreparedJournalRoot::Pointer> prepare_native_journal_root(
    PreparedJournalRootRequest request,JournalRootPreparationProgress& progress,std::stop_token stop,
    const std::function<void(const JournalRootPreparationProgress&)>& observer) {
    using R=Observation<PreparedJournalRoot::Pointer>;
    progress={};
    auto notify=[&](JournalRootPreparationPhase phase){progress.phase=phase;if(observer)observer(progress);};
    auto cancelled=[&] {return rejected<PreparedJournalRoot::Pointer>(AdapterError::InterruptedRead,"journal_root.cancelled",ObservationState::Changed);};
    if(!request.parent || request.max_ancestors<1 || request.max_ancestors>4096 ||
        static_cast<unsigned>(request.disposition)>static_cast<unsigned>(JournalRootDisposition::ProvisionChild) ||
        ((request.disposition==JournalRootDisposition::AdoptHeld)!=!request.child) ||
        (request.child && (!request.child->is_valid() || !request.child->posix_bytes())))
        return rejected<PreparedJournalRoot::Pointer>(AdapterError::InvalidIdentifier,"journal_root.request");
    if(stop.stop_requested())return cancelled();
    notify(JournalRootPreparationPhase::Acquiring);
    auto duplicate=detail::duplicate_posix_journal_directory(*request.parent);
    if(!duplicate.value())return R::unavailable(duplicate.state(),duplicate.unavailable_detail()->error);
    Fd parent(std::move(duplicate).take_value());
    struct stat original{};
    if(fstat(parent.value(),&original))return failure<PreparedJournalRoot::Pointer>(errno,"journal_root.parent_identity");
    const auto* identity=request.parent->identity().value();
    if(!identity || identity->scheme!=IdentityScheme::PosixDeviceInode ||
        identity->volume!=NativeIdentifier::from_u64(original.st_dev) || identity->object!=NativeIdentifier::from_u64(original.st_ino))
        return rejected<PreparedJournalRoot::Pointer>(AdapterError::MetadataChanged,"journal_root.parent_changed",ObservationState::Changed);
    auto checked=journal_storage(parent.value(),true);
    if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
    Fd root(-1);
    if(request.child) {
        notify(JournalRootPreparationPhase::Provisioning);
        if(stop.stop_requested())return cancelled();
        if(request.disposition==JournalRootDisposition::ProvisionChild) {
            if(mkdirat(parent.value(),request.child->posix_bytes()->c_str(),0700)==0)++progress.directory_creates;
            else if(errno!=EEXIST)return failure<PreparedJournalRoot::Pointer>(errno,"journal_root.mkdirat");
        }
        root=Fd(openat(parent.value(),request.child->posix_bytes()->c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        if(root.value()<0)return failure<PreparedJournalRoot::Pointer>(errno,"journal_root.openat_root");
    } else root=std::move(parent);
    checked=private_directory(root.value());if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
    checked=journal_storage(root.value(),true);if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
    auto node=journal_directory(std::move(root));if(!node.value())return R::unavailable(node.state(),node.unavailable_detail()->error);
    std::vector<JournalDirectory> chain;chain.reserve(16);chain.push_back(std::move(node).take_value());
    progress.acquired_directories=1;notify(JournalRootPreparationPhase::Ancestry);
    if(request.child) {
        struct stat edge{};
        if(fstatat(chain.front().fd.value(),"..",&edge,AT_SYMLINK_NOFOLLOW))return failure<PreparedJournalRoot::Pointer>(errno,"journal_root.provision_parent");
        if(edge.st_dev!=original.st_dev || edge.st_ino!=original.st_ino)
            return rejected<PreparedJournalRoot::Pointer>(AdapterError::MetadataChanged,"journal_root.provision_parent_changed",ObservationState::Changed);
        auto retained=journal_directory(std::move(parent));if(!retained.value())return R::unavailable(retained.state(),retained.unavailable_detail()->error);
        if(chain.size()>=request.max_ancestors)return rejected<PreparedJournalRoot::Pointer>(AdapterError::InventoryLimit,"journal_root.ancestor_limit",ObservationState::Unsupported);
        chain.push_back(std::move(retained).take_value());++progress.acquired_directories;
        if(chain.front().device!=chain[1].device || chain.front().mount!=chain[1].mount)
            return rejected<PreparedJournalRoot::Pointer>(AdapterError::PlanTopologyUnsafe,"journal_root.child_mount_crossing",ObservationState::Unsupported);
    }
    for(;;) {
        if(stop.stop_requested())return cancelled();
        auto up=journal_directory(Fd(openat(chain.back().fd.value(),"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)));
        if(!up.value())return R::unavailable(up.state(),up.unavailable_detail()->error);
        const auto& next=*up.value();const auto& current=chain.back();
        if(next.device==current.device && next.object==current.object && next.mount==current.mount) {
            auto redundant=std::move(up).take_value();
            const int closed=::close(redundant.fd.release());const int code=errno;
            if(closed)return failure<PreparedJournalRoot::Pointer>(code,"journal_root.ancestor_probe_close");
            break;
        }
        if(chain.size()>=request.max_ancestors)return rejected<PreparedJournalRoot::Pointer>(AdapterError::InventoryLimit,"journal_root.ancestor_limit",ObservationState::Unsupported);
#ifdef __linux__
        // Without a qualified physical-ancestor route for bind/submount roots,
        // a namespace '..' walk cannot prove all durable ancestors were held.
        if(next.mount!=current.mount)return rejected<PreparedJournalRoot::Pointer>(AdapterError::PlanTopologyUnsafe,"journal_root.ancestor_mount_crossing",ObservationState::Unsupported);
#elif defined(__APPLE__)
        // APFS/HFS native volume roots have object ID 2. A firmlink entering
        // below that root would hide physical ancestors and is refused.
        if(next.device!=current.device && current.object!=2)
            return rejected<PreparedJournalRoot::Pointer>(AdapterError::PlanTopologyUnsafe,"journal_root.hidden_volume_ancestors",ObservationState::Unsupported);
#endif
        if(chain.size()==1 && request.child && (next.device!=original.st_dev || next.object!=original.st_ino))
            return rejected<PreparedJournalRoot::Pointer>(AdapterError::MetadataChanged,"journal_root.provision_parent_changed",ObservationState::Changed);
        for(const auto& seen:chain)if(next.device==seen.device && next.object==seen.object && next.mount==seen.mount)
            return rejected<PreparedJournalRoot::Pointer>(AdapterError::PlanTopologyUnsafe,"journal_root.ancestor_cycle",ObservationState::Unsupported);
        chain.push_back(std::move(up).take_value());++progress.acquired_directories;notify(JournalRootPreparationPhase::Ancestry);
    }
    if(chain.size()<2)return rejected<PreparedJournalRoot::Pointer>(AdapterError::UnqualifiedIdentity,"journal_root.membership_unqualified",ObservationState::Unsupported);
    auto component=request.child?Observation<NativeName>::available(*request.child):discover_journal_component(chain[1].fd.value(),chain.front(),stop);
    if(!component.value())return R::unavailable(component.state(),component.unavailable_detail()->error);
    std::optional<std::uint64_t> root_generation;
#ifdef __APPLE__
    struct stat actual_root{};
    if(fstat(chain.front().fd.value(),&actual_root))return failure<PreparedJournalRoot::Pointer>(errno,"journal_root.created_identity");
    if(!S_ISDIR(actual_root.st_mode)||actual_root.st_dev!=chain.front().device||actual_root.st_ino!=chain.front().object)
        return rejected<PreparedJournalRoot::Pointer>(AdapterError::MetadataChanged,"journal_root.created_identity_changed",ObservationState::Changed);
    root_generation=static_cast<std::uint64_t>(actual_root.st_gen);
#endif
    ObjectIdentity root_identity{identity->scope,IdentityScheme::PosixDeviceInode,
        NativeIdentifier::from_u64(chain.front().device),NativeIdentifier::from_u64(chain.front().object),root_generation};
    auto navigation=std::move(request.navigation_hint);
#ifdef __APPLE__
    // Optional evidence only. Failure or path length never affects readiness.
    std::array<char,MAXPATHLEN> path{};
    if(fcntl(chain.front().fd.value(),F_GETPATH,path.data())==0) {
        auto address=NativeAbsolutePath::from_posix(path.data());
        if(address.value())navigation=std::move(address).take_value();
    }
#endif
    auto result=std::make_shared<PosixPreparedJournalRoot>(std::move(chain),std::move(root_identity),std::move(navigation),std::move(component).take_value());
    checked=result->revalidate();if(!checked.value()){result->finish_io();return R::unavailable(checked.state(),checked.unavailable_detail()->error);}
    notify(JournalRootPreparationPhase::Flushing);
    // Every barrier targets a retained directory, root first then ancestors.
    checked=result->flush_prepared(progress,stop,observer);
    if(!checked.value()){result->finish_io();return R::unavailable(checked.state(),checked.unavailable_detail()->error);}
    notify(JournalRootPreparationPhase::Ready);
    return R::available(std::move(result));
}

} // namespace ck::files
