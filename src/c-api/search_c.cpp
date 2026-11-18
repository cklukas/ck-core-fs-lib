// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_search.h"

#include "directory_cursor.hpp"
#include "file_metadata.hpp"
#include "native_filesystem.hpp"
#include "native_name.hpp"
#include "native_path.hpp"
#include "opened_entry.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

using namespace ck::files;

namespace {

std::atomic<std::uint32_t> g_live_search_jobs{0};

struct WorkerSlot final {
    bool held = false;
    bool acquire() noexcept {
        std::uint32_t cur = g_live_search_jobs.load(std::memory_order_relaxed);
        while (cur < CKFES_MAX_JOBS) {
            if (g_live_search_jobs.compare_exchange_weak(
                    cur, cur + 1, std::memory_order_acq_rel, std::memory_order_relaxed)) {
                held = true;
                return true;
            }
        }
        return false;
    }
    ~WorkerSlot() {
        if (held) g_live_search_jobs.fetch_sub(1, std::memory_order_acq_rel);
    }
};

void clear_error(ckfe_error *error) noexcept {
    if (!error) return;
    std::free(error->operation);
    std::memset(error, 0, sizeof(*error));
}

char *copy_text(std::string_view text) noexcept {
    auto *result = static_cast<char *>(std::malloc(text.size() + 1));
    if (!result) return nullptr;
    std::memcpy(result, text.data(), text.size());
    result[text.size()] = '\0';
    return result;
}

void set_error(ckfe_error *out, const UnavailableObservation &detail) noexcept {
    if (!out) return;
    clear_error(out);
    out->state = static_cast<ckfe_observation_state>(detail.state);
    out->domain = static_cast<ckfe_error_domain>(detail.error.domain);
    out->code = detail.error.code;
    out->operation = copy_text(detail.error.operation);
}

void require(bool ok) {
    if (!ok) throw std::invalid_argument("invalid search argument");
}

template <class F>
ckfe_api_status boundary(F &&fn) noexcept {
    try {
        return fn();
    } catch (const std::bad_alloc &) {
        return CKFE_API_OUT_OF_MEMORY;
    } catch (const std::invalid_argument &) {
        return CKFE_API_INVALID_ARGUMENT;
    } catch (...) {
        return CKFE_API_EXCEPTION;
    }
}

uint32_t to_ckfe_kind(ObjectKind kind) noexcept {
    switch (kind) {
    case ObjectKind::RegularFile: return CKFE_OBJECT_REGULAR_FILE;
    case ObjectKind::Directory: return CKFE_OBJECT_DIRECTORY;
    case ObjectKind::SymbolicLink: return CKFE_OBJECT_SYMBOLIC_LINK;
    case ObjectKind::Junction: return CKFE_OBJECT_JUNCTION;
    case ObjectKind::ReparsePoint: return CKFE_OBJECT_REPARSE_POINT;
    default: return CKFE_OBJECT_OTHER;
    }
}

unsigned char ascii_fold(unsigned char c, bool case_sensitive) noexcept {
    if (!case_sensitive && c >= 'A' && c <= 'Z') return static_cast<unsigned char>(c + ('a' - 'A'));
    return c;
}

char16_t utf16_fold(char16_t c, bool case_sensitive) noexcept {
    if (!case_sensitive && c >= u'A' && c <= u'Z') return static_cast<char16_t>(c + (u'a' - u'A'));
    return c;
}

template <class CharT, class FoldFn>
bool match_glob_units(std::basic_string_view<CharT> pat,
                      std::basic_string_view<CharT> str,
                      bool case_sensitive,
                      FoldFn fold) noexcept {
    std::size_t pi = 0, si = 0;
    std::size_t star_pi = std::basic_string_view<CharT>::npos;
    std::size_t star_si = 0;

    while (si < str.size()) {
        if (pi < pat.size() && pat[pi] == CharT('*')) {
            star_pi = pi++;
            star_si = si;
        } else if (pi < pat.size() && pat[pi] == CharT('?')) {
            ++pi;
            ++si;
        } else if (pi < pat.size() && pat[pi] == CharT('[')) {
            std::size_t close = pi + 1;
            bool neg = false;
            if (close < pat.size() && (pat[close] == CharT('!') || pat[close] == CharT('^'))) {
                neg = true;
                ++close;
            }
            if (close < pat.size() && pat[close] == CharT(']')) ++close;
            while (close < pat.size() && pat[close] != CharT(']')) ++close;
            if (close >= pat.size()) {
                if (fold(pat[pi], case_sensitive) == fold(str[si], case_sensitive)) {
                    ++pi;
                    ++si;
                    continue;
                }
            } else {
                const auto sc = fold(str[si], case_sensitive);
                bool matched_class = false;
                std::size_t k = pi + 1 + (neg ? 1 : 0);
                while (k < close) {
                    if (k + 2 < close && pat[k + 1] == CharT('-')) {
                        const auto lo = fold(pat[k], case_sensitive);
                        const auto hi = fold(pat[k + 2], case_sensitive);
                        if (sc >= lo && sc <= hi) matched_class = true;
                        k += 3;
                    } else {
                        if (sc == fold(pat[k], case_sensitive)) matched_class = true;
                        ++k;
                    }
                }
                if (neg) matched_class = !matched_class;
                if (matched_class) {
                    pi = close + 1;
                    ++si;
                    continue;
                }
            }
            if (star_pi != std::basic_string_view<CharT>::npos) {
                pi = star_pi + 1;
                si = ++star_si;
            } else {
                return false;
            }
        } else if (pi < pat.size() &&
                   fold(pat[pi], case_sensitive) == fold(str[si], case_sensitive)) {
            ++pi;
            ++si;
        } else if (star_pi != std::basic_string_view<CharT>::npos) {
            pi = star_pi + 1;
            si = ++star_si;
        } else {
            return false;
        }
    }

    while (pi < pat.size() && pat[pi] == CharT('*')) ++pi;
    return pi == pat.size();
}

template <class CharT, class FoldFn>
bool match_substring_units(std::basic_string_view<CharT> needle,
                           std::basic_string_view<CharT> hay,
                           bool case_sensitive,
                           FoldFn fold) noexcept {
    if (needle.empty()) return true;
    if (needle.size() > hay.size()) return false;
    const std::size_t limit = hay.size() - needle.size();
    for (std::size_t i = 0; i <= limit; ++i) {
        bool ok = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (fold(hay[i + j], case_sensitive) != fold(needle[j], case_sensitive)) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

bool bytes_contain(std::span<const std::byte> hay,
                   std::string_view needle,
                   bool case_sensitive) noexcept {
    if (needle.empty()) return true;
    if (needle.size() > hay.size()) return false;
    const auto n0 = ascii_fold(static_cast<unsigned char>(needle[0]), case_sensitive);
    const std::size_t limit = hay.size() - needle.size();
    for (std::size_t i = 0; i <= limit; ++i) {
        if (ascii_fold(static_cast<unsigned char>(hay[i]), case_sensitive) != n0) continue;
        bool ok = true;
        for (std::size_t j = 1; j < needle.size(); ++j) {
            if (ascii_fold(static_cast<unsigned char>(hay[i + j]), case_sensitive) !=
                ascii_fold(static_cast<unsigned char>(needle[j]), case_sensitive)) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

int compare_ts(const FileTimestamp &lhs, const ckfsp_timestamp &rhs) noexcept {
    if (lhs.seconds() < rhs.seconds) return -1;
    if (lhs.seconds() > rhs.seconds) return 1;
    if (lhs.nanoseconds() < rhs.nanoseconds) return -1;
    if (lhs.nanoseconds() > rhs.nanoseconds) return 1;
    return 0;
}

struct StoredHit final {
    ckfes_hit_v1 meta{};
    std::variant<std::string, std::u16string> rel_path;
};

struct ParsedSearchRequest final {
    std::optional<NativeAbsolutePath> root_path;
    uint32_t name_mode = CKFES_NAME_NONE;
    bool case_sensitive = false;
    bool include_hidden = false;
    bool skip_binary_content = true;
    std::string name_posix;
    std::u16string name_utf16;
    std::string content_bytes;
    bool has_min_size = false;
    bool has_max_size = false;
    uint64_t min_size = 0;
    uint64_t max_size = 0;
    bool has_mod_after = false;
    bool has_mod_before = false;
    ckfsp_timestamp mod_after{};
    ckfsp_timestamp mod_before{};
    uint64_t max_depth = 1024;
    uint64_t max_results = 10000;
    uint64_t max_content_file_bytes = 32ULL * 1024ULL * 1024ULL;
};

struct SearchShared final {
    std::mutex mutex;
    std::stop_source stop;
    ckfes_snapshot_v1 snapshot{};
    std::vector<StoredHit> hits;
    bool worker_drained = false;

    SearchShared() {
        snapshot.version = CKFES_VERSION;
        snapshot.struct_size = sizeof(ckfes_snapshot_v1);
        snapshot.state = CKFES_RUNNING;
        snapshot.sequence = 1;
    }

    void set_failure_locked(const UnavailableObservation &detail) noexcept {
        snapshot.failure_state = static_cast<uint32_t>(detail.state);
        snapshot.failure_domain = static_cast<uint32_t>(detail.error.domain);
        snapshot.failure_code = detail.error.code;
    }
};

std::string utf16_to_utf8_lossy(std::u16string_view units) {
    std::string out;
    out.reserve(units.size());
    for (std::size_t i = 0; i < units.size(); ++i) {
        uint32_t cp = units[i];
        if (cp >= 0xD800u && cp <= 0xDBFFu && i + 1 < units.size()) {
            const uint32_t lo = units[i + 1];
            if (lo >= 0xDC00u && lo <= 0xDFFFu) {
                cp = 0x10000u + (((cp - 0xD800u) << 10u) | (lo - 0xDC00u));
                ++i;
            }
        }
        if (cp < 0x80u) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800u) {
            out.push_back(static_cast<char>(0xC0u | (cp >> 6u)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else if (cp < 0x10000u) {
            out.push_back(static_cast<char>(0xE0u | (cp >> 12u)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 6u) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else {
            out.push_back(static_cast<char>(0xF0u | (cp >> 18u)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 12u) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 6u) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        }
    }
    return out;
}

std::u16string utf8_to_utf16_ascii(std::string_view bytes) {
    std::u16string out;
    out.reserve(bytes.size());
    for (unsigned char b : bytes) out.push_back(static_cast<char16_t>(b));
    return out;
}

bool is_hidden_entry(const NativeName &name, const BasicMetadata &meta) noexcept {
    if (const auto *p = name.posix_bytes()) {
        return !p->empty() && (*p)[0] == '.';
    }
    if (const auto *w = name.windows_units()) {
        if (!w->empty() && (*w)[0] == u'.') return true;
    }
    if (const auto *attr = meta.windows_attributes.value()) {
        if ((*attr & 0x2u) != 0u) return true; /* FILE_ATTRIBUTE_HIDDEN */
    }
    return false;
}

bool matches_name(const ParsedSearchRequest &req, const NativeName &name) {
    if (req.name_mode == CKFES_NAME_NONE) return true;
    if (const auto *p = name.posix_bytes()) {
        const std::string_view sv(*p);
        const std::string_view pat(req.name_posix);
        if (pat.empty()) return true;
        auto fold = [](char c, bool cs) {
            return static_cast<char>(ascii_fold(static_cast<unsigned char>(c), cs));
        };
        return req.name_mode == CKFES_NAME_GLOB
                   ? match_glob_units<char>(pat, sv, req.case_sensitive, fold)
                   : match_substring_units<char>(pat, sv, req.case_sensitive, fold);
    }
    if (const auto *w = name.windows_units()) {
        const std::u16string_view sv(*w);
        const std::u16string_view pat(req.name_utf16);
        if (pat.empty()) return true;
        return req.name_mode == CKFES_NAME_GLOB
                   ? match_glob_units<char16_t>(pat, sv, req.case_sensitive, utf16_fold)
                   : match_substring_units<char16_t>(pat, sv, req.case_sensitive, utf16_fold);
    }
    return false;
}

bool matches_content(const ParsedSearchRequest &req,
                     const OpenedEntry &entry,
                     uint64_t logical_size,
                     std::stop_token stop,
                     bool &denied_or_failed) {
    denied_or_failed = false;
    if (req.content_bytes.empty()) return true;
    if (logical_size < req.content_bytes.size() || logical_size > req.max_content_file_bytes) {
        return false;
    }
    ContentReadLimits limits;
    limits.max_bytes = 64 * 1024;
    const std::size_t overlap = req.content_bytes.size() > 1 ? req.content_bytes.size() - 1 : 0;
    std::vector<std::byte> window;
    window.reserve(overlap + limits.max_bytes);
    uint64_t offset = 0;

    while (!stop.stop_requested()) {
        auto rd = entry.read_content(limits, offset, stop);
        if (!rd.value()) {
            denied_or_failed = true;
            return false;
        }
        const auto &chunk = rd.value()->bytes;
        if (chunk.empty()) break;

        if (req.skip_binary_content) {
            const std::size_t check_n = offset == 0 ? std::min<std::size_t>(chunk.size(), 8192) : chunk.size();
            for (std::size_t i = 0; i < check_n; ++i) {
                if (chunk[i] == std::byte{0}) return false;
            }
        }

        const std::size_t prev_keep = std::min(window.size(), overlap);
        if (prev_keep < window.size()) {
            std::memmove(window.data(), window.data() + (window.size() - prev_keep), prev_keep);
        }
        window.resize(prev_keep);
        window.insert(window.end(), chunk.begin(), chunk.end());

        if (bytes_contain(window, req.content_bytes, req.case_sensitive)) {
            return true;
        }

        offset += chunk.size();
        if (rd.value()->complete || offset > req.max_content_file_bytes) break;
    }
    return false;
}

struct WalkFrame final {
    std::unique_ptr<DirectoryCursor> cursor;
    std::optional<ObjectIdentity> identity;
    std::string rel_posix;
    std::u16string rel_utf16;
    uint64_t depth = 1;
    std::vector<NativeName> batch;
    std::size_t batch_idx = 0;
    bool eof = false;
};

void search_worker_body(std::shared_ptr<SearchShared> shared, ParsedSearchRequest req) noexcept {
    try {
        std::stop_token stop = shared->stop.get_token();
        auto host_root = req.root_path->host_path();
        if (!host_root.value()) {
            std::lock_guard lock(shared->mutex);
            shared->set_failure_locked(*host_root.unavailable_detail());
            shared->snapshot.state = CKFES_FAILED;
            ++shared->snapshot.sequence;
            return;
        }
        NativeFileSystem fs;
        auto root_obs = fs.open_directory(*host_root.value(), DirectoryLinkPolicy::FollowFinalLink);
        if (!root_obs.value()) {
            std::lock_guard lock(shared->mutex);
            shared->set_failure_locked(*root_obs.unavailable_detail());
            shared->snapshot.state = CKFES_FAILED;
            ++shared->snapshot.sequence;
            return;
        }

        auto root_cursor = std::move(root_obs).take_value();
        std::optional<ObjectIdentity> root_id;
        if (root_cursor->identity().value()) root_id = *root_cursor->identity().value();

        const bool is_utf16 = req.root_path->encoding() == NameEncoding::WindowsUtf16;
        const bool require_regular = !req.content_bytes.empty() || req.has_min_size || req.has_max_size;
        const EntryAccess child_access =
            req.content_bytes.empty() ? EntryAccess::MetadataOnly : EntryAccess::ContentRead;

        std::vector<WalkFrame> stack;
        stack.reserve(16);
        WalkFrame root_frame;
        root_frame.cursor = std::move(root_cursor);
        root_frame.identity = root_id;
        root_frame.depth = 1;
        stack.push_back(std::move(root_frame));

        {
            std::lock_guard lock(shared->mutex);
            shared->snapshot.scanned_directories = 1;
            ++shared->snapshot.sequence;
        }

        while (!stack.empty()) {
            if (stop.stop_requested()) {
                std::lock_guard lock(shared->mutex);
                shared->snapshot.state = CKFES_CANCELLED;
                ++shared->snapshot.sequence;
                return;
            }

            auto &frame = stack.back();
            if (frame.batch_idx >= frame.batch.size()) {
                if (frame.eof) {
                    stack.pop_back();
                    continue;
                }
                auto rd = frame.cursor->read(256, stop);
                if (rd.state == DirectoryReadState::Cancelled || stop.stop_requested()) {
                    std::lock_guard lock(shared->mutex);
                    shared->snapshot.state = CKFES_CANCELLED;
                    ++shared->snapshot.sequence;
                    return;
                }
                if (rd.state == DirectoryReadState::Error) {
                    {
                        std::lock_guard lock(shared->mutex);
                        ++shared->snapshot.denied_entries;
                        ++shared->snapshot.sequence;
                    }
                    stack.pop_back();
                    continue;
                }
                frame.eof = (rd.state == DirectoryReadState::End);
                frame.batch = std::move(rd.names);
                frame.batch_idx = 0;
                if (frame.batch.empty()) {
                    if (frame.eof) stack.pop_back();
                    continue;
                }
            }

            NativeName child_name = std::move(frame.batch[frame.batch_idx++]);
            auto opened = frame.cursor->open_child(child_name, EntryAccess::MetadataOnly);
            if (!opened.value()) {
                std::lock_guard lock(shared->mutex);
                ++shared->snapshot.denied_entries;
                ++shared->snapshot.sequence;
                continue;
            }

            auto basic = (*opened.value())->inspect_basic();
            if (!basic.value() || !basic.value()->kind.value()) {
                std::lock_guard lock(shared->mutex);
                ++shared->snapshot.denied_entries;
                ++shared->snapshot.sequence;
                continue;
            }

            const BasicMetadata &meta = *basic.value();
            const ObjectKind kind = *meta.kind.value();

            if (!req.include_hidden && is_hidden_entry(child_name, meta)) {
                continue;
            }

            {
                std::lock_guard lock(shared->mutex);
                ++shared->snapshot.scanned_entries;
                if ((shared->snapshot.scanned_entries & 63u) == 0u) ++shared->snapshot.sequence;
            }

            const bool is_link = (kind == ObjectKind::SymbolicLink ||
                                  kind == ObjectKind::Junction ||
                                  kind == ObjectKind::ReparsePoint);
            const bool is_dir = (kind == ObjectKind::Directory && !is_link);
            const bool is_reg = (kind == ObjectKind::RegularFile);

            bool candidate = true;
            if (require_regular && !is_reg) candidate = false;
            if (candidate && !matches_name(req, child_name)) candidate = false;

            uint64_t lsize = 0;
            if (is_reg && meta.logical_size.value()) {
                lsize = *meta.logical_size.value();
            }
            if (candidate && req.has_min_size && (!is_reg || !meta.logical_size.value() || lsize < req.min_size)) {
                candidate = false;
            }
            if (candidate && req.has_max_size && (!is_reg || !meta.logical_size.value() || lsize > req.max_size)) {
                candidate = false;
            }
            if (candidate && req.has_mod_after) {
                if (!meta.modified.value() || compare_ts(*meta.modified.value(), req.mod_after) < 0) {
                    candidate = false;
                }
            }
            if (candidate && req.has_mod_before) {
                if (!meta.modified.value() || compare_ts(*meta.modified.value(), req.mod_before) >= 0) {
                    candidate = false;
                }
            }
            if (candidate && !req.content_bytes.empty()) {
                auto content_entry = frame.cursor->open_child(child_name, child_access);
                if (!content_entry.value()) {
                    std::lock_guard lock(shared->mutex);
                    ++shared->snapshot.denied_entries;
                    ++shared->snapshot.sequence;
                    candidate = false;
                } else {
                    bool io_denied = false;
                    candidate = matches_content(req, **content_entry.value(), lsize, stop, io_denied);
                    if (io_denied) {
                        std::lock_guard lock(shared->mutex);
                        ++shared->snapshot.denied_entries;
                        ++shared->snapshot.sequence;
                    }
                }
            }

            std::string child_rel_posix;
            std::u16string child_rel_utf16;
            if (!is_utf16) {
                const auto *pb = child_name.posix_bytes();
                if (pb) {
                    child_rel_posix = frame.rel_posix.empty() ? *pb : (frame.rel_posix + "/" + *pb);
                }
            } else {
                const auto *wu = child_name.windows_units();
                if (wu) {
                    child_rel_utf16 = frame.rel_utf16.empty() ? *wu : (frame.rel_utf16 + u"\\" + *wu);
                }
            }

            if (candidate) {
                StoredHit hit;
                hit.meta.kind = to_ckfe_kind(kind);
                hit.meta.logical_size = lsize;
                if (meta.modified.value()) {
                    hit.meta.has_modified = 1;
                    hit.meta.modified.seconds = meta.modified.value()->seconds();
                    hit.meta.modified.nanoseconds = meta.modified.value()->nanoseconds();
                }
                if (!is_utf16) {
                    hit.meta.encoding = CKFES_POSIX_BYTES;
                    hit.meta.relative_units = child_rel_posix.size();
                    hit.rel_path = child_rel_posix;
                } else {
                    hit.meta.encoding = CKFES_UTF16;
                    hit.meta.relative_units = child_rel_utf16.size();
                    hit.rel_path = child_rel_utf16;
                }

                bool reached_cap = false;
                {
                    std::lock_guard lock(shared->mutex);
                    hit.meta.hit_index = shared->hits.size();
                    shared->hits.push_back(std::move(hit));
                    shared->snapshot.matched_entries = shared->hits.size();
                    ++shared->snapshot.sequence;
                    if (shared->hits.size() >= req.max_results) {
                        shared->snapshot.truncated = 1;
                        shared->snapshot.state = CKFES_COMPLETE;
                        reached_cap = true;
                    }
                }
                if (reached_cap) return;
            }

            if (is_dir && frame.depth < req.max_depth) {
                bool cycle = false;
                if (meta.identity.value()) {
                    for (const auto &anc : stack) {
                        if (anc.identity &&
                            compare_identity(*anc.identity, *meta.identity.value()) == IdentityComparison::Same) {
                            cycle = true;
                            break;
                        }
                    }
                }
                if (!cycle) {
                    auto sub = frame.cursor->open_directory_child(child_name);
                    if (!sub.value()) {
                        std::lock_guard lock(shared->mutex);
                        ++shared->snapshot.denied_entries;
                        ++shared->snapshot.sequence;
                    } else {
                        WalkFrame sub_frame;
                        sub_frame.cursor = std::move(sub).take_value();
                        if (meta.identity.value()) sub_frame.identity = *meta.identity.value();
                        sub_frame.rel_posix = std::move(child_rel_posix);
                        sub_frame.rel_utf16 = std::move(child_rel_utf16);
                        sub_frame.depth = frame.depth + 1;
                        stack.push_back(std::move(sub_frame));
                        std::lock_guard lock(shared->mutex);
                        ++shared->snapshot.scanned_directories;
                        ++shared->snapshot.sequence;
                    }
                }
            }
        }

        std::lock_guard lock(shared->mutex);
        shared->snapshot.state = stop.stop_requested() ? CKFES_CANCELLED : CKFES_COMPLETE;
        ++shared->snapshot.sequence;
    } catch (...) {
        std::lock_guard lock(shared->mutex);
        shared->snapshot.state = CKFES_FAILED;
        shared->snapshot.failure_state = CKFE_OBSERVATION_FAILED;
        shared->snapshot.failure_domain = CKFE_ERROR_ADAPTER;
        shared->snapshot.failure_code = CKFE_ADAPTER_INVALID_NATIVE_RESULT;
        ++shared->snapshot.sequence;
    }
}

void search_worker_entry(std::shared_ptr<SearchShared> shared,
                         std::optional<ParsedSearchRequest> req,
                         std::unique_ptr<WorkerSlot> slot) noexcept {
    search_worker_body(shared, std::move(*req));
    req.reset();
    slot.reset();
    std::lock_guard lock(shared->mutex);
    shared->worker_drained = true;
}

ParsedSearchRequest parse_options(const ckfes_options_v1 *o, ckfe_error *err) {
    require(o && o->version == CKFES_VERSION && o->struct_size == sizeof(*o));
    for (uint64_t r : o->reserved) require(r == 0);
    require(o->name_mode <= CKFES_NAME_GLOB && o->case_sensitive <= 1 &&
            o->include_hidden <= 1 && o->skip_binary_content <= 1 &&
            o->has_minimum_size <= 1 && o->has_maximum_size <= 1 &&
            o->has_modified_not_before <= 1 && o->has_modified_before <= 1);
    require(!o->root_path.reserved && !o->name_query.reserved && !o->content_query.reserved);
    require(o->root_path.encoding <= CKFES_UTF16 &&
            o->name_query.encoding <= CKFES_UTF16 &&
            o->content_query.encoding <= CKFES_UTF16);
    require(o->root_path.data && o->root_path.units > 0 && o->root_path.units <= 262144);
    require((o->name_query.units == 0 && o->name_query.data == nullptr) ||
            (o->name_query.data != nullptr && o->name_query.units > 0 && o->name_query.units <= 65536));
    require((o->content_query.units == 0 && o->content_query.data == nullptr) ||
            (o->content_query.data != nullptr && o->content_query.units > 0 && o->content_query.units <= 65536));
    require(o->max_depth >= 1 && o->max_depth <= CKFES_HARD_MAX_DEPTH);
    require(o->max_results >= 1 && o->max_results <= CKFES_HARD_MAX_RESULTS);
    require(o->max_content_file_bytes >= 1);
    if (o->has_minimum_size && o->has_maximum_size) {
        require(o->minimum_size <= o->maximum_size);
    }
    if (o->has_modified_not_before) {
        require(o->modified_not_before.nanoseconds < 1000000000u && o->modified_not_before.reserved == 0);
    }
    if (o->has_modified_before) {
        require(o->modified_before.nanoseconds < 1000000000u && o->modified_before.reserved == 0);
    }
    if (o->has_modified_not_before && o->has_modified_before) {
        require(o->modified_not_before.seconds < o->modified_before.seconds ||
                (o->modified_not_before.seconds == o->modified_before.seconds &&
                 o->modified_not_before.nanoseconds < o->modified_before.nanoseconds));
    }

    std::optional<Observation<NativeAbsolutePath>> addr_obs;
    if (o->root_path.encoding == CKFES_POSIX_BYTES) {
        std::string bytes(static_cast<const char *>(o->root_path.data),
                          static_cast<std::size_t>(o->root_path.units));
        addr_obs.emplace(NativeAbsolutePath::from_posix(bytes));
    } else {
        std::u16string units(static_cast<std::size_t>(o->root_path.units), u'\0');
        std::memcpy(units.data(), o->root_path.data,
                    static_cast<std::size_t>(o->root_path.units) * sizeof(char16_t));
        addr_obs.emplace(NativeAbsolutePath::from_windows(units));
    }
    if (!addr_obs->value()) {
        if (addr_obs->unavailable_detail()) set_error(err, *addr_obs->unavailable_detail());
        throw std::invalid_argument("invalid search root path");
    }

    ParsedSearchRequest req;
    req.root_path = std::move(*addr_obs).take_value();
    req.name_mode = o->name_mode;
    req.case_sensitive = (o->case_sensitive != 0);
    req.include_hidden = (o->include_hidden != 0);
    req.skip_binary_content = (o->skip_binary_content != 0);
    req.has_min_size = (o->has_minimum_size != 0);
    req.has_max_size = (o->has_maximum_size != 0);
    req.min_size = o->minimum_size;
    req.max_size = o->maximum_size;
    req.has_mod_after = (o->has_modified_not_before != 0);
    req.has_mod_before = (o->has_modified_before != 0);
    req.mod_after = o->modified_not_before;
    req.mod_before = o->modified_before;
    req.max_depth = o->max_depth;
    req.max_results = o->max_results;
    req.max_content_file_bytes = o->max_content_file_bytes;

    if (o->name_query.units > 0 && o->name_mode != CKFES_NAME_NONE) {
        if (o->name_query.encoding == CKFES_POSIX_BYTES) {
            req.name_posix.assign(static_cast<const char *>(o->name_query.data),
                                  static_cast<std::size_t>(o->name_query.units));
            req.name_utf16 = utf8_to_utf16_ascii(req.name_posix);
        } else {
            req.name_utf16.resize(static_cast<std::size_t>(o->name_query.units));
            std::memcpy(req.name_utf16.data(), o->name_query.data,
                        static_cast<std::size_t>(o->name_query.units) * sizeof(char16_t));
            req.name_posix = utf16_to_utf8_lossy(req.name_utf16);
        }
    }

    if (o->content_query.units > 0) {
        if (o->content_query.encoding == CKFES_POSIX_BYTES) {
            req.content_bytes.assign(static_cast<const char *>(o->content_query.data),
                                     static_cast<std::size_t>(o->content_query.units));
        } else {
            std::u16string u16(static_cast<std::size_t>(o->content_query.units), u'\0');
            std::memcpy(u16.data(), o->content_query.data,
                        static_cast<std::size_t>(o->content_query.units) * sizeof(char16_t));
            req.content_bytes = utf16_to_utf8_lossy(u16);
        }
    }

    return req;
}

} // namespace

struct ckfes_job {
    std::shared_ptr<SearchShared> state;
};

extern "C" {

void ckfes_options_init_v1(ckfes_options_v1 *options) {
    if (!options) return;
    *options = {};
    options->version = CKFES_VERSION;
    options->struct_size = sizeof(*options);
    options->name_mode = CKFES_NAME_NONE;
    options->case_sensitive = 0;
    options->include_hidden = 0;
    options->skip_binary_content = 1;
    options->max_depth = 1024;
    options->max_results = 10000;
    options->max_content_file_bytes = 32ULL * 1024ULL * 1024ULL;
}

ckfe_api_status ckfes_start_v1(const ckfes_options_v1 *options,
                               ckfes_job **out_job,
                               ckfe_error *error) {
    if (out_job) *out_job = nullptr;
    clear_error(error);
    return boundary([&] {
        require(out_job != nullptr);
        ParsedSearchRequest req = parse_options(options, error);
        auto slot = std::make_unique<WorkerSlot>();
        if (!slot->acquire()) return CKFE_API_BUSY;
        auto job = std::make_unique<ckfes_job>();
        job->state = std::make_shared<SearchShared>();
        std::thread t(search_worker_entry, job->state, std::move(req), std::move(slot));
        try {
            t.detach();
        } catch (...) {
            job->state->stop.request_stop();
            t.join();
            throw;
        }
        *out_job = job.release();
        return CKFE_API_OK;
    });
}

ckfe_api_status ckfes_poll_v1(const ckfes_job *job, ckfes_snapshot_v1 *out_snapshot) {
    if (out_snapshot) *out_snapshot = {};
    return boundary([&] {
        require(job && job->state && out_snapshot);
        std::lock_guard lock(job->state->mutex);
        *out_snapshot = job->state->snapshot;
        return CKFE_API_OK;
    });
}

ckfe_api_status ckfes_worker_drained_v1(const ckfes_job *job, uint32_t *out_drained) {
    if (out_drained) *out_drained = 0;
    return boundary([&] {
        require(job && job->state && out_drained);
        std::lock_guard lock(job->state->mutex);
        *out_drained = job->state->worker_drained ? 1u : 0u;
        return CKFE_API_OK;
    });
}

ckfe_api_status ckfes_page_v1_get(const ckfes_job *job,
                                  uint64_t offset,
                                  ckfes_hit_v1 *out_hits,
                                  uint32_t capacity,
                                  uint32_t *out_count) {
    if (out_count) *out_count = 0;
    if (out_hits && capacity > 0) std::memset(out_hits, 0, sizeof(*out_hits) * capacity);
    return boundary([&] {
        require(job && job->state && out_count);
        require(capacity == 0 || out_hits != nullptr);
        std::lock_guard lock(job->state->mutex);
        const std::size_t total = job->state->hits.size();
        if (offset >= total || capacity == 0) {
            *out_count = 0;
            return CKFE_API_OK;
        }
        const std::size_t avail = std::min<std::size_t>(total - static_cast<std::size_t>(offset), capacity);
        for (std::size_t i = 0; i < avail; ++i) {
            out_hits[i] = job->state->hits[static_cast<std::size_t>(offset) + i].meta;
        }
        *out_count = static_cast<uint32_t>(avail);
        return CKFE_API_OK;
    });
}

ckfe_api_status ckfes_path_copy_v1(const ckfes_job *job,
                                   uint64_t hit_index,
                                   void *buffer,
                                   uint64_t capacity_units,
                                   uint64_t *out_required_units,
                                   uint32_t *out_encoding) {
    if (out_required_units) *out_required_units = 0;
    if (out_encoding) *out_encoding = 0;
    return boundary([&] {
        require(job && job->state && out_required_units && out_encoding);
        require(capacity_units == 0 || buffer != nullptr);
        std::lock_guard lock(job->state->mutex);
        require(hit_index < job->state->hits.size());
        const auto &hit = job->state->hits[static_cast<std::size_t>(hit_index)];
        *out_required_units = hit.meta.relative_units;
        *out_encoding = hit.meta.encoding;
        if (capacity_units < hit.meta.relative_units) {
            return CKFE_API_BUFFER_TOO_SMALL;
        }
        if (const auto *pb = std::get_if<std::string>(&hit.rel_path)) {
            if (!pb->empty()) std::memcpy(buffer, pb->data(), pb->size());
        } else if (const auto *wu = std::get_if<std::u16string>(&hit.rel_path)) {
            if (!wu->empty()) std::memcpy(buffer, wu->data(), wu->size() * sizeof(char16_t));
        }
        return CKFE_API_OK;
    });
}

void ckfes_request_cancel(ckfes_job *job) {
    if (job && job->state) {
        job->state->stop.request_stop();
    }
}

void ckfes_release(ckfes_job *job) {
    if (!job) return;
    if (job->state) {
        job->state->stop.request_stop();
    }
    delete job;
}

} // extern "C"
