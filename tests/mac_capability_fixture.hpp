// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#if defined(__APPLE__)
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <sys/stat.h>
namespace mac_capability_fixture {
// Observation only. Enumeration/read atime is deliberately not a preservation
// claim on Darwin. Names, identities, modes, flags, mtime/ctime and bytes are exact.
struct Entry {
    std::uint64_t device, inode, links;
    std::uint32_t mode, uid, gid, flags;
    std::int64_t modified, changed, born;
    long modified_ns, changed_ns, born_ns;
    std::string bytes;
    friend bool operator==(const Entry&,const Entry&)=default;
};
using Tree=std::map<std::string,Entry>;
inline Tree observe(const std::filesystem::path& root,bool contents=true) {
    Tree result;
    auto add=[&](const std::filesystem::path& p) {
        struct stat s{};
        if(lstat(p.c_str(),&s)!=0)throw std::runtime_error("Mac fixture stat failed");
        std::string bytes;
        if(contents&&S_ISREG(s.st_mode)){
            std::ifstream file(p,std::ios::binary);
            if(!file)throw std::runtime_error("Mac fixture read failed");
            bytes.assign(std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>());
            if(file.bad())throw std::runtime_error("Mac fixture read incomplete");
        }
        result.emplace(p==root?".":p.lexically_relative(root).native(),Entry{
            std::uint64_t(s.st_dev),std::uint64_t(s.st_ino),std::uint64_t(s.st_nlink),
            std::uint32_t(s.st_mode),s.st_uid,s.st_gid,s.st_flags,
            s.st_mtimespec.tv_sec,s.st_ctimespec.tv_sec,s.st_birthtimespec.tv_sec,
            s.st_mtimespec.tv_nsec,s.st_ctimespec.tv_nsec,s.st_birthtimespec.tv_nsec,std::move(bytes)});
    };
    add(root);
    if(std::filesystem::is_directory(root))for(const auto& entry:std::filesystem::recursive_directory_iterator(root))add(entry.path());
    return result;
}
inline bool absent(const std::filesystem::path& p) {
    struct stat s{};errno=0;return lstat(p.c_str(),&s)<0&&errno==ENOENT;
}
}
#endif
