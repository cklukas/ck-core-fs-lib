// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#ifndef _WIN32
#include "legacy_native_fixture_observation.hpp"
#include <cerrno>
#include <sys/stat.h>
namespace ck::files::detail {
inline int legacy_fstat(int fd,struct stat* output,const char* tag)noexcept {
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
    const int before=errno;
    observe_legacy_native_event({LegacyNativeOperation::Query,LegacyNativePhase::Before,LegacyNativeDomain::Errno,
        static_cast<std::uintptr_t>(fd),0,0,0,0,false,false,tag});
    errno=before;
#endif
    const int result=::fstat(fd,output);const int error=errno;
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
    observe_legacy_native_event({LegacyNativeOperation::Query,LegacyNativePhase::After,LegacyNativeDomain::Errno,
        static_cast<std::uintptr_t>(fd),0,0,result?static_cast<std::uint32_t>(error):0,result,result==0,false,tag});
#endif
    errno=error;return result;
}
} // namespace ck::files::detail
#endif
