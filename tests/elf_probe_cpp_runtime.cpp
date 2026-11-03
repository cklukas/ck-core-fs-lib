// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include <stdexcept>

// This plugin host loads a C++ SDK through dlopen rather than a link-time SDK
// dependency. Keep its C++ exception runtime present at process startup, when
// sanitizer interceptors resolve their real targets. The probe itself remains
// a separately compiled C translation unit and still resolves the exact DSO.
extern "C" int elf_probe_cpp_runtime_ready() noexcept {
    try {
        throw std::runtime_error("ELF probe exception-runtime control");
    } catch (const std::runtime_error&) {
        return 1;
    } catch (...) {
        return 0;
    }
}
