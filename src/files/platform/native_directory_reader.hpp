// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../directory_cursor.hpp"
namespace ck::files::detail {
#ifndef _WIN32
// Enumeration ONLY: fresh open description through a genuine held directory,
// identity/version checked. Never duplicate an old enumeration description or
// reopen its former address. Caller owns and explicitly drains the returned
// reader under its native close observer on every terminal path.
Observation<std::unique_ptr<DirectoryCursor>> open_posix_directory_reader(const DirectoryCursor&);
#endif
}
