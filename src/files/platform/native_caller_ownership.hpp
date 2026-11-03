// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../directory_cursor.hpp"
#include <array>
namespace ck::files::detail {
// Native effective-token owner/group, read on the owning worker before any
// target effects. Genuine native parent required. Not caller-authored expected
// metadata, a session/baseline authority, or permission to change ownership.
#ifdef _WIN32
Observation<std::array<std::byte,32>> native_metadata_caller_ownership(const DirectoryCursor&);
#else
inline Observation<std::array<std::byte,32>> native_metadata_caller_ownership(const DirectoryCursor&){
 return Observation<std::array<std::byte,32>>::unavailable(ObservationState::Unsupported,
  {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"caller_owner.native_context_unqualified"});
}
#endif
}
