// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "private_journal_membership.hpp"
#include <new>

namespace ck::files {
namespace {
template<class T> bool equal(const Observation<T>& a,const Observation<T>& b) noexcept {
    if(a.value()&&b.value())return *a.value()==*b.value();
    return !a.value()&&!b.value()&&a.state()==b.state()&&
        a.unavailable_detail()->error==b.unavailable_detail()->error;
}
}
Observation<bool> detail::PrivateMembershipFailure::result() const {
    if(!*this)return Observation<bool>::available(true);
    // Even an empty std::string may allocate a debug iterator proxy inside a
    // noexcept constructor on MSVC. Do not manufacture another diagnostic on
    // allocation failure: all owners have drained and Root retains the first
    // native close error in its fixed latch. Let bad_alloc reach the caller.
    return Observation<bool>::unavailable(state,{domain,code,operation.data()});
}
bool detail::private_membership_entry_qualified(const BasicMetadata& m) noexcept {
    return m.identity.value()&&compare_identity(*m.identity.value(),*m.identity.value())==IdentityComparison::Same&&
        m.kind.value()&&*m.kind.value()==ObjectKind::RegularFile&&m.logical_size.value()&&
        m.link_count.value()&&*m.link_count.value()>0&&m.mount_id.value()&&m.modified.value()&&m.changed.value();
}
bool detail::private_membership_entry_same(const BasicMetadata& a,const BasicMetadata& b) noexcept {
    return private_membership_entry_qualified(a)&&private_membership_entry_qualified(b)&&
        compare_identity(*a.identity.value(),*b.identity.value())==IdentityComparison::Same&&
        equal(a.kind,b.kind)&&equal(a.logical_size,b.logical_size)&&equal(a.link_count,b.link_count)&&
        equal(a.mount_id,b.mount_id)&&equal(a.modified,b.modified)&&equal(a.changed,b.changed)&&
        equal(a.posix_permissions,b.posix_permissions)&&equal(a.posix_uid,b.posix_uid)&&
        equal(a.posix_gid,b.posix_gid)&&equal(a.bsd_flags,b.bsd_flags)&&
        equal(a.windows_attributes,b.windows_attributes)&&equal(a.reparse_tag,b.reparse_tag);
}
Observation<bool> qualify_private_journal_disjointness(PreparedJournalRoot& root,const HeldChild& entry,
    PrivateJournalMembershipLimits limits,std::stop_token stop) {
    if(!entry.parent()||!limits.max_records||limits.max_records>65536||!limits.max_directories||
        limits.max_directories>1024||!limits.max_depth||limits.max_depth>256||
        !limits.max_name_bytes||limits.max_name_bytes>16*1024*1024)
        return Observation<bool>::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidLimit),"journal_membership.limits"});
    if(stop.stop_requested())return Observation<bool>::unavailable(ObservationState::Changed,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InterruptedRead),"journal_membership.cancelled"});
    return detail::native_private_journal_disjointness(root,entry,limits,stop);
}
} // namespace ck::files
