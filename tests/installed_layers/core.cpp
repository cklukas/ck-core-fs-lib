// SPDX-License-Identifier: LGPL-2.0-or-later
#include <directory_cursor.hpp>
#include <held_child.hpp>
#include <metadata_capture_job.hpp>
#include <metadata_replay.hpp>
#include <sync_session.hpp>
#include <cassert>
#include <cstdio>
using namespace ck::files;
namespace {
class Cursor final:public DirectoryCursor {
    Observation<DirectoryStep> next_step()override{return Observation<DirectoryStep>::available(DirectoryEnd{});}
};
class Cleanup final:public MetadataCaptureFailureLatch {
public:
    mutable unsigned calls=0;
    void record_first(MetadataCaptureCleanupError)const noexcept override{++calls;}
};
}
int main(){
    MetadataReplayPolicy policy;assert(policy.valid());policy.version=0;assert(!policy.valid());
    MetadataCaptureLimits limits;assert(limits.valid());limits.read.max_bytes=0;assert(!limits.valid());
    Cleanup latch;{detail::MetadataCaptureCleanupScope scope(&latch);
        detail::record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Adapter,7,"consumer"});}
    assert(latch.calls==1&&detail::current_metadata_capture_cleanup()==nullptr);
    auto cursor=std::make_shared<Cursor>();
    auto child=HeldChild::observe(cursor,*NativeName::from_posix("input"));
    assert(!child.value()&&child.state()==ObservationState::Unsupported);
    auto session=SyncSession::open({},SyncDigest{});assert(!session.value());
    std::puts("installed Core: portable metadata policy/limits, cleanup, HeldChild and session link/run PASS");
}
