// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Private cache test: compile the actual adapter in this TU so synthetic
// publications exercise the real C getter without adding a production test
// factory, public cache mutation API, native worker or filesystem fixture.
#include "../src/c-api/tree_c.cpp"
#include <cassert>
#include <new>

namespace {
std::atomic<bool> forbid_allocation{false};
std::atomic<unsigned> forbidden_allocations{0};
void* allocate(std::size_t size) {
    if(forbid_allocation.load()) {++forbidden_allocations;throw std::bad_alloc();}
    if(auto* value=std::malloc(size?size:1))return value;
    throw std::bad_alloc();
}
void unchanged_invalid(const ckfet_job* job,ckfet_failure_details_v1 value) {
    const auto original=value;
    assert(ckfet_get_failure_details_v1(job,&value)==CKFE_API_INVALID_ARGUMENT);
    assert(std::memcmp(&original,&value,sizeof(value))==0);
}
}
void* operator new(std::size_t size){return allocate(size);}
void* operator new[](std::size_t size){return allocate(size);}
void operator delete(void* value) noexcept{std::free(value);}
void operator delete[](void* value) noexcept{std::free(value);}
void operator delete(void* value,std::size_t) noexcept{std::free(value);}
void operator delete[](void* value,std::size_t) noexcept{std::free(value);}

int main() {
    auto shared=std::make_shared<Shared>();
    ckfet_job job{shared};
    ckfet_failure_details_v1 details;
    ckfet_failure_details_init_v1(&details);
    assert(details.version==1&&details.struct_size==192);
    assert(ckfet_get_failure_details_v1(&job,&details)==CKFE_API_OK&&!details.has_failure);
    assert(details.operation_bytes==0&&details.operation[0]=='\0'&&!details.operation_truncated);
    unchanged_invalid(nullptr,details);
    auto invalid=details;invalid.version=2;unchanged_invalid(&job,invalid);
    invalid=details;invalid.struct_size=sizeof(details)-1;unchanged_invalid(&job,invalid);
    invalid=details;invalid.struct_size=sizeof(details)+1;unchanged_invalid(&job,invalid);
    for(auto& reserved:invalid.reserved)reserved=0;
    for(unsigned i=0;i<4;++i) {
        invalid=details;invalid.reserved[i]=1;unchanged_invalid(&job,invalid);
    }
    assert(ckfet_get_failure_details_v1(&job,nullptr)==CKFE_API_INVALID_ARGUMENT);
    std::array<char,4096> tag;tag.fill('t');
    for(const auto length:{0U,95U,96U,4096U}) {
        shared->set_failure(ObservationState::Denied,ErrorDomain::None,0,{tag.data(),length});
        shared->snapshot.plan_generation=42;shared->snapshot.has_current_row=1;shared->snapshot.current_row=17;
        shared->publish();
        forbid_allocation=true;
        const auto status=ckfet_get_failure_details_v1(&job,&details);
        forbid_allocation=false;
        assert(status==CKFE_API_OK&&details.has_failure&&details.failure_state==CKFE_OBSERVATION_DENIED);
        assert(details.failure_domain==CKFE_ERROR_NONE&&details.failure_code==0);
        assert(details.plan_generation==42&&details.has_current_row&&details.current_row==17);
        assert(details.sequence==shared->snapshot.sequence);
        assert(details.operation_bytes==std::min(length,95U)&&details.operation_truncated==(length>95));
        assert(details.operation[details.operation_bytes]=='\0');
        assert(std::memcmp(details.operation,tag.data(),details.operation_bytes)==0);
        for(auto reserved:details.reserved)assert(reserved==0);
    }
    // A native domain or code alone must not be mistaken for "no failure".
    shared->set_failure(ObservationState::Available,ErrorDomain::Posix,0,{});
    assert(ckfet_get_failure_details_v1(&job,&details)==CKFE_API_OK&&details.has_failure);
    shared->set_failure(ObservationState::Available,ErrorDomain::None,5,{});
    assert(ckfet_get_failure_details_v1(&job,&details)==CKFE_API_OK&&details.has_failure);
    shared->clear_failure();
    assert(ckfet_get_failure_details_v1(&job,&details)==CKFE_API_OK&&!details.has_failure&&
        !details.operation_bytes&&!details.operation[0]&&!details.operation_truncated);
    std::atomic<bool> start{false},done{false};
    std::thread publisher([&] {
        while(!start.load())std::this_thread::yield();
        for(unsigned i=0;i<5000;++i) {
            std::lock_guard lock(shared->mutex);
            const auto next=shared->snapshot.sequence+1;
            shared->set_failure(ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(next),
                next%2?"odd":"even");
            shared->snapshot.plan_generation=next*2;
            shared->snapshot.has_current_row=1;shared->snapshot.current_row=next*3;
            shared->publish();
        }
        done=true;
    });
    // First publish a tuple with the same invariant before readers start.
    {
        std::lock_guard lock(shared->mutex);
        shared->snapshot.sequence=0;shared->set_failure(ObservationState::Failed,ErrorDomain::Adapter,1,"odd");
        shared->snapshot.plan_generation=2;shared->snapshot.current_row=3;shared->publish();
    }
    forbid_allocation=true;start=true;
    unsigned reads=0;
    do {
        assert(ckfet_get_failure_details_v1(&job,&details)==CKFE_API_OK);
        assert(details.has_failure&&details.failure_code==static_cast<std::int64_t>(details.sequence));
        assert(details.plan_generation==details.sequence*2&&details.current_row==details.sequence*3&&details.has_current_row);
        assert(std::strcmp(details.operation,details.sequence%2?"odd":"even")==0);
        ++reads;
    } while(!done.load()||reads<1000);
    forbid_allocation=false;publisher.join();
    // Cache ownership and terminal inspection survive cancellation requests.
    shared->terminal=true;shared->worker_drained=true;shared->snapshot.state=CKFET_FAILED;
    assert(ckfet_get_failure_details_v1(&job,&details)==CKFE_API_OK);
    const auto terminal=details;
    ckfet_request_cancel(&job);
    ckfet_snapshot_v1 snapshot{};snapshot.version=CKFET_VERSION;snapshot.struct_size=sizeof(snapshot);
    assert(ckfet_poll_v1(&job,&snapshot)==CKFE_API_OK&&snapshot.state==CKFET_FAILED);
    uint32_t drained=0;
    assert(ckfet_worker_drained_v1(&job,&drained)==CKFE_API_OK&&drained);
    assert(ckfet_get_failure_details_v1(&job,&details)==CKFE_API_OK&&std::memcmp(&terminal,&details,sizeof(details))==0);
    assert(forbidden_allocations==0);
    std::puts("Tree diagnostics: ABI boundaries, bounded tags, coherent concurrent publications, allocation-free reads and terminal cache passed");
}
