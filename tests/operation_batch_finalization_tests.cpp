// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "operation_batch_job.hpp"
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <new>
#include <stdexcept>
#include <string_view>
#include <utility>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

using namespace ck::files;
namespace { std::atomic<bool> deny_allocations{false}; }
void* operator new(std::size_t size) {
    if(deny_allocations.load())throw std::bad_alloc();
    if(auto* p=std::malloc(size?size:1))return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size){return ::operator new(size);}
void operator delete(void* p)noexcept{std::free(p);}
void operator delete[](void* p)noexcept{std::free(p);}
void operator delete(void* p,std::size_t)noexcept{std::free(p);}
void operator delete[](void* p,std::size_t)noexcept{std::free(p);}

namespace {
#define CHECK(value) do{if(!(value)){deny_allocations=false;throw std::runtime_error(#value);}}while(false)
template<class T>T take(Observation<T> value){CHECK(value.value());return std::move(value).take_value();}
struct NativeOwner {
#ifdef _WIN32
    HANDLE read=INVALID_HANDLE_VALUE,write=INVALID_HANDLE_VALUE;
    NativeOwner(){CHECK(CreatePipe(&read,&write,nullptr,0));}
    bool consume()noexcept{return CloseHandle(std::exchange(read,INVALID_HANDLE_VALUE))!=0;}
    ~NativeOwner(){if(read!=INVALID_HANDLE_VALUE)CloseHandle(read);if(write!=INVALID_HANDLE_VALUE)CloseHandle(write);}
#else
    int read=-1,write=-1;
    NativeOwner(){int fds[2];CHECK(pipe(fds)==0);read=fds[0];write=fds[1];}
    bool consume()noexcept{return close(std::exchange(read,-1))==0;}
    ~NativeOwner(){if(read>=0)close(read);if(write>=0)close(write);}
#endif
};
enum class Fault { None, Error, Exception, Oom };
#ifdef _WIN32
constexpr auto close_domain=ErrorDomain::Win32;
constexpr std::int64_t close_error=ERROR_READ_FAULT;
#else
constexpr auto close_domain=ErrorDomain::Posix;
constexpr std::int64_t close_error=5;
#endif
void run(Fault fault,bool cancel_before_start) {
    std::array<NativeOwner,3> owners;
    std::array<unsigned,3> finishes{};
    unsigned validations=0,prepares=0,protocol_writes=0,commits=0;
    OperationBatchRequest batch;
    for(unsigned index=0;index<owners.size();++index) {
        OperationJournalId id{};id.bytes[0]=std::byte{91};id.bytes[1]=std::byte(index);
        auto journal=take(OperationJournal::create(FileOperation::Copy,id));
        CHECK(journal->append({1,0,OperationJournalState::Planned,{}}).value());
        OperationCopyRequest copy;copy.journal=journal;
        copy.revalidate_source=copy.revalidate_destination=[&](std::stop_token){
            ++validations;return Observation<bool>::available(true);
        };
        copy.prepare_copy=[&](std::stop_token){++prepares;return Observation<StreamCopyJob::Pointer>::unavailable(ObservationState::Unknown);};
        copy.prepare_metadata=[](std::stop_token){return Observation<OperationMetadataJob::Pointer>::unavailable(ObservationState::Unknown);};
        copy.verify_copy=[](std::stop_token){return Observation<bool>::available(true);};
        copy.append_journal=[&,journal](OperationJournalRecord record){++protocol_writes;return journal->append(std::move(record));};
        OperationExecutionRequest request;request.copy=take(OperationCopyJob::create(std::move(copy)));
        request.prepare_commit=[&](std::stop_token){++commits;return Observation<OperationCommitJob::Pointer>::unavailable(ObservationState::Unknown);};
        request.finish_io=[&,index]{
            ++finishes[index];CHECK(owners[index].consume());
            if(index==0) {
                if(fault==Fault::Error)return Observation<bool>::unavailable(ObservationState::Failed,{close_domain,close_error,"test.batch.native_close"});
                if(fault==Fault::Exception)throw std::runtime_error("test.batch.close_exception");
                if(fault==Fault::Oom){deny_allocations=true;throw std::bad_alloc();}
            }
            return Observation<bool>::available(true);
        };
        batch.jobs.push_back(take(OperationExecutionJob::create(std::move(request))));
    }
    auto job=take(OperationBatchJob::create(std::move(batch)));
    std::stop_source stop;
    if(cancel_before_start)stop.request_stop();
    OperationBatchState state=job->state();
    for(unsigned step=0;step<20&&(state==OperationBatchState::Ready||state==OperationBatchState::Running);++step)
        state=job->advance(stop.get_token());
    const bool was_oom=deny_allocations.exchange(false);
    CHECK((finishes==std::array<unsigned,3>{1,1,1}));
    CHECK(state==(fault==Fault::None?OperationBatchState::Cancelled:OperationBatchState::NeedsReconciliation));
    CHECK(commits==0);
    if(cancel_before_start)CHECK(validations==0&&prepares==0&&protocol_writes==0);
    else CHECK(prepares==1); // Uncertain first entry never starts a later copy.
    for(unsigned index=1;index<owners.size();++index)
        CHECK(job->result().items[index].outcome==OperationItemOutcome::Pending);
    CHECK(was_oom==(fault==Fault::Oom));
    if(fault==Fault::Error&&cancel_before_start)CHECK(job->result().items[0].failure&&job->result().items[0].failure->error.domain==close_domain&&job->result().items[0].failure->error.code==close_error);
    for(unsigned repeat=0;repeat<3;++repeat)CHECK(job->advance(stop.get_token())==state);
    job.reset();CHECK((finishes==std::array<unsigned,3>{1,1,1}));
    std::printf("PASS batch terminal native drain cancel-before-start=%u fault=%u closures=3 no-protocol-for-pending no-retry\n",unsigned(cancel_before_start),unsigned(fault));
}
}
int main(int argc,char** argv) {
    std::set_terminate([]{deny_allocations=false;std::fputs("FAIL batch finalization terminated\n",stderr);std::_Exit(3);});
    try {
        CHECK(argc==2);const std::string_view mode=argv[1];
        if(mode=="cancel")run(Fault::None,true);
        else if(mode=="cancel-error")run(Fault::Error,true);
        else if(mode=="cancel-exception")run(Fault::Exception,true);
        else if(mode=="cancel-oom")run(Fault::Oom,true);
        else if(mode=="uncertain")run(Fault::Error,false);
        else if(mode=="uncertain-oom")run(Fault::Oom,false);
        else CHECK(false);
        return 0;
    } catch(const std::exception& error) {
        deny_allocations=false;std::fprintf(stderr,"FAIL %s\n",error.what());return 1;
    }
}
