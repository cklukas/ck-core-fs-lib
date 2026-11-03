// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "operation_execution_job.hpp"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <new>
#include <stdexcept>
#include <string_view>
#include <utility>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif
using namespace ck::files;
namespace {std::atomic<bool> deny=false;unsigned finalizers=0,closes=0,attempts=0,first_attempt_closes=0;}
void* operator new(std::size_t n){if(deny){if(!attempts++)first_attempt_closes=closes;throw std::bad_alloc();}if(void*p=std::malloc(n?n:1))return p;throw std::bad_alloc();}void* operator new[](std::size_t n){return ::operator new(n);}void operator delete(void*p)noexcept{std::free(p);}void operator delete[](void*p)noexcept{std::free(p);}void operator delete(void*p,std::size_t)noexcept{std::free(p);}void operator delete[](void*p,std::size_t)noexcept{std::free(p);}
namespace {
#define CHECK(x) do{if(!(x)){deny=false;throw std::runtime_error(#x);}}while(false)
template<class T>T take(Observation<T> x){CHECK(x.value());return std::move(x).take_value();}
struct NativeClose {
#ifdef _WIN32
 HANDLE source=INVALID_HANDLE_VALUE,other=INVALID_HANDLE_VALUE;
 NativeClose(){CHECK(CreatePipe(&source,&other,nullptr,0));}
 bool finish()noexcept{++closes;return CloseHandle(std::exchange(source,INVALID_HANDLE_VALUE))!=0;}
 ~NativeClose(){if(source!=INVALID_HANDLE_VALUE)CloseHandle(source);if(other!=INVALID_HANDLE_VALUE)CloseHandle(other);}
#else
 int source=-1,other=-1;
 NativeClose(){int fd[2];CHECK(pipe(fd)==0);source=fd[0];other=fd[1];CHECK(fcntl(source,F_SETFD,FD_CLOEXEC)==0&&fcntl(other,F_SETFD,FD_CLOEXEC)==0);}
 bool finish()noexcept{++closes;return close(std::exchange(source,-1))==0;}
 ~NativeClose(){if(source>=0)close(source);if(other>=0)close(other);}
#endif
};
void run(bool protocol){
 NativeClose native;bool actual_close_success=false;OperationJournalId id{};id.bytes[0]=std::byte{83};auto journal=take(OperationJournal::create(FileOperation::Copy,id));CHECK(journal->append({1,0,OperationJournalState::Planned,{}}).value());
 OperationCopyRequest copy;copy.journal=journal;copy.revalidate_source=copy.revalidate_destination=[](std::stop_token){return Observation<bool>::available(true);};copy.prepare_copy=[](std::stop_token){return Observation<StreamCopyJob::Pointer>::unavailable(ObservationState::Unknown);};copy.prepare_metadata=[](std::stop_token){return Observation<OperationMetadataJob::Pointer>::unavailable(ObservationState::Unknown);};copy.verify_copy=[](std::stop_token){return Observation<bool>::available(true);};
 copy.append_journal=[journal,protocol](OperationJournalRecord r){if(protocol){deny=true;throw std::bad_alloc();}return journal->append(std::move(r));};
 OperationExecutionRequest request;request.copy=take(OperationCopyJob::create(std::move(copy)));request.prepare_commit=[](std::stop_token){return Observation<OperationCommitJob::Pointer>::unavailable(ObservationState::Unknown);};request.finish_io=[&]{++finalizers;actual_close_success=native.finish();if(!protocol){deny=true;throw std::bad_alloc();}return Observation<bool>::available(true);};
 auto job=take(OperationExecutionJob::create(std::move(request)));std::stop_source stop;stop.request_stop();const auto state=job->advance(stop.get_token());CHECK(deny);deny=false;
 CHECK(state==OperationExecutionState::NeedsReconciliation&&actual_close_success&&finalizers==1&&closes==1);
 // Exactly one best-effort diagnostic allocation, after real close. A retry
 // with an allocating empty fallback would add another denied allocation.
 CHECK(attempts==1&&first_attempt_closes==1&&!job->failure());for(unsigned i=0;i<3;++i)CHECK(job->advance(stop.get_token())==state);job.reset();CHECK(finalizers==1&&closes==1);
 std::printf("PASS OperationExecution persistent C++ new exhaustion mode=%s nativeClose=1 finalizer=1 diagnosticAttempt=1 after-close no-fallback/no-retry\n",protocol?"protocol":"finalizer");
}
}
int main(int argc,char**argv){std::set_terminate([]{deny=false;std::fprintf(stderr,"FAIL terminate finalizers=%u closes=%u\n",finalizers,closes);std::_Exit(3);});try{CHECK(argc==2);const std::string_view mode=argv[1];CHECK(mode=="protocol"||mode=="finalizer");run(mode=="protocol");return 0;}catch(const std::exception&e){deny=false;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
