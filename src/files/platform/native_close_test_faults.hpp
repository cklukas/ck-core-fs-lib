// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include <atomic>
#include <cstdint>
namespace ck::files::detail {
enum class NativeTestIo {Query,Read,Write,Flush,WorkerStart,PendingWait,InputDrain};
// Compiled, failure-only native-close regression seam. Production builds have
// no callbacks. The native adapter ALWAYS calls the real CloseHandle first;
// a real failure cannot be suppressed or replaced by this seam.
#ifdef CK_FS_NATIVE_CLOSE_TEST_HOOKS
using NativeIoObserver=void(*)(NativeTestIo)noexcept;
inline std::atomic<NativeIoObserver> native_test_io_observer{nullptr};
inline void observe_native_test_io(NativeTestIo op)noexcept{if(const auto f=native_test_io_observer.load(std::memory_order_acquire))f(op);}
// Observation only: callbacks cannot replace a native result, alter bytes, or
// skip I/O. The after notification preserves the exact post-native boundary
// needed to arm allocation failure before a journal's subsequent revalidation.
using NativeFileIoBefore=void(*)(void*,NativeTestIo,std::uint32_t,const char*) noexcept;
using NativeFileIoAfter=void(*)(void*,NativeTestIo,bool,std::uint32_t,const char*) noexcept;
inline std::atomic<NativeFileIoBefore> native_file_test_before{nullptr};
inline std::atomic<NativeFileIoAfter> native_file_test_after{nullptr};
inline void observe_native_file_before(void* handle,NativeTestIo op,std::uint32_t count,const char* operation)noexcept {
 if(const auto f=native_file_test_before.load(std::memory_order_acquire))f(handle,op,count,operation);
}
inline void observe_native_file_after(void* handle,NativeTestIo op,bool succeeded,std::uint32_t error,const char* operation)noexcept {
 if(const auto f=native_file_test_after.load(std::memory_order_acquire))f(handle,op,succeeded,error,operation);
}
// One Request per real ReadFile; Completion only when that I/O completes (or
// its immediate native failure). FALSE/ERROR_IO_PENDING is Request only. Drain
// describes the real cancellation/wait result; it is not a successful proof.
// Pending is a real GetOverlappedResult FALSE/ERROR_IO_INCOMPLETE, not completion.
enum class NativeReadPhase {Request,Pending,Completion,Drain};
// copied is meaningful only for succeeded; zero otherwise, never pending data.
// Read-only post-native detail. Counts are values, not writable buffers or
// result pointers. Observers may arm a later allocator failure or cancellation;
// they cannot skip I/O, supply bytes, replace success, or throw across this ABI.
using NativeReadAfter=void(*)(void*,NativeReadPhase,std::uint32_t,std::uint32_t,bool,std::uint32_t,const char*) noexcept;
inline std::atomic<NativeReadAfter> native_read_test_after{nullptr};
inline void observe_native_read_after(void* handle,NativeReadPhase phase,std::uint32_t requested,std::uint32_t copied,
                                     bool succeeded,std::uint32_t error,const char* operation)noexcept {
 if(const auto f=native_read_test_after.load(std::memory_order_acquire))f(handle,phase,requested,copied,succeeded,error,operation);
}
#ifdef _WIN32
// Private hooks-only regression access to the EXACT adapter helpers. These
// functions do not mint filesystem authority, substitute results, or reopen
// addresses; fixtures supply their own genuine native handles. No C ABI/export.
bool probe_native_capture_read(void*,void*,std::uint32_t,std::uint32_t*,void* overlapped=nullptr) noexcept;
bool probe_native_capture_read_completion(void*,void*,std::uint32_t,std::uint32_t*,bool,NativeReadPhase) noexcept;
bool probe_native_capture_close(void*) noexcept;
#endif
using NativeCloseBefore=void(*)(void*,const char*,const char*) noexcept;
using NativeCloseAfter=std::uint32_t(*)(void*,const char*,bool,std::uint32_t) noexcept;
inline std::atomic<NativeCloseBefore> native_close_test_before{nullptr};
inline std::atomic<NativeCloseAfter> native_close_test_after{nullptr};
inline thread_local const char* native_close_test_role=nullptr;
struct NativeCloseRoleScope final {
 const char* previous;
 explicit NativeCloseRoleScope(const char* role)noexcept:previous(native_close_test_role){native_close_test_role=role;}
 ~NativeCloseRoleScope(){native_close_test_role=previous;}
};
inline void observe_native_close(void* handle,const char* operation)noexcept {
 if(const auto before=native_close_test_before.load(std::memory_order_acquire))before(handle,operation,native_close_test_role);
}
inline std::uint32_t inject_native_close_failure(void* handle,const char* operation,bool succeeded,std::uint32_t code)noexcept {
 const auto after=native_close_test_after.load(std::memory_order_acquire);
 return after?after(handle,operation,succeeded,code):0;
}
#else
inline void observe_native_test_io(NativeTestIo)noexcept{}
inline void observe_native_file_before(void*,NativeTestIo,std::uint32_t,const char*)noexcept{}
inline void observe_native_file_after(void*,NativeTestIo,bool,std::uint32_t,const char*)noexcept{}
enum class NativeReadPhase {Request,Pending,Completion,Drain};
inline void observe_native_read_after(void*,NativeReadPhase,std::uint32_t,std::uint32_t,bool,std::uint32_t,const char*)noexcept{}
struct NativeCloseRoleScope final {explicit NativeCloseRoleScope(const char*)noexcept{}};
inline void observe_native_close(void*,const char*)noexcept{}
inline std::uint32_t inject_native_close_failure(void*,const char*,bool,std::uint32_t)noexcept{return 0;}
#endif
}
