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
struct NativeCloseRoleScope final {explicit NativeCloseRoleScope(const char*)noexcept{}};
inline void observe_native_close(void*,const char*)noexcept{}
inline std::uint32_t inject_native_close_failure(void*,const char*,bool,std::uint32_t)noexcept{return 0;}
#endif
}
