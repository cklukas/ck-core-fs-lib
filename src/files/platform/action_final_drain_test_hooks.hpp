// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include <atomic>
#include <chrono>
#include <thread>
namespace ck::files::detail {
#ifdef CK_FS_ACTION_FINAL_DRAIN_TEST_HOOKS
using ActionFinalDrainObserve=void(*)()noexcept;
inline std::atomic<ActionFinalDrainObserve> action_final_drain_test_observe{nullptr};
inline std::atomic<bool> action_final_drain_test_hold{false};
// Ordinary worker checkpoint AFTER every native finalizer has returned.
// The fixed observer returns immediately; no close callback/destructor waits.
inline void action_final_drain_checkpoint()noexcept {
 if(const auto observe=action_final_drain_test_observe.load(std::memory_order_acquire)) {
  observe();
  while(action_final_drain_test_hold.load(std::memory_order_acquire))
   std::this_thread::sleep_for(std::chrono::milliseconds(1));
 }
}
#else
inline void action_final_drain_checkpoint()noexcept{}
#endif
}
