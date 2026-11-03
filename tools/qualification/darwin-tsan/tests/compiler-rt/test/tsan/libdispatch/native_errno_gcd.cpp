// RUN: %clangxx_tsan %darwin_min_target_with_tls_support -O1 -g %s -o %t
// RUN: %run %t gcd 2>&1 | FileCheck %s --check-prefix=GCD
// RUN: %run %t main-foreign 2>&1 | FileCheck %s --check-prefix=MAIN
// REQUIRES: libdispatch
// REQUIRES: system-darwin
//
// GCD workers are created without an observable pthread_create call. The gcd
// mode exercises that startup path and repeated dispatch errno use. The main-
// foreign mode checks that ordinary instrumentation still reports a worker
// writing through a pointer to the main thread's errno object, even though
// main-thread errno lifetime registration is intentionally excluded.

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dispatch/dispatch.h>
#include <sched.h>

namespace {

constexpr int kRounds = 16;
constexpr int kTasksPerRound = 128;

std::atomic<int> gcd_started;

int RunGcdErrnoReuse() {
  dispatch_queue_t queue =
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

  // The first task is held long enough to force libdispatch to start a worker
  // before the rest of the batch is released. Subsequent rounds exercise
  // worker/errno storage reuse without sharing any errno object between
  // tasks.
  for (int round = 0; round < kRounds; ++round) {
    gcd_started.store(0, std::memory_order_relaxed);
    dispatch_group_t group = dispatch_group_create();
    dispatch_semaphore_t release = dispatch_semaphore_create(0);
    for (int i = 0; i < kTasksPerRound; ++i) {
      dispatch_group_async(group, queue, ^{
        errno = 0;
        gcd_started.fetch_add(1, std::memory_order_relaxed);
        dispatch_semaphore_wait(release, DISPATCH_TIME_FOREVER);
      });
    }
    while (gcd_started.load(std::memory_order_acquire) == 0)
      sched_yield();
    for (int i = 0; i < kTasksPerRound; ++i)
      dispatch_semaphore_signal(release);
    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
  }

  std::printf("GCD PASS rounds=%d\n", kRounds);
  return 0;
}

std::atomic<bool> main_foreign_ready;
std::atomic<bool> main_foreign_go;

int RunMainForeignErrnoRace() {
  main_foreign_ready.store(false, std::memory_order_relaxed);
  main_foreign_go.store(false, std::memory_order_relaxed);
  int *const main_errno = &errno;
  dispatch_group_t group = dispatch_group_create();
  dispatch_queue_t queue =
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

  dispatch_group_async(group, queue, ^{
    // This is the worker's own errno and exercises its native lifetime
    // registration before the deliberate foreign-pointer access below.
    errno = 1;
    main_foreign_ready.store(true, std::memory_order_release);
    while (!main_foreign_go.load(std::memory_order_relaxed))
      sched_yield();
    // Intentionally unordered with the main-thread write below.
    *main_errno = 2;
  });

  while (!main_foreign_ready.load(std::memory_order_acquire))
    sched_yield();
  *main_errno = 3;
  main_foreign_go.store(true, std::memory_order_relaxed);
  dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
  std::printf("MAIN FOREIGN PASS\n");
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2)
    return 1;
  if (std::strcmp(argv[1], "gcd") == 0)
    return RunGcdErrnoReuse();
  if (std::strcmp(argv[1], "main-foreign") == 0)
    return RunMainForeignErrnoRace();
  return 1;
}

// GCD-NOT: ThreadSanitizer: data race
// GCD: GCD PASS rounds=16
// MAIN: ThreadSanitizer: data race
// MAIN: MAIN FOREIGN PASS
