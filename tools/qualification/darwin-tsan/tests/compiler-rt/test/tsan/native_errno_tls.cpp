// RUN: %clangxx_tsan %darwin_min_target_with_tls_support -pthread -O1 -g %s -o %t
// RUN: %run %t detached 2>&1 | FileCheck %s --check-prefix=DETACHED
// RUN: %run %t joined 2>&1 | FileCheck %s --check-prefix=JOINED
// RUN: %run %t shared 2>&1 | FileCheck %s --check-prefix=SHARED
// REQUIRES: system-darwin
//
// Exercises native errno lifetime registration without suppressing a genuine
// race through a foreign pointer into another thread's errno object.

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <sched.h>
#include <vector>

namespace {

constexpr int kWorkerCount = 1000;
std::atomic<int> completed;

void *ErrnoWorker(void *) {
  errno = 0;
  completed.fetch_add(1, std::memory_order_relaxed);
  return nullptr;
}

int RunDetached() {
  completed.store(0, std::memory_order_relaxed);
  pthread_attr_t attr;
  if (pthread_attr_init(&attr) != 0 ||
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0)
    return 2;
  for (int i = 0; i < kWorkerCount; ++i) {
    pthread_t thread;
    if (pthread_create(&thread, &attr, ErrnoWorker, nullptr) != 0)
      return 3;
  }
  pthread_attr_destroy(&attr);
  while (completed.load(std::memory_order_acquire) != kWorkerCount)
    sched_yield();
  std::printf("DETACHED PASS\n");
  return 0;
}

int RunJoined() {
  completed.store(0, std::memory_order_relaxed);
  std::vector<pthread_t> threads;
  threads.reserve(kWorkerCount);
  for (int i = 0; i < kWorkerCount; ++i) {
    pthread_t thread;
    if (pthread_create(&thread, nullptr, ErrnoWorker, nullptr) != 0)
      return 2;
    threads.push_back(thread);
  }
  for (pthread_t thread : threads) {
    if (pthread_join(thread, nullptr) != 0)
      return 3;
  }
  if (completed.load(std::memory_order_acquire) != kWorkerCount)
    return 4;
  std::printf("JOINED PASS\n");
  return 0;
}

std::atomic<int *> foreign_errno;
std::atomic<bool> shared_ready;
std::atomic<bool> shared_go;

void *SharedErrnoWorker(void *) {
  errno = 1;
  foreign_errno.store(&errno, std::memory_order_release);
  shared_ready.store(true, std::memory_order_release);
  while (!shared_go.load(std::memory_order_relaxed))
    sched_yield();
  // This is intentionally unordered with the main-thread write through the
  // published pointer. It must remain reportable by TSan.
  errno = 2;
  return nullptr;
}

int RunShared() {
  shared_ready.store(false, std::memory_order_relaxed);
  shared_go.store(false, std::memory_order_relaxed);
  foreign_errno.store(nullptr, std::memory_order_relaxed);
  pthread_t thread;
  if (pthread_create(&thread, nullptr, SharedErrnoWorker, nullptr) != 0)
    return 2;
  while (!shared_ready.load(std::memory_order_acquire))
    sched_yield();
  int *foreign = foreign_errno.load(std::memory_order_acquire);
  if (!foreign)
    return 3;
  *foreign = 3;
  shared_go.store(true, std::memory_order_relaxed);
  if (pthread_join(thread, nullptr) != 0)
    return 4;
  std::printf("SHARED PASS\n");
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2)
    return 1;
  if (std::strcmp(argv[1], "detached") == 0)
    return RunDetached();
  if (std::strcmp(argv[1], "joined") == 0)
    return RunJoined();
  if (std::strcmp(argv[1], "shared") == 0)
    return RunShared();
  return 1;
}

// DETACHED-NOT: ThreadSanitizer: data race
// DETACHED: DETACHED PASS
// JOINED-NOT: ThreadSanitizer: data race
// JOINED: JOINED PASS
// SHARED: ThreadSanitizer: data race
// SHARED: SHARED PASS
