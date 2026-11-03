//===-- tsan_native_tls_test.cpp ------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Focused tests for the private native-TLS shadow lifetime primitive.
//
//===----------------------------------------------------------------------===//

#include "tsan_mman.h"
#include "tsan_platform.h"
#include "tsan_rtl.h"
#include "gtest/gtest.h"

namespace __tsan {
namespace {

constexpr uptr kPc = 0;

FastState TestState(Sid sid = static_cast<Sid>(17),
                    Epoch epoch = static_cast<Epoch>(22)) {
  FastState state;
  state.SetSid(sid);
  state.SetEpoch(epoch);
  return state;
}

void ResetTestRange(ThreadState *thr, uptr addr, uptr size) {
  MemoryResetRange(thr, kPc, addr, size);
}

bool HasAccess(uptr addr, Sid sid, Epoch epoch, uptr expected_offset,
               uptr expected_size, AccessType expected_type) {
  RawShadow *shadow_mem = MemToShadow(RoundDown(addr, kShadowCell));
  for (uptr i = 0; i < kShadowCnt; ++i) {
    Shadow shadow(LoadShadow(&shadow_mem[i]));
    if (shadow.sid() != sid || shadow.epoch() != epoch)
      continue;
    uptr offset = 0;
    uptr size = 0;
    AccessType type = 0;
    shadow.GetAccess(&offset, &size, &type);
    if (offset == expected_offset && size == expected_size &&
        type == expected_type)
      return true;
  }
  return false;
}

bool CellIsEmpty(uptr addr) {
  RawShadow *shadow_mem = MemToShadow(RoundDown(addr, kShadowCell));
  for (uptr i = 0; i < kShadowCnt; ++i) {
    if (LoadShadow(&shadow_mem[i]) != Shadow::kEmpty)
      return false;
  }
  return true;
}

void StoreCellSlot(uptr addr, uptr slot, RawShadow raw) {
  RawShadow *shadow_mem = MemToShadow(RoundDown(addr, kShadowCell));
  StoreShadow(&shadow_mem[slot], raw);
}

RawShadow MalformedMask(RawShadow raw, u8 access_mask) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  constexpr uptr kAccessShift = 0;
#else
  constexpr uptr kAccessShift = 24;
#endif
  u32 value = static_cast<u32>(raw);
  value &= ~(0xffu << kAccessShift);
  value |= static_cast<u32>(access_mask) << kAccessShift;
  return static_cast<RawShadow>(value);
}

TEST(NativeTlsShadow, ExactMasksAllOffsetsAndSizes) {
  ThreadState *thr = cur_thread();
  char *storage = static_cast<char *>(user_alloc(thr, kPc, 64));
  ASSERT_NE(storage, nullptr);
  const Sid sid = thr->fast_state.sid();
  const Epoch epoch = thr->fast_state.epoch();

  for (uptr size : {1U, 2U, 4U}) {
    for (uptr offset = 0; offset < kShadowCell; ++offset) {
      ResetTestRange(thr, reinterpret_cast<uptr>(storage), 64);
      const uptr addr = reinterpret_cast<uptr>(storage) + offset;
      ASSERT_TRUE(MemoryImitateNativeTlsWrite(thr, kPc, addr, size));

      const uptr first = Min(size, kShadowCell - offset % kShadowCell);
      ASSERT_TRUE(HasAccess(addr, sid, epoch, offset % kShadowCell, first,
                            kAccessWrite));
      if (first != size) {
        ASSERT_TRUE(HasAccess(addr + first, sid, epoch, 0, size - first,
                              kAccessWrite));
      }

      ASSERT_TRUE(MemoryRetireNativeTls(thr, kPc, addr, size));
      ASSERT_TRUE(CellIsEmpty(addr));
      if (first != size)
        ASSERT_TRUE(CellIsEmpty(addr + first));
    }
  }

  // This is the explicit cross-cell boundary case (offset 7, size 4).
  ResetTestRange(thr, reinterpret_cast<uptr>(storage), 64);
  const uptr boundary =
      RoundDown(reinterpret_cast<uptr>(storage), kShadowCell) + 7;
  ASSERT_TRUE(MemoryImitateNativeTlsWrite(thr, kPc, boundary, 4));
  ASSERT_TRUE(HasAccess(boundary, sid, epoch, 7, 1, kAccessWrite));
  ASSERT_TRUE(HasAccess(boundary + 1, sid, epoch, 0, 3, kAccessWrite));
  ASSERT_TRUE(MemoryRetireNativeTls(thr, kPc, boundary, 4));
  ASSERT_TRUE(CellIsEmpty(boundary));
  ASSERT_TRUE(CellIsEmpty(boundary + 1));

  user_free(thr, kPc, storage);
}

TEST(NativeTlsShadow, NeighborHistoryIsRetained) {
  ThreadState *thr = cur_thread();
  char *storage = static_cast<char *>(user_alloc(thr, kPc, 32));
  ASSERT_NE(storage, nullptr);
  const uptr addr = reinterpret_cast<uptr>(storage) + 4;
  ResetTestRange(thr, reinterpret_cast<uptr>(storage), 32);

  Shadow neighbor(TestState(), 0, 2, kAccessWrite);
  StoreCellSlot(addr, 0, neighbor.raw());
  ASSERT_TRUE(MemoryImitateNativeTlsWrite(thr, kPc, addr, 2));
  RawShadow *shadow_mem = MemToShadow(RoundDown(addr, kShadowCell));
  ASSERT_EQ(LoadShadow(&shadow_mem[0]), neighbor.raw());
  ASSERT_TRUE(MemoryRetireNativeTls(thr, kPc, addr, 2));
  ASSERT_EQ(LoadShadow(&shadow_mem[0]), neighbor.raw());

  user_free(thr, kPc, storage);
}

void CheckRejectedShadow(RawShadow raw) {
  ThreadState *thr = cur_thread();
  char *storage = static_cast<char *>(user_alloc(thr, kPc, 16));
  ASSERT_NE(storage, nullptr);
  const uptr addr = reinterpret_cast<uptr>(storage);
  ResetTestRange(thr, addr, 16);
  StoreCellSlot(addr, 0, raw);
  ASSERT_FALSE(MemoryImitateNativeTlsWrite(thr, kPc, addr, 1));
  ASSERT_EQ(LoadShadow(MemToShadow(addr)), raw);
  ASSERT_FALSE(MemoryRetireNativeTls(thr, kPc, addr, 1));
  ASSERT_EQ(LoadShadow(MemToShadow(addr)), raw);
  user_free(thr, kPc, storage);
}

TEST(NativeTlsShadow, RejectsMalformedRodataAndFreedMarkers) {
  FastState state = TestState();
  Shadow ordinary(state, 0, 8, kAccessWrite);
  CheckRejectedShadow(MalformedMask(ordinary.raw(), 0x05));
  CheckRejectedShadow(Shadow::kRodata);
  CheckRejectedShadow(Shadow::FreedMarker());
  CheckRejectedShadow(Shadow::FreedInfo(state.sid(), state.epoch()));
}

TEST(NativeTlsShadow, RejectsNonContiguousResidualFreedMask) {
  ThreadState *thr = cur_thread();
  char *storage = static_cast<char *>(user_alloc(thr, kPc, 16));
  ASSERT_NE(storage, nullptr);
  const uptr addr = reinterpret_cast<uptr>(storage) + 1;
  ResetTestRange(thr, reinterpret_cast<uptr>(storage), 16);

  Shadow full(TestState(), 0, kShadowCell, kAccessWrite);
  StoreCellSlot(addr, 0, full.raw());
  const RawShadow before = LoadShadow(MemToShadow(addr));
  ASSERT_FALSE(MemoryRetireNativeTls(thr, kPc, addr, 6));
  ASSERT_EQ(LoadShadow(MemToShadow(addr)), before);

  user_free(thr, kPc, storage);
}

}  // namespace
}  // namespace __tsan
