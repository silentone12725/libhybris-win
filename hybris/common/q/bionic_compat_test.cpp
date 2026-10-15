#include <sys/cdefs.h>
#ifndef __LIBC_HIDDEN__
#define __LIBC_HIDDEN__
#endif

#include "private/bionic_futex.h"
#include "private/bionic_thread_id.h"

#include <atomic>
#include <chrono>
#include <thread>

#include <gtest/gtest.h>

TEST(BionicCompatibility, CurrentThreadIdIsStableAndNonzero) {
  const pid_t first = bionic_get_thread_id();
  EXPECT_GT(first, 0);
  EXPECT_EQ(first, bionic_get_thread_id());
}

TEST(BionicCompatibility, FutexWaitAndWake) {
  alignas(4) volatile int value = 0;
  std::atomic<bool> waiting{false};
  std::thread waiter([&] {
    waiting.store(true, std::memory_order_release);
    EXPECT_EQ(__futex_wait(&value, 0, nullptr), 0);
  });

  while (!waiting.load(std::memory_order_acquire)) std::this_thread::yield();
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  value = 1;
  EXPECT_GE(__futex_wake(&value, 1), 0);
  waiter.join();
}
