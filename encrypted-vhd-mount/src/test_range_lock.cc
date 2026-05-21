// Unit tests for RangeLock
// Tests concurrent shared locks, overlapping exclusive lock blocking,
// and non-overlapping exclusive lock concurrency.
//
// Requirements: 2.4, 1.4

#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "range_lock.h"

namespace {

using evhd::RangeLock;
using Clock = std::chrono::high_resolution_clock;

int g_passed = 0;
int g_failed = 0;

void check(bool condition, const char* testName) {
  if (condition) {
    std::cout << "  [PASS] " << testName << "\n";
    g_passed++;
  } else {
    std::cout << "  [FAIL] " << testName << "\n";
    g_failed++;
  }
}

// ============================================================================
// TEST 1: Concurrent shared locks on non-overlapping ranges succeed
// Multiple threads acquire shared locks on different ranges simultaneously.
// None should block.
// ============================================================================
void testConcurrentSharedNonOverlapping() {
  std::cout << "\n=== TEST 1: Concurrent shared locks on non-overlapping ranges ===\n";

  RangeLock rl;
  constexpr int kThreads = 8;
  constexpr uint64_t kBlockSize = 4096;

  std::atomic<int> readyCount{0};
  std::atomic<bool> go{false};
  std::atomic<int> lockedCount{0};
  std::vector<double> lockTimes(kThreads, 0.0);

  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&, t]() {
      uint64_t offset = static_cast<uint64_t>(t) * kBlockSize;

      readyCount.fetch_add(1, std::memory_order_release);
      while (!go.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }

      auto start = Clock::now();
      rl.lock(offset, kBlockSize, RangeLock::Mode::Shared);
      auto end = Clock::now();

      lockTimes[t] = std::chrono::duration<double, std::milli>(end - start).count();
      lockedCount.fetch_add(1, std::memory_order_release);

      // Hold the lock briefly to ensure all threads overlap in time
      std::this_thread::sleep_for(std::chrono::milliseconds(50));

      rl.unlock(offset, kBlockSize, RangeLock::Mode::Shared);
    });
  }

  // Wait for all threads to be ready, then release them simultaneously
  while (readyCount.load(std::memory_order_acquire) < kThreads) {
    std::this_thread::yield();
  }
  go.store(true, std::memory_order_release);

  for (auto& th : threads) th.join();

  // All threads should have acquired locks (non-overlapping shared = no blocking)
  check(lockedCount.load() == kThreads,
        "All threads acquired non-overlapping shared locks");

  // Lock acquisition should be fast (< 10ms each, since no blocking)
  double maxLockTime = 0;
  for (int t = 0; t < kThreads; ++t) {
    maxLockTime = std::max(maxLockTime, lockTimes[t]);
  }
  check(maxLockTime < 10.0,
        "Non-overlapping shared lock acquisition was fast (< 10ms)");
}

// ============================================================================
// TEST 2: Concurrent shared locks on OVERLAPPING ranges also succeed
// Shared locks should never block each other, even on the same range.
// ============================================================================
void testConcurrentSharedOverlapping() {
  std::cout << "\n=== TEST 2: Concurrent shared locks on overlapping ranges ===\n";

  RangeLock rl;
  constexpr int kThreads = 4;
  constexpr uint64_t kOffset = 0;
  constexpr uint64_t kLength = 4096;

  std::atomic<int> readyCount{0};
  std::atomic<bool> go{false};
  std::atomic<int> lockedCount{0};

  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&, t]() {
      (void)t;
      readyCount.fetch_add(1, std::memory_order_release);
      while (!go.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }

      rl.lock(kOffset, kLength, RangeLock::Mode::Shared);
      lockedCount.fetch_add(1, std::memory_order_release);

      // Hold lock to ensure overlap
      std::this_thread::sleep_for(std::chrono::milliseconds(50));

      rl.unlock(kOffset, kLength, RangeLock::Mode::Shared);
    });
  }

  while (readyCount.load(std::memory_order_acquire) < kThreads) {
    std::this_thread::yield();
  }
  go.store(true, std::memory_order_release);

  for (auto& th : threads) th.join();

  check(lockedCount.load() == kThreads,
        "All threads acquired overlapping shared locks concurrently");
}

// ============================================================================
// TEST 3: Overlapping exclusive locks block (second waits for first)
// ============================================================================
void testOverlappingExclusiveBlocks() {
  std::cout << "\n=== TEST 3: Overlapping exclusive locks block ===\n";

  RangeLock rl;
  constexpr uint64_t kOffset = 4096;
  constexpr uint64_t kLength = 4096;

  std::atomic<bool> firstLocked{false};
  std::atomic<bool> secondStarted{false};
  std::atomic<bool> secondLocked{false};

  // Thread 1: acquire exclusive lock and hold it
  std::thread t1([&]() {
    rl.lock(kOffset, kLength, RangeLock::Mode::Exclusive);
    firstLocked.store(true, std::memory_order_release);

    // Hold lock until thread 2 has started trying to acquire
    while (!secondStarted.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    // Hold a bit longer to ensure thread 2 is actually blocked
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Verify thread 2 is still blocked
    check(!secondLocked.load(std::memory_order_acquire),
          "Second exclusive lock is blocked while first is held");

    rl.unlock(kOffset, kLength, RangeLock::Mode::Exclusive);
  });

  // Thread 2: try to acquire overlapping exclusive lock (should block)
  std::thread t2([&]() {
    // Wait for thread 1 to acquire first
    while (!firstLocked.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }

    secondStarted.store(true, std::memory_order_release);

    // This should block until thread 1 releases
    rl.lock(kOffset, kLength, RangeLock::Mode::Exclusive);
    secondLocked.store(true, std::memory_order_release);

    rl.unlock(kOffset, kLength, RangeLock::Mode::Exclusive);
  });

  t1.join();
  t2.join();

  check(secondLocked.load(),
        "Second exclusive lock eventually acquired after first released");
}

// ============================================================================
// TEST 4: Non-overlapping exclusive locks pass concurrently
// Two threads acquire exclusive locks on different ranges — no blocking.
// ============================================================================
void testNonOverlappingExclusiveConcurrent() {
  std::cout << "\n=== TEST 4: Non-overlapping exclusive locks pass concurrently ===\n";

  RangeLock rl;
  constexpr uint64_t kBlock1Offset = 0;
  constexpr uint64_t kBlock2Offset = 8192;
  constexpr uint64_t kLength = 4096;

  std::atomic<int> readyCount{0};
  std::atomic<bool> go{false};
  std::atomic<int> lockedCount{0};
  std::atomic<bool> bothLockedSimultaneously{false};

  std::thread t1([&]() {
    readyCount.fetch_add(1, std::memory_order_release);
    while (!go.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }

    rl.lock(kBlock1Offset, kLength, RangeLock::Mode::Exclusive);
    lockedCount.fetch_add(1, std::memory_order_release);

    // Wait a bit and check if both are locked
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (lockedCount.load(std::memory_order_acquire) == 2) {
      bothLockedSimultaneously.store(true, std::memory_order_release);
    }

    rl.unlock(kBlock1Offset, kLength, RangeLock::Mode::Exclusive);
  });

  std::thread t2([&]() {
    readyCount.fetch_add(1, std::memory_order_release);
    while (!go.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }

    rl.lock(kBlock2Offset, kLength, RangeLock::Mode::Exclusive);
    lockedCount.fetch_add(1, std::memory_order_release);

    // Wait a bit and check if both are locked
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (lockedCount.load(std::memory_order_acquire) == 2) {
      bothLockedSimultaneously.store(true, std::memory_order_release);
    }

    rl.unlock(kBlock2Offset, kLength, RangeLock::Mode::Exclusive);
  });

  while (readyCount.load(std::memory_order_acquire) < 2) {
    std::this_thread::yield();
  }
  go.store(true, std::memory_order_release);

  t1.join();
  t2.join();

  check(lockedCount.load() == 2,
        "Both threads acquired non-overlapping exclusive locks");
  check(bothLockedSimultaneously.load(),
        "Non-overlapping exclusive locks were held simultaneously");
}

// ============================================================================
// TEST 5: Shared lock + overlapping exclusive lock blocks the exclusive
// ============================================================================
void testSharedBlocksOverlappingExclusive() {
  std::cout << "\n=== TEST 5: Shared lock blocks overlapping exclusive ===\n";

  RangeLock rl;
  constexpr uint64_t kOffset = 4096;
  constexpr uint64_t kLength = 4096;

  std::atomic<bool> sharedLocked{false};
  std::atomic<bool> exclusiveStarted{false};
  std::atomic<bool> exclusiveLocked{false};

  // Thread 1: acquire shared lock and hold it
  std::thread t1([&]() {
    rl.lock(kOffset, kLength, RangeLock::Mode::Shared);
    sharedLocked.store(true, std::memory_order_release);

    // Wait for exclusive thread to start trying
    while (!exclusiveStarted.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Exclusive should still be blocked
    check(!exclusiveLocked.load(std::memory_order_acquire),
          "Exclusive lock is blocked while shared lock is held on same range");

    rl.unlock(kOffset, kLength, RangeLock::Mode::Shared);
  });

  // Thread 2: try to acquire exclusive lock on same range (should block)
  std::thread t2([&]() {
    while (!sharedLocked.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }

    exclusiveStarted.store(true, std::memory_order_release);

    rl.lock(kOffset, kLength, RangeLock::Mode::Exclusive);
    exclusiveLocked.store(true, std::memory_order_release);

    rl.unlock(kOffset, kLength, RangeLock::Mode::Exclusive);
  });

  t1.join();
  t2.join();

  check(exclusiveLocked.load(),
        "Exclusive lock acquired after shared lock released");
}

// ============================================================================
// TEST 6: Exclusive lock blocks overlapping shared lock
// ============================================================================
void testExclusiveBlocksOverlappingShared() {
  std::cout << "\n=== TEST 6: Exclusive lock blocks overlapping shared ===\n";

  RangeLock rl;
  constexpr uint64_t kOffset = 4096;
  constexpr uint64_t kLength = 4096;

  std::atomic<bool> exclusiveLocked{false};
  std::atomic<bool> sharedStarted{false};
  std::atomic<bool> sharedLocked{false};

  // Thread 1: acquire exclusive lock and hold it
  std::thread t1([&]() {
    rl.lock(kOffset, kLength, RangeLock::Mode::Exclusive);
    exclusiveLocked.store(true, std::memory_order_release);

    // Wait for shared thread to start trying
    while (!sharedStarted.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Shared should still be blocked
    check(!sharedLocked.load(std::memory_order_acquire),
          "Shared lock is blocked while exclusive lock is held on same range");

    rl.unlock(kOffset, kLength, RangeLock::Mode::Exclusive);
  });

  // Thread 2: try to acquire shared lock on same range (should block)
  std::thread t2([&]() {
    while (!exclusiveLocked.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }

    sharedStarted.store(true, std::memory_order_release);

    rl.lock(kOffset, kLength, RangeLock::Mode::Shared);
    sharedLocked.store(true, std::memory_order_release);

    rl.unlock(kOffset, kLength, RangeLock::Mode::Shared);
  });

  t1.join();
  t2.join();

  check(sharedLocked.load(),
        "Shared lock acquired after exclusive lock released");
}

// ============================================================================
// TEST 7: RAII Guard auto-releases on destruction
// ============================================================================
void testRAIIGuard() {
  std::cout << "\n=== TEST 7: RAII Guard auto-releases ===\n";

  RangeLock rl;
  constexpr uint64_t kOffset = 0;
  constexpr uint64_t kLength = 4096;

  {
    auto guard = rl.guard(kOffset, kLength, RangeLock::Mode::Exclusive);
    // Lock is held here — tryLock on same range should fail
    bool acquired = rl.tryLock(kOffset, kLength, RangeLock::Mode::Exclusive);
    check(!acquired, "tryLock fails while RAII guard holds exclusive lock");
  }
  // Guard destroyed — lock should be released
  bool acquired = rl.tryLock(kOffset, kLength, RangeLock::Mode::Exclusive);
  check(acquired, "tryLock succeeds after RAII guard destroyed");
  if (acquired) {
    rl.unlock(kOffset, kLength, RangeLock::Mode::Exclusive);
  }
}

// ============================================================================
// TEST 8: Partially overlapping ranges conflict correctly
// ============================================================================
void testPartialOverlap() {
  std::cout << "\n=== TEST 8: Partially overlapping ranges conflict ===\n";

  RangeLock rl;

  // Lock [1000, 2000)
  rl.lock(1000, 1000, RangeLock::Mode::Exclusive);

  // [1500, 2500) overlaps — should fail
  bool overlap1 = rl.tryLock(1500, 1000, RangeLock::Mode::Exclusive);
  check(!overlap1, "Partially overlapping exclusive lock blocked (right overlap)");

  // [500, 1500) overlaps — should fail
  bool overlap2 = rl.tryLock(500, 1000, RangeLock::Mode::Exclusive);
  check(!overlap2, "Partially overlapping exclusive lock blocked (left overlap)");

  // [0, 1000) does NOT overlap — should succeed
  bool noOverlap1 = rl.tryLock(0, 1000, RangeLock::Mode::Exclusive);
  check(noOverlap1, "Adjacent range [0,1000) does not conflict with [1000,2000)");
  if (noOverlap1) rl.unlock(0, 1000, RangeLock::Mode::Exclusive);

  // [2000, 3000) does NOT overlap — should succeed
  bool noOverlap2 = rl.tryLock(2000, 1000, RangeLock::Mode::Exclusive);
  check(noOverlap2, "Adjacent range [2000,3000) does not conflict with [1000,2000)");
  if (noOverlap2) rl.unlock(2000, 1000, RangeLock::Mode::Exclusive);

  rl.unlock(1000, 1000, RangeLock::Mode::Exclusive);
}

} // namespace

int main() {
  std::cout << "[test-range-lock] RangeLock unit tests\n";

  testConcurrentSharedNonOverlapping();
  testConcurrentSharedOverlapping();
  testOverlappingExclusiveBlocks();
  testNonOverlappingExclusiveConcurrent();
  testSharedBlocksOverlappingExclusive();
  testExclusiveBlocksOverlappingShared();
  testRAIIGuard();
  testPartialOverlap();

  std::cout << "\n=== SUMMARY ===\n";
  std::cout << "[test-range-lock] " << g_passed << " passed, "
            << g_failed << " failed\n";

  if (g_failed == 0) {
    std::cout << "[test-range-lock] ALL TESTS PASSED\n";
    return 0;
  } else {
    std::cout << "[test-range-lock] SOME TESTS FAILED\n";
    return 1;
  }
}
