// Bug Condition Exploration Test
// Property 1: 并发场景下 4K 随机 I/O 被串行化
//
// 此测试在未修复代码上必须失败 — 失败即确认 bug 存在。
// 不要在测试失败时尝试修复测试或代码。
// 修复实现后测试通过即验证 bug 已解决。
//
// 目标：产出反例，证明全局互斥锁将并发 I/O 串行化，
//       且每次写入的多次刷盘限制了吞吐。

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "evhd.h"

namespace {

using evhd::Container;
using Clock = std::chrono::high_resolution_clock;

constexpr wchar_t kPassword[] = L"selftest-pass";
constexpr size_t kBlockSize = 4096;

// Test container size: 4 MiB plaintext (enough for non-overlapping 4K offsets)
constexpr uint64_t kContainerSize = 4ULL * 1024 * 1024;

// Test duration for throughput measurements
constexpr int kTestDurationMs = 3000;

// Thresholds for assertions (these encode EXPECTED behavior after fix)
// On unfixed code, these will FAIL — confirming the bug exists.
constexpr double kReadScalingFactor = 1.5;   // 4-thread total IOPS > 1.5x single-thread
constexpr double kScalability8xFactor = 3.0; // 8-thread total IOPS > 3x single-thread
constexpr double kMaxWriteLatencyUs = 20.0;  // target avg write latency < 20 µs

struct ThreadResult {
  uint64_t opsCompleted = 0;
  uint64_t bytesTransferred = 0;
  double elapsedMs = 0.0;
};

// Create a test .evhd container using the selftest infrastructure
std::filesystem::path createTestContainer(const std::filesystem::path& dir) {
  auto plainPath = dir / L"bug-condition-test.vhd";
  auto encPath = dir / L"bug-condition-test.evhd";

  // Create a plaintext VHD file with known pattern
  std::vector<uint8_t> plain(static_cast<size_t>(kContainerSize));
  // Fill with deterministic pattern
  std::mt19937 rng(42);
  for (size_t i = 0; i < plain.size(); i += 4) {
    uint32_t val = rng();
    size_t remaining = std::min<size_t>(4, plain.size() - i);
    memcpy(plain.data() + i, &val, remaining);
  }
  // MBR signature for valid VHD
  plain[510] = 0x55;
  plain[511] = 0xAA;
  plain[446 + 4] = 0x07; // NTFS partition type
  plain[446 + 8] = 0x20;
  plain[446 + 12] = 0x40;

  std::ofstream out(plainPath, std::ios::binary | std::ios::trunc);
  if (!out.is_open()) {
    std::wcerr << L"[bug-test] Failed to create plain VHD file\n";
    return {};
  }
  out.write(reinterpret_cast<const char*>(plain.data()),
            static_cast<std::streamsize>(plain.size()));
  out.close();

  Container c;
  if (!c.createFromPlainVhd(plainPath.wstring(), encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[bug-test] createFromPlainVhd failed\n";
    return {};
  }
  c.close();

  return encPath;
}

// Measure single-thread 4K random read IOPS
ThreadResult measureSingleThreadReadIOPS(Container& container, int durationMs) {
  ThreadResult result;
  const uint64_t maxOffset = kContainerSize - kBlockSize;
  std::mt19937_64 rng(12345);
  std::uniform_int_distribution<uint64_t> dist(0, maxOffset / kBlockSize);

  std::vector<uint8_t> buf(kBlockSize);
  auto start = Clock::now();
  auto deadline = start + std::chrono::milliseconds(durationMs);

  while (Clock::now() < deadline) {
    uint64_t offset = dist(rng) * kBlockSize;
    if (container.readPlain(offset, buf.data(), kBlockSize)) {
      result.opsCompleted++;
      result.bytesTransferred += kBlockSize;
    }
  }

  auto end = Clock::now();
  result.elapsedMs = std::chrono::duration<double, std::milli>(end - start).count();
  return result;
}

// ============================================================================
// TEST 1: Read Concurrency Test
// Launch 4 threads, each with QD=8 (simulated via sequential reads in tight loop)
// reading non-overlapping 4K offsets.
// Assert: all threads contribute non-zero bytes AND total IOPS > 1.5x single-thread
// ============================================================================
bool testReadConcurrency(Container& container) {
  std::wcout << L"\n=== TEST 1: Read Concurrency (4 threads) ===\n";

  // First measure single-thread baseline
  std::wcout << L"  Measuring single-thread baseline...\n";
  auto baseline = measureSingleThreadReadIOPS(container, kTestDurationMs);
  double baselineIOPS = baseline.opsCompleted / (baseline.elapsedMs / 1000.0);
  std::wcout << L"  Single-thread: " << baseline.opsCompleted << L" ops in "
             << baseline.elapsedMs << L" ms = " << baselineIOPS << L" IOPS\n";

  // Now measure 4-thread concurrent reads
  constexpr int kThreadCount = 4;
  std::wcout << L"  Measuring " << kThreadCount << L"-thread concurrent reads...\n";

  std::vector<ThreadResult> threadResults(kThreadCount);
  std::vector<std::thread> threads;
  std::atomic<bool> go{false};

  // Each thread reads from a non-overlapping region of the container
  uint64_t regionSize = kContainerSize / kThreadCount;

  for (int t = 0; t < kThreadCount; ++t) {
    threads.emplace_back([&, t]() {
      uint64_t regionStart = t * regionSize;
      uint64_t regionEnd = regionStart + regionSize - kBlockSize;
      std::mt19937_64 rng(static_cast<uint64_t>(t * 1000 + 7));
      std::uniform_int_distribution<uint64_t> dist(
          regionStart / kBlockSize, regionEnd / kBlockSize);
      std::vector<uint8_t> buf(kBlockSize);

      // Wait for go signal
      while (!go.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }

      auto start = Clock::now();
      auto deadline = start + std::chrono::milliseconds(kTestDurationMs);

      while (Clock::now() < deadline) {
        uint64_t offset = dist(rng) * kBlockSize;
        if (container.readPlain(offset, buf.data(), kBlockSize)) {
          threadResults[t].opsCompleted++;
          threadResults[t].bytesTransferred += kBlockSize;
        }
      }

      auto end = Clock::now();
      threadResults[t].elapsedMs =
          std::chrono::duration<double, std::milli>(end - start).count();
    });
  }

  // Start all threads simultaneously
  go.store(true, std::memory_order_release);
  for (auto& th : threads) th.join();

  // Report results
  uint64_t totalOps = 0;
  uint64_t totalBytes = 0;
  double maxElapsed = 0;
  int threadsWithZeroBytes = 0;

  for (int t = 0; t < kThreadCount; ++t) {
    totalOps += threadResults[t].opsCompleted;
    totalBytes += threadResults[t].bytesTransferred;
    maxElapsed = std::max(maxElapsed, threadResults[t].elapsedMs);
    double threadIOPS = threadResults[t].opsCompleted /
                        (threadResults[t].elapsedMs / 1000.0);
    std::wcout << L"  Thread " << t << L": " << threadResults[t].opsCompleted
               << L" ops, " << threadResults[t].bytesTransferred << L" bytes, "
               << threadIOPS << L" IOPS\n";
    if (threadResults[t].bytesTransferred == 0) {
      threadsWithZeroBytes++;
    }
  }

  double totalIOPS = totalOps / (maxElapsed / 1000.0);
  double scalingRatio = totalIOPS / baselineIOPS;
  std::wcout << L"  Total: " << totalOps << L" ops, " << totalIOPS << L" IOPS" << std::endl;
  std::wcout << L"  Scaling ratio (multi/single): " << scalingRatio << L"x" << std::endl;
  std::wcout << L"  Threads with zero bytes: " << threadsWithZeroBytes << std::endl;

  // ASSERTIONS (encode expected behavior — will FAIL on unfixed code)
  bool allThreadsContribute = (threadsWithZeroBytes == 0);
  bool scalesWithConcurrency = (scalingRatio >= kReadScalingFactor);

  if (!allThreadsContribute) {
    std::wcout << L"  [FAIL] Not all threads contributed non-zero bytes!\n";
    std::wcout << L"         Counterexample: " << kThreadCount << L" threads x QD=8 read: "
               << threadsWithZeroBytes << L" threads contributed 0 bytes\n";
  }
  if (!scalesWithConcurrency) {
    std::wcout << L"  [FAIL] Total IOPS did not scale with concurrency!\n";
    std::wcout << L"         Counterexample: " << kThreadCount << L"-thread total IOPS = "
               << totalIOPS << L", single-thread = " << baselineIOPS
               << L", ratio = " << scalingRatio << L"x (need >= "
               << kReadScalingFactor << L"x)\n";
  }

  bool passed = allThreadsContribute && scalesWithConcurrency;
  std::wcout << L"  Result: " << (passed ? L"PASS" : L"FAIL") << L"\n";
  return passed;
}

// ============================================================================
// TEST 2: Write Flush Overhead Test
// Issue 256 sequential 4K writes, measure wall-clock time.
// Assert: average write latency < 20 µs (target for NVMe with batched flushes)
// On unfixed code: expect ~40+ µs per write due to 3-4 FlushFileBuffers calls
// ============================================================================
bool testWriteFlushOverhead(Container& container) {
  std::wcout << L"\n=== TEST 2: Write Flush Overhead (256 x 4K writes) ===\n";

  constexpr int kWriteCount = 256;
  std::vector<uint8_t> data(kBlockSize);
  std::mt19937 rng(99);
  for (auto& b : data) b = static_cast<uint8_t>(rng() & 0xFF);

  // Sequential writes to non-overlapping offsets starting at offset 512K
  // (avoid relocation regions at the beginning)
  const uint64_t startOffset = 512 * 1024;

  auto start = Clock::now();
  for (int i = 0; i < kWriteCount; ++i) {
    uint64_t offset = startOffset + static_cast<uint64_t>(i) * kBlockSize;
    if (!container.writePlain(offset, data.data(), kBlockSize)) {
      std::wcerr << L"  [ERROR] writePlain failed at iteration " << i << L"\n";
      return false;
    }
  }
  auto end = Clock::now();

  double totalUs = std::chrono::duration<double, std::micro>(end - start).count();
  double avgLatencyUs = totalUs / kWriteCount;
  double writeIOPS = kWriteCount / (totalUs / 1e6);

  std::wcout << L"  Total time: " << totalUs << L" us for " << kWriteCount << L" writes" << std::endl;
  std::wcout << L"  Average write latency: " << avgLatencyUs << L" us" << std::endl;
  std::wcout << L"  Write IOPS: " << writeIOPS << std::endl;

  // ASSERTION: average write latency should be < 20 us with batched flushes
  // On unfixed code: each write does 3-4 FlushFileBuffers -> ~40-120+ us per write
  bool passed = (avgLatencyUs < kMaxWriteLatencyUs);

  if (!passed) {
    std::wcout << L"  [FAIL] Average write latency too high!" << std::endl;
    std::wcout << L"         Counterexample: " << kWriteCount << L" x 4K writes: avg latency = "
               << avgLatencyUs << L" us (threshold: < " << kMaxWriteLatencyUs << L" us)" << std::endl;
    std::wcout << L"         Estimated flushes per write: "
               << (avgLatencyUs / 10.0) << L" (assuming ~10 us per NVMe flush)" << std::endl;
  }

  std::wcout << L"  Result: " << (passed ? L"PASS" : L"FAIL") << std::endl;
  return passed;
}

// ============================================================================
// TEST 3: Concurrency Scaling Test
// Vary thread count from 1 → 4 → 8 for 4K random reads.
// Assert: 8-thread total IOPS > 3x single-thread IOPS
// ============================================================================
bool testConcurrencyScaling(Container& container) {
  std::wcout << L"\n=== TEST 3: Concurrency Scaling (1 -> 4 -> 8 threads) ===\n";

  auto measureNThreads = [&](int nThreads) -> double {
    std::vector<ThreadResult> results(nThreads);
    std::vector<std::thread> threads;
    std::atomic<bool> go{false};
    uint64_t regionSize = kContainerSize / nThreads;

    for (int t = 0; t < nThreads; ++t) {
      threads.emplace_back([&, t]() {
        uint64_t regionStart = t * regionSize;
        uint64_t regionEnd = regionStart + regionSize - kBlockSize;
        std::mt19937_64 rng(static_cast<uint64_t>(t * 777 + 13));
        std::uniform_int_distribution<uint64_t> dist(
            regionStart / kBlockSize, regionEnd / kBlockSize);
        std::vector<uint8_t> buf(kBlockSize);

        while (!go.load(std::memory_order_acquire)) {
          std::this_thread::yield();
        }

        auto start = Clock::now();
        auto deadline = start + std::chrono::milliseconds(kTestDurationMs);

        while (Clock::now() < deadline) {
          uint64_t offset = dist(rng) * kBlockSize;
          if (container.readPlain(offset, buf.data(), kBlockSize)) {
            results[t].opsCompleted++;
          }
        }

        auto end = Clock::now();
        results[t].elapsedMs =
            std::chrono::duration<double, std::milli>(end - start).count();
      });
    }

    go.store(true, std::memory_order_release);
    for (auto& th : threads) th.join();

    uint64_t totalOps = 0;
    double maxElapsed = 0;
    for (int t = 0; t < nThreads; ++t) {
      totalOps += results[t].opsCompleted;
      maxElapsed = std::max(maxElapsed, results[t].elapsedMs);
    }
    return totalOps / (maxElapsed / 1000.0);
  };

  double iops1 = measureNThreads(1);
  std::wcout << L"  1 thread:  " << iops1 << L" IOPS\n";

  double iops4 = measureNThreads(4);
  std::wcout << L"  4 threads: " << iops4 << L" IOPS\n";

  double iops8 = measureNThreads(8);
  std::wcout << L"  8 threads: " << iops8 << L" IOPS\n";

  double scaling4x = iops4 / iops1;
  double scaling8x = iops8 / iops1;
  std::wcout << L"  Scaling 4x: " << scaling4x << L"x\n";
  std::wcout << L"  Scaling 8x: " << scaling8x << L"x\n";

  // ASSERTION: 8-thread IOPS > 3x single-thread IOPS
  bool passed = (scaling8x >= kScalability8xFactor);

  if (!passed) {
    std::wcout << L"  [FAIL] IOPS does not scale with thread count!\n";
    std::wcout << L"         Counterexample: 1-thread=" << iops1
               << L" IOPS, 4-thread=" << iops4
               << L" IOPS, 8-thread=" << iops8 << L" IOPS\n";
    std::wcout << L"         8x/1x ratio = " << scaling8x
               << L" (need >= " << kScalability8xFactor << L"x)\n";
  }

  std::wcout << L"  Result: " << (passed ? L"PASS" : L"FAIL") << L"\n";
  return passed;
}

} // namespace

int wmain() {
  std::wcout << L"[bug-condition-test] Starting bug condition exploration tests\n";
  std::wcout << L"[bug-condition-test] These tests encode EXPECTED behavior.\n";
  std::wcout << L"[bug-condition-test] On UNFIXED code, they should FAIL.\n\n";

  // Create test directory
  std::filesystem::path dir = std::filesystem::current_path() / L"bug_condition_tmp";
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);

  // Create test container
  std::wcout << L"Creating test container (" << (kContainerSize / 1024 / 1024)
             << L" MiB)...\n";
  auto encPath = createTestContainer(dir);
  if (encPath.empty()) {
    std::wcerr << L"[bug-condition-test] FATAL: Failed to create test container\n";
    return 1;
  }
  std::wcout << L"Container created: " << encPath.wstring() << L"\n";

  // Open container for testing
  Container container;
  if (!container.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[bug-condition-test] FATAL: Failed to open test container\n";
    return 1;
  }

  // Run tests
  int failures = 0;

  if (!testReadConcurrency(container)) failures++;
  if (!testWriteFlushOverhead(container)) failures++;
  if (!testConcurrencyScaling(container)) failures++;

  container.close();

  // Summary
  std::wcout << L"\n=== SUMMARY ===\n";
  if (failures == 0) {
    std::wcout << L"[bug-condition-test] ALL TESTS PASSED\n";
    std::wcout << L"  This means the bug has been FIXED (or was not present).\n";
  } else {
    std::wcout << L"[bug-condition-test] " << failures << L" TEST(S) FAILED\n";
    std::wcout << L"  This confirms the bug EXISTS on unfixed code.\n";
    std::wcout << L"  The counterexamples above demonstrate:\n";
    std::wcout << L"    - Global mutex serializes concurrent I/O\n";
    std::wcout << L"    - Per-write flush overhead limits write IOPS\n";
    std::wcout << L"    - Throughput does not scale with thread count\n";
  }

  return failures > 0 ? 1 : 0;
}
