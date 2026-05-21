// Unit tests for JournalBatcher
// Tests: batch accumulation, threshold commit, single-write immediate commit,
//        commitNow() forces immediate commit, thread-safety.

#include "journal_batcher.h"

#include <iostream>
#include <cassert>
#include <thread>
#include <atomic>
#include <chrono>
#include <string>

using namespace evhd;

static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "[FAIL] " << msg << " (" << #cond << ")" << std::endl; \
        g_testsFailed++; \
        return; \
    } \
} while(0)

#define TEST_PASS(name) do { \
    std::cout << "[PASS] " << name << std::endl; \
    g_testsPassed++; \
} while(0)

// Helper: create a simple BatchTransaction with given data size.
static BatchTransaction makeTxn(size_t dataSize, uint64_t physOffset = 0) {
    BatchTransaction txn;
    txn.segments.push_back({physOffset, dataSize});
    txn.ciphertext.resize(dataSize, 0xAB);
    return txn;
}

// Helper: create a mock IO interface that tracks calls.
struct MockIO {
    std::atomic<int> writeJournalCount{0};
    std::atomic<int> flushJournalCount{0};
    std::atomic<int> writeMainCount{0};
    std::atomic<int> flushMainCount{0};
    std::atomic<int> clearJournalCount{0};
    std::atomic<int> totalTxnsCommitted{0};

    bool failWriteJournal{false};
    bool failFlushJournal{false};
    bool failWriteMain{false};
    bool failFlushMain{false};
    bool failClearJournal{false};

    JournalBatcherIO makeIO() {
        JournalBatcherIO io;
        io.writeJournalEntries = [this](const std::vector<BatchTransaction> &txns) -> bool {
            writeJournalCount++;
            totalTxnsCommitted += static_cast<int>(txns.size());
            return !failWriteJournal;
        };
        io.flushJournal = [this]() -> bool {
            flushJournalCount++;
            return !failFlushJournal;
        };
        io.writeMainData = [this](const std::vector<BatchTransaction> &txns) -> bool {
            writeMainCount++;
            return !failWriteMain;
        };
        io.flushMain = [this]() -> bool {
            flushMainCount++;
            return !failFlushMain;
        };
        io.clearJournal = [this]() -> bool {
            clearJournalCount++;
            return !failClearJournal;
        };
        return io;
    }
};

// Test 1: Single write is committed by the timer thread (fire-and-forget submit).
static void testSingleWriteImmediateCommit() {
    MockIO mock;
    JournalBatcherConfig config;
    config.maxBatchOps = 16;
    config.maxBatchBytes = 64 * 1024;
    config.timeout = std::chrono::milliseconds(5); // short timeout for quick commit

    JournalBatcher batcher(mock.makeIO(), config);

    bool ok = batcher.submit(makeTxn(4096));
    TEST_ASSERT(ok, "submit should succeed");

    // Fire-and-forget: submit returns immediately, commit happens via timer.
    // Wait for the timer to commit.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    TEST_ASSERT(mock.writeJournalCount == 1, "writeJournal should be called once");
    TEST_ASSERT(mock.flushJournalCount == 1, "flushJournal should be called once");
    TEST_ASSERT(mock.writeMainCount == 1, "writeMain should be called once");
    TEST_ASSERT(mock.flushMainCount == 1, "flushMain should be called once");
    TEST_ASSERT(mock.clearJournalCount == 1, "clearJournal should be called once");
    TEST_ASSERT(mock.totalTxnsCommitted == 1, "1 transaction should be committed");

    // No pending ops after commit.
    TEST_ASSERT(batcher.pendingOps() == 0, "no pending ops after commit");
    TEST_ASSERT(batcher.pendingBytes() == 0, "no pending bytes after commit");

    batcher.stop();
    TEST_PASS("testSingleWriteImmediateCommit");
}

// Test 2: Batch accumulation - multiple submits are batched together.
// We verify that multiple transactions submitted while a commit is in progress
// get batched and committed together (fewer total commit calls than transactions).
static void testBatchAccumulation() {
    std::atomic<int> commitCalls{0};
    std::atomic<int> totalTxns{0};
    std::atomic<bool> blockFirst{true};

    JournalBatcherConfig config;
    config.maxBatchOps = 100;           // high - won't trigger by count
    config.maxBatchBytes = 1024 * 1024; // high - won't trigger by size
    config.timeout = std::chrono::milliseconds(30); // timer will commit accumulated

    JournalBatcherIO io;
    io.writeJournalEntries = [&](const std::vector<BatchTransaction> &txns) -> bool {
        commitCalls++;
        totalTxns += static_cast<int>(txns.size());
        if (blockFirst.exchange(false)) {
            // Block the first commit to allow other threads to accumulate.
            std::this_thread::sleep_for(std::chrono::milliseconds(60));
        }
        return true;
    };
    io.flushJournal = [&]() -> bool { return true; };
    io.writeMainData = [&](const std::vector<BatchTransaction> &) -> bool { return true; };
    io.flushMain = [&]() -> bool { return true; };
    io.clearJournal = [&]() -> bool { return true; };

    JournalBatcher batcher(io, config);

    // Submit first transaction - it will start committing and block for 60ms.
    std::thread t1([&] { batcher.submit(makeTxn(4096, 0)); });

    // Give it time to enter the commit.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Now submit more transactions - they should accumulate while first is committing.
    std::thread t2([&] { batcher.submit(makeTxn(4096, 4096)); });
    std::thread t3([&] { batcher.submit(makeTxn(4096, 8192)); });

    t1.join();
    t2.join();
    t3.join();

    batcher.stop();

    // All 3 transactions should have been committed.
    TEST_ASSERT(totalTxns >= 3, "all 3 transactions should be committed");
    // The batch should have been committed in fewer calls than transactions
    // (first commit has 1 txn, second commit has 2 txns batched together).
    TEST_ASSERT(commitCalls <= 3, "batching should reduce commit calls");

    TEST_PASS("testBatchAccumulation");
}

// Test 3: Threshold triggers commit (ops count).
static void testOpsThresholdTriggersCommit() {
    std::atomic<int> totalCommitted{0};
    std::atomic<bool> blockFirst{true};

    JournalBatcherConfig config;
    config.maxBatchOps = 4;             // low threshold for testing
    config.maxBatchBytes = 1024 * 1024; // high - won't trigger
    config.timeout = std::chrono::milliseconds(5000); // long - won't trigger

    JournalBatcherIO io;
    io.writeJournalEntries = [&](const std::vector<BatchTransaction> &txns) -> bool {
        totalCommitted += static_cast<int>(txns.size());
        if (blockFirst.exchange(false)) {
            // Block the first commit to allow accumulation.
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return true;
    };
    io.flushJournal = [&]() -> bool { return true; };
    io.writeMainData = [&](const std::vector<BatchTransaction> &) -> bool { return true; };
    io.flushMain = [&]() -> bool { return true; };
    io.clearJournal = [&]() -> bool { return true; };

    JournalBatcher batcher(io, config);

    // Submit first - will start committing and block for 50ms.
    std::thread t0([&] { batcher.submit(makeTxn(1024, 0)); });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Submit 4 more while first is committing - reaches threshold of 4.
    std::vector<std::thread> threads;
    for (int i = 1; i <= 4; i++) {
        threads.emplace_back([&, i] {
            batcher.submit(makeTxn(1024, static_cast<uint64_t>(i) * 4096));
        });
    }

    t0.join();
    for (auto &t : threads) t.join();
    batcher.stop();

    // All 5 transactions should have been committed.
    TEST_ASSERT(totalCommitted >= 5, "all 5 transactions committed, got " + std::to_string(totalCommitted.load()));

    TEST_PASS("testOpsThresholdTriggersCommit");
}

// Test 4: Size threshold triggers commit (bytes).
static void testSizeThresholdTriggersCommit() {
    std::atomic<int> totalCommitted{0};
    std::atomic<bool> blockFirst{true};

    JournalBatcherConfig config;
    config.maxBatchOps = 1000;          // high - won't trigger
    config.maxBatchBytes = 16 * 1024;   // 16 KiB threshold for testing
    config.timeout = std::chrono::milliseconds(5000); // long - won't trigger

    JournalBatcherIO io;
    io.writeJournalEntries = [&](const std::vector<BatchTransaction> &txns) -> bool {
        totalCommitted += static_cast<int>(txns.size());
        if (blockFirst.exchange(false)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return true;
    };
    io.flushJournal = [&]() -> bool { return true; };
    io.writeMainData = [&](const std::vector<BatchTransaction> &) -> bool { return true; };
    io.flushMain = [&]() -> bool { return true; };
    io.clearJournal = [&]() -> bool { return true; };

    JournalBatcher batcher(io, config);

    // Submit first (8 KiB) - will start committing and block.
    std::thread t0([&] { batcher.submit(makeTxn(8192, 0)); });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Submit more 8 KiB writes - should trigger threshold (>= 16 KiB).
    std::vector<std::thread> threads;
    for (int i = 1; i <= 3; i++) {
        threads.emplace_back([&, i] {
            batcher.submit(makeTxn(8192, static_cast<uint64_t>(i) * 8192));
        });
    }

    t0.join();
    for (auto &t : threads) t.join();
    batcher.stop();

    TEST_ASSERT(totalCommitted >= 4, "all transactions committed after size threshold, got " + std::to_string(totalCommitted.load()));

    TEST_PASS("testSizeThresholdTriggersCommit");
}

// Test 5: commitNow() forces immediate commit.
static void testCommitNowForcesCommit() {
    MockIO mock;
    JournalBatcherConfig config;
    config.maxBatchOps = 1000;
    config.maxBatchBytes = 1024 * 1024;
    config.timeout = std::chrono::milliseconds(5000); // long - won't trigger

    std::atomic<int> totalCommitted{0};
    std::atomic<bool> blockFirst{true};

    JournalBatcherIO io;
    io.writeJournalEntries = [&](const std::vector<BatchTransaction> &txns) -> bool {
        if (blockFirst.load()) {
            blockFirst.store(false);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        totalCommitted += static_cast<int>(txns.size());
        return true;
    };
    io.flushJournal = [&]() -> bool { return true; };
    io.writeMainData = [&](const std::vector<BatchTransaction> &) -> bool { return true; };
    io.flushMain = [&]() -> bool { return true; };
    io.clearJournal = [&]() -> bool { return true; };

    JournalBatcher batcher(io, config);

    // Submit first - will commit immediately (QD=1) and block.
    std::thread t0([&] { batcher.submit(makeTxn(4096, 0)); });
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    // Submit more while first is committing.
    std::thread t1([&] { batcher.submit(makeTxn(4096, 4096)); });
    std::thread t2([&] { batcher.submit(makeTxn(4096, 8192)); });
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    // commitNow should force commit of pending.
    std::thread tFlush([&] { batcher.commitNow(); });

    t0.join();
    t1.join();
    t2.join();
    tFlush.join();

    TEST_ASSERT(totalCommitted >= 3, "commitNow should commit all pending");
    TEST_ASSERT(batcher.pendingOps() == 0, "no pending after commitNow");

    batcher.stop();
    TEST_PASS("testCommitNowForcesCommit");
}

// Test 6: Timeout triggers commit.
static void testTimeoutTriggersCommit() {
    std::atomic<int> totalCommitted{0};
    std::atomic<bool> blockFirst{true};

    JournalBatcherConfig config;
    config.maxBatchOps = 1000;
    config.maxBatchBytes = 1024 * 1024;
    config.timeout = std::chrono::milliseconds(30); // short timeout

    JournalBatcherIO io;
    io.writeJournalEntries = [&](const std::vector<BatchTransaction> &txns) -> bool {
        totalCommitted += static_cast<int>(txns.size());
        if (blockFirst.exchange(false)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
        }
        return true;
    };
    io.flushJournal = [&]() -> bool { return true; };
    io.writeMainData = [&](const std::vector<BatchTransaction> &) -> bool { return true; };
    io.flushMain = [&]() -> bool { return true; };
    io.clearJournal = [&]() -> bool { return true; };

    JournalBatcher batcher(io, config);

    // Submit first - will commit immediately (QD=1) and block for 80ms.
    std::thread t0([&] { batcher.submit(makeTxn(4096, 0)); });
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Submit more while first is committing.
    std::thread t1([&] { batcher.submit(makeTxn(4096, 4096)); });
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    std::thread t2([&] { batcher.submit(makeTxn(4096, 8192)); });

    t0.join();
    t1.join();
    t2.join();
    batcher.stop();

    // After timeout, all should be committed.
    TEST_ASSERT(totalCommitted >= 3, "timeout should trigger commit of pending, got " + std::to_string(totalCommitted.load()));

    TEST_PASS("testTimeoutTriggersCommit");
}

// Test 7: Thread-safety under concurrent submissions.
static void testConcurrentSubmissions() {
    MockIO mock;
    JournalBatcherConfig config;
    config.maxBatchOps = 8;
    config.maxBatchBytes = 64 * 1024;
    config.timeout = std::chrono::milliseconds(5);

    std::atomic<int> totalCommitted{0};

    JournalBatcherIO io;
    io.writeJournalEntries = [&](const std::vector<BatchTransaction> &txns) -> bool {
        totalCommitted += static_cast<int>(txns.size());
        return true;
    };
    io.flushJournal = [&]() -> bool { return true; };
    io.writeMainData = [&](const std::vector<BatchTransaction> &) -> bool { return true; };
    io.flushMain = [&]() -> bool { return true; };
    io.clearJournal = [&]() -> bool { return true; };

    JournalBatcher batcher(io, config);

    const int numThreads = 8;
    const int opsPerThread = 20;
    std::vector<std::thread> threads;
    std::atomic<int> failures{0};

    for (int t = 0; t < numThreads; t++) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < opsPerThread; i++) {
                uint64_t offset = static_cast<uint64_t>(t * opsPerThread + i) * 4096;
                if (!batcher.submit(makeTxn(4096, offset))) {
                    failures++;
                }
            }
        });
    }

    for (auto &t : threads) t.join();
    batcher.stop();

    int expected = numThreads * opsPerThread;
    TEST_ASSERT(failures == 0, "no submission failures");
    TEST_ASSERT(totalCommitted == expected,
                "all " + std::to_string(expected) + " transactions committed, got " +
                std::to_string(totalCommitted.load()));

    TEST_PASS("testConcurrentSubmissions");
}

// Test 8: WAL semantics - journal is written before main data.
static void testWALSemantics() {
    std::vector<std::string> callOrder;
    std::mutex orderMutex;

    JournalBatcherIO io;
    io.writeJournalEntries = [&](const std::vector<BatchTransaction> &) -> bool {
        std::lock_guard<std::mutex> lock(orderMutex);
        callOrder.push_back("writeJournal");
        return true;
    };
    io.flushJournal = [&]() -> bool {
        std::lock_guard<std::mutex> lock(orderMutex);
        callOrder.push_back("flushJournal");
        return true;
    };
    io.writeMainData = [&](const std::vector<BatchTransaction> &) -> bool {
        std::lock_guard<std::mutex> lock(orderMutex);
        callOrder.push_back("writeMain");
        return true;
    };
    io.flushMain = [&]() -> bool {
        std::lock_guard<std::mutex> lock(orderMutex);
        callOrder.push_back("flushMain");
        return true;
    };
    io.clearJournal = [&]() -> bool {
        std::lock_guard<std::mutex> lock(orderMutex);
        callOrder.push_back("clearJournal");
        return true;
    };

    JournalBatcherConfig config;
    config.timeout = std::chrono::milliseconds(100);
    JournalBatcher batcher(io, config);

    batcher.submit(makeTxn(4096));
    batcher.stop();

    // Verify WAL order: journal write → journal flush → main write → main flush → clear
    TEST_ASSERT(callOrder.size() == 5, "5 I/O operations in commit sequence");
    TEST_ASSERT(callOrder[0] == "writeJournal", "step 1: write journal entries");
    TEST_ASSERT(callOrder[1] == "flushJournal", "step 2: flush journal");
    TEST_ASSERT(callOrder[2] == "writeMain", "step 3: write main data");
    TEST_ASSERT(callOrder[3] == "flushMain", "step 4: flush main");
    TEST_ASSERT(callOrder[4] == "clearJournal", "step 5: clear journal state");

    TEST_PASS("testWALSemantics");
}

// Test 9: Error propagation - failure in I/O callback propagates via commitNow.
// With fire-and-forget submit, errors are detected through commitNow() or stop().
static void testErrorPropagation() {
    MockIO mock;
    mock.failFlushJournal = true;

    JournalBatcherConfig config;
    config.timeout = std::chrono::milliseconds(5000); // long timeout - won't trigger

    JournalBatcher batcher(mock.makeIO(), config);

    // Submit succeeds (fire-and-forget).
    bool ok = batcher.submit(makeTxn(4096));
    TEST_ASSERT(ok, "submit should succeed (fire-and-forget)");

    // commitNow should detect the failure.
    bool commitOk = batcher.commitNow();
    TEST_ASSERT(!commitOk, "commitNow should fail when flushJournal fails");

    batcher.stop();
    TEST_PASS("testErrorPropagation");
}

int main() {
    std::cout << "=== JournalBatcher Unit Tests ===" << std::endl;

    testSingleWriteImmediateCommit();
    testBatchAccumulation();
    testOpsThresholdTriggersCommit();
    testSizeThresholdTriggersCommit();
    testCommitNowForcesCommit();
    testTimeoutTriggersCommit();
    testConcurrentSubmissions();
    testWALSemantics();
    testErrorPropagation();

    std::cout << "\n=== Results: " << g_testsPassed << " passed, "
              << g_testsFailed << " failed ===" << std::endl;

    if (g_testsFailed > 0) {
        std::cerr << "[FAIL] Some tests failed!" << std::endl;
        return 1;
    }
    std::cout << "[OK] All tests passed." << std::endl;
    return 0;
}
