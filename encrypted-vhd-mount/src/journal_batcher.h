// Part of encrypted-vhd-mount
// JournalBatcher: group-commit journal batching to reduce FlushFileBuffers calls.
//
// Instead of 3-4 flushes per 4 KiB write, the batcher accumulates pending
// transactions and commits them as a batch with only 2 flushes total
// (1 journal + 1 main container), amortized across N writes.

#pragma once

#include <cstdint>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <chrono>
#include <thread>
#include <atomic>

namespace evhd {

// A single pending write transaction: physical segments + encrypted data.
struct BatchTransaction {
    // Physical segments to write (offset, length pairs)
    struct Segment {
        uint64_t physOffset;
        uint64_t length;
    };
    std::vector<Segment> segments;
    std::vector<uint8_t> ciphertext;  // encrypted data for all segments
};

// Callback interface for actual I/O operations.
// This allows unit testing without real file I/O.
struct JournalBatcherIO {
    // Write all journal entries for a batch atomically.
    // segments: list of (physOffset, length, dataOffset) tuples
    // ciphertext: concatenated encrypted data
    // Returns true on success.
    std::function<bool(const std::vector<BatchTransaction> &transactions)> writeJournalEntries;

    // Flush the journal file handle (single FlushFileBuffers call).
    std::function<bool()> flushJournal;

    // Write encrypted data to the main container at the given physical offsets.
    std::function<bool(const std::vector<BatchTransaction> &transactions)> writeMainData;

    // Flush the main container file handle (single FlushFileBuffers call).
    std::function<bool()> flushMain;

    // Clear journal state after successful commit.
    std::function<bool()> clearJournal;
};

// Configuration for the batcher.
struct JournalBatcherConfig {
    size_t maxBatchBytes = 64 * 1024;   // 64 KiB threshold
    size_t maxBatchOps = 16;            // 16 operations threshold
    std::chrono::milliseconds timeout{1}; // 1 ms timeout
};

// JournalBatcher accumulates write transactions and commits them as a group.
//
// Group commit sequence:
//   1. Write all journal entries atomically
//   2. Single FlushFileBuffers(journal)
//   3. Write all data to main container
//   4. Single FlushFileBuffers(main)
//   5. Clear journal state
//
// Special cases:
//   - QD=1 (single outstanding write with no other pending): immediate commit
//   - Explicit flush (commitNow): immediate batch commit
//   - Threshold reached: automatic commit
//   - Timeout expired: automatic commit
class JournalBatcher {
public:
    explicit JournalBatcher(JournalBatcherIO io, JournalBatcherConfig config = {});
    ~JournalBatcher();

    // Submit a write transaction to the batch.
    // If this is the only pending transaction (QD=1), commits immediately.
    // Otherwise, accumulates and may trigger a group commit if thresholds are met.
    // Returns true on success (transaction committed or queued and committed).
    // Thread-safe: multiple threads can call submit() concurrently.
    bool submit(BatchTransaction txn);

    // Force immediate commit of all pending transactions.
    // Called by Dokan FlushFileBuffers callback to preserve explicit fsync semantics.
    // Thread-safe.
    bool commitNow();

    // Stop the background timer thread (called on shutdown).
    void stop();

    // Query current batch state (for testing).
    size_t pendingOps() const;
    size_t pendingBytes() const;

private:
    // Execute group commit for all pending transactions.
    // Caller must hold m_mutex.
    bool commitBatch(std::unique_lock<std::mutex> &lock);

    // Check if batch thresholds are met.
    bool thresholdReached() const;

    // Timer thread function.
    void timerLoop();

    JournalBatcherIO m_io;
    JournalBatcherConfig m_config;

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;          // signals waiters that commit completed
    std::condition_variable m_timerCv;     // signals timer thread

    std::vector<BatchTransaction> m_pending;
    size_t m_pendingBytes{0};

    // Commit generation: incremented after each successful commit.
    // Waiters compare their submit generation to know if their txn was committed.
    uint64_t m_commitGeneration{0};
    uint64_t m_submitGeneration{0};

    std::atomic<bool> m_running{true};
    std::thread m_timerThread;

    // Track if a commit is currently in progress (to avoid re-entrant commits).
    bool m_committing{false};
};

} // namespace evhd
