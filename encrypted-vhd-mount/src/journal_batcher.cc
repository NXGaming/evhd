// Part of encrypted-vhd-mount

#include "journal_batcher.h"

namespace evhd {

JournalBatcher::JournalBatcher(JournalBatcherIO io, JournalBatcherConfig config)
    : m_io(std::move(io)), m_config(config) {
    // Timer thread is started lazily on first submit to avoid consuming
    // a thread slot when no writes are happening (e.g., during read-only workloads).
}

JournalBatcher::~JournalBatcher() {
    stop();
}

void JournalBatcher::stop() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_running.load()) return;
        m_running.store(false);
    }
    m_timerCv.notify_all();
    m_cv.notify_all();
    if (m_timerThread.joinable()) {
        m_timerThread.join();
    }
    // Commit any remaining pending transactions.
    std::unique_lock<std::mutex> lock(m_mutex);
    if (!m_pending.empty()) {
        commitBatch(lock);
    }
}

bool JournalBatcher::submit(BatchTransaction txn) {
    std::unique_lock<std::mutex> lock(m_mutex);

    // Lazily start the timer thread on first submit.
    if (!m_timerThread.joinable() && m_running.load()) {
        m_timerThread = std::thread(&JournalBatcher::timerLoop, this);
    }

    // Backpressure: if pending data exceeds limit, wait for a commit to drain.
    // This prevents unbounded memory growth when writes outpace disk I/O.
    if (m_pendingBytes >= m_config.maxPendingBytes) {
        m_timerCv.notify_one(); // wake timer to commit now
        m_cv.wait(lock, [&] {
            return m_pendingBytes < m_config.maxPendingBytes || !m_running.load();
        });
        if (!m_running.load()) return false;
    }

    // Calculate the size of this transaction.
    size_t txnBytes = txn.ciphertext.size();

    // Add to pending batch.
    m_pending.push_back(std::move(txn));
    m_pendingBytes += txnBytes;
    m_submitGeneration++;

    // Wake up the timer thread to handle the commit.
    // The timer thread will commit when threshold is reached or timeout expires.
    m_timerCv.notify_one();

    // Fire-and-forget: return immediately without waiting for commit.
    // Durability is guaranteed by:
    //   - Dokan FlushFileBuffers callback → commitNow()
    //   - Container::close() → batcher stop() → final commit
    //   - Timer-triggered commits (threshold or timeout)
    // This eliminates per-write flush overhead for sequential single-threaded writes.
    return true;
}

bool JournalBatcher::commitNow() {
    std::unique_lock<std::mutex> lock(m_mutex);
    if (m_pending.empty()) return true;

    // Wait if another commit is in progress.
    m_cv.wait(lock, [&] { return !m_committing; });

    if (m_pending.empty()) return true;
    return commitBatch(lock);
}

size_t JournalBatcher::pendingOps() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pending.size();
}

size_t JournalBatcher::pendingBytes() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pendingBytes;
}

bool JournalBatcher::commitBatch(std::unique_lock<std::mutex> &lock) {
    if (m_pending.empty()) return true;

    m_committing = true;

    // Move pending transactions out so we can release the lock during I/O.
    std::vector<BatchTransaction> batch = std::move(m_pending);
    m_pending.clear();
    size_t batchedBytes = m_pendingBytes;
    m_pendingBytes = 0;

    // Record the generation that this batch covers.
    uint64_t batchGeneration = m_submitGeneration;

    // Release lock during I/O operations (allows new submissions to queue up).
    lock.unlock();

    // Group commit sequence:
    // 1. Write all journal entries atomically
    bool ok = m_io.writeJournalEntries(batch);

    // 2. Single FlushFileBuffers(journal)
    if (ok) ok = m_io.flushJournal();

    // 3. Write all data to main container
    if (ok) ok = m_io.writeMainData(batch);

    // 4. Single FlushFileBuffers(main)
    if (ok) ok = m_io.flushMain();

    // 5. Clear journal state
    if (ok) ok = m_io.clearJournal();

    // Re-acquire lock and update generation.
    lock.lock();
    m_committing = false;

    if (ok) {
        m_commitGeneration = batchGeneration;
    }

    // Wake all waiters.
    m_cv.notify_all();

    // If new transactions accumulated while we were committing, commit them too.
    // They've already been batched during the previous commit's I/O time.
    if (ok && !m_pending.empty()) {
        return commitBatch(lock);
    }

    return ok;
}

bool JournalBatcher::thresholdReached() const {
    return m_pending.size() >= m_config.maxBatchOps ||
           m_pendingBytes >= m_config.maxBatchBytes;
}

void JournalBatcher::timerLoop() {
    std::unique_lock<std::mutex> lock(m_mutex);
    while (m_running.load()) {
        // Wait until there are pending transactions or we're shutting down.
        m_timerCv.wait(lock, [&] {
            return !m_pending.empty() || !m_running.load();
        });

        if (!m_running.load()) break;
        if (m_pending.empty()) continue;

        // If threshold is already reached, commit immediately.
        if (thresholdReached() && !m_committing) {
            commitBatch(lock);
            continue;
        }

        // Wait for the configured timeout or until threshold is reached.
        auto deadline = std::chrono::steady_clock::now() + m_config.timeout;
        m_timerCv.wait_until(lock, deadline, [&] {
            // Wake early if batch was already committed, threshold reached, or shutting down.
            return m_pending.empty() || thresholdReached() || !m_running.load();
        });

        if (!m_running.load()) break;

        // If there are still pending transactions after timeout/threshold, commit them.
        if (!m_pending.empty() && !m_committing) {
            commitBatch(lock);
        }
    }
}

} // namespace evhd
