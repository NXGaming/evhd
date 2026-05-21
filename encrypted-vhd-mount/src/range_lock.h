// Part of encrypted-vhd-mount
// RangeLock: lightweight interval-based lock manager
//
// Tracks active [offset, offset+length) intervals with shared (read) /
// exclusive (write) semantics. Non-overlapping shared locks never block
// each other. Exclusive locks only block when overlapping with existing locks.
//
// Requirements: 2.4, 1.4

#pragma once

#include <cstdint>
#include <condition_variable>
#include <mutex>
#include <vector>

namespace evhd {

class RangeLock {
public:
  enum class Mode { Shared, Exclusive };

  RangeLock() = default;
  ~RangeLock() = default;

  // Non-copyable, non-movable
  RangeLock(const RangeLock&) = delete;
  RangeLock& operator=(const RangeLock&) = delete;

  // Acquire a lock on [offset, offset+length). Blocks until the range is available.
  void lock(uint64_t offset, uint64_t length, Mode mode) {
    std::unique_lock<std::mutex> ul(m_mutex);
    m_cv.wait(ul, [&] { return !hasConflict(offset, length, mode); });
    m_entries.push_back({offset, length, mode});
  }

  // Try to acquire a lock without blocking. Returns true on success.
  bool tryLock(uint64_t offset, uint64_t length, Mode mode) {
    std::lock_guard<std::mutex> lg(m_mutex);
    if (hasConflict(offset, length, mode)) {
      return false;
    }
    m_entries.push_back({offset, length, mode});
    return true;
  }

  // Release a previously acquired lock on [offset, offset+length).
  void unlock(uint64_t offset, uint64_t length, Mode mode) {
    {
      std::lock_guard<std::mutex> lg(m_mutex);
      for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
        if (it->offset == offset && it->length == length && it->mode == mode) {
          m_entries.erase(it);
          break;
        }
      }
    }
    m_cv.notify_all();
  }

  // RAII guard for automatic unlock
  class Guard {
  public:
    Guard() : m_lock(nullptr), m_offset(0), m_length(0), m_mode(Mode::Shared) {}

    Guard(RangeLock& lock, uint64_t offset, uint64_t length, Mode mode)
        : m_lock(&lock), m_offset(offset), m_length(length), m_mode(mode) {
      m_lock->lock(offset, length, mode);
    }

    ~Guard() {
      if (m_lock) {
        m_lock->unlock(m_offset, m_length, m_mode);
      }
    }

    // Non-copyable
    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;

    // Movable
    Guard(Guard&& other) noexcept
        : m_lock(other.m_lock), m_offset(other.m_offset),
          m_length(other.m_length), m_mode(other.m_mode) {
      other.m_lock = nullptr;
    }

    Guard& operator=(Guard&& other) noexcept {
      if (this != &other) {
        if (m_lock) {
          m_lock->unlock(m_offset, m_length, m_mode);
        }
        m_lock = other.m_lock;
        m_offset = other.m_offset;
        m_length = other.m_length;
        m_mode = other.m_mode;
        other.m_lock = nullptr;
      }
      return *this;
    }

  private:
    RangeLock* m_lock;
    uint64_t m_offset;
    uint64_t m_length;
    Mode m_mode;
  };

  // Create a RAII guard that acquires the lock and releases on destruction
  Guard guard(uint64_t offset, uint64_t length, Mode mode) {
    return Guard(*this, offset, length, mode);
  }

private:
  struct Entry {
    uint64_t offset;
    uint64_t length;
    Mode mode;
  };

  // Check if two ranges overlap: [a, a+aLen) and [b, b+bLen)
  static bool overlaps(uint64_t aOff, uint64_t aLen, uint64_t bOff, uint64_t bLen) {
    return aOff < (bOff + bLen) && bOff < (aOff + aLen);
  }

  // Check if acquiring [offset, offset+length) with given mode would conflict
  // with any existing entry.
  // Conflict rules:
  //   - Shared vs Shared on overlapping range: NO conflict (reads can coexist)
  //   - Shared vs Exclusive on overlapping range: CONFLICT
  //   - Exclusive vs Shared on overlapping range: CONFLICT
  //   - Exclusive vs Exclusive on overlapping range: CONFLICT
  //   - Any mode on non-overlapping range: NO conflict
  bool hasConflict(uint64_t offset, uint64_t length, Mode mode) const {
    for (const auto& entry : m_entries) {
      if (!overlaps(offset, length, entry.offset, entry.length)) {
        continue; // Non-overlapping: no conflict regardless of mode
      }
      // Overlapping ranges: conflict unless both are shared
      if (mode == Mode::Exclusive || entry.mode == Mode::Exclusive) {
        return true;
      }
    }
    return false;
  }

  std::mutex m_mutex;
  std::condition_variable m_cv;
  std::vector<Entry> m_entries;
};

} // namespace evhd
