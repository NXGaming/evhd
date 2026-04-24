#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "evhd.h"

namespace {

using evhd::Container;

constexpr wchar_t kPassword[] = L"selftest-pass";
constexpr char kJournalMagic[8] = {'E','V','J','N','0','0','0','1'};
constexpr uint32_t kJournalVersion = 1;
constexpr uint32_t kJournalStateClean = 0;
constexpr uint32_t kJournalStatePrepared = 1;

struct JournalHeaderState {
  char magic[8];
  uint32_t version;
  uint32_t state;
  uint32_t dirty;
  uint32_t entryCount;
  uint64_t dataSize;
  uint64_t sequence;
  uint32_t entriesCRC32;
  uint32_t dataCRC32;
};

struct JournalEntryState {
  uint64_t physOffset;
  uint64_t length;
  uint64_t dataOffset;
};

static_assert(sizeof(JournalHeaderState) == 48, "Unexpected journal header size");
static_assert(sizeof(JournalEntryState) == 24, "Unexpected journal entry size");

std::vector<uint8_t> makePattern(size_t size, uint8_t seed) {
  std::vector<uint8_t> data(size);
  for (size_t i = 0; i < size; ++i) {
    data[i] = static_cast<uint8_t>((seed + i * 13) & 0xFF);
  }
  return data;
}

uint32_t crc32_update_test(uint32_t crc, const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    crc ^= data[i];
    for (int j = 0; j < 8; ++j) {
      uint32_t mask = -(int)(crc & 1U);
      crc = (crc >> 1) ^ (0xEDB88320U & mask);
    }
  }
  return crc;
}

bool writeFile(const std::filesystem::path &path, const std::vector<uint8_t> &data) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out.is_open()) return false;
  out.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
  return !!out;
}

bool writeRawBytes(const std::filesystem::path &path, uint64_t offset, const std::vector<uint8_t> &data) {
  std::fstream io(path, std::ios::binary | std::ios::in | std::ios::out);
  if (!io.is_open()) return false;
  io.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
  io.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
  io.flush();
  return !!io;
}

std::vector<uint8_t> readRawBytes(const std::filesystem::path &path, uint64_t offset, size_t len) {
  std::vector<uint8_t> data(len);
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) return {};
  in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  in.read(reinterpret_cast<char *>(data.data()), static_cast<std::streamsize>(len));
  if (!in) return {};
  return data;
}

std::filesystem::path journalPathFor(const std::filesystem::path &encPath) {
  return std::filesystem::path(encPath.wstring() + L".journal");
}

bool writeJournalFile(const std::filesystem::path &journalPath,
                     const JournalHeaderState &header,
                     const std::vector<JournalEntryState> &entries,
                     const std::vector<uint8_t> &data) {
  SetFileAttributesW(journalPath.c_str(), FILE_ATTRIBUTE_NORMAL);
  std::ofstream out(journalPath, std::ios::binary | std::ios::trunc);
  if (!out.is_open()) return false;
  out.write(reinterpret_cast<const char *>(&header), sizeof(header));
  if (!entries.empty()) {
    out.write(reinterpret_cast<const char *>(entries.data()),
              static_cast<std::streamsize>(entries.size() * sizeof(JournalEntryState)));
  }
  if (!data.empty()) {
    out.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
  }
  out.flush();
  return !!out;
}

std::vector<uint8_t> makeMbrPlain() {
  std::vector<uint8_t> plain(1 << 20, 0);
  for (size_t i = 0; i < plain.size(); ++i) {
    plain[i] = static_cast<uint8_t>((i * 29 + 7) & 0xFF);
  }
  plain[510] = 0x55;
  plain[511] = 0xAA;
  plain[446 + 4] = 0x07;
  plain[446 + 8] = 0x20;
  plain[446 + 12] = 0x40;
  return plain;
}

void writeLe32(std::vector<uint8_t> &buf, size_t off, uint32_t value) {
  buf[off + 0] = static_cast<uint8_t>(value & 0xFF);
  buf[off + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
  buf[off + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
  buf[off + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

void writeLe64(std::vector<uint8_t> &buf, size_t off, uint64_t value) {
  for (size_t i = 0; i < 8; ++i) {
    buf[off + i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
  }
}

std::vector<uint8_t> makeGptPlain() {
  constexpr uint64_t totalSectors = 32768;
  constexpr uint32_t sectorSize = 512;
  constexpr uint64_t totalSize = totalSectors * sectorSize;
  constexpr uint64_t primaryHeaderLba = 1;
  constexpr uint64_t primaryEntriesLba = 2;
  constexpr uint32_t entryCount = 128;
  constexpr uint32_t entrySize = 128;
  constexpr uint32_t entriesBytes = entryCount * entrySize;
  constexpr uint32_t entriesSectors = entriesBytes / sectorSize;
  constexpr uint64_t backupHeaderLba = totalSectors - 1;
  constexpr uint64_t backupEntriesLba = backupHeaderLba - entriesSectors;

  std::vector<uint8_t> plain(static_cast<size_t>(totalSize), 0);
  for (size_t i = 0; i < plain.size(); ++i) {
    plain[i] = static_cast<uint8_t>((i * 17 + 11) & 0xFF);
  }

  plain[510] = 0x55;
  plain[511] = 0xAA;
  plain[446 + 4] = 0xEE;
  writeLe32(plain, 446 + 8, 1);
  writeLe32(plain, 446 + 12, 0xFFFFFFFFu);

  auto writeHeader = [&](uint64_t lba, uint64_t alternateLba, uint64_t entriesLba) {
    size_t off = static_cast<size_t>(lba * sectorSize);
    memcpy(plain.data() + off, "EFI PART", 8);
    writeLe32(plain, off + 0x08, 0x00010000u);
    writeLe32(plain, off + 0x0C, 92);
    writeLe64(plain, off + 0x18, lba);
    writeLe64(plain, off + 0x20, alternateLba);
    writeLe64(plain, off + 0x28, 34);
    writeLe64(plain, off + 0x30, backupEntriesLba - 1);
    writeLe64(plain, off + 0x48, entriesLba);
    writeLe32(plain, off + 0x50, entryCount);
    writeLe32(plain, off + 0x54, entrySize);
  };

  auto writeEntries = [&](uint64_t lba, uint8_t seed) {
    size_t off = static_cast<size_t>(lba * sectorSize);
    for (uint32_t entry = 0; entry < entryCount; ++entry) {
      size_t entryOff = off + static_cast<size_t>(entry) * entrySize;
      for (uint32_t i = 0; i < entrySize; ++i) {
        plain[entryOff + i] = static_cast<uint8_t>(seed + entry + i);
      }
    }
  };

  writeHeader(primaryHeaderLba, backupHeaderLba, primaryEntriesLba);
  writeHeader(backupHeaderLba, primaryHeaderLba, backupEntriesLba);
  writeEntries(primaryEntriesLba, 0x20);
  writeEntries(backupEntriesLba, 0x80);
  return plain;
}

bool reopenOk(const std::filesystem::path &encPath) {
  Container reopened;
  bool ok = reopened.openEncrypted(encPath.wstring(), kPassword, L"");
  reopened.close();
  return ok;
}

bool writeThenReopen(const std::filesystem::path &encPath, uint64_t offset,
                    const std::vector<uint8_t> &data, const wchar_t *label) {
  Container c;
  if (!c.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] open before write failed: " << label << std::endl;
    return false;
  }
  if (!c.writePlain(offset, data.data(), data.size())) {
    std::wcerr << L"[selftest] writePlain failed: " << label << std::endl;
    return false;
  }
  c.close();
  if (!reopenOk(encPath)) {
    std::wcerr << L"[selftest] reopen after write failed: " << label << std::endl;
    return false;
  }
  return true;
}

bool concurrentWriteThenReopen(const std::filesystem::path &encPath,
                               const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> &writes,
                               const wchar_t *label) {
  Container c;
  if (!c.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] open before concurrent write failed: " << label << std::endl;
    return false;
  }

  std::vector<std::thread> workers;
  workers.reserve(writes.size());
  for (const auto &write : writes) {
    workers.emplace_back([&c, &write]() {
      for (int i = 0; i < 64; ++i) {
        c.writePlain(write.first, write.second.data(), write.second.size());
      }
    });
  }
  for (auto &worker : workers) {
    worker.join();
  }

  c.close();
  if (!reopenOk(encPath)) {
    std::wcerr << L"[selftest] reopen after concurrent write failed: " << label << std::endl;
    return false;
  }
  return true;
}

bool runScenario(const std::filesystem::path &dir, const wchar_t *name,
                 const std::vector<uint8_t> &plain,
                 const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> &writes,
                 const std::vector<std::pair<uint64_t, std::vector<uint8_t>>> &concurrentWrites = {}) {
  auto plainPath = dir / (std::wstring(name) + L".vhd");
  auto encPath = dir / (std::wstring(name) + L".evhd");
  if (!writeFile(plainPath, plain)) {
    std::wcerr << L"[selftest] write plain failed: " << plainPath.c_str() << std::endl;
    return false;
  }

  Container created;
  if (!created.createFromPlainVhd(plainPath.wstring(), encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] createFromPlainVhd failed: " << name << std::endl;
    return false;
  }
  created.close();

  if (!reopenOk(encPath)) {
    std::wcerr << L"[selftest] initial reopen failed: " << name << std::endl;
    return false;
  }

  for (size_t i = 0; i < writes.size(); ++i) {
    std::wstring label = std::wstring(name) + L"#write" + std::to_wstring(i);
    if (!writeThenReopen(encPath, writes[i].first, writes[i].second, label.c_str())) {
      return false;
    }
  }
  if (!concurrentWrites.empty()) {
    std::wstring label = std::wstring(name) + L"#concurrent";
    if (!concurrentWriteThenReopen(encPath, concurrentWrites, label.c_str())) {
      return false;
    }
  }
  return true;
}

bool testDirtyFlagNoPending(const std::filesystem::path &dir) {
  auto plainPath = dir / L"dirty-flag.vhd";
  auto encPath = dir / L"dirty-flag.evhd";
  if (!writeFile(plainPath, makeMbrPlain())) return false;

  Container created;
  if (!created.createFromPlainVhd(plainPath.wstring(), encPath.wstring(), kPassword, L"")) return false;
  created.close();

  JournalHeaderState header{};
  memcpy(header.magic, kJournalMagic, sizeof(header.magic));
  header.version = kJournalVersion;
  header.state = kJournalStateClean;
  header.dirty = 1;
  header.entryCount = 0;
  header.dataSize = 0;
  header.sequence = 3;
  header.entriesCRC32 = 0;
  header.dataCRC32 = 0;
  if (!writeJournalFile(journalPathFor(encPath), header, {}, {})) return false;

  Container reopened;
  if (!reopened.openEncrypted(encPath.wstring(), kPassword, L"")) return false;
  bool ok = reopened.previousSessionDirty() && !reopened.recoveredPendingJournal();
  reopened.close();
  return ok;
}

bool testPendingJournalRecovery(const std::filesystem::path &dir) {
  auto plainPath = dir / L"journal-recovery.vhd";
  auto encPath = dir / L"journal-recovery.evhd";
  if (!writeFile(plainPath, makeMbrPlain())) {
    std::wcerr << L"[selftest] recovery: write plain failed" << std::endl;
    return false;
  }

  Container created;
  if (!created.createFromPlainVhd(plainPath.wstring(), encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] recovery: create failed" << std::endl;
    return false;
  }
  created.close();

  Container probe;
  if (!probe.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] recovery: probe open failed" << std::endl;
    return false;
  }
  uint64_t payloadOffset = probe.payloadOffset();
  probe.close();

  const uint64_t logicalOffset = 4096;
  const auto newPlain = makePattern(4096, 0x6A);
  auto oldCipher = readRawBytes(encPath, payloadOffset + logicalOffset, newPlain.size());
  if (oldCipher.size() != newPlain.size()) {
    std::wcerr << L"[selftest] recovery: old cipher size mismatch" << std::endl;
    return false;
  }

  Container writer;
  if (!writer.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] recovery: writer open failed" << std::endl;
    return false;
  }
  if (!writer.writePlain(logicalOffset, newPlain.data(), newPlain.size())) {
    std::wcerr << L"[selftest] recovery: writer write failed" << std::endl;
    return false;
  }
  writer.close();

  auto newCipher = readRawBytes(encPath, payloadOffset + logicalOffset, newPlain.size());
  if (newCipher.size() != newPlain.size()) {
    std::wcerr << L"[selftest] recovery: new cipher size mismatch" << std::endl;
    return false;
  }
  if (!writeRawBytes(encPath, payloadOffset + logicalOffset, oldCipher)) {
    std::wcerr << L"[selftest] recovery: restore old cipher failed" << std::endl;
    return false;
  }

  JournalEntryState entry{};
  entry.physOffset = logicalOffset;
  entry.length = static_cast<uint64_t>(newCipher.size());
  entry.dataOffset = 0;
  std::vector<JournalEntryState> entries{entry};

  JournalHeaderState header{};
  memcpy(header.magic, kJournalMagic, sizeof(header.magic));
  header.version = kJournalVersion;
  header.state = kJournalStatePrepared;
  header.dirty = 1;
  header.entryCount = 1;
  header.dataSize = static_cast<uint64_t>(newCipher.size());
  header.sequence = 9;
  header.entriesCRC32 = crc32_update_test(0xFFFFFFFFU,
                                          reinterpret_cast<const uint8_t *>(entries.data()),
                                          entries.size() * sizeof(JournalEntryState)) ^ 0xFFFFFFFFU;
  header.dataCRC32 = crc32_update_test(0xFFFFFFFFU, newCipher.data(), newCipher.size()) ^ 0xFFFFFFFFU;
  if (!writeJournalFile(journalPathFor(encPath), header, entries, newCipher)) {
    std::wcerr << L"[selftest] recovery: write journal failed" << std::endl;
    return false;
  }

  Container recovered;
  if (!recovered.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] recovery: recovered open failed" << std::endl;
    return false;
  }
  if (!recovered.previousSessionDirty() || !recovered.recoveredPendingJournal()) {
    std::wcerr << L"[selftest] recovery: flags dirty=" << (recovered.previousSessionDirty() ? L"1" : L"0")
               << L" recovered=" << (recovered.recoveredPendingJournal() ? L"1" : L"0") << std::endl;
    return false;
  }
  std::vector<uint8_t> plain(newPlain.size());
  if (!recovered.readPlain(logicalOffset, plain.data(), plain.size())) {
    std::wcerr << L"[selftest] recovery: read after recovery failed" << std::endl;
    return false;
  }
  recovered.close();
  if (plain != newPlain) {
    std::wcerr << L"[selftest] recovery: plaintext mismatch after replay" << std::endl;
    return false;
  }
  return true;
}

// v4 backward compatibility: create v4 container, verify open/read/write works
bool testV4BackwardCompat(const std::filesystem::path &dir) {
  auto plainPath = dir / L"v4-compat.vhd";
  auto encPath = dir / L"v4-compat.evhd";
  if (!writeFile(plainPath, makeMbrPlain())) return false;

  Container c;
  if (!c.createFromPlainVhd(plainPath.wstring(), encPath.wstring(), kPassword, L"", 200000, 4)) {
    std::wcerr << L"[selftest] v4-compat: create failed" << std::endl;
    return false;
  }
  c.close();

  Container reopen;
  if (!reopen.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v4-compat: reopen failed" << std::endl;
    return false;
  }
  std::vector<uint8_t> readBuf(512);
  if (!reopen.readPlain(0, readBuf.data(), readBuf.size())) {
    std::wcerr << L"[selftest] v4-compat: read failed" << std::endl;
    return false;
  }
  // verify MBR signature
  if (readBuf[510] != 0x55 || readBuf[511] != 0xAA) {
    std::wcerr << L"[selftest] v4-compat: MBR signature mismatch" << std::endl;
    return false;
  }
  reopen.close();
  return true;
}

// v5 header HMAC tamper detection: flip a byte in header, verify open fails
bool testV5HeaderHmacTamper(const std::filesystem::path &dir) {
  auto plainPath = dir / L"v5-header-tamper.vhd";
  auto encPath = dir / L"v5-header-tamper.evhd";
  if (!writeFile(plainPath, makeMbrPlain())) return false;

  Container c;
  if (!c.createFromPlainVhd(plainPath.wstring(), encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-header-tamper: create failed" << std::endl;
    return false;
  }
  c.close();

  // Flip a byte in the version field (offset 8)
  {
    std::fstream fs(encPath, std::ios::binary | std::ios::in | std::ios::out);
    if (!fs) return false;
    fs.seekp(8, std::ios::beg);
    uint8_t byte = 0xFF;
    fs.write(reinterpret_cast<const char*>(&byte), 1);
  }

  Container reopen;
  if (reopen.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-header-tamper: expected open to fail after tampering" << std::endl;
    reopen.close();
    return false;
  }
  return true;
}

// v5 pad HMAC tamper detection: flip a byte in pad HMAC, verify open fails
bool testV5PadHmacTamper(const std::filesystem::path &dir) {
  auto plainPath = dir / L"v5-pad-tamper.vhd";
  auto encPath = dir / L"v5-pad-tamper.evhd";
  if (!writeFile(plainPath, makeMbrPlain())) return false;

  Container c;
  if (!c.createFromPlainVhd(plainPath.wstring(), encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-pad-tamper: create failed" << std::endl;
    return false;
  }
  uint64_t payloadOffset = c.payloadOffset();
  c.close();

  // In v5: padHmac is 32 bytes immediately before authBlockSize
  // payloadOffset = padHmacPos + 32(padHmac) + 4(authBlockSize) + 32(headerHmac) + 4(relocAuthCount) + 32(relocAuthHmacs)
  // = padHmacPos + 104
  uint64_t padHmacPos = payloadOffset - 104;

  // Flip a byte in padHMAC field
  {
    std::fstream fs(encPath, std::ios::binary | std::ios::in | std::ios::out);
    if (!fs) return false;
    fs.seekp(static_cast<std::streamoff>(padHmacPos), std::ios::beg);
    uint8_t byte = 0xFF;
    fs.write(reinterpret_cast<const char*>(&byte), 1);
    fs.flush();
  }

  Container reopen;
  if (reopen.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-pad-tamper: expected open to fail after tampering" << std::endl;
    reopen.close();
    return false;
  }
  return true;
}

// v5 journal HMAC tamper detection: tamper journal data HMAC, verify recovery fails
bool testV5JournalHmacTamper(const std::filesystem::path &dir) {
  auto plainPath = dir / L"v5-journal-tamper.vhd";
  auto encPath = dir / L"v5-journal-tamper.evhd";
  if (!writeFile(plainPath, makeMbrPlain())) return false;

  Container created;
  if (!created.createFromPlainVhd(plainPath.wstring(), encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-journal-tamper: create failed" << std::endl;
    return false;
  }
  created.close();

  // Create a journal with tampered data HMAC
  auto jpath = journalPathFor(encPath);
  std::vector<uint8_t> journalContent;
  {
    JournalHeaderState header{};
    memcpy(header.magic, kJournalMagic, sizeof(header.magic));
    header.version = kJournalVersion;
    header.state = kJournalStatePrepared;
    header.dirty = 1;
    header.entryCount = 1;
    header.dataSize = 64;
    header.sequence = 1;

    JournalEntryState entry{};
    entry.physOffset = 4096;
    entry.length = 64;
    entry.dataOffset = 0;

    std::vector<uint8_t> data(64, 0xAB);

    // Serialize to buffer
    journalContent.resize(sizeof(header) + sizeof(entry) + data.size() + 64); // +64 for HMAC placeholders
    memcpy(journalContent.data(), &header, sizeof(header));
    memcpy(journalContent.data() + sizeof(header), &entry, sizeof(entry));
    memcpy(journalContent.data() + sizeof(header) + sizeof(entry), data.data(), data.size());
    // HMAC placeholders: fill with non-zero to simulate tampered HMACs
    memset(journalContent.data() + sizeof(header) + sizeof(entry) + data.size(), 0xCD, 64);
  }
  if (!writeFile(jpath, journalContent)) return false;

  // Attempt to open: should detect tampered journal HMAC and fail recovery
  Container reopen;
  if (reopen.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-journal-tamper: expected open to fail after journal tampering" << std::endl;
    reopen.close();
    return false;
  }
  return true;
}

// v5 concurrent writes: multi-thread writes followed by reopen
bool testV5ConcurrentWrites(const std::filesystem::path &dir) {
  auto plainPath = dir / L"v5-concurrent.vhd";
  auto encPath = dir / L"v5-concurrent.evhd";
  if (!writeFile(plainPath, makeMbrPlain())) return false;

  Container created;
  if (!created.createFromPlainVhd(plainPath.wstring(), encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-concurrent: create failed" << std::endl;
    return false;
  }
  created.close();

  Container c;
  if (!c.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-concurrent: open failed" << std::endl;
    return false;
  }

  std::vector<std::thread> workers;
  for (int t = 0; t < 8; ++t) {
    workers.emplace_back([&c, t]() {
      std::vector<uint8_t> data(512, static_cast<uint8_t>(t + 1));
      for (int i = 0; i < 32; ++i) {
        uint64_t off = 4096 + static_cast<uint64_t>(t) * 512 + static_cast<uint64_t>(i) * 4096;
        if (off + 512 <= 1024 * 1024) {
          c.writePlain(off, data.data(), data.size());
        }
      }
    });
  }
  for (auto &w : workers) w.join();
  c.close();

  // Reopen and verify a sample write
  Container verify;
  if (!verify.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-concurrent: reopen failed" << std::endl;
    return false;
  }
  std::vector<uint8_t> readBuf(512);
  if (!verify.readPlain(4096, readBuf.data(), readBuf.size())) {
    std::wcerr << L"[selftest] v5-concurrent: read failed" << std::endl;
    return false;
  }
  // Any of the 8 thread patterns is acceptable
  bool found = false;
  for (int t = 0; t < 8; ++t) {
    bool match = true;
    for (size_t i = 0; i < readBuf.size(); ++i) {
      if (readBuf[i] != static_cast<uint8_t>(t + 1)) { match = false; break; }
    }
    if (match) { found = true; break; }
  }
  if (!found) {
    std::wcerr << L"[selftest] v5-concurrent: data mismatch" << std::endl;
    return false;
  }
  verify.close();
  return true;
}

// v5 read/write consistency: write known pattern, read back and verify
bool testV5ReadWriteConsistency(const std::filesystem::path &dir) {
  auto plainPath = dir / L"v5-consistency.vhd";
  auto encPath = dir / L"v5-consistency.evhd";
  auto plain = makeMbrPlain();
  if (!writeFile(plainPath, plain)) return false;

  Container created;
  if (!created.createFromPlainVhd(plainPath.wstring(), encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-consistency: create failed" << std::endl;
    return false;
  }
  created.close();

  // Write at various offsets
  Container writer;
  if (!writer.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-consistency: writer open failed" << std::endl;
    return false;
  }

  std::vector<uint8_t> patternA = makePattern(512, 0xA1);
  std::vector<uint8_t> patternB = makePattern(4096, 0xB2);
  std::vector<uint8_t> patternC = makePattern(64, 0xC3);
  if (!writer.writePlain(0, patternA.data(), patternA.size())) {
    std::wcerr << L"[selftest] v5-consistency: writePlain A failed" << std::endl;
    return false;
  }
  if (!writer.writePlain(512, patternB.data(), patternB.size())) {
    std::wcerr << L"[selftest] v5-consistency: writePlain B failed" << std::endl;
    return false;
  }
  // Write patternC at offset 8192 to avoid overlapping with patternA/B
  if (!writer.writePlain(8192, patternC.data(), patternC.size())) {
    std::wcerr << L"[selftest] v5-consistency: writePlain C failed" << std::endl;
    return false;
  }
  writer.close();

  // Read back and verify
  Container reader;
  if (!reader.openEncrypted(encPath.wstring(), kPassword, L"")) {
    std::wcerr << L"[selftest] v5-consistency: reader open failed" << std::endl;
    return false;
  }

  std::vector<uint8_t> readA(512), readB(4096), readC(64);
  if (!reader.readPlain(0, readA.data(), readA.size())) {
    std::wcerr << L"[selftest] v5-consistency: readPlain A failed" << std::endl;
    reader.close();
    return false;
  }
  if (!reader.readPlain(512, readB.data(), readB.size())) {
    std::wcerr << L"[selftest] v5-consistency: readPlain B failed" << std::endl;
    reader.close();
    return false;
  }
  if (!reader.readPlain(8192, readC.data(), readC.size())) {
    std::wcerr << L"[selftest] v5-consistency: readPlain C failed" << std::endl;
    reader.close();
    return false;
  }
  reader.close();

  if (readA != patternA) {
    std::wcerr << L"[selftest] v5-consistency: patternA mismatch" << std::endl;
    return false;
  }
  if (readB != patternB) {
    std::wcerr << L"[selftest] v5-consistency: patternB mismatch" << std::endl;
    return false;
  }
  if (readC != patternC) {
    std::wcerr << L"[selftest] v5-consistency: patternC mismatch" << std::endl;
    return false;
  }
  return true;
}

} // namespace

int wmain() {
  std::filesystem::path dir = std::filesystem::current_path() / L"selftest_tmp";
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);

  const auto mbrSector = makePattern(512, 0x41);
  const auto mbrPayload = makePattern(4096, 0x57);
  if (!runScenario(dir, L"mbr-write-reopen", makeMbrPlain(), {
        {4096, mbrPayload},
        {0, mbrSector},
        {446, makePattern(64, 0x73)}
      })) {
    return 1;
  }

  const auto gptSector = makePattern(512, 0x91);
  const auto gptEntries = makePattern(4096, 0x33);
  if (!runScenario(dir, L"gpt-write-reopen", makeGptPlain(), {
        {4096, makePattern(8192, 0x27)},
        {0, gptSector},
        {512, gptSector},
        {1024, gptEntries},
        {(32768ull * 512ull) - 512ull, gptSector}
      }, {
        {0, makePattern(512, 0xA1)},
        {512, makePattern(512, 0xB2)},
        {1024, makePattern(4096, 0xC3)},
        {4096, makePattern(4096, 0xD4)},
        {(32768ull * 512ull) - 512ull, makePattern(512, 0xE5)}
      })) {
    return 1;
  }

  if (!testDirtyFlagNoPending(dir)) {
    std::wcerr << L"[selftest] dirty-flag test failed" << std::endl;
    return 1;
  }

  if (!testPendingJournalRecovery(dir)) {
    std::wcerr << L"[selftest] journal recovery test failed" << std::endl;
    return 1;
  }

  if (!testV4BackwardCompat(dir)) {
    std::wcerr << L"[selftest] v4 backward compat test failed" << std::endl;
    return 1;
  }

  if (!testV5HeaderHmacTamper(dir)) {
    std::wcerr << L"[selftest] v5 header HMAC tamper test failed" << std::endl;
    return 1;
  }

  if (!testV5PadHmacTamper(dir)) {
    std::wcerr << L"[selftest] v5 pad HMAC tamper test failed" << std::endl;
    return 1;
  }

  if (!testV5JournalHmacTamper(dir)) {
    std::wcerr << L"[selftest] v5 journal HMAC tamper test failed" << std::endl;
    return 1;
  }

  if (!testV5ConcurrentWrites(dir)) {
    std::wcerr << L"[selftest] v5 concurrent writes test failed" << std::endl;
    return 1;
  }

  if (!testV5ReadWriteConsistency(dir)) {
    std::wcerr << L"[selftest] v5 read/write consistency test failed" << std::endl;
    return 1;
  }

  std::wcout << L"[selftest] OK" << std::endl;
  return 0;
}