// Part of encrypted-vhd-mount

#include "evhd.h"

#include <random>
#include <cstring>
#include <iostream>
#include <string>
#include <array>
#include <filesystem>
#include <algorithm>
#include <malloc.h>

namespace evhd {

static void randomBytes(uint8_t *buf, size_t n) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint32_t> dist(0, 255);
  for (size_t i = 0; i < n; ++i) buf[i] = static_cast<uint8_t>(dist(gen));
}

static std::wstring hexBytes(const uint8_t *data, size_t n) {
  static const wchar_t *digits = L"0123456789abcdef";
  std::wstring out; out.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    uint8_t v = data[i];
    out.push_back(digits[v >> 4]);
    out.push_back(digits[v & 0x0F]);
  }
  return out;
}

// splitmix64: 简单可复现的伪随机生成器（基于块索引）。
static inline uint64_t splitmix64(uint64_t x) {
  x += 0x9e3779b97f4a7c15ULL;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
  return x ^ (x >> 31);
}

// 从16字节盐派生64位种子（无需密码，独立用于填充生成）。
static uint64_t deriveSeedFromSalt(const uint8_t *salt16) {
  uint64_t s0 = 0, s1 = 0;
  for (int i = 0; i < 8; ++i) { s0 = (s0 << 8) ^ salt16[i]; }
  for (int i = 8; i < 16; ++i) { s1 = (s1 << 8) ^ salt16[i]; }
  return splitmix64(s0 ^ s1 ^ 0x6a09e667f3bcc908ULL);
}

// 在绝对偏移 absStart 处生成长度 len 的伪随机填充，写入 dst。
static void fillPseudoRandom(uint8_t *dst, size_t len, uint64_t seed, uint64_t absStart) {
  uint64_t firstBlock = absStart / 8ULL;
  size_t offsetInBlock = static_cast<size_t>(absStart % 8ULL);
  size_t produced = 0;
  while (produced < len) {
    uint64_t r = splitmix64(seed ^ (firstBlock));
    uint8_t block[8];
    memcpy(block, &r, 8);
    size_t take = std::min<size_t>(len - produced, 8 - offsetInBlock);
    memcpy(dst + produced, block + offsetInBlock, take);
    produced += take;
    firstBlock += 1;
    offsetInBlock = 0;
  }
}

// 朴素 CRC32 实现（poly 0xEDB88320），支持增量更新。
static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
  // 约定：调用者将初始 crc 设置为 0xFFFFFFFF，最终取反得到结果。
  for (size_t i = 0; i < len; ++i) {
    crc ^= data[i];
    for (int j = 0; j < 8; ++j) {
      uint32_t mask = -(int)(crc & 1U);
      crc = (crc >> 1) ^ (0xEDB88320U & mask);
    }
  }
  return crc;
}

constexpr const char JOURNAL_MAGIC[8] = {'E','V','J','N','0','0','0','1'};
constexpr uint32_t JOURNAL_VERSION = 1;
constexpr uint32_t JOURNAL_STATE_CLEAN = 0;
constexpr uint32_t JOURNAL_STATE_PREPARED = 1;

static bool readHandleExact(HANDLE handle, uint64_t offset, void *buffer, size_t len) {
  LARGE_INTEGER pos{};
  pos.QuadPart = static_cast<LONGLONG>(offset);
  if (!SetFilePointerEx(handle, pos, nullptr, FILE_BEGIN)) return false;
  size_t doneTotal = 0;
  while (doneTotal < len) {
    DWORD done = 0;
    DWORD want = static_cast<DWORD>(std::min<size_t>(len - doneTotal, 1u << 20));
    if (!ReadFile(handle, static_cast<uint8_t *>(buffer) + doneTotal, want, &done, nullptr)) return false;
    if (done != want) return false;
    doneTotal += done;
  }
  return true;
}

static bool writeHandleExact(HANDLE handle, uint64_t offset, const void *buffer, size_t len) {
  LARGE_INTEGER pos{};
  pos.QuadPart = static_cast<LONGLONG>(offset);
  if (!SetFilePointerEx(handle, pos, nullptr, FILE_BEGIN)) return false;
  size_t doneTotal = 0;
  while (doneTotal < len) {
    DWORD done = 0;
    DWORD want = static_cast<DWORD>(std::min<size_t>(len - doneTotal, 1u << 20));
    if (!WriteFile(handle, static_cast<const uint8_t *>(buffer) + doneTotal, want, &done, nullptr)) return false;
    if (done != want) return false;
    doneTotal += done;
  }
  return true;
}

static bool resizeHandle(HANDLE handle, uint64_t size) {
  LARGE_INTEGER pos{};
  pos.QuadPart = static_cast<LONGLONG>(size);
  if (!SetFilePointerEx(handle, pos, nullptr, FILE_BEGIN)) return false;
  return !!SetEndOfFile(handle);
}

static uint64_t getHandleSize(HANDLE handle) {
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(handle, &size)) return 0;
  return static_cast<uint64_t>(size.QuadPart);
}

bool Container::openEncrypted(const std::wstring &path, const std::wstring &password,
                              const std::wstring &keyFilePath) {
  std::lock_guard<std::recursive_mutex> lg(m_mutex);
  close();
  m_path = path;
  m_previousSessionDirty = false;
  m_recoveredPendingJournal = false;
  m_file.open(path.c_str(), std::ios::binary | std::ios::in | std::ios::out);
  if (!m_file.is_open()) { std::wcerr << L"[evhd] open file failed: " << path << std::endl; return false; }

  if (!readHeader()) { std::wcerr << L"[evhd] read header failed" << std::endl; return false; }

  // 打开一个原生文件句柄以支持偏移式并发I/O
  DWORD flags = FILE_FLAG_OVERLAPPED | FILE_FLAG_WRITE_THROUGH;
  if (m_unbuffered) {
    flags |= FILE_FLAG_NO_BUFFERING;
  }
  m_handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, flags, nullptr);
  if (m_handle == INVALID_HANDLE_VALUE) {
    if (m_debug) {
      std::wcerr << L"[evhd] CreateFileW failed, err=" << GetLastError() << L"\n";
    }
    return false;
  }

  if (m_debug) {
    LARGE_INTEGER sz{};
    if (GetFileSizeEx(m_handle, &sz)) {
      std::wcerr << L"[evhd] fileSize=" << sz.QuadPart
                 << L" payloadOffset=" << m_payloadOffset
                 << L" payloadEnd=" << (m_payloadOffset + m_header.originalSize) << L"\n";
    }
  }

  // Query sector size for alignment when using unbuffered I/O
  if (m_unbuffered) {
    // Prefer the file's alignment requirement over volume bytes-per-sector.
    // On Windows, FileAlignmentInfo.AlignmentRequirement + 1 is the required alignment in bytes
    // for unbuffered I/O on this specific handle.
    FILE_ALIGNMENT_INFO alignInfo{};
    if (GetFileInformationByHandleEx(m_handle, FileAlignmentInfo, &alignInfo, sizeof(alignInfo))) {
      DWORD align = alignInfo.AlignmentRequirement + 1; // documented requirement
      if (align == 0) align = 4096; // safety fallback
      m_sectorSize = std::max<DWORD>(align, 512);
    } else {
      // Fallback: query volume bytes-per-sector
      DWORD spc = 0, bps = 0, nfc = 0, tnc = 0;
      std::filesystem::path p(path);
      std::wstring root = p.root_path().c_str();
      if (GetDiskFreeSpaceW(root.c_str(), &spc, &bps, &nfc, &tnc)) {
        m_sectorSize = std::max<DWORD>(bps, 512);
      } else {
        m_sectorSize = 4096;
      }
    }
    if (m_debug) {
      std::wcerr << L"[evhd] unbuffered mode. sectorSize=" << m_sectorSize << L" bytes\n";
    }
  }

  if (m_debug) {
    const wchar_t *kdfName = L"password";
    if (m_header.kdfMethod == 1) kdfName = L"keyfile";
    else if (m_header.kdfMethod == 2) kdfName = L"password+keyfile";
    std::wcerr << L"[evhd] header ok. plaintext size=" << m_header.originalSize
               << L" bytes, iterations=" << m_header.kdfIterations
               << L", kdfMethod=" << kdfName << L"\n";
    std::wcerr << L"[evhd] version=" << m_header.version
               << L" payloadOffset=" << m_payloadOffset
               << L" relocCount=" << m_relocations.size() << L"\n";
    if (m_header.version >= 4 && !m_relocations.empty()) {
      std::wcerr << L"[evhd] relocations:" << L"\n";
      for (size_t i = 0; i < m_relocations.size(); ++i) {
        const auto &e = m_relocations[i];
        std::wcerr << L"  reloc[" << i << L"] logic=" << e.logicalOffset
                    << L" len=" << e.length
                    << L" phys=" << e.physicalOffset << L"\n";
      }
      size_t invalid = 0;
      for (size_t i = 0; i < m_relocations.size(); ++i) {
        const auto &e = m_relocations[i];
        bool bad = (e.length == 0) || (e.logicalOffset >= m_header.originalSize) ||
                   (e.logicalOffset + e.length > m_header.originalSize);
        if (bad) {
          ++invalid;
          std::wcerr << L"  [evhd] invalid reloc entry index=" << i
                     << L" (logic=" << e.logicalOffset
                     << L" len=" << e.length
                     << L" phys=" << e.physicalOffset << L")\n";
        }
      }
      if (invalid > 0) {
        std::wcerr << L"[evhd] WARNING: detected " << invalid << L" invalid relocation entries (out of range)." << L"\n";
      }
    }
  }

  if (!openJournal()) {
    std::wcerr << L"[evhd] open journal failed" << std::endl;
    return false;
  }

  if (m_previousSessionDirty) {
    std::wcerr << L"[evhd] journal: detected previous unclean shutdown" << std::endl;
  }
  if (m_recoveredPendingJournal) {
    std::wcerr << L"[evhd] journal: recovered pending write transaction" << std::endl;
  }

  CryptoContext::Params p;
  p.salt.assign(std::begin(m_header.salt), std::end(m_header.salt));
  p.nonce.assign(std::begin(m_header.nonce), std::end(m_header.nonce));
  p.iterations = m_header.kdfIterations;
  p.kdfMethod = m_header.kdfMethod;
  p.keyFilePath = keyFilePath;
  if (!m_crypto.init(password, p)) { std::wcerr << L"[evhd] crypto init failed" << std::endl; return false; }

  // Print KDF diagnostics: salt, nonce, and key prefix fingerprint
  if (m_debug) {
    auto keyPrefix = m_crypto.keyPrefix8();
    std::wcerr << L"[evhd] kdf salt=" << hexBytes(m_header.salt, sizeof(m_header.salt))
               << L" nonce=" << hexBytes(m_header.nonce, sizeof(m_header.nonce))
               << L" key[0..7]=" << hexBytes(keyPrefix.data(), keyPrefix.size()) << L"\n";
  }

  // Integrity check: validate pseudo-random pad fingerprint over cut ranges
  bool integrityOk = verifyIntegrity();
  if (!integrityOk) {
    std::wcerr << L"[evhd] integrity check FAILED: pseudo pad CRC mismatch or read error" << std::endl;
    // 严格模式：校验失败则拒绝打开
    m_ready = false;
    return false;
  } else {
    if (m_debug) std::wcerr << L"[evhd] integrity check OK" << std::endl;
  }

  m_ready = true;
  return true;
}

bool Container::createFromPlainVhd(const std::wstring &plainVhdPath, const std::wstring &encOutPath,
                                   const std::wstring &password, const std::wstring &keyFilePath,
                                   uint32_t iterations) {
  std::lock_guard<std::recursive_mutex> lg(m_mutex);
  close();
  m_path = encOutPath;
  m_previousSessionDirty = false;
  m_recoveredPendingJournal = false;
  DeleteFileW((encOutPath + L".journal").c_str());

  std::ifstream in(plainVhdPath.c_str(), std::ios::binary | std::ios::in);
  if (!in.is_open()) return false;

  in.seekg(0, std::ios::end);
  uint64_t size = static_cast<uint64_t>(in.tellg());
  in.seekg(0, std::ios::beg);

  m_file.open(encOutPath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
  if (!m_file.is_open()) return false;

  // Prepare header
  memset(&m_header, 0, sizeof(m_header));
  memcpy(m_header.magic, MAGIC, sizeof(m_header.magic));
  m_header.version = 4; // v4: add relocation metadata for partition table obfuscation
  m_header.kdfIterations = iterations;
  m_header.originalSize = size;
  randomBytes(m_header.salt, sizeof(m_header.salt));
  randomBytes(m_header.nonce, sizeof(m_header.nonce));
  // decide kdf method
  if (!keyFilePath.empty() && !password.empty()) m_header.kdfMethod = KDF_PASSWORD_PLUS_KEYFILE;
  else if (!keyFilePath.empty() && password.empty()) m_header.kdfMethod = KDF_KEYFILE;
  else m_header.kdfMethod = KDF_PASSWORD;

  // Write header + metadata (original filename)
  // original name = filename of plainVhdPath
  std::wstring baseName = std::filesystem::path(plainVhdPath).filename().c_str();
  m_originalName = baseName;
  if (!writeHeader()) { std::wcerr << L"EVHD header write failed" << std::endl; return false; }
  // Compute payload offset using the same layout logic as readHeader
  struct HeaderV1 { char magic[8]; uint32_t version; uint32_t kdfIterations; uint64_t originalSize; uint8_t salt[16]; uint8_t nonce[16]; };
  m_payloadOffset = sizeof(HeaderV1);
  if (m_header.version >= 3) {
    m_payloadOffset += sizeof(uint32_t); // kdfMethod
  }
  if (m_header.version >= 2) {
    uint32_t nameLen = static_cast<uint32_t>(m_originalName.size());
    m_file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
    if (nameLen > 0) {
      m_file.write(reinterpret_cast<const char*>(m_originalName.c_str()), nameLen * sizeof(wchar_t));
    }
    if (!m_file) { std::wcerr << L"Write metadata (filename) failed" << std::endl; return false; }
    m_payloadOffset += sizeof(uint32_t) + static_cast<uint64_t>(nameLen) * sizeof(wchar_t);
  }
  // v4: 写入重定位条目占位（稍后实际写入前需确定条目），先准备重定位计划
  // 检测并收集需要剪切的分区表范围
  const uint64_t sectorSize = 512;
  struct PlanItem { uint64_t logicalOffset; uint64_t length; };
  std::vector<PlanItem> plan;
  {
    // 读取MBR扇区 0 作为判断依据
    std::vector<uint8_t> sec0(sectorSize);
    in.read(reinterpret_cast<char*>(sec0.data()), sec0.size());
    if (!in) { std::wcerr << L"Read sector0 failed" << std::endl; return false; }
    // 恢复读指针
    in.seekg(0, std::ios::beg);
    bool has55AA = (sec0[510] == 0x55 && sec0[511] == 0xAA);
    if (has55AA) {
      // MBR分区表条目 446..509 (64字节)。保留签名(510..511)不剪切。
      plan.push_back({446, 64});
      // 检测GPT：保护MBR类型0xEE在第一个分区条目
      bool protectiveGPT = (sec0[446 + 4] == 0xEE);
      if (protectiveGPT && size >= sectorSize * 2) {
        // 读取LBA1 GPT头
        std::vector<uint8_t> gpt(sectorSize);
        in.seekg(sectorSize, std::ios::beg);
        in.read(reinterpret_cast<char*>(gpt.data()), gpt.size());
        if (in) {
          const char sig[8] = {'E','F','I',' ','P','A','R','T'};
          if (memcmp(gpt.data(), sig, 8) == 0) {
            // Partition entries start LBA @ offset 0x48 (uint64), number @ 0x2C (uint32), size @ 0x30 (uint32)
            uint64_t partStartLBA = *reinterpret_cast<const uint64_t*>(&gpt[0x48]);
            uint32_t numEntries = *reinterpret_cast<const uint32_t*>(&gpt[0x2C]);
            uint32_t entrySize = *reinterpret_cast<const uint32_t*>(&gpt[0x30]);
            bool validLBA = (partStartLBA >= 2) && (partStartLBA < (size / sectorSize));
            bool validEntrySize = (entrySize >= 128) && (entrySize <= 4096) && (entrySize % 8 == 0);
            bool validNum = (numEntries > 0) && (numEntries <= 4096);
            uint64_t gptEntriesOffset = validLBA ? (sectorSize * partStartLBA) : 0;
            uint64_t entriesBytes = 0;
            if (validEntrySize && validNum && validLBA) {
              entriesBytes = static_cast<uint64_t>(numEntries) * entrySize;
              uint64_t maxBytes = (gptEntriesOffset < size) ? (size - gptEntriesOffset) : 0;
              if (entriesBytes > maxBytes) entriesBytes = maxBytes;
            }
            uint64_t gptHeaderOffset = sectorSize * 1;
            // 迁移主GPT头 + 主分区表（仅当参数有效且长度>0）
            plan.push_back({gptHeaderOffset, sectorSize});
            if (entriesBytes > 0) {
              plan.push_back({gptEntriesOffset, entriesBytes});
            }
            // 处理备份GPT：剪切备份头与备份分区表
            uint64_t backupLBA = *reinterpret_cast<const uint64_t*>(&gpt[0x20]);
            uint64_t backupHeaderOffset = sectorSize * backupLBA;
            if (backupHeaderOffset + sectorSize <= size) {
              std::vector<uint8_t> gptBackup(sectorSize);
              in.seekg(static_cast<std::streamoff>(backupHeaderOffset), std::ios::beg);
              in.read(reinterpret_cast<char*>(gptBackup.data()), gptBackup.size());
              if (in && memcmp(gptBackup.data(), sig, 8) == 0) {
                uint64_t backupPartStartLBA = *reinterpret_cast<const uint64_t*>(&gptBackup[0x48]);
                uint32_t backupNumEntries = *reinterpret_cast<const uint32_t*>(&gptBackup[0x2C]);
                uint32_t backupEntrySize = *reinterpret_cast<const uint32_t*>(&gptBackup[0x30]);
                bool bValidLBA = (backupPartStartLBA >= 2) && (backupPartStartLBA < (size / sectorSize));
                bool bValidEntrySize = (backupEntrySize >= 128) && (backupEntrySize <= 4096) && (backupEntrySize % 8 == 0);
                bool bValidNum = (backupNumEntries > 0) && (backupNumEntries <= 4096);
                uint64_t backupEntriesOffset = bValidLBA ? (sectorSize * backupPartStartLBA) : 0;
                uint64_t backupEntriesBytes = 0;
                if (bValidEntrySize && bValidNum && bValidLBA) {
                  backupEntriesBytes = static_cast<uint64_t>(backupNumEntries) * backupEntrySize;
                  uint64_t bMaxBytes = (backupEntriesOffset < size) ? (size - backupEntriesOffset) : 0;
                  if (backupEntriesBytes > bMaxBytes) backupEntriesBytes = bMaxBytes;
                }
                plan.push_back({backupHeaderOffset, sectorSize});
                if (backupEntriesBytes > 0) {
                  plan.push_back({backupEntriesOffset, backupEntriesBytes});
                }
              }
              // 恢复读指针
              in.seekg(0, std::ios::beg);
            }
          }
        }
        // 恢复读指针
        in.seekg(0, std::ios::beg);
      }
    }
  }
  // 计划健壮化：排序、去重并合并重叠区间，过滤非法/零长度条目
  if (!plan.empty()) {
    // 过滤非法
    std::vector<PlanItem> filtered; filtered.reserve(plan.size());
    for (const auto &pi : plan) {
      if (pi.length == 0) continue;
      if (pi.logicalOffset >= size) continue;
      uint64_t maxLen = size - pi.logicalOffset;
      uint64_t len = (pi.length > maxLen) ? maxLen : pi.length;
      if (len == 0) continue;
      filtered.push_back({pi.logicalOffset, len});
    }
    plan.swap(filtered);

    // 排序
    std::sort(plan.begin(), plan.end(), [](const PlanItem &a, const PlanItem &b){
      if (a.logicalOffset == b.logicalOffset) return a.length < b.length;
      return a.logicalOffset < b.logicalOffset;
    });
    // 合并重叠
    std::vector<PlanItem> merged; merged.reserve(plan.size());
    for (const auto &pi : plan) {
      if (merged.empty()) { merged.push_back(pi); continue; }
      auto &last = merged.back();
      uint64_t lastEnd = last.logicalOffset + last.length;
      uint64_t curEnd = pi.logicalOffset + pi.length;
      if (pi.logicalOffset <= lastEnd) {
        // 重叠或相邻，合并到更大的范围
        if (curEnd > lastEnd) {
          last.length = curEnd - last.logicalOffset;
        }
      } else {
        merged.push_back(pi);
      }
    }
    plan.swap(merged);
  }
  // 为每个条目分配物理存放位置（尾部追加），按512对齐
  auto align512 = [](uint64_t x) { return (x + 511ULL) & ~511ULL; };
  uint64_t relocBase = size;
  uint64_t accum = 0;
  m_relocations.clear();
  std::vector<std::vector<uint8_t>> relocData; relocData.reserve(plan.size());
  for (const auto &pi : plan) {
    RelocEntry e{}; e.logicalOffset = pi.logicalOffset; e.length = pi.length; e.physicalOffset = align512(relocBase + accum);
    accum = align512(accum + pi.length);
    m_relocations.push_back(e);
    // 捕获原始数据备份
    std::vector<uint8_t> data(pi.length);
    in.seekg(static_cast<std::streamoff>(pi.logicalOffset), std::ios::beg);
    in.read(reinterpret_cast<char*>(data.data()), data.size());
    if (!in) { std::wcerr << L"Capture relocation bytes failed at logical=" << pi.logicalOffset << L" len=" << pi.length << std::endl; return false; }
    relocData.push_back(std::move(data));
  }

  // 诊断：打印将要写入的重定位条目
  std::wcerr << L"[evhd] create: relocations to write:" << L"\n";
  for (size_t i = 0; i < m_relocations.size(); ++i) {
    const auto &e = m_relocations[i];
    std::wcerr << L"  reloc[" << i << L"] logic=" << e.logicalOffset
               << L" len=" << e.length
               << L" phys=" << e.physicalOffset << L"\n";
  }
  // 写入重定位元数据：count + entries
  if (m_header.version >= 4) {
    uint32_t count = static_cast<uint32_t>(m_relocations.size());
    m_file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto &e : m_relocations) {
      m_file.write(reinterpret_cast<const char*>(&e.logicalOffset), sizeof(e.logicalOffset));
      m_file.write(reinterpret_cast<const char*>(&e.length), sizeof(e.length));
      m_file.write(reinterpret_cast<const char*>(&e.physicalOffset), sizeof(e.physicalOffset));
    }
    if (!m_file) { std::wcerr << L"Write relocation metadata failed" << std::endl; return false; }
    m_payloadOffset += sizeof(uint32_t) + static_cast<uint64_t>(count) * (sizeof(uint64_t) * 3);
    // v4 扩展：写入填充指纹盐与占位CRC32，稍后回填CRC结果
    randomBytes(m_padSalt, sizeof(m_padSalt));
    uint32_t zeroCRC = 0;
    m_file.write(reinterpret_cast<const char*>(m_padSalt), sizeof(m_padSalt));
    m_file.write(reinterpret_cast<const char*>(&zeroCRC), sizeof(zeroCRC));
    if (!m_file) { std::wcerr << L"Write pad fingerprint failed" << std::endl; return false; }
    m_payloadOffset += sizeof(m_padSalt) + sizeof(uint32_t);
    // 诊断：打印写入后的条目数量与负载起始偏移
    std::wcerr << L"[evhd] create: relocCount=" << count
               << L" payloadOffset=" << m_payloadOffset << L"\n";
  }
  // Ensure write pointer is at payload start
  m_file.seekp(m_payloadOffset, std::ios::beg);
  // 重置明文输入流位置，开始顺序加密写入
  in.seekg(0, std::ios::beg);

  // Init crypto
  CryptoContext::Params p;
  p.salt.assign(std::begin(m_header.salt), std::end(m_header.salt));
  p.nonce.assign(std::begin(m_header.nonce), std::end(m_header.nonce));
  p.iterations = m_header.kdfIterations;
  p.kdfMethod = m_header.kdfMethod;
  p.keyFilePath = keyFilePath;
  if (!m_crypto.init(password, p)) { std::wcerr << L"Init crypto context failed" << std::endl; return false; }

  // 打印 KDF 诊断：salt、nonce 和派生密钥前缀指纹
  {
    auto keyPrefix = m_crypto.keyPrefix8();
    std::wcerr << L"[evhd] kdf salt=" << hexBytes(m_header.salt, sizeof(m_header.salt))
               << L" nonce=" << hexBytes(m_header.nonce, sizeof(m_header.nonce))
               << L" key[0..7]=" << hexBytes(keyPrefix.data(), keyPrefix.size()) << L"\n";
  }

  // Stream encrypt
  const size_t bufSize = 1024 * 1024; // 1MB buffer
  std::vector<uint8_t> buf(bufSize);
  uint64_t offset = 0;
  // 初始化伪随机填充生成的种子与CRC
  uint64_t padSeed = deriveSeedFromSalt(m_padSalt);
  uint32_t padCRC = 0xFFFFFFFFU;
  while (offset < size) {
    size_t chunk = static_cast<size_t>(std::min<uint64_t>(bufSize, size - offset));
    in.read(reinterpret_cast<char*>(buf.data()), chunk);
    if (!in) { std::wcerr << L"Read plaintext VHD failed" << std::endl; return false; }
    // 对本chunk内的重定位范围进行剪切（填充0），使原位置不再含原分区表
    if (!m_relocations.empty()) {
      for (const auto &e : m_relocations) {
        uint64_t lo = e.logicalOffset;
        uint64_t hi = e.logicalOffset + e.length;
        uint64_t cLo = offset;
        uint64_t cHi = offset + chunk;
        if (cHi <= lo || hi <= cLo) continue; // no overlap
        uint64_t s = std::max<uint64_t>(cLo, lo);
        uint64_t t = std::min<uint64_t>(cHi, hi);
        size_t relStart = static_cast<size_t>(s - cLo);
        size_t relLen   = static_cast<size_t>(t - s);
        // 生成伪随机填充并更新指纹 CRC
        fillPseudoRandom(buf.data() + relStart, relLen, padSeed, s);
        padCRC = crc32_update(padCRC, buf.data() + relStart, relLen);
      }
    }
    if (!m_crypto.encryptRange(offset, buf.data(), chunk)) { std::wcerr << L"Encrypt block failed" << std::endl; return false; }
    m_file.write(reinterpret_cast<const char*>(buf.data()), chunk);
    if (!m_file) { std::wcerr << L"Write ciphertext payload failed" << std::endl; return false; }
    offset += chunk;
  }
  
  // 最终 CRC 取反得到结果，回填到头部扩展
  m_padCRC32 = padCRC ^ 0xFFFFFFFFU;
  if (m_header.version >= 4) {
    // 计算 CRC 字段的绝对文件偏移（严格对齐 readHeader 布局）：
    struct HeaderV1 { char magic[8]; uint32_t version; uint32_t kdfIterations; uint64_t originalSize; uint8_t salt[16]; uint8_t nonce[16]; };
    uint64_t base = sizeof(HeaderV1);
    if (m_header.version >= 3) {
      base += sizeof(uint32_t); // kdfMethod
    }
    if (m_header.version >= 2) {
      uint32_t nameLen = static_cast<uint32_t>(m_originalName.size());
      base += sizeof(uint32_t) + static_cast<uint64_t>(nameLen) * sizeof(wchar_t);
    }
    uint32_t count = static_cast<uint32_t>(m_relocations.size());
    base += sizeof(uint32_t) + static_cast<uint64_t>(count) * (sizeof(uint64_t) * 3);
    uint64_t padCRCPos = base + sizeof(m_padSalt); // 在盐之后的CRC位置
    m_file.seekp(padCRCPos, std::ios::beg);
    m_file.write(reinterpret_cast<const char*>(&m_padCRC32), sizeof(m_padCRC32));
    if (!m_file) { std::wcerr << L"Backfill pad CRC32 failed" << std::endl; return false; }
  }

  // 追加尾部：写入被剪切出来的原始数据（使用其物理偏移作为CTR偏移）
  for (size_t i = 0; i < m_relocations.size(); ++i) {
    const auto &e = m_relocations[i];
    std::vector<uint8_t> tmp = relocData[i];
    if (!m_crypto.encryptRange(e.physicalOffset, tmp.data(), tmp.size())) { std::wcerr << L"Encrypt relocated segment failed" << std::endl; return false; }
    m_file.seekp(m_payloadOffset + e.physicalOffset, std::ios::beg);
    m_file.write(reinterpret_cast<const char*>(tmp.data()), tmp.size());
    if (!m_file) { std::wcerr << L"Write relocated segment failed" << std::endl; return false; }
  }

  m_file.flush();
  in.close();

  m_ready = true;
  return true;
}

bool Container::readPlain(uint64_t offset, uint8_t *buffer, size_t length) {
  std::lock_guard<std::recursive_mutex> lg(m_mutex);
  if (!m_ready || !buffer || length == 0) return false;
  if (m_debug) {
    std::wcerr << L"[evhd] readPlain offset=" << offset << L" len=" << length << L"\n";
  }
  // 将逻辑请求映射为一个或多个物理段
  std::vector<RelocEntry> segs; mapLogicalToPhysical(offset, length, segs);
  // 合并相邻且物理/逻辑连续的段，减少 seek/read 次数
  std::vector<RelocEntry> merged; merged.reserve(segs.size());
  for (const auto &s : segs) {
    if (!merged.empty()) {
      auto &last = merged.back();
      if (last.physicalOffset + last.length == s.physicalOffset &&
          last.logicalOffset + last.length == s.logicalOffset) {
        last.length += s.length;
        continue;
      }
    }
    merged.push_back(s);
  }
  if (m_debug) {
    std::wcerr << L"[evhd] segments count=" << segs.size() << L", merged=" << merged.size() << L"\n";
    for (size_t i = 0; i < merged.size(); ++i) {
      const auto &s = merged[i];
      std::wcerr << L"  seg[" << i << L"] logic=" << s.logicalOffset << L" phys=" << s.physicalOffset << L" len=" << s.length << L"\n";
    }
  }
  size_t bufPos = 0;
  for (const auto &s : merged) {
    if (!readRawPhys(s.physicalOffset, buffer + bufPos, static_cast<size_t>(s.length))) {
      if (m_debug) {
        std::wcerr << L"[evhd] readRawPhys fail at phys=" << s.physicalOffset << L" len=" << s.length << L"\n";
      }
      return false;
    }
    if (!m_crypto.decryptRange(s.physicalOffset, buffer + bufPos, static_cast<size_t>(s.length))) {
      if (m_debug) {
        std::wcerr << L"[evhd] decryptRange failed at phys=" << s.physicalOffset << L" len=" << s.length << L"\n";
      }
      return false;
    }
    bufPos += static_cast<size_t>(s.length);
  }
  return true;
}

bool Container::writePlain(uint64_t offset, const uint8_t *buffer, size_t length) {
  std::lock_guard<std::recursive_mutex> lg(m_mutex);
  if (!m_ready || !buffer || length == 0) return false;
  // 将逻辑写入拆分为物理段（重定位范围写入尾部）
  std::vector<RelocEntry> segs; mapLogicalToPhysical(offset, length, segs);
  // 合并相邻且物理/逻辑连续的段，减少 seek/write 次数
  std::vector<RelocEntry> merged; merged.reserve(segs.size());
  for (const auto &s : segs) {
    if (!merged.empty()) {
      auto &last = merged.back();
      if (last.physicalOffset + last.length == s.physicalOffset &&
          last.logicalOffset + last.length == s.logicalOffset) {
        last.length += s.length;
        continue;
      }
    }
    merged.push_back(s);
  }
  size_t bufPos = 0;
  std::vector<uint8_t> tmp; tmp.reserve(length);
  std::vector<uint8_t> ciphertext;
  ciphertext.reserve(length);
  for (const auto &s : merged) {
    tmp.assign(buffer + bufPos, buffer + bufPos + static_cast<size_t>(s.length));
    if (!m_crypto.encryptRange(s.physicalOffset, tmp.data(), static_cast<size_t>(s.length))) return false;
    ciphertext.insert(ciphertext.end(), tmp.begin(), tmp.end());
    bufPos += static_cast<size_t>(s.length);
  }

  if (!prepareJournalTransaction(merged, ciphertext)) {
    m_ready = false;
    return false;
  }

  size_t cipherPos = 0;
  for (const auto &s : merged) {
    if (!writeRawPhys(s.physicalOffset, ciphertext.data() + cipherPos, static_cast<size_t>(s.length))) {
      m_ready = false;
      return false;
    }
    cipherPos += static_cast<size_t>(s.length);
  }

  if (!flush()) {
    m_ready = false;
    return false;
  }

  if (!clearJournalState(true)) {
    m_ready = false;
    return false;
  }

  return true;
}

bool Container::readHeader() {
  m_file.seekg(0, std::ios::beg);
  // Read base v1 header (56 bytes)
  struct HeaderV1 {
    char magic[8];
    uint32_t version;
    uint32_t kdfIterations;
    uint64_t originalSize;
    uint8_t  salt[16];
    uint8_t  nonce[16];
  } v1{};
  m_file.read(reinterpret_cast<char*>(&v1), sizeof(v1));
  if (!m_file) return false;
  if (memcmp(v1.magic, MAGIC, sizeof(v1.magic)) != 0) return false;
  if (v1.version != 1 && v1.version != 2 && v1.version != 3 && v1.version != 4) return false;
  // fill common fields
  memcpy(m_header.magic, v1.magic, sizeof(m_header.magic));
  m_header.version = v1.version;
  m_header.kdfIterations = v1.kdfIterations;
  m_header.originalSize = v1.originalSize;
  memcpy(m_header.salt, v1.salt, sizeof(m_header.salt));
  memcpy(m_header.nonce, v1.nonce, sizeof(m_header.nonce));
  m_header.kdfMethod = KDF_PASSWORD; // default
  // default payload offset
  m_payloadOffset = sizeof(HeaderV1);
  // if v3, read kdfMethod (4 bytes)
  if (m_header.version >= 3) {
    uint32_t method = 0;
    m_file.read(reinterpret_cast<char*>(&method), sizeof(method));
    if (!m_file) return false;
    m_header.kdfMethod = method;
    m_payloadOffset += sizeof(uint32_t);
  }
  // read optional metadata for version >= 2: original filename
  if (m_header.version >= 2) {
    uint32_t nameLen = 0;
    m_file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
    if (!m_file) { return false; }
    if (nameLen > 0) {
      std::vector<wchar_t> buf(nameLen);
      m_file.read(reinterpret_cast<char*>(buf.data()), nameLen * sizeof(wchar_t));
      if (!m_file) return false;
      m_originalName.assign(buf.begin(), buf.end());
    }
    m_payloadOffset += sizeof(uint32_t) + static_cast<uint64_t>(nameLen) * sizeof(wchar_t);
  }
  // v4: 读取重定位条目（如存在）
  if (m_header.version >= 4) {
    uint32_t count = 0;
    m_file.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!m_file) return false;
    m_relocations.clear(); m_relocations.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
      RelocEntry e{};
      m_file.read(reinterpret_cast<char*>(&e.logicalOffset), sizeof(e.logicalOffset));
      m_file.read(reinterpret_cast<char*>(&e.length), sizeof(e.length));
      m_file.read(reinterpret_cast<char*>(&e.physicalOffset), sizeof(e.physicalOffset));
      if (!m_file) return false;
      m_relocations.push_back(e);
    }
    m_payloadOffset += sizeof(uint32_t) + static_cast<uint64_t>(count) * (sizeof(uint64_t) * 3);
    // 额外读取填充指纹：16字节盐 + 4字节CRC32
    m_file.read(reinterpret_cast<char*>(m_padSalt), sizeof(m_padSalt));
    m_file.read(reinterpret_cast<char*>(&m_padCRC32), sizeof(m_padCRC32));
    if (!m_file) return false;
    m_payloadOffset += sizeof(m_padSalt) + sizeof(uint32_t);
  }
  return true;
}

bool Container::writeHeader() {
  std::lock_guard<std::recursive_mutex> lg(m_mutex);
  // 规范化写入：按 readHeader 使用的布局逐字段写入，避免结构体填充差异
  m_file.seekp(0, std::ios::beg);
  struct HeaderV1 {
    char magic[8];
    uint32_t version;
    uint32_t kdfIterations;
    uint64_t originalSize;
    uint8_t  salt[16];
    uint8_t  nonce[16];
  } v1{};
  memcpy(v1.magic, m_header.magic, sizeof(v1.magic));
  v1.version = m_header.version;
  v1.kdfIterations = m_header.kdfIterations;
  v1.originalSize = m_header.originalSize;
  memcpy(v1.salt, m_header.salt, sizeof(v1.salt));
  memcpy(v1.nonce, m_header.nonce, sizeof(v1.nonce));
  m_file.write(reinterpret_cast<const char*>(&v1), sizeof(v1));
  if (!m_file) return false;
  if (m_header.version >= 3) {
    uint32_t method = m_header.kdfMethod;
    m_file.write(reinterpret_cast<const char*>(&method), sizeof(method));
    if (!m_file) return false;
  }
  m_file.flush();
  return !!m_file;
}

bool Container::initializeJournal() {
  memset(&m_journal, 0, sizeof(m_journal));
  memcpy(m_journal.magic, JOURNAL_MAGIC, sizeof(m_journal.magic));
  m_journal.version = JOURNAL_VERSION;
  m_journal.state = JOURNAL_STATE_CLEAN;
  m_journal.dirty = 0;
  m_journal.entryCount = 0;
  m_journal.dataSize = 0;
  m_journal.sequence = 0;
  m_journal.entriesCRC32 = 0;
  m_journal.dataCRC32 = 0;
  return writeJournalHeader(true, true);
}

bool Container::readJournalHeader() {
  if (m_journalHandle == INVALID_HANDLE_VALUE) return false;
  uint64_t size = getHandleSize(m_journalHandle);
  if (size == 0) {
    return initializeJournal();
  }
  if (size < sizeof(m_journal)) {
    return false;
  }
  if (!readHandleExact(m_journalHandle, 0, &m_journal, sizeof(m_journal))) {
    return false;
  }
  if (memcmp(m_journal.magic, JOURNAL_MAGIC, sizeof(m_journal.magic)) != 0) return false;
  if (m_journal.version != JOURNAL_VERSION) return false;
  return true;
}

bool Container::writeJournalHeader(bool flushToDisk, bool trimToHeader) {
  if (m_journalHandle == INVALID_HANDLE_VALUE) return false;
  if (!writeHandleExact(m_journalHandle, 0, &m_journal, sizeof(m_journal))) {
    return false;
  }
  if (trimToHeader && !resizeHandle(m_journalHandle, sizeof(m_journal))) {
    return false;
  }
  if (flushToDisk && !FlushFileBuffers(m_journalHandle)) {
    return false;
  }
  return true;
}

bool Container::ensureJournalDirty() {
  if (m_journalHandle == INVALID_HANDLE_VALUE) return false;
  if (m_journal.dirty != 0) return true;
  m_journal.state = JOURNAL_STATE_CLEAN;
  m_journal.dirty = 1;
  m_journal.entryCount = 0;
  m_journal.dataSize = 0;
  m_journal.entriesCRC32 = 0;
  m_journal.dataCRC32 = 0;
  return writeJournalHeader(true, true);
}

bool Container::clearJournalState(bool dirtyFlag) {
  if (m_journalHandle == INVALID_HANDLE_VALUE) return false;
  m_journal.state = JOURNAL_STATE_CLEAN;
  m_journal.dirty = dirtyFlag ? 1u : 0u;
  m_journal.entryCount = 0;
  m_journal.dataSize = 0;
  m_journal.entriesCRC32 = 0;
  m_journal.dataCRC32 = 0;
  return writeJournalHeader(true, true);
}

bool Container::prepareJournalTransaction(const std::vector<RelocEntry> &segments,
                                         const std::vector<uint8_t> &ciphertext) {
  if (m_journalHandle == INVALID_HANDLE_VALUE) return false;
  if (!ensureJournalDirty()) return false;

  std::vector<JournalEntryState> entries;
  entries.reserve(segments.size());
  uint64_t dataOffset = 0;
  for (const auto &seg : segments) {
    JournalEntryState entry{};
    entry.physOffset = seg.physicalOffset;
    entry.length = seg.length;
    entry.dataOffset = dataOffset;
    entries.push_back(entry);
    dataOffset += seg.length;
  }
  if (dataOffset != ciphertext.size()) return false;

  uint32_t entriesCRC = 0;
  if (!entries.empty()) {
    entriesCRC = crc32_update(0xFFFFFFFFU,
                              reinterpret_cast<const uint8_t *>(entries.data()),
                              entries.size() * sizeof(JournalEntryState)) ^ 0xFFFFFFFFU;
  }
  uint32_t dataCRC = 0;
  if (!ciphertext.empty()) {
    dataCRC = crc32_update(0xFFFFFFFFU, ciphertext.data(), ciphertext.size()) ^ 0xFFFFFFFFU;
  }

  m_journal.sequence += 1;
  m_journal.state = JOURNAL_STATE_PREPARED;
  m_journal.dirty = 1;
  m_journal.entryCount = static_cast<uint32_t>(entries.size());
  m_journal.dataSize = static_cast<uint64_t>(ciphertext.size());
  m_journal.entriesCRC32 = entriesCRC;
  m_journal.dataCRC32 = dataCRC;

  const uint64_t entriesOffset = sizeof(m_journal);
  const uint64_t dataOffsetBase = entriesOffset + static_cast<uint64_t>(entries.size()) * sizeof(JournalEntryState);
  if (!writeHandleExact(m_journalHandle, 0, &m_journal, sizeof(m_journal))) return false;
  if (!entries.empty() && !writeHandleExact(m_journalHandle, entriesOffset, entries.data(),
                                            entries.size() * sizeof(JournalEntryState))) {
    return false;
  }
  if (!ciphertext.empty() && !writeHandleExact(m_journalHandle, dataOffsetBase, ciphertext.data(), ciphertext.size())) {
    return false;
  }
  if (!resizeHandle(m_journalHandle, dataOffsetBase + ciphertext.size())) return false;
  return !!FlushFileBuffers(m_journalHandle);
}

bool Container::recoverPendingJournal() {
  if (m_journalHandle == INVALID_HANDLE_VALUE) return false;
  if (m_journal.state != JOURNAL_STATE_PREPARED || m_journal.entryCount == 0) {
    return true;
  }

  const uint64_t entriesOffset = sizeof(m_journal);
  const uint64_t dataOffsetBase = entriesOffset + static_cast<uint64_t>(m_journal.entryCount) * sizeof(JournalEntryState);
  std::vector<JournalEntryState> entries(m_journal.entryCount);
  if (!readHandleExact(m_journalHandle, entriesOffset, entries.data(), entries.size() * sizeof(JournalEntryState))) {
    return false;
  }
  if (!entries.empty()) {
    uint32_t entriesCRC = crc32_update(0xFFFFFFFFU,
                                       reinterpret_cast<const uint8_t *>(entries.data()),
                                       entries.size() * sizeof(JournalEntryState)) ^ 0xFFFFFFFFU;
    if (entriesCRC != m_journal.entriesCRC32) return false;
  }

  std::vector<uint8_t> data(static_cast<size_t>(m_journal.dataSize));
  if (!data.empty() && !readHandleExact(m_journalHandle, dataOffsetBase, data.data(), data.size())) {
    return false;
  }
  if (!data.empty()) {
    uint32_t dataCRC = crc32_update(0xFFFFFFFFU, data.data(), data.size()) ^ 0xFFFFFFFFU;
    if (dataCRC != m_journal.dataCRC32) return false;
  }

  for (const auto &entry : entries) {
    if (entry.dataOffset + entry.length > data.size()) return false;
    if (!writeRawPhys(entry.physOffset, data.data() + entry.dataOffset, static_cast<size_t>(entry.length))) {
      return false;
    }
  }
  if (!flush()) return false;
  return clearJournalState(false);
}

bool Container::openJournal() {
  m_journalPath = m_path + L".journal";
  m_journalHandle = CreateFileW(m_journalPath.c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_WRITE_THROUGH,
                                nullptr);
  if (m_journalHandle == INVALID_HANDLE_VALUE) {
    return false;
  }
  if (!readJournalHeader()) {
    closeJournal(false);
    return false;
  }

  m_previousSessionDirty = (m_journal.dirty != 0);
  m_recoveredPendingJournal = (m_journal.state == JOURNAL_STATE_PREPARED && m_journal.entryCount > 0);
  if (m_recoveredPendingJournal && !recoverPendingJournal()) {
    closeJournal(false);
    return false;
  }
  if (m_journal.state == JOURNAL_STATE_CLEAN && m_journal.dirty != 0) {
    if (!clearJournalState(false)) {
      closeJournal(false);
      return false;
    }
  }
  return true;
}

void Container::closeJournal(bool cleanShutdown) {
  if (m_journalHandle == INVALID_HANDLE_VALUE) return;
  if (cleanShutdown && m_journal.state == JOURNAL_STATE_CLEAN) {
    clearJournalState(false);
  }
  CloseHandle(m_journalHandle);
  m_journalHandle = INVALID_HANDLE_VALUE;
}

bool Container::flush() {
  std::lock_guard<std::recursive_mutex> lg(m_mutex);
  bool ok = true;
  if (m_file.is_open()) {
    m_file.flush();
    ok = ok && !!m_file;
  }
  if (m_handle != INVALID_HANDLE_VALUE) {
    ok = ok && !!FlushFileBuffers(m_handle);
  }
  if (m_journalHandle != INVALID_HANDLE_VALUE) {
    ok = ok && !!FlushFileBuffers(m_journalHandle);
  }
  return ok;
}

void Container::close() {
  std::lock_guard<std::recursive_mutex> lg(m_mutex);
  bool cleanShutdown = (m_journalHandle != INVALID_HANDLE_VALUE && m_journal.state == JOURNAL_STATE_CLEAN);
  m_ready = false;
  if (m_handle != INVALID_HANDLE_VALUE) {
    FlushFileBuffers(m_handle);
  }
  if (m_file.is_open()) m_file.close();
  if (m_handle != INVALID_HANDLE_VALUE) { CloseHandle(m_handle); m_handle = INVALID_HANDLE_VALUE; }
  closeJournal(cleanShutdown);
}

// 将逻辑范围拆分为一个或多个物理段，以便读取/写入时正确应用CTR偏移
void Container::mapLogicalToPhysical(uint64_t logicalOffset, size_t length,
                                     std::vector<RelocEntry> &outSegments) const {
  outSegments.clear();
  uint64_t cur = logicalOffset;
  uint64_t end = logicalOffset + static_cast<uint64_t>(length);
  while (cur < end) {
    // 查找覆盖当前偏移的重定位条目
    const RelocEntry *hit = nullptr;
    for (const auto &e : m_relocations) {
      if (cur >= e.logicalOffset && cur < e.logicalOffset + e.length) { hit = &e; break; }
    }
    if (hit) {
      uint64_t within = cur - hit->logicalOffset;
      uint64_t maxLen = hit->length - within;
      uint64_t segLen = std::min<uint64_t>(maxLen, end - cur);
      RelocEntry seg{}; seg.logicalOffset = cur; seg.length = segLen; seg.physicalOffset = hit->physicalOffset + within;
      outSegments.push_back(seg);
      cur += segLen;
    } else {
      // 非重定位区：物理偏移==逻辑偏移，长度直到下一个重定位开始或请求结束
      uint64_t nextRelocStart = end;
      for (const auto &e : m_relocations) {
        if (e.logicalOffset > cur) nextRelocStart = std::min(nextRelocStart, e.logicalOffset);
      }
      uint64_t segLen = std::min<uint64_t>(nextRelocStart - cur, end - cur);
      RelocEntry seg{}; seg.logicalOffset = cur; seg.length = segLen; seg.physicalOffset = cur;
      outSegments.push_back(seg);
      cur += segLen;
    }
  }
}

// 打开时完整性校验：读取主负载区中被剪切的逻辑范围，解密并计算CRC，与头部指纹对比
bool Container::verifyIntegrity() {
  if (m_header.version < 4) {
    // v1-v3 不包含剪切填充指纹，视为跳过校验
    return true;
  }
  // 诊断输出基础信息
  if (m_debug) {
    std::wcerr << L"[evhd] integrity: payloadOffset=" << m_payloadOffset
               << L" relocCount=" << m_relocations.size() << L" padSalt="
               << hexBytes(m_padSalt, sizeof(m_padSalt)) << L"\n";
  }

  // 以逻辑顺序处理所有剪切范围，逐段从主负载区读取并解密
  std::vector<RelocEntry> ranges = m_relocations;
  std::sort(ranges.begin(), ranges.end(), [](const RelocEntry &a, const RelocEntry &b){
    return a.logicalOffset < b.logicalOffset;
  });

  uint32_t crc = 0xFFFFFFFFU;
  const size_t bufSize = 1 << 20; // 1MB
  std::vector<uint8_t> buf; buf.reserve(bufSize);

  for (const auto &e : ranges) {
    uint64_t processed = 0;
    while (processed < e.length) {
      size_t take = static_cast<size_t>(std::min<uint64_t>(bufSize, e.length - processed));
      buf.assign(take, 0);
      // 读取主负载区（不应用重定位映射）：绝对文件偏移 = payloadOffset + 逻辑偏移
      if (!readRawPhys(e.logicalOffset + processed, buf.data(), take)) {
        if (m_debug) {
          std::wcerr << L"[evhd] integrity: read fail at logical=" << (e.logicalOffset + processed)
                     << L" len=" << take << L"\n";
        }
        return false;
      }
      // 使用逻辑偏移作为CTR偏移进行解密（与创建时一致）
      if (!m_crypto.decryptRange(e.logicalOffset + processed, buf.data(), take)) {
        if (m_debug) {
          std::wcerr << L"[evhd] integrity: decrypt fail at logical=" << (e.logicalOffset + processed)
                     << L" len=" << take << L"\n";
        }
        return false;
      }
      // 累积CRC（创建时对伪随机填充的CRC应与此解密结果一致）
      crc = crc32_update(crc, buf.data(), take);
      processed += take;
    }
  }

  uint32_t computed = crc ^ 0xFFFFFFFFU;
  if (computed != m_padCRC32) {
    if (m_debug) {
      std::wcerr << L"[evhd] integrity: padCRC32 mismatch. expected=0x" << std::hex << m_padCRC32
                 << L" computed=0x" << computed << std::dec << L"\n";
    }
    return false;
  }
  return true;
}
 
// 原生偏移式I/O（Overlapped）辅助：在不改变文件指针的情况下按物理偏移读取
bool Container::readRawPhys(uint64_t physOffset, uint8_t *dst, size_t len) {
  if (m_handle == INVALID_HANDLE_VALUE) return false;
  ULONGLONG abs = m_payloadOffset + physOffset;
  if (!m_unbuffered) {
    OVERLAPPED ov{};
    ov.Offset     = static_cast<DWORD>(abs & 0xFFFFFFFFULL);
    ov.OffsetHigh = static_cast<DWORD>(abs >> 32);
    HANDLE hEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvt) return false;
    ov.hEvent = hEvt;
    DWORD want = static_cast<DWORD>(len);
    DWORD done = 0;
    BOOL ok = ReadFile(m_handle, dst, want, nullptr, &ov);
    if (!ok) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(m_handle, &ov, &done, TRUE);
      } else {
        CloseHandle(hEvt);
        return false;
      }
    } else {
      done = want; // synchronous path
    }
    CloseHandle(hEvt);
    return ok && done == want;
  } else {
    const uint64_t ss = m_sectorSize;
    uint64_t start = (abs / ss) * ss;
    uint64_t end   = ((abs + len + ss - 1) / ss) * ss;
    size_t need = static_cast<size_t>(end - start);

    // If the aligned range would exceed file size (EOF), fall back to buffered read
    LARGE_INTEGER fsz{};
    if (!GetFileSizeEx(m_handle, &fsz)) { return false; }
    ULONGLONG fileSize = (ULONGLONG)fsz.QuadPart;
    if (start + need > fileSize) {
      if (m_debug) {
        std::wcerr << L"[evhd] unbuffered read touches EOF. Falling back to buffered path. "
                   << L"abs=" << abs << L" len=" << len << L" start=" << start
                   << L" alignedNeed=" << need << L" fileSize=" << fileSize << L"\n";
      }
      // buffered fallback using std::fstream (thread-safe via mutex)
      std::lock_guard<std::recursive_mutex> lg(m_mutex);
      m_file.clear();
      m_file.seekg(static_cast<std::streamoff>(abs), std::ios::beg);
      m_file.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(len));
      return !!m_file;
    }

    uint8_t *buf = (uint8_t *)_aligned_malloc(need, ss);
    if (!buf) return false;
    OVERLAPPED ov{};
    ov.Offset     = static_cast<DWORD>(start & 0xFFFFFFFFULL);
    ov.OffsetHigh = static_cast<DWORD>(start >> 32);
    HANDLE hEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvt) { _aligned_free(buf); return false; }
    ov.hEvent = hEvt;
    DWORD want = static_cast<DWORD>(need);
    DWORD done = 0;
    BOOL ok = ReadFile(m_handle, buf, want, nullptr, &ov);
    if (!ok) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(m_handle, &ov, &done, TRUE);
      } else {
        if (m_debug) {
          std::wcerr << L"[evhd] ReadFile(unbuffered) failed. err=" << err
                     << L" start=" << start << L" want=" << want << L" ss=" << ss << L"\n";
        }
        CloseHandle(hEvt);
        _aligned_free(buf);
        return false;
      }
    } else {
      done = want;
    }
    CloseHandle(hEvt);
    if (!(ok && done == want)) { _aligned_free(buf); return false; }
    size_t inner = static_cast<size_t>(abs - start);
    memcpy(dst, buf + inner, len);
    _aligned_free(buf);
    return true;
  }
}

bool Container::writeRawPhys(uint64_t physOffset, const uint8_t *src, size_t len) {
  if (m_handle == INVALID_HANDLE_VALUE) return false;
  ULONGLONG abs = m_payloadOffset + physOffset;
  if (!m_unbuffered) {
    OVERLAPPED ov{};
    ov.Offset     = static_cast<DWORD>(abs & 0xFFFFFFFFULL);
    ov.OffsetHigh = static_cast<DWORD>(abs >> 32);
    HANDLE hEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvt) return false;
    ov.hEvent = hEvt;
    DWORD want = static_cast<DWORD>(len);
    DWORD done = 0;
    BOOL ok = WriteFile(m_handle, src, want, nullptr, &ov);
    if (!ok) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(m_handle, &ov, &done, TRUE);
      } else {
        CloseHandle(hEvt);
        return false;
      }
    } else {
      done = want; // synchronous path
    }
    CloseHandle(hEvt);
    return ok && done == want;
  } else {
    const uint64_t ss = m_sectorSize;
    uint64_t start = (abs / ss) * ss;
    uint64_t end   = ((abs + len + ss - 1) / ss) * ss;
    size_t need = static_cast<size_t>(end - start);
    uint8_t *buf = (uint8_t *)_aligned_malloc(need, ss);
    if (!buf) return false;
    // Read-modify-write for partial sector updates
    OVERLAPPED ovR{};
    ovR.Offset     = static_cast<DWORD>(start & 0xFFFFFFFFULL);
    ovR.OffsetHigh = static_cast<DWORD>(start >> 32);
    HANDLE hEvtR = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvtR) { _aligned_free(buf); return false; }
    ovR.hEvent = hEvtR;
    DWORD wantR = static_cast<DWORD>(need);
    DWORD doneR = 0;
    BOOL okR = ReadFile(m_handle, buf, wantR, nullptr, &ovR);
    if (!okR) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        okR = GetOverlappedResult(m_handle, &ovR, &doneR, TRUE);
      } else {
        CloseHandle(hEvtR);
        _aligned_free(buf);
        return false;
      }
    } else {
      doneR = wantR;
    }
    CloseHandle(hEvtR);
    if (!(okR && doneR == wantR)) { _aligned_free(buf); return false; }

    size_t inner = static_cast<size_t>(abs - start);
    memcpy(buf + inner, src, len);

    OVERLAPPED ovW{};
    ovW.Offset     = static_cast<DWORD>(start & 0xFFFFFFFFULL);
    ovW.OffsetHigh = static_cast<DWORD>(start >> 32);
    HANDLE hEvtW = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvtW) { _aligned_free(buf); return false; }
    ovW.hEvent = hEvtW;
    DWORD wantW = static_cast<DWORD>(need);
    DWORD doneW = 0;
    BOOL okW = WriteFile(m_handle, buf, wantW, nullptr, &ovW);
    if (!okW) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        okW = GetOverlappedResult(m_handle, &ovW, &doneW, TRUE);
      } else {
        CloseHandle(hEvtW);
        _aligned_free(buf);
        return false;
      }
    } else {
      doneW = wantW;
    }
    CloseHandle(hEvtW);
    _aligned_free(buf);
    return okW && doneW == wantW;
  }
}

} // namespace evhd