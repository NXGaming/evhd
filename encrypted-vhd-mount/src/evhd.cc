// Part of encrypted-vhd-mount

#include "evhd.h"

#include "vmprotect_scope.h"

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
  if (n == 0) return;
  BCRYPT_ALG_HANDLE hRand = nullptr;
  NTSTATUS status = BCryptOpenAlgorithmProvider(&hRand, BCRYPT_RNG_ALGORITHM, nullptr, 0);
  if (status == 0) {
    status = BCryptGenRandom(hRand, buf, static_cast<ULONG>(n), 0);
    BCryptCloseAlgorithmProvider(hRand, 0);
    if (status == 0) return;
  }
  // Fallback: std::random_device (usually CSPRNG on Windows)
  std::random_device rd;
  for (size_t i = 0; i < n; ++i) buf[i] = static_cast<uint8_t>(rd() & 0xFF);
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
  size_t doneTotal = 0;
  while (doneTotal < len) {
    DWORD want = static_cast<DWORD>(std::min<size_t>(len - doneTotal, 1u << 20));
    OVERLAPPED ov{};
    ov.Offset     = static_cast<DWORD>((offset + doneTotal) & 0xFFFFFFFFULL);
    ov.OffsetHigh = static_cast<DWORD>((offset + doneTotal) >> 32);
    HANDLE hEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvt) return false;
    ov.hEvent = hEvt;
    DWORD done = 0;
    BOOL ok = ReadFile(handle, static_cast<uint8_t *>(buffer) + doneTotal, want, nullptr, &ov);
    if (!ok) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(handle, &ov, &done, TRUE);
      } else {
        CloseHandle(hEvt);
        return false;
      }
    } else {
      done = want;
    }
    CloseHandle(hEvt);
    if (!ok || done != want) return false;
    doneTotal += done;
  }
  return true;
}

static bool writeHandleExact(HANDLE handle, uint64_t offset, const void *buffer, size_t len) {
  size_t doneTotal = 0;
  while (doneTotal < len) {
    DWORD want = static_cast<DWORD>(std::min<size_t>(len - doneTotal, 1u << 20));
    OVERLAPPED ov{};
    ov.Offset     = static_cast<DWORD>((offset + doneTotal) & 0xFFFFFFFFULL);
    ov.OffsetHigh = static_cast<DWORD>((offset + doneTotal) >> 32);
    HANDLE hEvt = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEvt) return false;
    ov.hEvent = hEvt;
    DWORD done = 0;
    BOOL ok = WriteFile(handle, static_cast<const uint8_t *>(buffer) + doneTotal, want, nullptr, &ov);
    if (!ok) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(handle, &ov, &done, TRUE);
      } else {
        CloseHandle(hEvt);
        return false;
      }
    } else {
      done = want;
    }
    CloseHandle(hEvt);
    if (!ok || done != want) return false;
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
  std::unique_lock<std::shared_mutex> ul(m_rwMutex);
  closeInternal();
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

  if (!initCryptoContext(password, keyFilePath)) {
    std::wcerr << L"[evhd] crypto init failed" << std::endl;
    return false;
  }

  // v5: 验证 headerHMAC（必须在 crypto init 之后，因为需要 hmacKey）
  if (m_header.version >= 5) {
    std::vector<uint8_t> computedHeaderHmac(32);
    if (!computeHeaderHmac(computedHeaderHmac)) {
      std::wcerr << L"[evhd] compute header HMAC failed" << std::endl;
      return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; ++i) diff |= (computedHeaderHmac[i] ^ m_headerHmac[i]);
    if (diff != 0) {
      std::wcerr << L"[evhd] header HMAC verification FAILED" << std::endl;
      return false;
    }
    if (m_debug) std::wcerr << L"[evhd] header HMAC verification OK" << std::endl;

    // v5: 读取 payload auth tags
    if (m_header.authBlockSize > 0) {
      if (!readPayloadAuthTags()) {
        std::wcerr << L"[evhd] read payload auth tags failed" << std::endl;
        return false;
      }
      if (m_debug) {
        std::wcerr << L"[evhd] payload auth tags loaded. count="
                   << (m_payloadAuthTags.size() / 32) << L"\n";
      }
    }
  }

  // Integrity check: validate pseudo-random pad fingerprint over cut ranges
  bool integrityOk = verifyIntegrity();
  if (!integrityOk) {
    std::wcerr << L"[evhd] integrity check FAILED: pseudo pad mismatch or read error" << std::endl;
    // 严格模式：校验失败则拒绝打开
    m_ready = false;
    return false;
  } else {
    if (m_debug) std::wcerr << L"[evhd] integrity check OK" << std::endl;
  }

  m_ready = true;

  // Create memory mapping for fast reads (buffered mode only).
  // This eliminates kernel transitions for read I/O by mapping the file directly.
  if (!m_unbuffered && m_handle != INVALID_HANDLE_VALUE) {
    LARGE_INTEGER fileSize{};
    if (GetFileSizeEx(m_handle, &fileSize) && fileSize.QuadPart > 0) {
      m_mappingHandle = CreateFileMappingW(m_handle, nullptr, PAGE_READWRITE, 0, 0, nullptr);
      if (m_mappingHandle) {
        m_mappedView = static_cast<const uint8_t*>(
            MapViewOfFile(m_mappingHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0));
        if (m_mappedView) {
          m_mappedSize = static_cast<uint64_t>(fileSize.QuadPart);
        } else {
          CloseHandle(m_mappingHandle);
          m_mappingHandle = nullptr;
        }
      }
    }
  }

  // Initialize the JournalBatcher for group-commit write batching
  // (only if journal is available — v4+ containers with successful journal init)
  if (m_journalHandle != INVALID_HANDLE_VALUE) {
    initBatcher();
  }

  return true;
}

bool Container::createFromPlainVhd(const std::wstring &plainVhdPath, const std::wstring &encOutPath,
                                   const std::wstring &password, const std::wstring &keyFilePath,
                                   uint32_t iterations, uint32_t targetVersion) {
  std::unique_lock<std::shared_mutex> ul(m_rwMutex);
  closeInternal();
  m_path = encOutPath;
  m_previousSessionDirty = false;
  m_recoveredPendingJournal = false;
  DeleteFileW((encOutPath + L".journal").c_str());

  std::ifstream in(plainVhdPath.c_str(), std::ios::binary | std::ios::in);
  if (!in.is_open()) return false;

  in.seekg(0, std::ios::end);
  uint64_t size = static_cast<uint64_t>(in.tellg());
  in.seekg(0, std::ios::beg);

  m_file.open(encOutPath.c_str(), std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
  if (!m_file.is_open()) return false;

  std::vector<std::vector<uint8_t>> relocData;
  {
    evhd_vmp::Scope scope("container_create_layout", evhd_vmp::Mode::Mutation);

    // Prepare header
    memset(&m_header, 0, sizeof(m_header));
    memcpy(m_header.magic, MAGIC, sizeof(m_header.magic));
    m_header.version = targetVersion; // v4 or v5
    m_header.kdfIterations = iterations;
    m_header.originalSize = size;
    m_header.authBlockSize = 0; // disable payload auth tags by default (performance vs security tradeoff)
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
    relocData.reserve(plan.size());
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
      // v4/v5 扩展：写入填充指纹盐与占位指纹，稍后回填结果
      randomBytes(m_padSalt, sizeof(m_padSalt));
      if (m_header.version >= 5) {
        m_padHmac.assign(32, 0);
        m_file.write(reinterpret_cast<const char*>(m_padSalt), sizeof(m_padSalt));
        m_file.write(reinterpret_cast<const char*>(m_padHmac.data()), m_padHmac.size());
        m_payloadOffset += sizeof(m_padSalt) + m_padHmac.size();
      } else {
        uint32_t zeroCRC = 0;
        m_file.write(reinterpret_cast<const char*>(m_padSalt), sizeof(m_padSalt));
        m_file.write(reinterpret_cast<const char*>(&zeroCRC), sizeof(zeroCRC));
        m_payloadOffset += sizeof(m_padSalt) + sizeof(uint32_t);
      }
      if (!m_file) { std::wcerr << L"Write pad fingerprint failed" << std::endl; return false; }
      // 诊断：打印写入后的条目数量与负载起始偏移
      std::wcerr << L"[evhd] create: relocCount=" << count
                 << L" payloadOffset=" << m_payloadOffset << L"\n";
    }
    // v5 扩展：写入 authBlockSize + headerHMAC 占位 + relocAuthHMACs 占位
    if (m_header.version >= 5) {
      m_file.write(reinterpret_cast<const char*>(&m_header.authBlockSize), sizeof(m_header.authBlockSize));
      if (!m_file) { std::wcerr << L"Write v5 authBlockSize failed" << std::endl; return false; }
      // headerHMAC placeholder (32 bytes, backfilled later)
      m_headerHmac.assign(32, 0);
      m_file.write(reinterpret_cast<const char*>(m_headerHmac.data()), m_headerHmac.size());
      if (!m_file) { std::wcerr << L"Write v5 headerHMAC placeholder failed" << std::endl; return false; }
      // reloc auth HMAC placeholders
      uint32_t relocAuthCount = static_cast<uint32_t>(m_relocations.size());
      m_file.write(reinterpret_cast<const char*>(&relocAuthCount), sizeof(relocAuthCount));
      m_relocAuthHmacs.resize(relocAuthCount, std::vector<uint8_t>(32, 0));
      for (const auto &hmac : m_relocAuthHmacs) {
        m_file.write(reinterpret_cast<const char*>(hmac.data()), 32);
      }
      if (!m_file) { std::wcerr << L"Write v5 reloc auth HMACs failed" << std::endl; return false; }
      m_payloadOffset += sizeof(m_header.authBlockSize) + 32 + sizeof(uint32_t) + relocAuthCount * 32;
      std::wcerr << L"[evhd] create: v5 ext written. authBlockSize=" << m_header.authBlockSize
                 << L" payloadOffset=" << m_payloadOffset << L"\n";
    }
  }
  // Ensure write pointer is at payload start
  m_file.seekp(m_payloadOffset, std::ios::beg);
  // 重置明文输入流位置，开始顺序加密写入
  in.seekg(0, std::ios::beg);

  // Init crypto
  CryptoContext::Params p;
  p.salt.assign(std::begin(m_header.salt), std::end(m_header.salt));
  p.nonce.assign(std::begin(m_header.nonce), std::end(m_header.nonce));
  if (!initCryptoContext(password, keyFilePath)) {
    std::wcerr << L"Init crypto context failed" << std::endl;
    return false;
  }

  // Stream encrypt
  const size_t bufSize = 1024 * 1024; // 1MB buffer
  std::vector<uint8_t> buf(bufSize);
  uint64_t offset = 0;
  // 初始化伪随机填充生成的种子
  uint64_t padSeed = deriveSeedFromSalt(m_padSalt);
  // v4: CRC32 初始值
  uint32_t padCRC = 0xFFFFFFFFU;
  // v5: 收集所有填充数据用于 HMAC
  std::vector<uint8_t> padHmacInput;
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
        // 生成伪随机填充
        fillPseudoRandom(buf.data() + relStart, relLen, padSeed, s);
        // v5: 收集填充数据
        if (m_header.version >= 5) {
          size_t oldSize = padHmacInput.size();
          padHmacInput.resize(oldSize + relLen);
          memcpy(padHmacInput.data() + oldSize, buf.data() + relStart, relLen);
        }
        // v4: 更新 CRC（v5 不再使用）
        if (m_header.version < 5) {
          padCRC = crc32_update(padCRC, buf.data() + relStart, relLen);
        }
      }
    }
    if (!m_crypto.encryptRange(offset, buf.data(), chunk)) { std::wcerr << L"Encrypt block failed" << std::endl; return false; }
    m_file.write(reinterpret_cast<const char*>(buf.data()), chunk);
    if (!m_file) { std::wcerr << L"Write ciphertext payload failed" << std::endl; return false; }
    offset += chunk;
  }

  // v5: 计算 padHmac
  if (m_header.version >= 5 && !padHmacInput.empty()) {
    m_padHmac.resize(32);
    if (!m_crypto.hmacData(padHmacInput.data(), padHmacInput.size(), m_padHmac)) {
      std::wcerr << L"Compute pad HMAC failed" << std::endl; return false;
    }
  }

  // v4: 最终 CRC 取反得到结果，回填到头部扩展
  if (m_header.version < 5) {
    m_padCRC32 = padCRC ^ 0xFFFFFFFFU;
  }

  // 回填填充指纹到头部
  if (m_header.version >= 4) {
    // 计算指纹字段的绝对文件偏移（严格对齐 readHeader 布局）：
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

    if (m_header.version >= 5) {
      // v5: 回填 padHmac
      uint64_t padHmacPos = base + sizeof(m_padSalt);
      m_file.seekp(padHmacPos, std::ios::beg);
      m_file.write(reinterpret_cast<const char*>(m_padHmac.data()), m_padHmac.size());
      if (!m_file) { std::wcerr << L"Backfill pad HMAC failed" << std::endl; return false; }
    } else {
      // v4: 回填 CRC32
      uint64_t padCRCPos = base + sizeof(m_padSalt);
      m_file.seekp(padCRCPos, std::ios::beg);
      m_file.write(reinterpret_cast<const char*>(&m_padCRC32), sizeof(m_padCRC32));
      if (!m_file) { std::wcerr << L"Backfill pad CRC32 failed" << std::endl; return false; }
    }
  }

  // 追加尾部：写入被剪切出来的原始数据（使用其物理偏移作为CTR偏移）
  for (size_t i = 0; i < m_relocations.size(); ++i) {
    const auto &e = m_relocations[i];
    std::vector<uint8_t> tmp = relocData[i];
    if (!m_crypto.encryptRange(e.physicalOffset, tmp.data(), tmp.size())) { std::wcerr << L"Encrypt relocated segment failed" << std::endl; return false; }
    // v5: 计算重定位数据 HMAC
    if (m_header.version >= 5) {
      if (!computeRelocHmac(e.physicalOffset, tmp.data(), tmp.size(), m_relocAuthHmacs[i])) {
        std::wcerr << L"Compute reloc HMAC failed" << std::endl; return false;
      }
    }
    m_file.seekp(m_payloadOffset + e.physicalOffset, std::ios::beg);
    m_file.write(reinterpret_cast<const char*>(tmp.data()), tmp.size());
    if (!m_file) { std::wcerr << L"Write relocated segment failed" << std::endl; return false; }
  }

  // v5: 写入 payload auth tags 到文件尾部
  if (m_header.version >= 5 && m_header.authBlockSize > 0) {
    // Flush writes before reading back via separate ifstream
    m_file.flush();
    uint64_t numBlocks = (m_header.originalSize + m_header.authBlockSize - 1) / m_header.authBlockSize;
    std::vector<uint8_t> tags;
    tags.resize(static_cast<size_t>(numBlocks * 32));
    std::ifstream readBack(m_path.c_str(), std::ios::binary | std::ios::in);
    if (!readBack.is_open()) {
      std::wcerr << L"Open read-back stream for auth tags failed" << std::endl; return false;
    }
    for (uint64_t b = 0; b < numBlocks; ++b) {
      uint64_t physOff = b * m_header.authBlockSize;
      uint64_t blockLen = std::min<uint64_t>(m_header.authBlockSize, m_header.originalSize - physOff);
      // 回读刚写入的密文
      std::vector<uint8_t> cipher(static_cast<size_t>(blockLen));
      readBack.seekg(static_cast<std::streamoff>(m_payloadOffset + physOff), std::ios::beg);
      readBack.read(reinterpret_cast<char*>(cipher.data()), static_cast<std::streamsize>(blockLen));
      if (!readBack) { std::wcerr << L"Read back ciphertext for auth tag failed" << std::endl; return false; }
      std::vector<uint8_t> tag(32);
      if (!computePayloadAuthTag(physOff, cipher.data(), cipher.size(), tag)) {
        std::wcerr << L"Compute payload auth tag failed" << std::endl; return false;
      }
      memcpy(tags.data() + b * 32, tag.data(), 32);
    }
    readBack.close();
    m_file.seekp(0, std::ios::end);
    m_file.write(reinterpret_cast<const char*>(tags.data()), tags.size());
    if (!m_file) { std::wcerr << L"Write payload auth tags failed" << std::endl; return false; }
  }

  m_file.flush();
  in.close();

  // v5: 使用独立的 fstream 回填 HMAC 字段（避免大量写入后 seekp 的问题）
  if (m_header.version >= 5) {
    m_file.close();
    std::fstream backfill(m_path.c_str(), std::ios::binary | std::ios::in | std::ios::out);
    if (!backfill.is_open()) {
      std::wcerr << L"Open backfill stream failed" << std::endl; return false;
    }

    // 回填 padHmac
    struct HeaderV1 { char magic[8]; uint32_t version; uint32_t kdfIterations; uint64_t originalSize; uint8_t salt[16]; uint8_t nonce[16]; };
    uint64_t base = sizeof(HeaderV1);
    if (m_header.version >= 3) base += sizeof(uint32_t);
    if (m_header.version >= 2) {
      uint32_t nameLen = static_cast<uint32_t>(m_originalName.size());
      base += sizeof(uint32_t) + static_cast<uint64_t>(nameLen) * sizeof(wchar_t);
    }
    uint32_t count = static_cast<uint32_t>(m_relocations.size());
    base += sizeof(uint32_t) + static_cast<uint64_t>(count) * (sizeof(uint64_t) * 3);

    uint64_t padHmacPos = base + sizeof(m_padSalt);
    backfill.seekp(static_cast<std::streamoff>(padHmacPos), std::ios::beg);
    backfill.write(reinterpret_cast<const char*>(m_padHmac.data()), m_padHmac.size());
    if (!backfill) { std::wcerr << L"Backfill pad HMAC failed" << std::endl; return false; }

    // 回填 headerHMAC
    if (!computeHeaderHmac(m_headerHmac)) {
      std::wcerr << L"Compute header HMAC failed" << std::endl; return false;
    }
    uint64_t hmacPos = padHmacPos + m_padHmac.size() + sizeof(m_header.authBlockSize);
    backfill.seekp(static_cast<std::streamoff>(hmacPos), std::ios::beg);
    backfill.write(reinterpret_cast<const char*>(m_headerHmac.data()), m_headerHmac.size());
    if (!backfill) { std::wcerr << L"Backfill header HMAC failed" << std::endl; return false; }

    // 回填 reloc auth HMACs
    uint64_t relocHmacPos = hmacPos + 32 + sizeof(uint32_t);
    backfill.seekp(static_cast<std::streamoff>(relocHmacPos), std::ios::beg);
    for (const auto &hmac : m_relocAuthHmacs) {
      backfill.write(reinterpret_cast<const char*>(hmac.data()), 32);
    }
    if (!backfill) { std::wcerr << L"Backfill reloc auth HMACs failed" << std::endl; return false; }

    backfill.flush();
    backfill.close();

    // 重新打开 m_file 以保持 Container 状态一致
    m_file.open(m_path.c_str(), std::ios::binary | std::ios::in | std::ios::out);
  }

  m_ready = true;
  return true;
}

bool Container::readPlain(uint64_t offset, uint8_t *buffer, size_t length) {
  // Fast path: no shared_lock for reads. We use an atomic m_ready flag to detect
  // if the container is being closed. The shared_mutex is only acquired for writes
  // and lifecycle operations (open/close/flush).
  if (!m_ready.load(std::memory_order_acquire) || !buffer || length == 0) return false;
  if (m_debug) {
    std::wcerr << L"[evhd] readPlain offset=" << offset << L" len=" << length << L"\n";
  }

  // Fast path: if the read range doesn't overlap any relocation entry,
  // physicalOffset == logicalOffset and we can skip mapLogicalToPhysical entirely.
  bool hitsRelocation = false;
  uint64_t readEnd = offset + static_cast<uint64_t>(length);
  for (const auto &e : m_relocations) {
    uint64_t relocEnd = e.logicalOffset + e.length;
    if (offset < relocEnd && readEnd > e.logicalOffset) {
      hitsRelocation = true;
      break;
    }
  }

  if (!hitsRelocation) {
    // Simple case: single contiguous segment, physOffset == logicalOffset
    if (!readRawPhys(offset, buffer, length)) {
      if (m_debug) {
        std::wcerr << L"[evhd] readRawPhys fail at phys=" << offset << L" len=" << length << L"\n";
      }
      return false;
    }
    if (!m_crypto.decryptRange(offset, buffer, length)) {
      if (m_debug) {
        std::wcerr << L"[evhd] decryptRange failed at phys=" << offset << L" len=" << length << L"\n";
      }
      return false;
    }
    return true;
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
    // v5: verify payload auth tags for each auth block before decrypting
    if (m_crypto.isV5() && m_header.authBlockSize > 0) {
      uint64_t segPos = 0;
      while (segPos < s.length) {
        uint64_t blockStart = ((s.physicalOffset + segPos) / m_header.authBlockSize) * m_header.authBlockSize;
        uint64_t blockEnd = blockStart + m_header.authBlockSize;
        uint64_t inBlockOffset = (s.physicalOffset + segPos) - blockStart;
        uint64_t take = std::min<uint64_t>(blockEnd - (s.physicalOffset + segPos), s.length - segPos);
        // We need the full auth block ciphertext to verify HMAC
        // Read the full block from file (we already have partial in buffer)
        std::vector<uint8_t> blockCipher(static_cast<size_t>(m_header.authBlockSize));
        if (!readRawPhys(blockStart, blockCipher.data(), static_cast<size_t>(m_header.authBlockSize))) {
          if (m_debug) {
            std::wcerr << L"[evhd] auth tag verification read fail at blockStart=" << blockStart << L"\n";
          }
          return false;
        }
        if (!verifyPayloadAuthTag(blockStart, blockCipher.data(), static_cast<size_t>(m_header.authBlockSize))) {
          if (m_debug) {
            std::wcerr << L"[evhd] payload auth tag verification FAILED at blockStart=" << blockStart << L"\n";
          }
          return false;
        }
        segPos += take;
      }
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

void Container::initBatcher() {
  JournalBatcherIO io;

  // writeJournalEntries: for each transaction in the batch, call prepareJournalTransaction
  io.writeJournalEntries = [this](const std::vector<BatchTransaction> &transactions) -> bool {
    // Combine all transactions into a single journal transaction
    // (the journal supports multiple entries in one prepare call)
    std::vector<RelocEntry> allSegments;
    std::vector<uint8_t> allCiphertext;
    for (const auto &txn : transactions) {
      size_t cipherPos = 0;
      for (const auto &seg : txn.segments) {
        RelocEntry re{};
        re.physicalOffset = seg.physOffset;
        re.length = seg.length;
        re.logicalOffset = 0; // not used by prepareJournalTransaction
        allSegments.push_back(re);
        cipherPos += static_cast<size_t>(seg.length);
      }
      allCiphertext.insert(allCiphertext.end(), txn.ciphertext.begin(), txn.ciphertext.end());
    }
    return prepareJournalTransaction(allSegments, allCiphertext, false);
  };

  // flushJournal: single FlushFileBuffers on journal handle.
  // With FILE_FLAG_WRITE_THROUGH, writes are already durable so this is a no-op.
  io.flushJournal = [this]() -> bool {
    if (m_journalHandle == INVALID_HANDLE_VALUE) return false;
    // FILE_FLAG_WRITE_THROUGH guarantees write durability without explicit flush.
    // Skip FlushFileBuffers to avoid redundant ~7ms NVMe flush penalty per call.
    return true;
  };

  // writeMainData: write encrypted data to main container for each transaction
  io.writeMainData = [this](const std::vector<BatchTransaction> &transactions) -> bool {
    for (const auto &txn : transactions) {
      size_t cipherPos = 0;
      for (const auto &seg : txn.segments) {
        if (!writeRawPhys(seg.physOffset, txn.ciphertext.data() + cipherPos,
                          static_cast<size_t>(seg.length))) {
          return false;
        }
        // v5: update payload auth tags for this block if enabled
        if (m_crypto.isV5() && m_header.authBlockSize > 0 && !m_payloadAuthTags.empty()) {
          // Compute and update auth tag for each auth block touched by this segment
          uint64_t segStart = seg.physOffset;
          uint64_t segEnd = seg.physOffset + seg.length;
          uint64_t blockStart = (segStart / m_header.authBlockSize) * m_header.authBlockSize;
          while (blockStart < segEnd) {
            uint64_t blockLen = std::min<uint64_t>(m_header.authBlockSize,
                                                    m_header.originalSize - blockStart);
            // Read the full block ciphertext to compute the tag
            std::vector<uint8_t> blockCipher(static_cast<size_t>(blockLen));
            if (readRawPhys(blockStart, blockCipher.data(), static_cast<size_t>(blockLen))) {
              std::vector<uint8_t> tag(32);
              if (computePayloadAuthTag(blockStart, blockCipher.data(), blockCipher.size(), tag)) {
                uint64_t blockIndex = blockStart / m_header.authBlockSize;
                size_t tagOffset = static_cast<size_t>(blockIndex * 32);
                if (tagOffset + 32 <= m_payloadAuthTags.size()) {
                  memcpy(m_payloadAuthTags.data() + tagOffset, tag.data(), 32);
                  // Write updated tag to disk
                  uint64_t tagsFileOffset = m_payloadAuthTagsOffset + tagOffset;
                  writeHandleExact(m_handle, tagsFileOffset, tag.data(), 32);
                }
              }
            }
            blockStart += m_header.authBlockSize;
          }
        }
        cipherPos += static_cast<size_t>(seg.length);
      }
    }
    return true;
  };

  // flushMain: single FlushFileBuffers on main container handle.
  // With FILE_FLAG_WRITE_THROUGH, writes are already durable so this is a no-op.
  io.flushMain = [this]() -> bool {
    if (m_handle == INVALID_HANDLE_VALUE) return false;
    // FILE_FLAG_WRITE_THROUGH guarantees write durability without explicit flush.
    // Skip FlushFileBuffers to avoid redundant ~7ms NVMe flush penalty per call.
    return true;
  };

  // clearJournal: clear journal state after successful commit.
  // We skip the flush here because the journal is already safely committed
  // and the next batch will overwrite it anyway. This eliminates one
  // FlushFileBuffers call per batch.
  io.clearJournal = [this]() -> bool {
    return clearJournalStateNoFlush();
  };

  JournalBatcherConfig config;
  config.maxBatchBytes = 64 * 1024;  // 64 KiB
  config.maxBatchOps = 16;           // 16 operations
  config.timeout = std::chrono::milliseconds(1);

  m_batcher = std::make_unique<JournalBatcher>(std::move(io), config);
}

bool Container::writePlain(uint64_t offset, const uint8_t *buffer, size_t length) {
  std::shared_lock<std::shared_mutex> sl(m_rwMutex);
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

  // Compute the overall physical range for the range lock
  // (covers all merged segments from min physOffset to max physOffset+length)
  uint64_t rangeStart = merged.front().physicalOffset;
  uint64_t rangeEnd = merged.back().physicalOffset + merged.back().length;
  uint64_t rangeLen = rangeEnd - rangeStart;

  // Acquire exclusive range lock on the target physical offset range
  // This allows non-overlapping writes to proceed concurrently
  auto rangeLockGuard = m_rangeLock.guard(rangeStart, rangeLen, RangeLock::Mode::Exclusive);
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

  // If batcher is available, submit to it for group-commit batching.
  // Otherwise fall back to direct journal + write + flush + clear.
  if (m_batcher) {
    BatchTransaction txn;
    txn.segments.reserve(merged.size());
    for (const auto &s : merged) {
      txn.segments.push_back({s.physicalOffset, s.length});
    }
    txn.ciphertext = std::move(ciphertext);
    if (!m_batcher->submit(std::move(txn))) {
      m_ready = false;
      return false;
    }
    return true;
  }

  // Fallback: direct write path (no journal or batcher not available)
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

  if (!flushInternal()) {
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
  if (v1.version != 1 && v1.version != 2 && v1.version != 3 && v1.version != 4 && v1.version != 5) return false;
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
    if (m_header.version >= 5) {
      m_padHmac.resize(32);
      m_file.read(reinterpret_cast<char*>(m_padHmac.data()), 32);
      if (!m_file) return false;
      m_payloadOffset += sizeof(m_padSalt) + 32;
    } else {
      m_file.read(reinterpret_cast<char*>(&m_padCRC32), sizeof(m_padCRC32));
      if (!m_file) return false;
      m_payloadOffset += sizeof(m_padSalt) + sizeof(uint32_t);
    }
  }
  // v5: 读取扩展字段
  if (m_header.version >= 5) {
    m_file.read(reinterpret_cast<char*>(&m_header.authBlockSize), sizeof(m_header.authBlockSize));
    if (!m_file) return false;
    m_payloadOffset += sizeof(m_header.authBlockSize);

    // 读取 headerHMAC（稍后验证，在 crypto init 之后）
    m_headerHmac.resize(32);
    m_file.read(reinterpret_cast<char*>(m_headerHmac.data()), 32);
    if (!m_file) return false;
    m_payloadOffset += 32;

    // 读取重定位数据 auth HMACs
    uint32_t relocAuthCount = 0;
    m_file.read(reinterpret_cast<char*>(&relocAuthCount), sizeof(relocAuthCount));
    if (!m_file) return false;
    m_payloadOffset += sizeof(uint32_t);
    m_relocAuthHmacs.resize(relocAuthCount);
    for (uint32_t i = 0; i < relocAuthCount; ++i) {
      m_relocAuthHmacs[i].resize(32);
      m_file.read(reinterpret_cast<char*>(m_relocAuthHmacs[i].data()), 32);
      if (!m_file) return false;
      m_payloadOffset += 32;
    }
  }
  return true;
}

bool Container::writeHeader() {
  // Note: caller must hold m_rwMutex (exclusive lock)
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

// No-flush variant for the JournalBatcher: clears journal state in memory
// and writes the header to disk but skips FlushFileBuffers.
// The dirty flag is kept set so that ensureJournalDirty() won't flush on the
// next prepareJournalTransaction call (the batcher's flushJournal callback
// handles durability).
bool Container::clearJournalStateNoFlush() {
  if (m_journalHandle == INVALID_HANDLE_VALUE) return false;
  m_journal.state = JOURNAL_STATE_CLEAN;
  m_journal.dirty = 1u;  // keep dirty so ensureJournalDirty() is a no-op
  m_journal.entryCount = 0;
  m_journal.dataSize = 0;
  m_journal.entriesCRC32 = 0;
  m_journal.dataCRC32 = 0;
  return writeJournalHeader(false, true);  // write header but don't flush
}

bool Container::prepareJournalTransaction(const std::vector<RelocEntry> &segments,
                                         const std::vector<uint8_t> &ciphertext,
                                         bool flushAfter) {
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

  // v5: compute HMACs; v4: compute CRC32
  std::vector<uint8_t> entriesHmac(32), dataHmac(32);
  uint32_t entriesCRC = 0, dataCRC = 0;
  if (m_crypto.isV5()) {
    if (!entries.empty()) {
      if (!m_crypto.hmacData(reinterpret_cast<const uint8_t *>(entries.data()),
                             entries.size() * sizeof(JournalEntryState), entriesHmac)) {
        return false;
      }
    }
    if (!ciphertext.empty()) {
      if (!m_crypto.hmacData(ciphertext.data(), ciphertext.size(), dataHmac)) {
        return false;
      }
    }
  } else {
    if (!entries.empty()) {
      entriesCRC = crc32_update(0xFFFFFFFFU,
                                reinterpret_cast<const uint8_t *>(entries.data()),
                                entries.size() * sizeof(JournalEntryState)) ^ 0xFFFFFFFFU;
    }
    if (!ciphertext.empty()) {
      dataCRC = crc32_update(0xFFFFFFFFU, ciphertext.data(), ciphertext.size()) ^ 0xFFFFFFFFU;
    }
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
  const uint64_t totalDataSize = dataOffsetBase + ciphertext.size();
  if (!writeHandleExact(m_journalHandle, 0, &m_journal, sizeof(m_journal))) return false;
  if (!entries.empty() && !writeHandleExact(m_journalHandle, entriesOffset, entries.data(),
                                            entries.size() * sizeof(JournalEntryState))) {
    return false;
  }
  if (!ciphertext.empty() && !writeHandleExact(m_journalHandle, dataOffsetBase, ciphertext.data(), ciphertext.size())) {
    return false;
  }
  // v5: append HMACs at the end of journal file
  if (m_crypto.isV5()) {
    if (!writeHandleExact(m_journalHandle, totalDataSize, entriesHmac.data(), entriesHmac.size())) return false;
    if (!writeHandleExact(m_journalHandle, totalDataSize + entriesHmac.size(), dataHmac.data(), dataHmac.size())) return false;
    if (!resizeHandle(m_journalHandle, totalDataSize + entriesHmac.size() + dataHmac.size())) return false;
  } else {
    if (!resizeHandle(m_journalHandle, totalDataSize)) return false;
  }
  if (!flushAfter) return true;
  return !!FlushFileBuffers(m_journalHandle);
}

bool Container::recoverPendingJournal() {
  if (m_journalHandle == INVALID_HANDLE_VALUE) return false;
  if (m_journal.state != JOURNAL_STATE_PREPARED || m_journal.entryCount == 0) {
    return true;
  }

  evhd_vmp::Scope scope("journal_recover", evhd_vmp::Mode::Virtualization);

  const uint64_t entriesOffset = sizeof(m_journal);
  const uint64_t dataOffsetBase = entriesOffset + static_cast<uint64_t>(m_journal.entryCount) * sizeof(JournalEntryState);
  std::vector<JournalEntryState> entries(m_journal.entryCount);
  if (!readHandleExact(m_journalHandle, entriesOffset, entries.data(), entries.size() * sizeof(JournalEntryState))) {
    return false;
  }

  std::vector<uint8_t> data(static_cast<size_t>(m_journal.dataSize));
  if (!data.empty() && !readHandleExact(m_journalHandle, dataOffsetBase, data.data(), data.size())) {
    return false;
  }

  // v5: verify HMACs appended at end of journal file
  if (m_crypto.isV5()) {
    uint64_t totalDataSize = dataOffsetBase + m_journal.dataSize;
    std::vector<uint8_t> storedEntriesHmac(32), storedDataHmac(32);
    if (!readHandleExact(m_journalHandle, totalDataSize, storedEntriesHmac.data(), 32)) return false;
    if (!readHandleExact(m_journalHandle, totalDataSize + 32, storedDataHmac.data(), 32)) return false;

    if (!entries.empty()) {
      std::vector<uint8_t> computedEntriesHmac(32);
      if (!m_crypto.hmacData(reinterpret_cast<const uint8_t *>(entries.data()),
                             entries.size() * sizeof(JournalEntryState), computedEntriesHmac)) {
        return false;
      }
      if (!m_crypto.verifyHmac(reinterpret_cast<const uint8_t *>(entries.data()),
                               entries.size() * sizeof(JournalEntryState), storedEntriesHmac.data())) {
        std::wcerr << L"[evhd] journal entries HMAC verification FAILED" << std::endl;
        return false;
      }
    }
    if (!data.empty()) {
      if (!m_crypto.verifyHmac(data.data(), data.size(), storedDataHmac.data())) {
        std::wcerr << L"[evhd] journal data HMAC verification FAILED" << std::endl;
        return false;
      }
    }
  } else {
    // v4: verify CRC32
    if (!entries.empty()) {
      uint32_t entriesCRC = crc32_update(0xFFFFFFFFU,
                                         reinterpret_cast<const uint8_t *>(entries.data()),
                                         entries.size() * sizeof(JournalEntryState)) ^ 0xFFFFFFFFU;
      if (entriesCRC != m_journal.entriesCRC32) return false;
    }
    if (!data.empty()) {
      uint32_t dataCRC = crc32_update(0xFFFFFFFFU, data.data(), data.size()) ^ 0xFFFFFFFFU;
      if (dataCRC != m_journal.dataCRC32) return false;
    }
  }

  for (const auto &entry : entries) {
    if (entry.dataOffset + entry.length > data.size()) return false;
    if (!writeRawPhys(entry.physOffset, data.data() + entry.dataOffset, static_cast<size_t>(entry.length))) {
      return false;
    }
  }
  if (!flushInternal()) return false;
  return clearJournalState(false);
}

bool Container::openJournal() {
  m_journalPath = m_path + L".journal";
  m_journalHandle = CreateFileW(m_journalPath.c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED,
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
  std::unique_lock<std::shared_mutex> ul(m_rwMutex);
  // Commit any pending batched writes before flushing file handles
  if (m_batcher) {
    if (!m_batcher->commitNow()) return false;
  }
  return flushInternal();
}

bool Container::flushInternal() {
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
  std::unique_lock<std::shared_mutex> ul(m_rwMutex);
  closeInternal();
}

void Container::closeInternal() {
  bool cleanShutdown = (m_journalHandle != INVALID_HANDLE_VALUE && m_journal.state == JOURNAL_STATE_CLEAN);
  m_ready = false;
  // Stop the batcher first — flushes any pending writes before closing handles
  if (m_batcher) {
    m_batcher->stop();
    m_batcher.reset();
  }
  // Unmap memory-mapped view before closing handles
  if (m_mappedView) {
    UnmapViewOfFile(m_mappedView);
    m_mappedView = nullptr;
    m_mappedSize = 0;
  }
  if (m_mappingHandle) {
    CloseHandle(m_mappingHandle);
    m_mappingHandle = nullptr;
  }
  if (m_handle != INVALID_HANDLE_VALUE) {
    FlushFileBuffers(m_handle);
  }
  if (m_file.is_open()) m_file.close();
  if (m_handle != INVALID_HANDLE_VALUE) { CloseHandle(m_handle); m_handle = INVALID_HANDLE_VALUE; }
  closeJournal(cleanShutdown);
  // Clear v5 sensitive state
  m_padHmac.clear();
  m_headerHmac.clear();
  m_relocAuthHmacs.clear();
  m_payloadAuthTags.clear();
  m_payloadAuthTagsOffset = 0;
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

  evhd_vmp::Scope scope("container_verifyIntegrity", evhd_vmp::Mode::Virtualization);

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

  // v5: collect all pad data for HMAC; v4: use CRC32
  std::vector<uint8_t> padHmacInput;
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
      if (m_header.version >= 5) {
        size_t oldSize = padHmacInput.size();
        padHmacInput.resize(oldSize + take);
        memcpy(padHmacInput.data() + oldSize, buf.data(), take);
      } else {
        crc = crc32_update(crc, buf.data(), take);
      }
      processed += take;
    }
  }

  if (m_header.version >= 5) {
    std::vector<uint8_t> computedHmac(32);
    if (!padHmacInput.empty()) {
      if (!m_crypto.hmacData(padHmacInput.data(), padHmacInput.size(), computedHmac)) {
        if (m_debug) std::wcerr << L"[evhd] integrity: HMAC computation failed\n";
        return false;
      }
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; ++i) {
      diff |= (computedHmac[i] ^ m_padHmac[i]);
    }
    if (diff != 0) {
      if (m_debug) {
        std::wcerr << L"[evhd] integrity: padHMAC mismatch\n";
      }
      return false;
    }
  } else {
    uint32_t computed = crc ^ 0xFFFFFFFFU;
    if (computed != m_padCRC32) {
      if (m_debug) {
        std::wcerr << L"[evhd] integrity: padCRC32 mismatch. expected=0x" << std::hex << m_padCRC32
                   << L" computed=0x" << computed << std::dec << L"\n";
      }
      return false;
    }
  }
  return true;
}
 
// 原生偏移式I/O（Overlapped）辅助：在不改变文件指针的情况下按物理偏移读取
bool Container::readRawPhys(uint64_t physOffset, uint8_t *dst, size_t len) {
  if (m_handle == INVALID_HANDLE_VALUE) return false;
  ULONGLONG abs = m_payloadOffset + physOffset;

  // Fast path: use memory-mapped I/O if available (zero kernel transitions).
  if (m_mappedView && abs + len <= m_mappedSize) {
    memcpy(dst, m_mappedView + abs, len);
    return true;
  }

  // Thread-local event handle: created once per thread, reused across calls.
  // Manual-reset event (bManualReset=TRUE) is required for overlapped I/O.
  static thread_local HANDLE tlsEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!tlsEvent) return false;
  if (!m_unbuffered) {
    ResetEvent(tlsEvent);
    OVERLAPPED ov{};
    ov.Offset     = static_cast<DWORD>(abs & 0xFFFFFFFFULL);
    ov.OffsetHigh = static_cast<DWORD>(abs >> 32);
    ov.hEvent = tlsEvent;
    DWORD want = static_cast<DWORD>(len);
    DWORD done = 0;
    BOOL ok = ReadFile(m_handle, dst, want, nullptr, &ov);
    if (!ok) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(m_handle, &ov, &done, TRUE);
      } else {
        return false;
      }
    } else {
      done = want; // synchronous path
    }
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
      std::lock_guard<std::mutex> lg(m_fstreamMutex);
      m_file.clear();
      m_file.seekg(static_cast<std::streamoff>(abs), std::ios::beg);
      m_file.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(len));
      return !!m_file;
    }

    uint8_t *buf = (uint8_t *)_aligned_malloc(need, ss);
    if (!buf) return false;
    ResetEvent(tlsEvent);
    OVERLAPPED ov{};
    ov.Offset     = static_cast<DWORD>(start & 0xFFFFFFFFULL);
    ov.OffsetHigh = static_cast<DWORD>(start >> 32);
    ov.hEvent = tlsEvent;
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
        _aligned_free(buf);
        return false;
      }
    } else {
      done = want;
    }
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
  // Thread-local event handle: created once per thread, reused across calls.
  // Manual-reset event (bManualReset=TRUE) is required for overlapped I/O.
  static thread_local HANDLE tlsEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!tlsEvent) return false;
  if (!m_unbuffered) {
    ResetEvent(tlsEvent);
    OVERLAPPED ov{};
    ov.Offset     = static_cast<DWORD>(abs & 0xFFFFFFFFULL);
    ov.OffsetHigh = static_cast<DWORD>(abs >> 32);
    ov.hEvent = tlsEvent;
    DWORD want = static_cast<DWORD>(len);
    DWORD done = 0;
    BOOL ok = WriteFile(m_handle, src, want, nullptr, &ov);
    if (!ok) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(m_handle, &ov, &done, TRUE);
      } else {
        return false;
      }
    } else {
      done = want; // synchronous path
    }
    return ok && done == want;
  } else {
    const uint64_t ss = m_sectorSize;
    uint64_t start = (abs / ss) * ss;
    uint64_t end   = ((abs + len + ss - 1) / ss) * ss;
    size_t need = static_cast<size_t>(end - start);
    uint8_t *buf = (uint8_t *)_aligned_malloc(need, ss);
    if (!buf) return false;
    // Read-modify-write for partial sector updates
    ResetEvent(tlsEvent);
    OVERLAPPED ovR{};
    ovR.Offset     = static_cast<DWORD>(start & 0xFFFFFFFFULL);
    ovR.OffsetHigh = static_cast<DWORD>(start >> 32);
    ovR.hEvent = tlsEvent;
    DWORD wantR = static_cast<DWORD>(need);
    DWORD doneR = 0;
    BOOL okR = ReadFile(m_handle, buf, wantR, nullptr, &ovR);
    if (!okR) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        okR = GetOverlappedResult(m_handle, &ovR, &doneR, TRUE);
      } else {
        _aligned_free(buf);
        return false;
      }
    } else {
      doneR = wantR;
    }
    if (!(okR && doneR == wantR)) { _aligned_free(buf); return false; }

    size_t inner = static_cast<size_t>(abs - start);
    memcpy(buf + inner, src, len);

    ResetEvent(tlsEvent);
    OVERLAPPED ovW{};
    ovW.Offset     = static_cast<DWORD>(start & 0xFFFFFFFFULL);
    ovW.OffsetHigh = static_cast<DWORD>(start >> 32);
    ovW.hEvent = tlsEvent;
    DWORD wantW = static_cast<DWORD>(need);
    DWORD doneW = 0;
    BOOL okW = WriteFile(m_handle, buf, wantW, nullptr, &ovW);
    if (!okW) {
      DWORD err = GetLastError();
      if (err == ERROR_IO_PENDING) {
        okW = GetOverlappedResult(m_handle, &ovW, &doneW, TRUE);
      } else {
        _aligned_free(buf);
        return false;
      }
    } else {
      doneW = wantW;
    }
    _aligned_free(buf);
    return okW && doneW == wantW;
  }
}

// ---------------------------------------------------------------------------
// v5: Crypto context initialization with version-aware key derivation
// ---------------------------------------------------------------------------
bool Container::initCryptoContext(const std::wstring &password,
                                  const std::wstring &keyFilePath) {
  CryptoContext::Params p;
  p.salt.assign(std::begin(m_header.salt), std::end(m_header.salt));
  p.nonce.assign(std::begin(m_header.nonce), std::end(m_header.nonce));
  p.iterations = m_header.kdfIterations;
  p.kdfMethod = m_header.kdfMethod;
  p.keyFilePath = keyFilePath;
  if (m_header.version >= 5) {
    return m_crypto.initV5(password, p);
  }
  return m_crypto.init(password, p);
}

// ---------------------------------------------------------------------------
// v5: HMAC helpers
// ---------------------------------------------------------------------------
bool Container::computeHeaderHmac(std::vector<uint8_t> &hmacOut) const {
  hmacOut.assign(32, 0);
  if (!m_crypto.isV5()) return false;
  // HMAC covers: Header v1 + v3 ext + v2 ext + v4 ext + authBlockSize
  // Build a contiguous buffer of all header fields before the HMAC field itself
  std::vector<uint8_t> input;
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
  input.resize(sizeof(v1));
  memcpy(input.data(), &v1, sizeof(v1));
  if (m_header.version >= 3) {
    size_t oldSize = input.size();
    input.resize(oldSize + sizeof(uint32_t));
    memcpy(input.data() + oldSize, &m_header.kdfMethod, sizeof(uint32_t));
  }
  if (m_header.version >= 2) {
    uint32_t nameLen = static_cast<uint32_t>(m_originalName.size());
    size_t oldSize = input.size();
    input.resize(oldSize + sizeof(uint32_t) + nameLen * sizeof(wchar_t));
    memcpy(input.data() + oldSize, &nameLen, sizeof(uint32_t));
    if (nameLen > 0) {
      memcpy(input.data() + oldSize + sizeof(uint32_t), m_originalName.c_str(), nameLen * sizeof(wchar_t));
    }
  }
  if (m_header.version >= 4) {
    uint32_t count = static_cast<uint32_t>(m_relocations.size());
    size_t oldSize = input.size();
    input.resize(oldSize + sizeof(uint32_t) + count * sizeof(RelocEntry));
    memcpy(input.data() + oldSize, &count, sizeof(uint32_t));
    if (count > 0) {
      memcpy(input.data() + oldSize + sizeof(uint32_t), m_relocations.data(), count * sizeof(RelocEntry));
    }
    oldSize = input.size();
    if (m_header.version >= 5) {
      input.resize(oldSize + sizeof(m_padSalt) + m_padHmac.size());
      memcpy(input.data() + oldSize, m_padSalt, sizeof(m_padSalt));
      memcpy(input.data() + oldSize + sizeof(m_padSalt), m_padHmac.data(), m_padHmac.size());
    } else {
      input.resize(oldSize + sizeof(m_padSalt) + sizeof(uint32_t));
      memcpy(input.data() + oldSize, m_padSalt, sizeof(m_padSalt));
      memcpy(input.data() + oldSize + sizeof(m_padSalt), &m_padCRC32, sizeof(uint32_t));
    }
  }
  if (m_header.version >= 5) {
    size_t oldSize = input.size();
    input.resize(oldSize + sizeof(m_header.authBlockSize));
    memcpy(input.data() + oldSize, &m_header.authBlockSize, sizeof(m_header.authBlockSize));
  }
  return m_crypto.hmacData(input.data(), input.size(), hmacOut);
}

bool Container::computeRelocHmac(uint64_t physOffset, const uint8_t *cipherData,
                                 size_t len, std::vector<uint8_t> &hmacOut) const {
  hmacOut.assign(32, 0);
  if (!m_crypto.isV5() || !cipherData || len == 0) return false;
  std::vector<uint8_t> input(sizeof(physOffset) + len);
  memcpy(input.data(), &physOffset, sizeof(physOffset));
  memcpy(input.data() + sizeof(physOffset), cipherData, len);
  return m_crypto.hmacData(input.data(), input.size(), hmacOut);
}

bool Container::computePayloadAuthTag(uint64_t physBlockOffset, const uint8_t *cipherData,
                                      size_t len, std::vector<uint8_t> &tagOut) const {
  tagOut.assign(32, 0);
  if (!m_crypto.isV5() || !cipherData || len == 0) return false;
  std::vector<uint8_t> input(sizeof(physBlockOffset) + len);
  memcpy(input.data(), &physBlockOffset, sizeof(physBlockOffset));
  memcpy(input.data() + sizeof(physBlockOffset), cipherData, len);
  return m_crypto.hmacData(input.data(), input.size(), tagOut);
}

bool Container::verifyPayloadAuthTag(uint64_t physBlockOffset, const uint8_t *cipherData,
                                     size_t len) const {
  if (!m_crypto.isV5() || m_header.authBlockSize == 0) return true;
  if (!cipherData || len == 0) return false;
  uint64_t blockIndex = physBlockOffset / m_header.authBlockSize;
  if (m_payloadAuthTags.empty()) return false;
  size_t tagOffset = static_cast<size_t>(blockIndex * 32);
  if (tagOffset + 32 > m_payloadAuthTags.size()) return false;
  std::vector<uint8_t> computed(32);
  if (!computePayloadAuthTag(physBlockOffset, cipherData, len, computed)) return false;
  // Constant-time compare
  uint8_t diff = 0;
  for (size_t i = 0; i < 32; ++i) {
    diff |= (computed[i] ^ m_payloadAuthTags[tagOffset + i]);
  }
  return diff == 0;
}

uint64_t Container::payloadAuthTagsOffset() const {
  if (!m_crypto.isV5() || m_header.authBlockSize == 0 || m_relocations.empty()) {
    return m_payloadOffset + m_header.originalSize;
  }
  // Find max physical offset among relocations
  uint64_t maxPhys = m_header.originalSize;
  for (const auto &e : m_relocations) {
    uint64_t end = e.physicalOffset + e.length;
    if (end > maxPhys) maxPhys = end;
  }
  return m_payloadOffset + maxPhys;
}

bool Container::readPayloadAuthTags() {
  if (!m_crypto.isV5() || m_header.authBlockSize == 0) return true;
  uint64_t numBlocks = (m_header.originalSize + m_header.authBlockSize - 1) / m_header.authBlockSize;
  size_t tagsSize = static_cast<size_t>(numBlocks * 32);
  m_payloadAuthTags.resize(tagsSize);
  uint64_t tagsOffset = payloadAuthTagsOffset();
  if (!readHandleExact(m_handle, tagsOffset, m_payloadAuthTags.data(), tagsSize)) {
    m_payloadAuthTags.clear();
    return false;
  }
  m_payloadAuthTagsOffset = tagsOffset;
  return true;
}

} // namespace evhd