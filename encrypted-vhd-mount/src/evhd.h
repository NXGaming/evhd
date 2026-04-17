// Part of encrypted-vhd-mount

#pragma once

#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <array>
#include <vector>
#define NOMINMAX
#include <Windows.h>

#include "crypto.h"

namespace evhd {

constexpr const char MAGIC[8] = {'E','V','H','D','0','0','0','1'};

// KDF 方法
enum KdfMethod : uint32_t {
  KDF_PASSWORD = 0,              // 仅密码: PBKDF2-HMAC-SHA256(password)
  KDF_KEYFILE = 1,               // 仅密钥文件: PBKDF2-HMAC-SHA256(SHA256(keyfile))
  KDF_PASSWORD_PLUS_KEYFILE = 2  // 组合: HMAC-SHA256(keyfileDigest, pbkdfKey||salt||nonce)
};

struct Header {
  char magic[8];
  uint32_t version;        // 1
  uint32_t kdfIterations;  // e.g. 200000
  uint64_t originalSize;   // size of plaintext VHD
  uint8_t  salt[16];       // PBKDF2 salt
  uint8_t  nonce[16];      // CTR IV base
  uint32_t kdfMethod;      // since version 3
};

// 逻辑->物理重定位条目：将明文视图中的某段（逻辑偏移）剪切到尾部（物理偏移）
struct RelocEntry {
  uint64_t logicalOffset;  // 在原始VHD视图中的起始偏移（字节）
  uint64_t length;         // 被剪切的长度（字节，尽量对齐到512）
  uint64_t physicalOffset; // 在密文负载中的真实存放偏移（字节），通常 originalSize + ...
};

class Container {
public:
  Container() = default;
  ~Container() { close(); }

  bool openEncrypted(const std::wstring &path, const std::wstring &password,
                     const std::wstring &keyFilePath);
  bool createFromPlainVhd(const std::wstring &plainVhdPath, const std::wstring &encOutPath,
                          const std::wstring &password, const std::wstring &keyFilePath,
                          uint32_t iterations = 200000);

  bool readPlain(uint64_t offset, uint8_t *buffer, size_t length);
  bool writePlain(uint64_t offset, const uint8_t *buffer, size_t length);
  bool flush();

  void setDebug(bool on) { m_debug = on; }
  void setUnbuffered(bool on) { m_unbuffered = on; }

  uint64_t plaintextSize() const { return m_header.originalSize; }
  std::wstring underlyingPath() const { return m_path; }
  uint64_t payloadOffset() const { return m_payloadOffset; }
  std::wstring originalName() const { return m_originalName; }
  bool previousSessionDirty() const { return m_previousSessionDirty; }
  bool recoveredPendingJournal() const { return m_recoveredPendingJournal; }

  const std::vector<RelocEntry> &relocations() const { return m_relocations; }

  void close();

private:
  bool readHeader();
  bool writeHeader();
  // 读取/写入时将逻辑范围拆分为一个或多个物理片段（考虑重定位覆盖）
  void mapLogicalToPhysical(uint64_t logicalOffset, size_t length,
                            std::vector<RelocEntry> &outSegments) const;
  // 打开时完整性校验：验证剪切区域在主负载中的伪随机填充是否匹配头部指纹
  bool verifyIntegrity();
  bool openJournal();
  bool initializeJournal();
  bool readJournalHeader();
  bool writeJournalHeader(bool flushToDisk, bool trimToHeader);
  bool ensureJournalDirty();
  bool clearJournalState(bool dirtyFlag);
  bool recoverPendingJournal();
  bool prepareJournalTransaction(const std::vector<RelocEntry> &segments,
                                 const std::vector<uint8_t> &ciphertext);
  void closeJournal(bool cleanShutdown);

private:
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

  std::wstring m_path;
  Header m_header{};
  std::fstream m_file;
  HANDLE m_handle{INVALID_HANDLE_VALUE};
  HANDLE m_journalHandle{INVALID_HANDLE_VALUE};
  std::recursive_mutex m_mutex;
  CryptoContext m_crypto;
  bool m_ready{false};
  bool m_debug{false};
  bool m_previousSessionDirty{false};
  bool m_recoveredPendingJournal{false};
  uint64_t m_payloadOffset{sizeof(Header)};
  std::wstring m_originalName; // exposed file name in mount
  std::wstring m_journalPath;
  std::vector<RelocEntry> m_relocations; // v4: 分区表等剪切后的重定位条目
  JournalHeaderState m_journal{};
  // v4 扩展：剪切填充指纹与盐（用于生成伪随机填充）
  uint8_t m_padSalt[16]{};
  uint32_t m_padCRC32{0};
  bool m_unbuffered{false};
  uint32_t m_sectorSize{4096};
  // 原生偏移式I/O（Overlapped）辅助
  bool readRawPhys(uint64_t physOffset, uint8_t *dst, size_t len);
  bool writeRawPhys(uint64_t physOffset, const uint8_t *src, size_t len);
};

} // namespace evhd