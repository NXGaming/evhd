// Part of encrypted-vhd-mount

#pragma once

#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

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

  uint64_t plaintextSize() const { return m_header.originalSize; }
  std::wstring underlyingPath() const { return m_path; }
  uint64_t payloadOffset() const { return m_payloadOffset; }
  std::wstring originalName() const { return m_originalName; }

  void close();

private:
  bool readHeader();
  bool writeHeader();

private:
  std::wstring m_path;
  Header m_header{};
  std::fstream m_file;
  std::mutex m_mutex;
  CryptoContext m_crypto;
  bool m_ready{false};
  uint64_t m_payloadOffset{sizeof(Header)};
  std::wstring m_originalName; // exposed file name in mount
};

} // namespace evhd