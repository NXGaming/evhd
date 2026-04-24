// Part of encrypted-vhd-mount

#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>

class CryptoContext {
public:
  struct Params {
    std::vector<uint8_t> salt;      // 16 bytes
    std::vector<uint8_t> nonce;     // 16 bytes (CTR IV base)
    uint32_t iterations;            // PBKDF2 iterations
    uint32_t kdfMethod;             // see evhd::KdfMethod
    std::wstring keyFilePath;       // optional key file path
  };

  CryptoContext();
  ~CryptoContext();

  bool init(const std::wstring &password, const Params &params);

  // v5: dual-key derivation (aesKey + hmacKey)
  bool initV5(const std::wstring &password, const Params &params);

  // In-place decrypt/encrypt using AES-256-CTR with per-block IV derived from file offset
  bool decryptRange(uint64_t fileOffset, uint8_t *buffer, size_t length);
  bool encryptRange(uint64_t fileOffset, uint8_t *buffer, size_t length);

  // v5: HMAC-SHA256 for data authentication
  bool hmacData(const uint8_t *data, size_t length, std::vector<uint8_t> &tagOut) const;
  bool verifyHmac(const uint8_t *data, size_t length, const uint8_t *tag) const;

  bool isReady() const { return m_ready; }
  bool isV5() const { return m_v5; }

private:
  bool deriveKey(const std::wstring &password, const Params &params,
                 std::vector<uint8_t> &keyOut);

  bool aesCtrCrypt(uint64_t fileOffset, uint8_t *buffer, size_t length);

  void makeIV(uint64_t fileOffset, std::vector<uint8_t> &ivOut) const;

private:
  BCRYPT_ALG_HANDLE m_aesAlg{nullptr};
  BCRYPT_KEY_HANDLE m_aesKey{nullptr};
  std::vector<uint8_t> m_key; // 32 bytes
  std::vector<uint8_t> m_nonce; // 16 bytes
  std::vector<uint8_t> m_keyObject; // must live as long as m_aesKey
  std::vector<uint8_t> m_hmacKey; // 32 bytes, v5 only
  bool m_ready{false};
  bool m_v5{false};
};