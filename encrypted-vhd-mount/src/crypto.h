// Part of encrypted-vhd-mount

#pragma once

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

  // In-place decrypt/encrypt using AES-256-CTR with per-block IV derived from file offset
  bool decryptRange(uint64_t fileOffset, uint8_t *buffer, size_t length);
  bool encryptRange(uint64_t fileOffset, uint8_t *buffer, size_t length);

  bool isReady() const { return m_ready; }

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
  bool m_ready{false};
};