// Part of encrypted-vhd-mount

#include "crypto.h"

#include <stdexcept>
#include <cstring>
#include <iostream>

static std::string WideToUtf8(const std::wstring &w) {
  if (w.empty()) return std::string();
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), NULL, 0, NULL, NULL);
  std::string strTo(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), &strTo[0], size_needed, NULL, NULL);
  return strTo;
}

CryptoContext::CryptoContext() {}

CryptoContext::~CryptoContext() {
  if (m_aesKey) {
    BCryptDestroyKey(m_aesKey);
    m_aesKey = nullptr;
  }
  if (m_aesAlg) {
    BCryptCloseAlgorithmProvider(m_aesAlg, 0);
    m_aesAlg = nullptr;
  }
}

bool CryptoContext::init(const std::wstring &password, const Params &params) {
  NTSTATUS status = BCryptOpenAlgorithmProvider(&m_aesAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
  if (status != 0) { std::cerr << "Open AES provider failed: 0x" << std::hex << status << std::dec << std::endl; return false; }

  // We'll set chaining mode on the key after generation

  m_nonce = params.nonce;
  if (m_nonce.size() != 16) return false;

  m_key.resize(32);
  if (!deriveKey(password, params.salt, params.iterations, m_key)) {
    std::cerr << "PBKDF2 derive key failed" << std::endl; return false;
  }

  // Allocate key object buffer (must persist for key lifetime)
  DWORD objLen = 0;
  DWORD cbRes = 0;
  status = BCryptGetProperty(m_aesAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbRes, 0);
  if (status != 0) { std::cerr << "Get OBJECT_LENGTH failed: 0x" << std::hex << status << std::dec << std::endl; return false; }
  m_keyObject.assign(objLen, 0);

  status = BCryptGenerateSymmetricKey(m_aesAlg, &m_aesKey, m_keyObject.data(), (ULONG)m_keyObject.size(),
                                      (PUCHAR)m_key.data(), (ULONG)m_key.size(), 0);
  if (status != 0) { std::cerr << "GenerateSymmetricKey failed: 0x" << std::hex << status << std::dec << std::endl; return false; }

  // Set chaining mode to ECB on the key, CTR is implemented manually
  status = BCryptSetProperty(m_aesKey, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                             (ULONG)sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
  if (status != 0) { std::cerr << "Set CHAINING_MODE ECB failed: 0x" << std::hex << status << std::dec << std::endl; return false; }

  m_ready = true;
  return true;
}

bool CryptoContext::deriveKey(const std::wstring &password, const std::vector<uint8_t> &salt,
                              uint32_t iterations, std::vector<uint8_t> &keyOut) {
  BCRYPT_ALG_HANDLE hAlg = nullptr;
  NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (status != 0) return false;

  std::string pwUtf8 = WideToUtf8(password);
  keyOut.resize(32);

  status = BCryptDeriveKeyPBKDF2(hAlg,
                                 (PUCHAR)pwUtf8.data(), (ULONG)pwUtf8.size(),
                                 (PUCHAR)salt.data(), (ULONG)salt.size(),
                                 (ULONGLONG)iterations,
                                 (PUCHAR)keyOut.data(), (ULONG)keyOut.size(), 0);
  if (status != 0) { std::cerr << "BCryptDeriveKeyPBKDF2 failed: 0x" << std::hex << status << std::dec << std::endl; }
  BCryptCloseAlgorithmProvider(hAlg, 0);
  return status == 0;
}

void CryptoContext::makeIV(uint64_t fileOffset, std::vector<uint8_t> &ivOut) const {
  // AES CTR IV: 16 bytes = 8 bytes nonce prefix + 8 bytes counter
  ivOut.resize(16);
  // Use first 8 bytes of file nonce as prefix
  memcpy(ivOut.data(), m_nonce.data(), 8);
  // Counter = block index (offset / 16)
  uint64_t blockIndex = fileOffset / 16;
  memcpy(ivOut.data() + 8, &blockIndex, sizeof(blockIndex));
}

bool CryptoContext::aesCtrCrypt(uint64_t fileOffset, uint8_t *buffer, size_t length) {
  if (!m_ready) return false;
  if (length == 0) return true;

  // CTR: keystream = AES(IV+counter) under ECB, XOR with plaintext/ciphertext
  size_t processed = 0;
  uint64_t blockIndex = fileOffset / 16;
  size_t blockOffset = (size_t)(fileOffset % 16);

  while (processed < length) {
    std::vector<uint8_t> iv;
    // IV with current counter
    uint64_t offsetForIv = (blockIndex * 16);
    makeIV(offsetForIv, iv);

    uint8_t ks[16] = {0};
    ULONG outLen = 0;
    // Encrypt IV under ECB to produce keystream block
    NTSTATUS status = BCryptEncrypt(m_aesKey,
                                    iv.data(), (ULONG)iv.size(),
                                    nullptr,
                                    nullptr, 0,
                                    ks, (ULONG)sizeof(ks), &outLen,
                                    0);
    if (status != 0 || outLen != sizeof(ks)) return false;

    // Determine how many bytes from this block
    size_t take = std::min<size_t>(length - processed, 16 - blockOffset);
    for (size_t i = 0; i < take; ++i) {
      buffer[processed + i] ^= ks[blockOffset + i];
    }

    processed += take;
    blockIndex += 1;
    blockOffset = 0; // after first partial block, no offset
  }

  return true;
}

bool CryptoContext::decryptRange(uint64_t fileOffset, uint8_t *buffer, size_t length) {
  return aesCtrCrypt(fileOffset, buffer, length);
}

bool CryptoContext::encryptRange(uint64_t fileOffset, uint8_t *buffer, size_t length) {
  return aesCtrCrypt(fileOffset, buffer, length);
}