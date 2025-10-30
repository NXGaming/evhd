// Part of encrypted-vhd-mount

#include "crypto.h"

#include <stdexcept>
#include <cstring>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <array>

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
  if (!deriveKey(password, params, m_key)) {
    std::cerr << "deriveKey failed" << std::endl; return false;
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

static bool sha256File(const std::wstring &path, std::vector<uint8_t> &digestOut) {
  digestOut.assign(32, 0);
  BCRYPT_ALG_HANDLE hAlg = nullptr;
  NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (status != 0) { std::cerr << "Open SHA256 provider failed: 0x" << std::hex << status << std::dec << std::endl; return false; }

  DWORD objLen = 0, cbRes = 0, hashLen = 0;
  status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbRes, 0);
  if (status != 0) { std::cerr << "Get hash OBJECT_LENGTH failed: 0x" << std::hex << status << std::dec << std::endl; BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cbRes, 0);
  if (status != 0 || hashLen != 32) { std::cerr << "Get HASH_LENGTH failed: 0x" << std::hex << status << std::dec << std::endl; BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

  std::vector<uint8_t> obj(objLen);
  BCRYPT_HASH_HANDLE hHash = nullptr;
  status = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, nullptr, 0, 0);
  if (status != 0) { std::cerr << "CreateHash failed: 0x" << std::hex << status << std::dec << std::endl; BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

  std::ifstream in(path.c_str(), std::ios::binary | std::ios::in);
  if (!in.is_open()) { std::wcerr << L"[crypto] open keyfile failed: " << path << std::endl; BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  const size_t bufSize = 1 << 20; // 1MB
  std::vector<uint8_t> buf(bufSize);
  while (in) {
    in.read(reinterpret_cast<char*>(buf.data()), bufSize);
    std::streamsize got = in.gcount();
    if (got <= 0) break;
    status = BCryptHashData(hHash, buf.data(), (ULONG)got, 0);
    if (status != 0) { std::cerr << "HashData failed: 0x" << std::hex << status << std::dec << std::endl; in.close(); BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  }
  in.close();

  status = BCryptFinishHash(hHash, digestOut.data(), hashLen, 0);
  if (status != 0) { std::cerr << "FinishHash failed: 0x" << std::hex << status << std::dec << std::endl; }
  BCryptDestroyHash(hHash);
  BCryptCloseAlgorithmProvider(hAlg, 0);
  return status == 0;
}

static bool hmacSha256(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data, std::vector<uint8_t> &out) {
  out.assign(32, 0);
  BCRYPT_ALG_HANDLE hAlg = nullptr;
  NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (status != 0) { std::cerr << "Open HMAC-SHA256 provider failed: 0x" << std::hex << status << std::dec << std::endl; return false; }
  DWORD objLen = 0, cbRes = 0, hashLen = 0;
  status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbRes, 0);
  if (status != 0) { std::cerr << "Get HMAC OBJECT_LENGTH failed: 0x" << std::hex << status << std::dec << std::endl; BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cbRes, 0);
  if (status != 0 || hashLen != 32) { std::cerr << "Get HMAC HASH_LENGTH failed: 0x" << std::hex << status << std::dec << std::endl; BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  std::vector<uint8_t> obj(objLen);
  BCRYPT_HASH_HANDLE hHash = nullptr;
  status = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, (PUCHAR)key.data(), (ULONG)key.size(), 0);
  if (status != 0) { std::cerr << "Create HMAC hash failed: 0x" << std::hex << status << std::dec << std::endl; BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  status = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
  if (status != 0) { std::cerr << "HMAC HashData failed: 0x" << std::hex << status << std::dec << std::endl; BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  status = BCryptFinishHash(hHash, (PUCHAR)out.data(), (ULONG)out.size(), 0);
  if (status != 0) { std::cerr << "HMAC FinishHash failed: 0x" << std::hex << status << std::dec << std::endl; }
  BCryptDestroyHash(hHash);
  BCryptCloseAlgorithmProvider(hAlg, 0);
  return status == 0;
}

bool CryptoContext::deriveKey(const std::wstring &password, const Params &params,
                              std::vector<uint8_t> &keyOut) {
  // Common: open PBKDF2 provider (HMAC-SHA256)
  BCRYPT_ALG_HANDLE hPbkdf = nullptr;
  NTSTATUS status = BCryptOpenAlgorithmProvider(&hPbkdf, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (status != 0) { std::cerr << "Open PBKDF2 provider failed: 0x" << std::hex << status << std::dec << std::endl; return false; }

  keyOut.resize(32);

  std::vector<uint8_t> finalKey(32);

  // Enforce header-selected KDF strictly. Do not fall back silently.
  if (params.kdfMethod == 0 /*KDF_PASSWORD*/) {
    // Require non-empty password
    if (password.empty()) {
      std::cerr << "KDF_PASSWORD requires a non-empty password" << std::endl;
      BCryptCloseAlgorithmProvider(hPbkdf, 0);
      return false;
    }
    std::string pwUtf8 = WideToUtf8(password);
    status = BCryptDeriveKeyPBKDF2(hPbkdf,
                                   (PUCHAR)pwUtf8.data(), (ULONG)pwUtf8.size(),
                                   (PUCHAR)params.salt.data(), (ULONG)params.salt.size(),
                                   (ULONGLONG)params.iterations,
                                   (PUCHAR)finalKey.data(), (ULONG)finalKey.size(), 0);
    if (status != 0) { std::cerr << "BCryptDeriveKeyPBKDF2(pw) failed: 0x" << std::hex << status << std::dec << std::endl; BCryptCloseAlgorithmProvider(hPbkdf, 0); return false; }
  } else if (params.kdfMethod == 1 /*KDF_KEYFILE*/) {
    // Require key file path
    if (params.keyFilePath.empty()) {
      std::cerr << "KDF_KEYFILE requires a key file path" << std::endl;
      BCryptCloseAlgorithmProvider(hPbkdf, 0);
      return false;
    }
    std::vector<uint8_t> digest;
    if (!sha256File(params.keyFilePath, digest)) { BCryptCloseAlgorithmProvider(hPbkdf, 0); return false; }
    status = BCryptDeriveKeyPBKDF2(hPbkdf,
                                   (PUCHAR)digest.data(), (ULONG)digest.size(),
                                   (PUCHAR)params.salt.data(), (ULONG)params.salt.size(),
                                   (ULONGLONG)params.iterations,
                                   (PUCHAR)finalKey.data(), (ULONG)finalKey.size(), 0);
    if (status != 0) { std::cerr << "BCryptDeriveKeyPBKDF2(keyfile) failed: 0x" << std::hex << status << std::dec << std::endl; BCryptCloseAlgorithmProvider(hPbkdf, 0); return false; }
  } else if (params.kdfMethod == 2 /*KDF_PASSWORD_PLUS_KEYFILE*/) {
    // Require both password and key file
    if (password.empty() || params.keyFilePath.empty()) {
      std::cerr << "KDF_PASSWORD_PLUS_KEYFILE requires both password and key file" << std::endl;
      BCryptCloseAlgorithmProvider(hPbkdf, 0);
      return false;
    }
    std::string pwUtf8 = WideToUtf8(password);
    std::vector<uint8_t> pbkdfKey(32);
    status = BCryptDeriveKeyPBKDF2(hPbkdf,
                                   (PUCHAR)pwUtf8.data(), (ULONG)pwUtf8.size(),
                                   (PUCHAR)params.salt.data(), (ULONG)params.salt.size(),
                                   (ULONGLONG)params.iterations,
                                   (PUCHAR)pbkdfKey.data(), (ULONG)pbkdfKey.size(), 0);
    if (status != 0) { std::cerr << "BCryptDeriveKeyPBKDF2(pw) failed: 0x" << std::hex << status << std::dec << std::endl; BCryptCloseAlgorithmProvider(hPbkdf, 0); return false; }

    std::vector<uint8_t> digest;
    if (!sha256File(params.keyFilePath, digest)) { BCryptCloseAlgorithmProvider(hPbkdf, 0); return false; }

    // data = pbkdfKey || salt || nonce
    std::vector<uint8_t> data;
    data.reserve(pbkdfKey.size() + params.salt.size() + params.nonce.size());
    data.insert(data.end(), pbkdfKey.begin(), pbkdfKey.end());
    data.insert(data.end(), params.salt.begin(), params.salt.end());
    data.insert(data.end(), params.nonce.begin(), params.nonce.end());

    if (!hmacSha256(digest, data, finalKey)) { BCryptCloseAlgorithmProvider(hPbkdf, 0); return false; }
  } else {
    std::cerr << "Unsupported KDF method: " << params.kdfMethod << std::endl;
    BCryptCloseAlgorithmProvider(hPbkdf, 0);
    return false;
  }

  BCryptCloseAlgorithmProvider(hPbkdf, 0);
  keyOut = finalKey;
  return true;
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

std::array<uint8_t, 8> CryptoContext::keyPrefix8() const {
  std::array<uint8_t, 8> fp{};
  if (!m_key.empty()) {
    size_t take = (m_key.size() < fp.size()) ? m_key.size() : fp.size();
    memcpy(fp.data(), m_key.data(), take);
  }
  return fp;
}