// Part of encrypted-vhd-mount

#include "crypto.h"

#include "vmprotect_scope.h"

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
  if (!m_key.empty()) {
    SecureZeroMemory(m_key.data(), m_key.size());
    m_key.clear();
  }
  if (!m_keyObject.empty()) {
    SecureZeroMemory(m_keyObject.data(), m_keyObject.size());
    m_keyObject.clear();
  }
  if (!m_hmacKey.empty()) {
    SecureZeroMemory(m_hmacKey.data(), m_hmacKey.size());
    m_hmacKey.clear();
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

  {
    evhd_vmp::Scope scope("crypto_init", evhd_vmp::Mode::Virtualization);

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
  }

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

bool CryptoContext::initV5(const std::wstring &password, const Params &params) {
  // First do standard init to derive masterKey -> m_key
  if (!init(password, params)) return false;

  {
    evhd_vmp::Scope scope("crypto_initV5", evhd_vmp::Mode::Virtualization);

    // Derive hmacKey = HMAC-SHA256(masterKey, "hmac-auth-v5" || nonce)
    std::vector<uint8_t> prk = m_key; // masterKey reused as PRK
    const char label[] = "hmac-auth-v5";
    std::vector<uint8_t> info;
    info.insert(info.end(), reinterpret_cast<const uint8_t*>(label),
                reinterpret_cast<const uint8_t*>(label) + sizeof(label) - 1);
    info.insert(info.end(), params.nonce.begin(), params.nonce.end());

    m_hmacKey.resize(32);
    if (!hmacSha256(prk, info, m_hmacKey)) {
      SecureZeroMemory(m_hmacKey.data(), m_hmacKey.size());
      m_hmacKey.clear();
      return false;
    }

    if (!prk.empty()) {
      SecureZeroMemory(prk.data(), prk.size());
    }
  }

  m_v5 = true;
  return true;
}

bool CryptoContext::deriveKey(const std::wstring &password, const Params &params,
                              std::vector<uint8_t> &keyOut) {
  evhd_vmp::Scope scope("crypto_deriveKey", evhd_vmp::Mode::Virtualization);

  // Common: open PBKDF2 provider (HMAC-SHA256)
  BCRYPT_ALG_HANDLE hPbkdf = nullptr;
  NTSTATUS status = BCryptOpenAlgorithmProvider(&hPbkdf, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (status != 0) { std::cerr << "Open PBKDF2 provider failed: 0x" << std::hex << status << std::dec << std::endl; return false; }

  keyOut.resize(32);

  // 声明所有敏感局部变量在函数顶部，以便统一清理
  std::string pwUtf8;
  std::vector<uint8_t> pbkdfKey;
  std::vector<uint8_t> finalKey(32);
  std::vector<uint8_t> digest;
  bool ok = false;

  // Enforce header-selected KDF strictly. Do not fall back silently.
  if (params.kdfMethod == 0 /*KDF_PASSWORD*/) {
    // Require non-empty password
    if (password.empty()) {
      std::cerr << "KDF_PASSWORD requires a non-empty password" << std::endl;
      goto cleanup;
    }
    pwUtf8 = WideToUtf8(password);
    status = BCryptDeriveKeyPBKDF2(hPbkdf,
                                   (PUCHAR)pwUtf8.data(), (ULONG)pwUtf8.size(),
                                   (PUCHAR)params.salt.data(), (ULONG)params.salt.size(),
                                   (ULONGLONG)params.iterations,
                                   (PUCHAR)finalKey.data(), (ULONG)finalKey.size(), 0);
    if (status != 0) { std::cerr << "BCryptDeriveKeyPBKDF2(pw) failed: 0x" << std::hex << status << std::dec << std::endl; goto cleanup; }
  } else if (params.kdfMethod == 1 /*KDF_KEYFILE*/) {
    // Require key file path
    if (params.keyFilePath.empty()) {
      std::cerr << "KDF_KEYFILE requires a key file path" << std::endl;
      goto cleanup;
    }
    if (!sha256File(params.keyFilePath, digest)) { goto cleanup; }
    status = BCryptDeriveKeyPBKDF2(hPbkdf,
                                   (PUCHAR)digest.data(), (ULONG)digest.size(),
                                   (PUCHAR)params.salt.data(), (ULONG)params.salt.size(),
                                   (ULONGLONG)params.iterations,
                                   (PUCHAR)finalKey.data(), (ULONG)finalKey.size(), 0);
    if (status != 0) { std::cerr << "BCryptDeriveKeyPBKDF2(keyfile) failed: 0x" << std::hex << status << std::dec << std::endl; goto cleanup; }
  } else if (params.kdfMethod == 2 /*KDF_PASSWORD_PLUS_KEYFILE*/) {
    // Require both password and key file
    if (password.empty() || params.keyFilePath.empty()) {
      std::cerr << "KDF_PASSWORD_PLUS_KEYFILE requires both password and key file" << std::endl;
      goto cleanup;
    }
    pwUtf8 = WideToUtf8(password);
    pbkdfKey.resize(32);
    status = BCryptDeriveKeyPBKDF2(hPbkdf,
                                   (PUCHAR)pwUtf8.data(), (ULONG)pwUtf8.size(),
                                   (PUCHAR)params.salt.data(), (ULONG)params.salt.size(),
                                   (ULONGLONG)params.iterations,
                                   (PUCHAR)pbkdfKey.data(), (ULONG)pbkdfKey.size(), 0);
    if (status != 0) { std::cerr << "BCryptDeriveKeyPBKDF2(pw) failed: 0x" << std::hex << status << std::dec << std::endl; goto cleanup; }

    if (!sha256File(params.keyFilePath, digest)) { goto cleanup; }

    // data = pbkdfKey || salt || nonce
    std::vector<uint8_t> data;
    data.reserve(pbkdfKey.size() + params.salt.size() + params.nonce.size());
    data.insert(data.end(), pbkdfKey.begin(), pbkdfKey.end());
    data.insert(data.end(), params.salt.begin(), params.salt.end());
    data.insert(data.end(), params.nonce.begin(), params.nonce.end());

    if (!hmacSha256(digest, data, finalKey)) { goto cleanup; }
  } else {
    std::cerr << "Unsupported KDF method: " << params.kdfMethod << std::endl;
    goto cleanup;
  }

  keyOut = finalKey;
  ok = true;

cleanup:
  if (!pwUtf8.empty()) SecureZeroMemory(pwUtf8.data(), pwUtf8.size());
  if (!pbkdfKey.empty()) SecureZeroMemory(pbkdfKey.data(), pbkdfKey.size());
  if (!finalKey.empty()) SecureZeroMemory(finalKey.data(), finalKey.size());
  if (!digest.empty()) SecureZeroMemory(digest.data(), digest.size());
  if (hPbkdf) BCryptCloseAlgorithmProvider(hPbkdf, 0);
  return ok;
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
  // 优化：一次生成多个连续块的 keystream，减少 BCryptEncrypt 调用。
  size_t processed = 0;
  uint64_t blockIndex = fileOffset / 16;
  size_t blockOffset = (size_t)(fileOffset % 16);

  // 每批次最多生成的块数（64KB keystream）
  const size_t maxBlocksPerBatch = 4096; // 4096 * 16 = 65536 bytes
  // Thread-local buffers to avoid heap allocation on every call.
  static thread_local std::vector<uint8_t> ivs;
  static thread_local std::vector<uint8_t> ks;
  ivs.reserve(maxBlocksPerBatch * 16);
  ks.reserve(maxBlocksPerBatch * 16);

  while (processed < length) {
    size_t remaining = length - processed;
    // 需要的块数：覆盖当前剩余数据，加上首块偏移
    size_t blocksNeeded = (blockOffset + remaining + 15) / 16;
    size_t blocks = std::min(blocksNeeded, maxBlocksPerBatch);

    // 构造连续的 IV 序列：nonce[0..7] + counter(blockIndex + i)
    ivs.resize(blocks * 16);
    for (size_t b = 0; b < blocks; ++b) {
      // nonce 前8字节
      memcpy(ivs.data() + b * 16, m_nonce.data(), 8);
      // counter 为 64-bit 小端（与原实现 memcpy 一致）
      uint64_t ctr = blockIndex + b;
      memcpy(ivs.data() + b * 16 + 8, &ctr, sizeof(ctr));
    }

    // 批量 ECB 加密，得到 keystream blocks
    ks.resize(blocks * 16);
    ULONG outLen = 0;
    NTSTATUS status = BCryptEncrypt(
        m_aesKey,
        ivs.data(), (ULONG)ivs.size(),
        nullptr,
        nullptr, 0,
        ks.data(), (ULONG)ks.size(), &outLen,
        0);
    if (status != 0 || outLen != ks.size()) return false;

    // 从 keystream 中应用到当前待处理数据
    size_t keystreamOffset = blockOffset;
    size_t available = ks.size() - keystreamOffset;
    size_t take = std::min(available, remaining);
    for (size_t i = 0; i < take; ++i) {
      buffer[processed + i] ^= ks[keystreamOffset + i];
    }

    processed += take;
    blockIndex += blocks;
    blockOffset = 0; // 首批处理后，后续批次从块边界开始
  }

  return true;
}

bool CryptoContext::decryptRange(uint64_t fileOffset, uint8_t *buffer, size_t length) {
  return aesCtrCrypt(fileOffset, buffer, length);
}

bool CryptoContext::encryptRange(uint64_t fileOffset, uint8_t *buffer, size_t length) {
  return aesCtrCrypt(fileOffset, buffer, length);
}

bool CryptoContext::hmacData(const uint8_t *data, size_t length, std::vector<uint8_t> &tagOut) const {
  tagOut.assign(32, 0);
  if (!m_v5 || m_hmacKey.empty()) return false;
  BCRYPT_ALG_HANDLE hAlg = nullptr;
  NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (status != 0) return false;
  DWORD objLen = 0, cbRes = 0, hashLen = 0;
  status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cbRes, 0);
  if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &cbRes, 0);
  if (status != 0 || hashLen != 32) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  std::vector<uint8_t> obj(objLen);
  BCRYPT_HASH_HANDLE hHash = nullptr;
  status = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen,
                            (PUCHAR)m_hmacKey.data(), (ULONG)m_hmacKey.size(), 0);
  if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  status = BCryptHashData(hHash, (PUCHAR)data, (ULONG)length, 0);
  if (status != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  status = BCryptFinishHash(hHash, (PUCHAR)tagOut.data(), (ULONG)tagOut.size(), 0);
  if (status != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
  BCryptDestroyHash(hHash);
  BCryptCloseAlgorithmProvider(hAlg, 0);
  return true;
}

bool CryptoContext::verifyHmac(const uint8_t *data, size_t length, const uint8_t *tag) const {
  if (!tag) return false;
  std::vector<uint8_t> computed(32);
  if (!hmacData(data, length, computed)) return false;
  // Constant-time comparison to prevent timing attacks
  uint8_t diff = 0;
  for (size_t i = 0; i < 32; ++i) {
    diff |= (computed[i] ^ tag[i]);
  }
  return diff == 0;
}