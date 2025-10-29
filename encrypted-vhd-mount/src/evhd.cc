// Part of encrypted-vhd-mount

#include "evhd.h"

#include <random>
#include <cstring>
#include <iostream>
#include <filesystem>

namespace evhd {

static void randomBytes(uint8_t *buf, size_t n) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint32_t> dist(0, 255);
  for (size_t i = 0; i < n; ++i) buf[i] = static_cast<uint8_t>(dist(gen));
}

bool Container::openEncrypted(const std::wstring &path, const std::wstring &password,
                              const std::wstring &keyFilePath) {
  close();
  m_path = path;
  m_file.open(path.c_str(), std::ios::binary | std::ios::in | std::ios::out);
  if (!m_file.is_open()) { std::wcerr << L"[evhd] open file failed: " << path << std::endl; return false; }

  if (!readHeader()) { std::wcerr << L"[evhd] read header failed" << std::endl; return false; }
  std::wcerr << L"[evhd] header ok. plaintext size=" << m_header.originalSize << L" bytes, iterations=" << m_header.kdfIterations << L"\n";

  CryptoContext::Params p;
  p.salt.assign(std::begin(m_header.salt), std::end(m_header.salt));
  p.nonce.assign(std::begin(m_header.nonce), std::end(m_header.nonce));
  p.iterations = m_header.kdfIterations;
  p.kdfMethod = m_header.kdfMethod;
  p.keyFilePath = keyFilePath;
  if (!m_crypto.init(password, p)) { std::wcerr << L"[evhd] crypto init failed" << std::endl; return false; }

  m_ready = true;
  return true;
}

bool Container::createFromPlainVhd(const std::wstring &plainVhdPath, const std::wstring &encOutPath,
                                   const std::wstring &password, const std::wstring &keyFilePath,
                                   uint32_t iterations) {
  close();
  m_path = encOutPath;

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
  m_header.version = 3; // v3: add kdfMethod + metadata (original filename)
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
  // Compute payload offset
  m_payloadOffset = sizeof(Header);
  if (m_header.version >= 2) {
    uint32_t nameLen = static_cast<uint32_t>(m_originalName.size());
    m_file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
    if (nameLen > 0) {
      m_file.write(reinterpret_cast<const char*>(m_originalName.c_str()), nameLen * sizeof(wchar_t));
    }
    if (!m_file) { std::wcerr << L"Write metadata (filename) failed" << std::endl; return false; }
    m_payloadOffset += sizeof(uint32_t) + static_cast<uint64_t>(nameLen) * sizeof(wchar_t);
  }
  // Ensure write pointer is at payload start
  m_file.seekp(m_payloadOffset, std::ios::beg);

  // Init crypto
  CryptoContext::Params p;
  p.salt.assign(std::begin(m_header.salt), std::end(m_header.salt));
  p.nonce.assign(std::begin(m_header.nonce), std::end(m_header.nonce));
  p.iterations = m_header.kdfIterations;
  p.kdfMethod = m_header.kdfMethod;
  p.keyFilePath = keyFilePath;
  if (!m_crypto.init(password, p)) { std::wcerr << L"Init crypto context failed" << std::endl; return false; }

  // Stream encrypt
  const size_t bufSize = 1024 * 1024; // 1MB buffer
  std::vector<uint8_t> buf(bufSize);
  uint64_t offset = 0;
  while (offset < size) {
    size_t chunk = static_cast<size_t>(std::min<uint64_t>(bufSize, size - offset));
    in.read(reinterpret_cast<char*>(buf.data()), chunk);
    if (!in) { std::wcerr << L"Read plaintext VHD failed" << std::endl; return false; }
    if (!m_crypto.encryptRange(offset, buf.data(), chunk)) { std::wcerr << L"Encrypt block failed" << std::endl; return false; }
    m_file.write(reinterpret_cast<const char*>(buf.data()), chunk);
    if (!m_file) { std::wcerr << L"Write ciphertext payload failed" << std::endl; return false; }
    offset += chunk;
  }

  m_file.flush();
  in.close();

  m_ready = true;
  return true;
}

bool Container::readPlain(uint64_t offset, uint8_t *buffer, size_t length) {
  if (!m_ready || !buffer || length == 0) return false;
  std::lock_guard<std::mutex> lock(m_mutex);
  // Seek to encrypted payload offset (header + offset)
  m_file.seekg(m_payloadOffset + offset, std::ios::beg);
  m_file.read(reinterpret_cast<char*>(buffer), length);
  if (!m_file) return false;
  return m_crypto.decryptRange(offset, buffer, length);
}

bool Container::writePlain(uint64_t offset, const uint8_t *buffer, size_t length) {
  if (!m_ready || !buffer || length == 0) return false;
  std::lock_guard<std::mutex> lock(m_mutex);
  // Copy into temp to encrypt in-place
  std::vector<uint8_t> tmp(buffer, buffer + length);
  if (!m_crypto.encryptRange(offset, tmp.data(), length)) return false;
  m_file.seekp(m_payloadOffset + offset, std::ios::beg);
  m_file.write(reinterpret_cast<const char*>(tmp.data()), length);
  return !!m_file;
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
  if (v1.version != 1 && v1.version != 2 && v1.version != 3) return false;
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
  return true;
}

bool Container::writeHeader() {
  m_file.seekp(0, std::ios::beg);
  m_file.write(reinterpret_cast<const char*>(&m_header), sizeof(m_header));
  return !!m_file;
}

void Container::close() {
  m_ready = false;
  if (m_file.is_open()) m_file.close();
}

} // namespace evhd