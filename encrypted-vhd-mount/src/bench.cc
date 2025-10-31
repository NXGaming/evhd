// Simple bench harness for Container I/O without Dokan
#include <Windows.h>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "evhd.h"

using namespace std::chrono;

static void gen_plain_file(const std::wstring &path, uint64_t size_bytes) {
  // Generate deterministic pseudo-random content; optionally write 0x55AA at end of sector 0
  std::ofstream out(path.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
  std::mt19937_64 rng(123456789ULL);
  const size_t chunk = 1 << 20; // 1 MiB
  std::vector<uint8_t> buf(chunk);
  uint64_t written = 0;
  while (written < size_bytes) {
    size_t take = static_cast<size_t>(std::min<uint64_t>(size_bytes - written, chunk));
    for (size_t i = 0; i < take; ++i) buf[i] = static_cast<uint8_t>(rng() & 0xFF);
    out.write(reinterpret_cast<const char*>(buf.data()), take);
    written += take;
  }
  // Write MBR signature to trigger relocation path if desired
  if (size_bytes >= 512) {
    out.seekp(510, std::ios::beg);
    uint8_t sig[2] = {0x55, 0xAA};
    out.write(reinterpret_cast<const char*>(sig), 2);
  }
  out.close();
}

static double mbps(uint64_t bytes, double seconds) {
  return (bytes / (1024.0 * 1024.0)) / seconds;
}

int wmain() {
  const std::wstring plain = L"bench_plain.vhd";
  const std::wstring enc   = L"bench_enc.evhd";
  const std::wstring password = L"bench-pass";
  const uint64_t size = 64ull * 1024 * 1024; // 64 MiB

  std::wcout << L"[bench] generating plain file..." << std::endl;
  gen_plain_file(plain, size);

  std::wcout << L"[bench] creating encrypted file..." << std::endl;
  evhd::Container cCreate;
  if (!cCreate.createFromPlainVhd(plain, enc, password, L"")) {
    std::wcerr << L"[bench] createFromPlainVhd failed" << std::endl; return 1;
  }

  std::wcout << L"[bench] opening encrypted file..." << std::endl;
  evhd::Container c;
  c.setDebug(false);
  if (!c.openEncrypted(enc, password, L"")) {
    std::wcerr << L"[bench] openEncrypted failed" << std::endl; return 1;
  }

  // Sequential read 128 KiB
  const size_t seq_chunk = 128 * 1024;
  std::vector<uint8_t> buf(seq_chunk);
  uint64_t total = 0;
  auto t0 = steady_clock::now();
  for (uint64_t off = 0; off + seq_chunk <= size; off += seq_chunk) {
    if (!c.readPlain(off, buf.data(), seq_chunk)) { std::wcerr << L"[bench] seq read fail" << std::endl; return 1; }
    total += seq_chunk;
  }
  auto t1 = steady_clock::now();
  std::wcout << L"[bench] SEQ128K read MB/s=" << mbps(total, duration<double>(t1 - t0).count()) << std::endl;

  // Random 4 KiB, QD=1
  const size_t rnd_chunk = 4 * 1024;
  std::mt19937_64 prng(777);
  total = 0;
  t0 = steady_clock::now();
  for (int i = 0; i < 5000; ++i) {
    uint64_t off = (prng() % (size / rnd_chunk)) * rnd_chunk;
    if (!c.readPlain(off, buf.data(), rnd_chunk)) { std::wcerr << L"[bench] rnd read fail" << std::endl; return 1; }
    total += rnd_chunk;
  }
  t1 = steady_clock::now();
  std::wcout << L"[bench] RND4K QD1 MB/s=" << mbps(total, duration<double>(t1 - t0).count()) << std::endl;

  // Random 4 KiB, multi-thread (QD≈32)
  const int threads = 16;
  const int ops_per_thread = 4000;
  std::atomic<uint64_t> sumBytes{0};
  t0 = steady_clock::now();
  std::vector<std::thread> ths;
  for (int t = 0; t < threads; ++t) {
    ths.emplace_back([&]{
      std::mt19937_64 rngt(static_cast<uint64_t>(t + 1) * 12345ULL);
      std::vector<uint8_t> local(rnd_chunk);
      for (int i = 0; i < ops_per_thread; ++i) {
        uint64_t off = (rngt() % (size / rnd_chunk)) * rnd_chunk;
        c.readPlain(off, local.data(), rnd_chunk);
        sumBytes += rnd_chunk;
      }
    });
  }
  for (auto &th : ths) th.join();
  t1 = steady_clock::now();
  std::wcout << L"[bench] RND4K QD~" << threads << L" MB/s=" << mbps(sumBytes.load(), duration<double>(t1 - t0).count()) << std::endl;

  std::wcout << L"[bench] done." << std::endl;
  return 0;
}