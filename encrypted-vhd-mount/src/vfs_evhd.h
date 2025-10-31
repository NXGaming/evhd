// Part of encrypted-vhd-mount

#pragma once

#include <dokan/dokan.h>
#include <string>

#include "evhd.h"

namespace vfs_evhd {

struct MountConfig {
  std::wstring encryptedFilePath;
  std::wstring password;
  std::wstring exposedFileName; // e.g. decrypted.vhd
  std::wstring keyFilePath;     // optional key file
  bool debug{false};            // enable container debug logs
  bool directIO{false};         // use unbuffered, write-through I/O
};

class MountContext {
public:
  bool setup(const MountConfig &cfg);
  const MountConfig &config() const { return m_cfg; }
  evhd::Container &container() { return m_container; }
private:
  MountConfig m_cfg;
  evhd::Container m_container;
};

void setup_dokan_ops(DOKAN_OPERATIONS &ops);

} // namespace vfs_evhd