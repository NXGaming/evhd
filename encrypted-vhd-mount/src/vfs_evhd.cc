// Part of encrypted-vhd-mount

#include "vfs_evhd.h"

#include <dokan/dokan.h>
#include <dokan/fileinfo.h>
#include <filesystem>
#include <string>
#include <iostream>
#define NOMINMAX
#include <Windows.h>

namespace vfs_evhd {

bool MountContext::setup(const MountConfig &cfg) {
  m_cfg = cfg;
  if (m_cfg.debug) {
    std::wcerr << L"[vfs] MountContext.setup enc=" << cfg.encryptedFilePath << L"\n";
    std::wcerr << L"[vfs] keyfile=" << (cfg.keyFilePath.empty() ? L"(none)" : cfg.keyFilePath) << L"\n";
  }
  bool ok = m_container.openEncrypted(cfg.encryptedFilePath, cfg.password, cfg.keyFilePath);
  if (m_cfg.debug) {
    std::wcerr << L"[vfs] openEncrypted result=" << (ok ? L"ok" : L"fail") << L"\n";
  }
  if (ok) {
    m_container.setDebug(cfg.debug);
    m_container.setUnbuffered(cfg.directIO);
    // If container carries original filename metadata, expose it
    if (!m_container.originalName().empty()) {
      m_cfg.exposedFileName = m_container.originalName();
      if (m_cfg.debug) {
        std::wcerr << L"[vfs] exposed name from metadata: " << m_cfg.exposedFileName << L"\n";
      }
    } else {
      if (m_cfg.debug) {
        std::wcerr << L"[vfs] no metadata filename, using default: " << m_cfg.exposedFileName << L"\n";
      }
    }
  }
  return ok;
}

namespace utils {
static MountContext *getContext(PDOKAN_FILE_INFO info) {
  return reinterpret_cast<MountContext *>(info->DokanOptions->GlobalContext);
}

static bool isRoot(const std::wstring &path) {
  return path == L"\\" || path.empty();
}
}

static NTSTATUS DOKAN_CALLBACK createfile(
    LPCWSTR filename, PDOKAN_IO_SECURITY_CONTEXT, ACCESS_MASK desiredaccess,
    ULONG fileattributes, ULONG shareaccess, ULONG createdisposition, ULONG createoptions,
    PDOKAN_FILE_INFO dokanfileinfo) {
  auto ctx = utils::getContext(dokanfileinfo);
  std::wstring path(filename);
  if (ctx->config().debug) {
    std::wcerr << L"[dokan] ZwCreateFile path=" << path << L" desired=0x" << std::hex << desiredaccess << std::dec << L"\n";
  }

  if (utils::isRoot(path)) {
    dokanfileinfo->IsDirectory = TRUE;
    return STATUS_SUCCESS;
  }

  if (path == (L"\\" + ctx->config().exposedFileName)) {
    dokanfileinfo->IsDirectory = FALSE;
    // allow read/write if allowed
    if ((desiredaccess & FILE_WRITE_DATA) || (desiredaccess & FILE_APPEND_DATA)) {
      // We support write-through
    }
    return STATUS_SUCCESS;
  }

  return STATUS_OBJECT_NAME_NOT_FOUND;
}

static void DOKAN_CALLBACK cleanup(LPCWSTR filename, PDOKAN_FILE_INFO dokanfileinfo) {
  auto ctx = utils::getContext(dokanfileinfo);
  if (ctx->config().debug) {
    std::wcerr << L"[dokan] Cleanup path=" << filename << L"\n";
  }
}

static void DOKAN_CALLBACK closefile(LPCWSTR filename, PDOKAN_FILE_INFO dokanfileinfo) {
  auto ctx = utils::getContext(dokanfileinfo);
  if (ctx->config().debug) {
    std::wcerr << L"[dokan] CloseFile path=" << filename << L"\n";
  }
}

static NTSTATUS DOKAN_CALLBACK readfile(LPCWSTR filename, LPVOID buffer, DWORD bufferlength,
                                        LPDWORD readlength, LONGLONG offset,
                                        PDOKAN_FILE_INFO dokanfileinfo) {
  auto ctx = utils::getContext(dokanfileinfo);
  std::wstring path(filename);
  if (ctx->config().debug) {
    std::wcerr << L"[dokan] ReadFile path=" << path << L" offset=" << offset << L" len=" << bufferlength << L"\n";
  }

  if (path == (L"\\" + ctx->config().exposedFileName)) {
    size_t len = (size_t)bufferlength;
    if (offset >= (LONGLONG)ctx->container().plaintextSize()) {
      *readlength = 0;
      return STATUS_SUCCESS;
    }
    uint64_t maxLen = ctx->container().plaintextSize() - (uint64_t)offset;
    len = (size_t)std::min<uint64_t>((uint64_t)len, maxLen);
    if (len == 0) {
      *readlength = 0;
      return STATUS_SUCCESS;
    }
    if (!ctx->container().readPlain((uint64_t)offset, (uint8_t *)buffer, len)) {
      return STATUS_UNSUCCESSFUL;
    }
    *readlength = (DWORD)len;
    return STATUS_SUCCESS;
  }

  return STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS DOKAN_CALLBACK writefile(LPCWSTR filename, LPCVOID buffer, DWORD numberofbytesToWrite,
                                         LPDWORD numberofbytesWritten, LONGLONG offset,
                                         PDOKAN_FILE_INFO dokanfileinfo) {
  auto ctx = utils::getContext(dokanfileinfo);
  std::wstring path(filename);
  if (ctx->config().debug) {
    std::wcerr << L"[dokan] WriteFile path=" << path << L" offset=" << offset << L" len=" << numberofbytesToWrite << L"\n";
  }

  if (path == (L"\\" + ctx->config().exposedFileName)) {
    size_t len = (size_t)numberofbytesToWrite;
    if ((uint64_t)offset + len > ctx->container().plaintextSize()) {
      // Do not support extending the file
      len = (size_t)std::max<int64_t>(0, (LONGLONG)ctx->container().plaintextSize() - offset);
    }
    if (len == 0) {
      *numberofbytesWritten = 0;
      return STATUS_SUCCESS;
    }
    if (!ctx->container().writePlain((uint64_t)offset, (const uint8_t *)buffer, len)) {
      return STATUS_UNSUCCESSFUL;
    }
    *numberofbytesWritten = (DWORD)len;
    return STATUS_SUCCESS;
  }

  return STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS DOKAN_CALLBACK getfileInformation(LPCWSTR filename, LPBY_HANDLE_FILE_INFORMATION info,
                                                  PDOKAN_FILE_INFO dokanfileinfo) {
  auto ctx = utils::getContext(dokanfileinfo);
  std::wstring path(filename);
  if (ctx->config().debug) {
    std::wcerr << L"[dokan] GetFileInformation path=" << path << L"\n";
  }

  if (utils::isRoot(path)) {
    info->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    info->ftCreationTime.dwHighDateTime = 0;
    info->ftCreationTime.dwLowDateTime = 0;
    info->ftLastAccessTime = info->ftCreationTime;
    info->ftLastWriteTime = info->ftCreationTime;
    info->nFileSizeHigh = 0;
    info->nFileSizeLow = 0;
    return STATUS_SUCCESS;
  }

  if (path == (L"\\" + ctx->config().exposedFileName)) {
    info->dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
    uint64_t size = ctx->container().plaintextSize();
    info->nFileSizeHigh = (DWORD)(size >> 32);
    info->nFileSizeLow = (DWORD)(size & 0xFFFFFFFF);
    return STATUS_SUCCESS;
  }

  return STATUS_OBJECT_NAME_NOT_FOUND;
}

static NTSTATUS DOKAN_CALLBACK findfiles(LPCWSTR filename, PFillFindData fill_finddata,
                                         PDOKAN_FILE_INFO dokanfileinfo) {
  auto ctx = utils::getContext(dokanfileinfo);
  std::wstring path(filename);
  if (ctx->config().debug) {
    std::wcerr << L"[dokan] FindFiles path=" << path << L"\n";
  }

  if (!utils::isRoot(path)) {
    return STATUS_OBJECT_PATH_NOT_FOUND;
  }

  WIN32_FIND_DATAW wfd{};
  wfd.dwFileAttributes = FILE_ATTRIBUTE_ARCHIVE;
  uint64_t size = ctx->container().plaintextSize();
  wfd.nFileSizeHigh = (DWORD)(size >> 32);
  wfd.nFileSizeLow = (DWORD)(size & 0xFFFFFFFF);
  wcsncpy_s(wfd.cFileName, _countof(wfd.cFileName), ctx->config().exposedFileName.c_str(), _TRUNCATE);
  fill_finddata(&wfd, dokanfileinfo);
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK getdiskfreespace(PULONGLONG free_bytes_available,
                                                PULONGLONG total_number_of_bytes,
                                                PULONGLONG total_number_of_free_bytes,
                                                PDOKAN_FILE_INFO dokanfileinfo) {
  auto ctx = utils::getContext(dokanfileinfo);
  if (ctx->config().debug) {
    std::wcerr << L"[dokan] GetDiskFreeSpace" << L"\n";
  }
  uint64_t size = ctx->container().plaintextSize();
  *total_number_of_bytes = size;
  *free_bytes_available = 0;
  *total_number_of_free_bytes = 0;
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK getvolumeinformation(LPWSTR volumename_buffer, DWORD volumename_size,
                                                    LPDWORD volume_serialnumber,
                                                    LPDWORD maximum_component_length,
                                                    LPDWORD filesystem_flags,
                                                    LPWSTR filesystem_name_buffer,
                                                    DWORD filesystem_name_size,
                                                    PDOKAN_FILE_INFO dokanfileinfo) {
  auto ctx = utils::getContext(dokanfileinfo);
  std::wstring vn = L"EVHD Mount";
  wcsncpy_s(volumename_buffer, volumename_size, vn.c_str(), _TRUNCATE);
  *volume_serialnumber = 0xE1E4D001;
  *maximum_component_length = 255;
  // 更贴近 Windows 期望的卷能力：保留大小写、支持重解析点与稀疏文件
  *filesystem_flags = FILE_CASE_PRESERVED_NAMES | FILE_SUPPORTS_REPARSE_POINTS | FILE_SUPPORTS_SPARSE_FILES;
  std::wstring fsn = L"EVHDFS";
  wcsncpy_s(filesystem_name_buffer, filesystem_name_size, fsn.c_str(), _TRUNCATE);
  if (ctx->config().debug) {
    std::wcerr << L"[dokan] GetVolumeInformation" << L"\n";
  }
  return STATUS_SUCCESS;
}

void setup_dokan_ops(DOKAN_OPERATIONS &ops) {
  ZeroMemory(&ops, sizeof(ops));
  ops.ZwCreateFile = createfile;
  ops.Cleanup = cleanup;
  ops.CloseFile = closefile;
  ops.ReadFile = readfile;
  ops.WriteFile = writefile;
  ops.GetFileInformation = getfileInformation;
  ops.FindFiles = findfiles;
  ops.GetDiskFreeSpace = getdiskfreespace;
  ops.GetVolumeInformation = getvolumeinformation;
}

} // namespace vfs_evhd