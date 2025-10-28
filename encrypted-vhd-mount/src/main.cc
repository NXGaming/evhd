// Part of encrypted-vhd-mount

#include <dokan/dokan.h>
#include <dokan/fileinfo.h>
#include <Windows.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include "vfs_evhd.h"

struct Parameters {
  std::wstring encFilePath;
  std::wstring mountPoint;
  std::wstring password;
  std::wstring initVhdPath; // if provided, create encrypted from plain VHD
  bool debugMode{false};
  bool launchMountPath{false};
};

static void showUsage() {
  std::wcout << L"encrypted-vhd-mount 用于以AES-256-CTR加密VHD并通过Dokan直接挂载解密视图\n";
  std::wcout << L"用法:\n";
  std::wcout << L"  encrypted-vhd-mount.exe [/d|/l] /p <password> <enc_file> <mount_path>\n";
  std::wcout << L"  初始化加密:\n";
  std::wcout << L"  encrypted-vhd-mount.exe /init <plain_vhd> /o <enc_file> /p <password>\n";
  std::wcout << L"参数:\n";
  std::wcout << L"  /d           在控制台显示Dokan调试输出\n";
  std::wcout << L"  /l           挂载后打开资源管理器到挂载路径\n";
  std::wcout << L"  /p           文本密码\n";
  std::wcout << L"  /init        输入明文VHD进行加密初始化\n";
  std::wcout << L"  /o           输出加密文件路径\n";
}

static bool readParameters(Parameters &params, int argc, wchar_t **argv) {
  for (int i = 1; i < argc; ++i) {
    std::wstring arg = argv[i];
    if (arg == L"/h" || arg == L"--help") { showUsage(); return false; }
    else if (arg == L"/d" || arg == L"--debug") { params.debugMode = true; }
    else if (arg == L"/l" || arg == L"--launch") { params.launchMountPath = true; }
    else if (arg == L"/p" || arg == L"--password") { if (i + 1 >= argc) { std::wcout << L"缺少密码\n"; return false; } params.password = argv[++i]; }
    else if (arg == L"/init") { if (i + 1 >= argc) { std::wcout << L"缺少plain_vhd路径\n"; return false; } params.initVhdPath = argv[++i]; }
    else if (arg == L"/o" || arg == L"--output") { if (i + 1 >= argc) { std::wcout << L"缺少输出文件路径\n"; return false; } params.encFilePath = argv[++i]; }
    else {
      // positional args: <enc_file> <mount_path>
      if (params.encFilePath.empty()) params.encFilePath = arg; else if (params.mountPoint.empty()) params.mountPoint = arg; else { std::wcout << L"多余参数: " << arg << L"\n"; return false; }
    }
  }

  if (!params.initVhdPath.empty()) {
    if (params.encFilePath.empty() || params.password.empty()) {
      std::wcout << L"初始化模式需要 /o <enc_file> 与 /p <password>\n"; return false;
    }
    return true;
  }

  if (params.password.empty()) { std::wcout << L"缺少 /p <password>\n"; return false; }
  if (params.encFilePath.empty()) { std::wcout << L"缺少 <enc_file>\n"; return false; }
  if (params.mountPoint.empty()) { std::wcout << L"缺少 <mount_path>\n"; return false; }
  return true;
}

static void fileWatcher(std::wstring path) {
  std::filesystem::path mp(path);
  std::error_code ec;
  do { std::this_thread::sleep_for(std::chrono::milliseconds(50)); } while (std::filesystem::exists(mp, ec) == false);
  ShellExecuteW(0, L"explore", path.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

static BOOL WINAPI CtrlHandler(DWORD dwCtrlType) {
  switch (dwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      SetConsoleCtrlHandler(CtrlHandler, FALSE);
      return TRUE;
    default: return FALSE;
  }
}

int wmain(int argc, wchar_t **argv) {
  Parameters params;
  if (!readParameters(params, argc, argv)) return 0;

  std::wcout << L"[main] args parsed. debug=" << (params.debugMode ? L"on" : L"off")
             << L" initVhdPath=" << (params.initVhdPath.empty() ? L"(none)" : params.initVhdPath)
             << L" encFilePath=" << params.encFilePath << L" mountPoint=" << params.mountPoint << L"\n";

  if (!params.initVhdPath.empty()) {
    evhd::Container c;
    if (!c.createFromPlainVhd(params.initVhdPath, params.encFilePath, params.password)) {
      std::wcout << L"初始化加密失败\n"; return 1;
    }
    std::wcout << L"已生成加密文件: " << params.encFilePath << L"\n";
    return 0;
  }

  vfs_evhd::MountConfig cfg;
  cfg.encryptedFilePath = params.encFilePath;
  cfg.password = params.password;
  cfg.exposedFileName = L"decrypted.vhd";

  vfs_evhd::MountContext mountCtx;
  std::wcout << L"[main] opening encrypted: " << cfg.encryptedFilePath << L"\n";
  if (!mountCtx.setup(cfg)) {
    std::wcout << L"[main] 打开加密文件或密码错误\n";
    return 1;
  }

  std::wcout << L"[main] encrypted opened. plaintext size=" << mountCtx.container().plaintextSize() << L" bytes\n";

  DokanInit();

  DOKAN_OPTIONS dokanOptions; ZeroMemory(&dokanOptions, sizeof(DOKAN_OPTIONS));
  dokanOptions.Version = DOKAN_VERSION;
  dokanOptions.SingleThread = FALSE;
  dokanOptions.Timeout = 0;
  dokanOptions.GlobalContext = reinterpret_cast<ULONG64>(&mountCtx);
  dokanOptions.MountPoint = params.mountPoint.c_str();
  dokanOptions.Options |= DOKAN_OPTION_CURRENT_SESSION | DOKAN_OPTION_ALT_STREAM | DOKAN_OPTION_MOUNT_MANAGER;
  // 允许写入
  // dokanOptions.Options |= DOKAN_OPTION_WRITE_PROTECT; // 不设置，提供写能力
  if (params.debugMode) dokanOptions.Options |= DOKAN_OPTION_STDERR | DOKAN_OPTION_DEBUG;

  DOKAN_OPERATIONS ops; ZeroMemory(&ops, sizeof(DOKAN_OPERATIONS));
  vfs_evhd::setup_dokan_ops(ops);

  SetConsoleCtrlHandler(CtrlHandler, TRUE);

  std::wcout << L"[main] Dokan options: 0x" << std::hex << dokanOptions.Options << std::dec << L"\n";
  std::wcout << L"[main] entering DokanMain at mountpoint: " << params.mountPoint << L"\n";
  std::thread watcher;
  if (params.launchMountPath) watcher = std::thread(fileWatcher, params.mountPoint);

  auto status = DokanMain(&dokanOptions, &ops);
  std::wcout << L"[main] DokanMain returned status=" << status << L"\n";

  switch (status) {
    case DOKAN_SUCCESS: break;
    case DOKAN_ERROR: std::wcout << L"Dokan未知错误\n"; break;
    case DOKAN_DRIVE_LETTER_ERROR: std::wcout << L"驱动器号不可用\n"; break;
    case DOKAN_DRIVER_INSTALL_ERROR: std::wcout << L"Dokan驱动通信失败\n"; break;
    case DOKAN_START_ERROR: std::wcout << L"Dokan启动失败\n"; break;
    case DOKAN_MOUNT_ERROR: std::wcout << L"挂载失败: " << params.mountPoint << L"\n"; break;
    case DOKAN_MOUNT_POINT_ERROR: std::wcout << L"挂载点错误\n"; break;
    case DOKAN_VERSION_ERROR: std::wcout << L"Dokan版本不匹配\n"; break;
    default: std::wcout << L"未知错误: " << status << L"\n"; break;
  }

  DokanShutdown();
  if (watcher.joinable()) watcher.detach();
  return 0;
}