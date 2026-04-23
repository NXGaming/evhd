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
#include <vector>
#include <vector>

#include "vfs_evhd.h"

struct Parameters {
  std::wstring encFilePath;
  std::wstring mountPoint;
  std::wstring password;
  std::wstring initVhdPath; // if provided, create encrypted from plain VHD
  bool debugMode{false};
  bool launchMountPath{false};
  std::wstring keyFilePath; // optional key file
  bool directIO{false};      // disable OS cache, use unbuffered I/O
  bool passwordFromStdin{false};
};

static bool utf8ToWide(const std::vector<char> &input, std::wstring &out) {
  out.clear();
  if (input.empty()) return true;

  int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                  input.data(), static_cast<int>(input.size()),
                                  nullptr, 0);
  if (chars <= 0) return false;

  out.resize(chars);
  return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                             input.data(), static_cast<int>(input.size()),
                             out.data(), chars) == chars;
}

static bool readPasswordFromStdin(std::wstring &password) {
  password.clear();
  HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
  if (stdinHandle == INVALID_HANDLE_VALUE || stdinHandle == nullptr) {
    return false;
  }

  constexpr size_t maxPasswordBytes = 1 << 20;
  std::vector<char> bytes;
  bytes.reserve(256);

  char chunk[256];
  bool sawLineEnding = false;
  while (!sawLineEnding && bytes.size() < maxPasswordBytes) {
    DWORD read = 0;
    if (!ReadFile(stdinHandle, chunk, sizeof(chunk), &read, nullptr)) {
      return false;
    }
    if (read == 0) break;

    for (DWORD i = 0; i < read; ++i) {
      char ch = chunk[i];
      if (ch == '\n') {
        sawLineEnding = true;
        break;
      }
      if (ch != '\r') {
        bytes.push_back(ch);
        if (bytes.size() == maxPasswordBytes) break;
      }
    }
  }

  if (bytes.empty()) {
    return false;
  }

  return utf8ToWide(bytes, password);
}

static void showUsage() {
  std::wcout << L"encrypted-vhd-mount: AES-256-CTR encrypt VHD, mount decrypted view via Dokan\n";
  std::wcout << L"Usage:\n";
  std::wcout << L"  encrypted-vhd-mount.exe [/d|/l] [/p <password> | --password-stdin] <enc_file> <mount_path>\n";
  std::wcout << L"  Optional: /k <keyfile> participate in key derivation\n";
  std::wcout << L"  Optional: /direct disable file cache, use unbuffered direct I/O (needs alignment)\n";
  std::wcout << L"  Initialize encrypted file:\n";
  std::wcout << L"  encrypted-vhd-mount.exe /init <plain_vhd> /o <enc_file> [/p <password> | --password-stdin]\n";
  std::wcout << L"Args:\n";
  std::wcout << L"  /d           print Dokan debug logs\n";
  std::wcout << L"  /l           open Explorer at mount path after mount\n";
  std::wcout << L"  /p           plaintext password\n";
  std::wcout << L"  --password-stdin  read UTF-8 password from stdin\n";
  std::wcout << L"  /k           key file path\n";
  std::wcout << L"  /init        initialize from plaintext VHD\n";
  std::wcout << L"  /o           output encrypted file path\n";
  std::wcout.flush();
}

static bool ensureDokanLoaded() {
  HMODULE h = GetModuleHandleW(L"dokan2.dll");
  if (!h) h = LoadLibraryW(L"dokan2.dll");
  if (!h) h = LoadLibraryW(L"C:\\Windows\\System32\\dokan2.dll");
  if (!h) {
    std::wcout << L"[main] Failed to load dokan2.dll. Install Dokan v2 (x64) or check DLL version\n";
    return false;
  }
  return true;
}

static bool readParameters(Parameters &params, int argc, wchar_t **argv) {
  bool usedPasswordArg = false;
  for (int i = 1; i < argc; ++i) {
    std::wstring arg = argv[i];
    if (arg == L"/h" || arg == L"--help") { showUsage(); return false; }
    else if (arg == L"/d" || arg == L"--debug") { params.debugMode = true; }
    else if (arg == L"/l" || arg == L"--launch") { params.launchMountPath = true; }
    else if (arg == L"/direct" || arg == L"--direct") { params.directIO = true; }
    else if (arg == L"--password-stdin") { params.passwordFromStdin = true; }
    else if (arg == L"/p" || arg == L"--password") { 
      if (i + 1 >= argc) { std::wcout << L"Missing password\n"; return false; } 
      params.password = argv[++i]; 
      usedPasswordArg = true;
    }
    else if (arg == L"/k" || arg == L"--keyfile") { 
      if (i + 1 >= argc) { std::wcout << L"Missing keyfile path\n"; return false; } 
      params.keyFilePath = argv[++i]; 
    }
    else if (arg == L"/init") { 
      if (i + 1 >= argc) { std::wcout << L"Missing plain_vhd path\n"; return false; } 
      params.initVhdPath = argv[++i]; 
    }
    else if (arg == L"/o" || arg == L"--output") { 
      if (i + 1 >= argc) { std::wcout << L"Missing output file path\n"; return false; } 
      params.encFilePath = argv[++i]; 
    }
    else {
      // positional args: <enc_file> <mount_path>
      if (params.encFilePath.empty()) {
        params.encFilePath = arg;
      } else if (params.mountPoint.empty()) {
        params.mountPoint = arg; 
      } else { 
        std::wcout << L"Extra argument: " << arg << L"\n"; 
        return false; 
      }
    }
  }

  if (usedPasswordArg && params.passwordFromStdin) {
    std::wcout << L"Choose only one password source\n";
    return false;
  }
  if (params.passwordFromStdin && !readPasswordFromStdin(params.password)) {
    std::wcout << L"Failed to read UTF-8 password from stdin\n";
    return false;
  }

  if (!params.initVhdPath.empty()) {
    if (params.encFilePath.empty()) { std::wcout << L"Init mode needs /o <enc_file>\n"; return false; }
    if (params.password.empty() && params.keyFilePath.empty()) { 
      std::wcout << L"Init mode needs /p <password>, --password-stdin or /k <keyfile>\n";
      return false; 
    }
    return true;
  }

  if (params.password.empty() && params.keyFilePath.empty()) { 
    std::wcout << L"Missing /p <password>, --password-stdin or /k <keyfile>\n";
    return false; 
  }
  if (params.encFilePath.empty()) { std::wcout << L"Missing <enc_file>\n"; return false; }
  if (params.mountPoint.empty()) { std::wcout << L"Missing <mount_path>\n"; return false; }
  return true;
}

static bool isRedirectedHandle(HANDLE handle) {
  if (handle == INVALID_HANDLE_VALUE || handle == nullptr) {
    return false;
  }

  DWORD mode = 0;
  if (GetConsoleMode(handle, &mode)) {
    return false;
  }

  DWORD type = GetFileType(handle);
  return type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK;
}

static void fileWatcher(std::wstring path) {
  std::filesystem::path mp(path);
  std::error_code ec;
  do {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  } while (std::filesystem::exists(mp, ec) == false);
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
    default:
      return FALSE;
  }
}

int wmain(int argc, wchar_t **argv) {
  const bool stdinRedirected = isRedirectedHandle(GetStdHandle(STD_INPUT_HANDLE));
  const bool stdoutRedirected = isRedirectedHandle(GetStdHandle(STD_OUTPUT_HANDLE));
  const bool stderrRedirected = isRedirectedHandle(GetStdHandle(STD_ERROR_HANDLE));

  // Allocate console only for interactive double-click scenarios.
  // Preserve redirected stdio handles from parent processes.
  if (GetConsoleWindow() == NULL && !stdinRedirected && !stdoutRedirected && !stderrRedirected) {
    AllocConsole();
    FILE *fp;
    fp = freopen("CONOUT$", "w", stdout);
    fp = freopen("CONOUT$", "w", stderr);
    fp = freopen("CONIN$", "r", stdin);
    (void)fp;
  }
  
  std::wcout << L"[main] starting. argc=" << argc << L"\n";
  std::wcout.flush();
  
  Parameters params;
  if (!readParameters(params, argc, argv)) {
    if (!params.password.empty()) SecureZeroMemory(params.password.data(), params.password.size() * sizeof(wchar_t));
    return 0;
  }

  std::wcout << L"[main] args parsed. debug=" << (params.debugMode ? L"on" : L"off")
             << L" initVhdPath=" << (params.initVhdPath.empty() ? L"(none)" : params.initVhdPath)
             << L" encFilePath=" << params.encFilePath << L" mountPoint=" << params.mountPoint
             << L" keyFilePath=" << (params.keyFilePath.empty() ? L"(none)" : params.keyFilePath)
             << L" directIO=" << (params.directIO ? L"on" : L"off") << L"\n";

  if (!params.initVhdPath.empty()) {
    evhd::Container c;
    if (!c.createFromPlainVhd(params.initVhdPath, params.encFilePath, params.password, params.keyFilePath)) {
      std::wcout << L"Encryption init failed\n";
      if (!params.password.empty()) SecureZeroMemory(params.password.data(), params.password.size() * sizeof(wchar_t));
      return 1;
    }
    std::wcout << L"Generated encrypted file: " << params.encFilePath << L"\n";
    if (!params.password.empty()) SecureZeroMemory(params.password.data(), params.password.size() * sizeof(wchar_t));
    return 0;
  }

  vfs_evhd::MountConfig cfg;
  cfg.encryptedFilePath = params.encFilePath;
  cfg.password = params.password;
  cfg.exposedFileName = L"decrypted.vhd";
  cfg.keyFilePath = params.keyFilePath;
  cfg.debug = params.debugMode;
  cfg.directIO = params.directIO;

  vfs_evhd::MountContext mountCtx;
  std::wcout << L"[main] opening encrypted: " << cfg.encryptedFilePath << L"\n";
  if (!mountCtx.setup(cfg)) {
    std::wcout << L"[main] Failed to open encrypted file or wrong password\n";
    if (!params.password.empty()) SecureZeroMemory(params.password.data(), params.password.size() * sizeof(wchar_t));
    if (!cfg.password.empty()) SecureZeroMemory(cfg.password.data(), cfg.password.size() * sizeof(wchar_t));
    return 1;
  }

  std::wcout << L"[main] encrypted opened. plaintext size=" << mountCtx.container().plaintextSize() << L" bytes\n";
  std::wcout << L"[main] exposing file name: " << mountCtx.config().exposedFileName << L"\n";
  
  // Ensure Dokan2 DLL is loaded before entering DokanMain
  if (!ensureDokanLoaded()) {
    if (!params.password.empty()) SecureZeroMemory(params.password.data(), params.password.size() * sizeof(wchar_t));
    if (!cfg.password.empty()) SecureZeroMemory(cfg.password.data(), cfg.password.size() * sizeof(wchar_t));
    return 1;
  }
  DokanInit();

  DOKAN_OPTIONS dokanOptions;
  ZeroMemory(&dokanOptions, sizeof(DOKAN_OPTIONS));
  dokanOptions.Version = DOKAN_VERSION;
  dokanOptions.SingleThread = FALSE;
  dokanOptions.Timeout = 0;
  dokanOptions.GlobalContext = reinterpret_cast<ULONG64>(&mountCtx);
  dokanOptions.MountPoint = params.mountPoint.c_str();
  dokanOptions.Options |= DOKAN_OPTION_CURRENT_SESSION | DOKAN_OPTION_ALT_STREAM | DOKAN_OPTION_MOUNT_MANAGER;

  if (params.debugMode) {
    dokanOptions.Options |= DOKAN_OPTION_STDERR | DOKAN_OPTION_DEBUG;
  }

  DOKAN_OPERATIONS ops;
  ZeroMemory(&ops, sizeof(DOKAN_OPERATIONS));
  vfs_evhd::setup_dokan_ops(ops);

  SetConsoleCtrlHandler(CtrlHandler, TRUE);

  std::wcout << L"[main] Dokan options: 0x" << std::hex << dokanOptions.Options << std::dec << L"\n";
  std::wcout << L"[main] entering DokanMain at mountpoint: " << params.mountPoint << L"\n";
  
  std::thread watcher;
  if (params.launchMountPath) {
    watcher = std::thread(fileWatcher, params.mountPoint);
  }

  auto status = DokanMain(&dokanOptions, &ops);
  std::wcout << L"[main] DokanMain returned status=" << status << L"\n";

  switch (status) {
    case DOKAN_SUCCESS: break;
    case DOKAN_ERROR: std::wcout << L"Dokan unknown error\n"; break;
    case DOKAN_DRIVE_LETTER_ERROR: std::wcout << L"Drive letter unavailable\n"; break;
    case DOKAN_DRIVER_INSTALL_ERROR: std::wcout << L"Dokan driver comm failed\n"; break;
    case DOKAN_START_ERROR: std::wcout << L"Dokan start failed\n"; break;
    case DOKAN_MOUNT_ERROR: std::wcout << L"Mount failed: " << params.mountPoint << L"\n"; break;
    case DOKAN_MOUNT_POINT_ERROR: std::wcout << L"Mount point error\n"; break;
    case DOKAN_VERSION_ERROR: std::wcout << L"Dokan version mismatch\n"; break;
    default: std::wcout << L"Unknown error: " << status << L"\n"; break;
  }

  DokanShutdown();
  if (watcher.joinable()) {
    watcher.detach();
  }

  if (!params.password.empty()) SecureZeroMemory(params.password.data(), params.password.size() * sizeof(wchar_t));
  if (!cfg.password.empty()) SecureZeroMemory(cfg.password.data(), cfg.password.size() * sizeof(wchar_t));
  return 0;
}