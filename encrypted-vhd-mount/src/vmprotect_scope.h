#pragma once

#if defined(EVHD_USE_VMPROTECT)
#include "../third_party/VMProtect/VMProtectSDK.h"
#endif

namespace evhd_vmp {

enum class Mode {
  Basic,
  Mutation,
  Virtualization,
  Ultra,
};

class Scope {
public:
  Scope(const char *marker, Mode mode = Mode::Basic) noexcept {
#if defined(EVHD_USE_VMPROTECT)
    switch (mode) {
      case Mode::Mutation:
        VMProtectBeginMutation(marker);
        break;
      case Mode::Virtualization:
        VMProtectBeginVirtualization(marker);
        break;
      case Mode::Ultra:
        VMProtectBeginUltra(marker);
        break;
      case Mode::Basic:
      default:
        VMProtectBegin(marker);
        break;
    }
#else
    (void)marker;
    (void)mode;
#endif
  }

  ~Scope() noexcept {
#if defined(EVHD_USE_VMPROTECT)
    VMProtectEnd();
#endif
  }

  Scope(const Scope &) = delete;
  Scope &operator=(const Scope &) = delete;
};

inline bool isProtected() noexcept {
#if defined(EVHD_USE_VMPROTECT)
  return VMProtectIsProtected();
#else
  return false;
#endif
}

inline bool isDebuggerPresent(bool checkKernel = true) noexcept {
#if defined(EVHD_USE_VMPROTECT)
  return VMProtectIsDebuggerPresent(checkKernel);
#else
  (void)checkKernel;
  return false;
#endif
}

inline bool isVirtualMachinePresent() noexcept {
#if defined(EVHD_USE_VMPROTECT)
  return VMProtectIsVirtualMachinePresent();
#else
  return false;
#endif
}

inline bool isValidImageCRC() noexcept {
#if defined(EVHD_USE_VMPROTECT)
  return VMProtectIsValidImageCRC();
#else
  return true;
#endif
}

} // namespace evhd_vmp