; NSIS installer: Encrypted VHD Mount
; Features:
; - Install to Program Files\EncryptedVHDMount
; - Optional Dokan installation (download Dokan_x64.msi from GitHub releases) and wait until it exits
; - Append install directory to system PATH for CLI usage

Unicode true
!include "MUI2.nsh"
!include "x64.nsh"

Name "Encrypted VHD Mount"
OutFile "EncryptedVHDMount-Setup.exe"
InstallDir "$PROGRAMFILES64\EncryptedVHDMount"
RequestExecutionLevel admin

; Reference app binary relative to script folder (installer\ ..\encrypted-vhd-mount\...)
!define APP_BIN "..\\build\\encrypted-vhd-mount.exe"

; MUI 页面
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

; Ensure 64-bit registry view where applicable
Function .onInit
  SetRegView 64
FunctionEnd

; Components: Dokan (optional) + Application (required)
Section "Install Dokan (optional)" SEC_DOKAN
  ; Download latest x64 release (GitHub redirects latest to current release)
  DetailPrint "Downloading Dokan_x64.msi..."
  NSISdl::download /TIMEOUT=60000 "https://github.com/dokan-dev/dokany/releases/latest/download/Dokan_x64.msi" "$TEMP\Dokan_x64.msi"
  Pop $0
  StrCmp $0 "success" 0 +3
    DetailPrint "Dokan_x64.msi downloaded"
    Goto +4
  DetailPrint "Download failed: $0"
  MessageBox MB_ICONSTOP "Failed to download Dokan installer ($0). Please retry later or install Dokan manually." IDOK
  Goto dokan_done

  ; Run MSI installer and wait until it exits
  DetailPrint "Starting Dokan installer..."
  ExecWait '"$SYSDIR\msiexec.exe" /i "$TEMP\Dokan_x64.msi" /passive' $1
  DetailPrint "Dokan installer exited with code: $1"

  ; Optional: Warn if exit code is non-zero
  StrCmp $1 "0" 0 +3
    DetailPrint "Dokan installed or already present"
    Goto dokan_done
  MessageBox MB_ICONEXCLAMATION "Dokan installer exit code: $1. If issues occur, verify Dokan is properly installed."

  dokan_done:
SectionEnd

Section "Install Encrypted VHD Mount" SEC_APP
  SetOutPath "$INSTDIR"
  ; Application binary
  File /oname=encrypted-vhd-mount.exe "${APP_BIN}"

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Append install directory to system PATH
  Call AddToPath

  ; Notify
  DetailPrint "Installed to: $INSTDIR"
SectionIn RO
SectionEnd

Section "Uninstall" SEC_UNINSTALL
  Delete "$INSTDIR\encrypted-vhd-mount.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd

; Append install directory to PATH (system HKLM) and broadcast environment change
Function AddToPath
  ; Use 64-bit registry view to write system PATH
  SetRegView 64
  ReadRegStr $0 HKLM "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" "Path"
  StrCmp $0 "" 0 +3
    StrCpy $1 "$INSTDIR"
    Goto +5
  ; Naive duplicate avoidance (best-effort)
  StrCpy $1 "$0"
  StrCpy $2 ";$INSTDIR"
  StrLen $3 $2
  ; Simple check before append
  StrCpy $4 "$0"
  ; If already contains, return
  FindWindow $5 "Shell_TrayWnd" "" "" ""
  StrCmp $4 "$INSTDIR" 0 +2
    Return
  StrCpy $1 "$0;$INSTDIR"

  WriteRegExpandStr HKLM "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" "Path" "$1"
  ; Broadcast environment variable update (WM_SETTINGCHANGE=0x001A)
  System::Call 'USER32::SendMessageTimeoutW(i 0xffff, i 0x001A, i 0, w "Environment", i 0, i 5000, *i .r0)'
FunctionEnd