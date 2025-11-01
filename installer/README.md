# Encrypted VHD Mount 安装器（NSIS）

本目录包含 NSIS 安装脚本，用于：
- 将程序安装到标准目录（`$PROGRAMFILES64\EncryptedVHDMount`）
- 可选安装 Dokan（从 GitHub releases 下载 `Dokan_x64.msi` 并等待安装完成）
- 将安装目录追加到系统 `PATH`，方便在命令行直接调用 `encrypted-vhd-mount.exe`

## 文件

- `EncryptedVHDMount.nsi`：安装器主脚本

## 编译前准备

1. 使用 CMake/Visual Studio 以 Release 构建程序，得到：
   - `encrypted-vhd-mount\build\Release\encrypted-vhd-mount.exe`
2. 安装 NSIS（3.x），确保可在命令行执行 `makensis`。

## 生成安装包

在仓库根目录，运行：

```powershell
makensis installer\EncryptedVHDMount.nsi
```

生成的安装包文件：`EncryptedVHDMount-Setup.exe`

## 安装流程说明

- 若勾选“安装 Dokan (可选)”，安装器会从 `https://github.com/dokan-dev/dokany/releases/latest/download/Dokan_x64.msi` 下载 Dokan 安装包，并以 `msiexec /passive` 方式启动安装；安装器会等待 Dokan 安装程序退出后再继续安装程序主体。
- 程序安装完成后会将安装目录追加到系统 `PATH`，无需重启即可在新打开的命令行窗口中使用。

## 注意事项

- 若未安装 Dokan，程序可能无法正常挂载文件系统；可在安装器中选择安装，或在此后手动安装 Dokan。
- 如需以管理员权限运行（修改系统 PATH、安装到 Program Files），安装器已请求管理员权限（`RequestExecutionLevel admin`）。