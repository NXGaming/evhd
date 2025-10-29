# encrypted-vhd-mount

一个支持流式加解密的VHD处理程序：将VHD以AES-256-CTR加密（PBKDF2密码派生），并通过Dokan桥接提供一个“解密视图文件”，无需解密到临时文件即可被系统直接访问与挂载。

## 依赖

- Dokan v2（已在本仓库的 `third_party/Dokan/` 集成）
- Windows CNG (`bcrypt`) 库
- CMake 3.10+，Visual Studio 2019

## 构建

```powershell
mkdir encrypted-vhd-mount\build
cd encrypted-vhd-mount\build
cmake .. -G "Visual Studio 16 2019"
cmake --build . --config Release
```

## 使用

### 初始化加密

将明文VHD加密为EVHD文件（包含头部、盐值与随机IV），加密为流式进行，无需一次性加载整文件。

```powershell
encrypted-vhd-mount.exe /init c:\path\to\plain.vhd /o c:\path\to\encrypted.evhd /p "YourPassword"
# 仅密钥文件：
encrypted-vhd-mount.exe /init c:\path\to\plain.vhd /o c:\path\to\encrypted.evhd /k c:\path\to\keyfile.bin
# 密码 + 密钥文件组合：
encrypted-vhd-mount.exe /init c:\path\to\plain.vhd /o c:\path\to\encrypted.evhd /p "YourPassword" /k c:\path\to\keyfile.bin
```

### 挂载解密视图

将加密文件通过Dokan挂载为一个虚拟盘，盘内包含一个文件 `decrypted.vhd`，其内容为对加密文件的解密视图：

```powershell
encrypted-vhd-mount.exe /p "YourPassword" c:\path\to\encrypted.evhd M:\
# 仅密钥文件：
encrypted-vhd-mount.exe /k c:\path\to\keyfile.bin c:\path\to\encrypted.evhd M:\
# 密码 + 密钥文件组合：
encrypted-vhd-mount.exe /p "YourPassword" /k c:\path\to\keyfile.bin c:\path\to\encrypted.evhd M:\
```

- 可选：`/d` 显示Dokan调试日志；`/l` 挂载后打开资源管理器。
- `M:\` 可以是盘符或NTFS文件夹路径。
- 若容器头部包含原始文件名元数据，则挂载盘内文件名会显示为该原始名；否则默认展示为 `decrypted.vhd`。

### 密钥派生（KDF）

本工具支持三种KDF方法，可根据输入自动选择或由容器记录在头部以便解密端复现：

- `KDF_PASSWORD`：仅密码派生，`PBKDF2-HMAC-SHA256(password, salt, iterations)` → 32字节密钥。
- `KDF_KEYFILE`：仅密钥文件，`SHA256(keyfile)` 作为 PBKDF2 的“密码”输入。
- `KDF_PASSWORD_PLUS_KEYFILE`：组合派生，先用密码PBKDF2得到 `pbkdfKey`，再计算 `finalKey = HMAC-SHA256(key=digest(keyfile), data=pbkdfKey||salt||nonce)`。

### 挂载VHD到系统（可选）

挂载完成后，系统或你可以直接使用 `M:\decrypted.vhd` 进行VHD挂载，例如在PowerShell中：

```powershell
Mount-VHD -Path "M:\\decrypted.vhd" -ReadOnly:$false
```

此过程不会生成临时明文文件，所有读写均通过AES-CTR在块级别流式加解密并直写到加密文件。

## 格式说明

EVHD 文件头（逐版本扩展）：

- 公共字段（v1/v2/v3）：
  - `magic[8] = "EVHD0001"`
  - `version`
  - `kdfIterations`（默认 200000）
  - `originalSize`（明文 VHD 大小）
  - `salt[16]`（PBKDF2 盐）
  - `nonce[16]`（AES-CTR IV 基）
- v2：在头部之后追加“原始文件名元数据”：`nameLen(4B)` + `name(wchar_t[nameLen])`
- v3：在 v1 字段后新增 `kdfMethod(4B)`，再追加与 v2 相同的文件名元数据。

负载起始偏移（payloadOffset）：

- v1：`56` 字节（基础头大小）。
- v2：`56 + 4 + nameLen * sizeof(wchar_t)`。
- v3：`56 + 4(kdfMethod) + 4 + nameLen * sizeof(wchar_t)`。

负载部分为密文，按偏移基于 CTR 计数进行随机访问解密/加密。

## 注意事项

- 当前不支持扩展VHD大小（写入超过原始大小将被拒绝）。
- 建议使用足够强度的密码，并妥善备份密钥材料（密码与密钥文件）。一旦遗失或泄露，数据安全不可保证且不可恢复。
- 密钥文件建议使用随机二进制内容，并与密文分开存放；组合方式（密码+密钥文件）可降低单点泄露风险。
- 读写并发已通过文件级互斥保护；如需高并发可进一步引入分块锁策略。