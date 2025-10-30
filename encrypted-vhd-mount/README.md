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

- v4：在 v3 基础上追加两部分：
  - 重定位元数据：`count(4B)` + `entries[count]`，每个条目为 `logicalOffset(8B)` + `length(8B)` + `physicalOffset(8B)`，用于将分区表等敏感范围剪切到尾部。
  - 填充指纹：`padSalt(16B)` + `padCRC32(4B)`，用于打开时的完整性校验（验证主负载中剪切位置的伪随机填充是否未被破坏）。

负载起始偏移（payloadOffset）：

- v1：`56` 字节（基础头大小）。
- v2：`56 + 4 + nameLen * sizeof(wchar_t)`。
- v3：`56 + 4(kdfMethod) + 4 + nameLen * sizeof(wchar_t)`。

- v4：`v3 + 4(count) + count * (8*3) + 16(padSalt) + 4(padCRC32)`。

负载部分为密文，按偏移基于 CTR 计数进行随机访问解密/加密。

### 重定位与剪切

- 为隐藏分区表等结构，创建阶段会将若干逻辑范围（如 `MBR 446..509`、`GPT LBA1 头`、`GPT 分区项`、`备份 GPT` 等）剪切到密文尾部，并在主负载原位置用伪随机填充替换。
- 剪切范围的真实数据在尾部以 `physicalOffset` 形式存放；读写时通过“逻辑→物理”映射保证 CTR 偏移使用物理位置，从而解密/加密正确。

### 打开时完整性校验（严格模式）

- 打开 EVHD 时，程序会：
  - 遍历所有剪切的逻辑范围，从“主负载区”位置读取密文；
  - 以逻辑偏移作为 CTR 偏移解密得到伪随机填充；
  - 对填充内容计算 CRC32 并与头部记录的 `padCRC32` 比对。
- 若不一致或读取/解密失败，视为完整性校验失败，当前版本会直接拒绝挂载并返回错误。
- 常见原因：
  - 使用旧版本创建的 EVHD（头部布局与偏移计算不一致）；
  - 密文主负载被安全软件或其他程序写入/篡改；
  - 密码或密钥文件与容器记录的 KDF 方法不匹配。

### 升级与兼容性

- 旧版本创建的 EVHD 文件可能无法通过新的完整性校验。请使用新可执行文件重新初始化（`/init`）生成新的 EVHD 后再挂载。
- 创建与读取侧的 `payloadOffset` 计算已统一为“逐字段布局”（不使用结构体 `sizeof`），避免对齐差导致的偏移误差。

### 故障排查

- 启用 `/d` 查看调试日志，关注：
  - `version`、`payloadOffset`、`relocCount`；
  - `kdf salt/nonce/key[0..7]` 指纹是否正常输出；
  - 完整性校验：`integrity check OK` 或 `FAILED` 以及期望/实际 CRC32。
- 若失败：
  - 确认使用最新 `encrypted-vhd-mount.exe` 重新执行 `/init`；
  - 排除磁盘/安全软件对 EVHD 主负载的写入；
  - 检查密码/密钥文件路径与 KDF 方法是否一致。

## 构建与编码提示

- 如出现 MSVC `C4819` 编码警告，请将源文件保存为 UTF-8（建议无 BOM）。

## 注意事项

- 当前不支持扩展VHD大小（写入超过原始大小将被拒绝）。
- 建议使用足够强度的密码，并妥善备份密钥材料（密码与密钥文件）。一旦遗失或泄露，数据安全不可保证且不可恢复。
- 密钥文件建议使用随机二进制内容，并与密文分开存放；组合方式（密码+密钥文件）可降低单点泄露风险。
- 读写并发已通过文件级互斥保护；如需高并发可进一步引入分块锁策略。