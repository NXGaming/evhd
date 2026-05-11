# encrypted-vhd-mount

一个支持流式加解密的VHD处理程序：将VHD以AES-256-CTR加密（PBKDF2密码派生），并通过Dokan桥接提供一个"解密视图文件"，无需解密到临时文件即可被系统直接访问与挂载。当前默认创建 v5 容器，全程以 HMAC-SHA256 提供完整性与防篡改保护。

## 依赖

- Dokan v2（已在本仓库的 `third_party/Dokan/` 集成）
- Windows CNG (`bcrypt`) 库
- CMake 3.15+，Visual Studio 2019 及以上（项目使用 C++17、`/MT` 静态运行库）

## 构建

```powershell
cmake -S encrypted-vhd-mount -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

CMake 配置共生成三个目标：

- `encrypted-vhd-mount.exe`：CLI 主程序，负责创建（`/init`）与挂载（Dokan）。
- `evhd-bench.exe`：脱离 Dokan 直接对 `Container` 进行顺序/随机读基准。
- `evhd-selftest.exe`：内建自检套件（CTest 注册名同名），覆盖 v4/v5 兼容、HMAC 篡改检测、journal 回放、并发读写一致性等。可在构建目录下用 `ctest -C Release` 触发。

## 使用

### 初始化加密

将明文VHD加密为EVHD文件（包含头部、盐值、随机IV、HMAC 完整性指纹），加密为流式进行，无需一次性加载整文件。

```powershell
"YourPassword" | encrypted-vhd-mount.exe /init c:\path\to\plain.vhd /o c:\path\to\encrypted.evhd --password-stdin
# 仅密钥文件：
encrypted-vhd-mount.exe /init c:\path\to\plain.vhd /o c:\path\to\encrypted.evhd /k c:\path\to\keyfile.bin
# 密码 + 密钥文件组合：
"YourPassword" | encrypted-vhd-mount.exe /init c:\path\to\plain.vhd /o c:\path\to\encrypted.evhd --password-stdin /k c:\path\to\keyfile.bin
```

### 挂载解密视图

将加密文件通过Dokan挂载为一个虚拟盘，盘内包含一个文件 `decrypted.vhd`，其内容为对加密文件的解密视图：

```powershell
"YourPassword" | encrypted-vhd-mount.exe --password-stdin c:\path\to\encrypted.evhd M:\
# 仅密钥文件：
encrypted-vhd-mount.exe /k c:\path\to\keyfile.bin c:\path\to\encrypted.evhd M:\
# 密码 + 密钥文件组合：
"YourPassword" | encrypted-vhd-mount.exe --password-stdin /k c:\path\to\keyfile.bin c:\path\to\encrypted.evhd M:\
# 启用 directIO 模式（提升性能）：
"YourPassword" | encrypted-vhd-mount.exe --password-stdin /direct c:\path\to\encrypted.evhd M:\
```

- 可选：`/d` 显示Dokan调试日志；`/l` 挂载后打开资源管理器；`/direct` 启用 directIO 模式。
- 推荐使用 `--password-stdin` 从 stdin 读取 UTF-8 密码；`/p <password>` 仍可用于兼容场景。
- `M:\` 可以是盘符或NTFS文件夹路径。
- 若容器头部包含原始文件名元数据，则挂载盘内文件名会显示为该原始名；否则默认展示为 `decrypted.vhd`。
- 当前版本默认启用崩溃恢复 Journal：每次写请求都会先把将要写入的密文记录到同目录 sidecar journal，再落盘到主容器；若机台直接断电，下次打开时会自动回放未完成事务并提示上次是异常关闭。v5 容器的 journal 头与负载均带有 HMAC，被外部篡改后会拒绝挂载，而不是静默回放伪造数据。
- 程序会用 `SecureZeroMemory` 在退出与失败路径主动擦除驻留在内存中的密码与密钥派生中间量。

### 密钥派生（KDF）

本工具支持三种KDF方法，可根据输入自动选择或由容器记录在头部以便解密端复现：

- `KDF_PASSWORD`：仅密码派生，`PBKDF2-HMAC-SHA256(password, salt, iterations)` → 32字节密钥。
- `KDF_KEYFILE`：仅密钥文件，`SHA256(keyfile)` 作为 PBKDF2 的"密码"输入。
- `KDF_PASSWORD_PLUS_KEYFILE`：组合派生，先用密码PBKDF2得到 `pbkdfKey`，再计算 `finalKey = HMAC-SHA256(key=digest(keyfile), data=pbkdfKey||salt||nonce)`。

v5 容器在派生出 32 字节主密钥后，再经一次 `hmacKey = HMAC-SHA256(masterKey, "hmac-auth-v5" || nonce)` 派生独立的认证密钥；AES-256-CTR 仍使用主密钥，所有 HMAC-SHA256 计算改用 `hmacKey`，避免认证密钥与加密密钥混用。

### 挂载VHD到系统（可选）

挂载完成后，系统或你可以直接使用 `M:\decrypted.vhd` 进行VHD挂载，例如在PowerShell中：

```powershell
Mount-VHD -Path "M:\\decrypted.vhd" -ReadOnly:$false
```

此过程不会生成临时明文文件，所有读写均通过AES-CTR在块级别流式加解密并直写到加密文件。

## 格式说明

EVHD 文件头（逐版本扩展，所有偏移按"逐字段布局"计算，不依赖 `sizeof(Header)`）：

- 公共字段（v1+）：
  - `magic[8] = "EVHD0001"`
  - `version`（当前默认创建 `5`，仍可读取 v1–v4）
  - `kdfIterations`（默认 200000）
  - `originalSize`（明文 VHD 大小）
  - `salt[16]`（PBKDF2 盐）
  - `nonce[16]`（AES-CTR IV 基）
- v2 起：在 v1 字段之后追加"原始文件名元数据"：`nameLen(4B)` + `name(wchar_t[nameLen])`。
- v3 起：在 v1 字段之后、文件名元数据之前新增 `kdfMethod(4B)`。
- v4 起：在 v3 之上追加：
  - 重定位元数据：`count(4B)` + `entries[count]`，每条 `logicalOffset(8B)` + `length(8B)` + `physicalOffset(8B)`，用于将分区表等敏感范围剪切到尾部。
  - 填充指纹：`padSalt(16B)` + `padCRC32(4B)`，用于打开时校验主负载中剪切位置的伪随机填充。
- v5 起：用 HMAC 替代 CRC，并新增 payload 认证扩展：
  - `padHmac(32B)` 取代 `padCRC32(4B)`。
  - `authBlockSize(4B)`：payload 认证块大小，`0` 表示禁用整体 payload 认证；当前 `/init` 默认写入 `0`，把性能保留为优先项。
  - `headerHmac(32B)`：覆盖前述全部头部字段（含 v5 的 `authBlockSize`）的 HMAC-SHA256。
  - `relocAuthCount(4B)` + `relocAuthHmacs[relocAuthCount]`（每条 32B）：每个重定位条目对应一条覆盖 `physOffset || cipherText` 的 HMAC，挂载时逐条校验。

负载部分为密文，按偏移基于 CTR 计数进行随机访问解密/加密。当 `authBlockSize > 0` 时，紧随 payload 之后再追加 `payloadAuthTags`：每 `authBlockSize` 字节一个 32B HMAC，挂载时按需校验所读取的块。

### 重定位与剪切

- 为隐藏分区表等结构，创建阶段会将若干逻辑范围（如 `MBR 446..509`、`GPT LBA1 头`、`GPT 分区项`、`备份 GPT` 等）剪切到密文尾部，并在主负载原位置用伪随机填充替换。
- 剪切范围的真实数据在尾部以 `physicalOffset` 形式存放；读写时通过"逻辑→物理"映射保证 CTR 偏移使用物理位置，从而解密/加密正确。
- v5 容器对每个剪切片段额外保存一条 HMAC（覆盖 `physOffset || ciphertext`），挂载时与主 payload 校验并行进行；任何外部对剪切区域的篡改都会被拒绝。

### 打开时完整性校验（v5 严格模式）

挂载 v5 容器时按以下顺序进行强校验，任何一步失败都会直接拒绝挂载：

1. 读取头部全部字段（含 `padHmac`、`headerHmac`、`relocAuthHmacs` 等占位）。
2. 打开 sidecar journal，若发现 `state == PREPARED` 则立即回放未提交事务到主容器，再清理脏标志。
3. 经 KDF 派生主密钥与 `hmacKey`。
4. 用 `hmacKey` 重算 `headerHmac` 并以常量时间比对。
5. 若 `authBlockSize > 0`，加载尾部的 `payloadAuthTags`（每读取一块时再做单块 HMAC 校验）。
6. 遍历所有剪切的逻辑范围，按逻辑偏移作为 CTR 偏移解密得到伪随机填充，将所得字节流统一计算 HMAC 并与头部记录的 `padHmac` 做常量时间比对。

v4 容器在打开时仍按原 `padCRC32` 行为进行校验；既有数据可继续打开，但建议升级到 v5 以获得真正的完整性保证。

### 升级与兼容性

- 程序仍能读取 v1–v4 容器，但只有 v5 启用 HMAC 防篡改与 journal 认证。
- 旧版本（v1–v3）创建的 EVHD 通常会因为完整性指纹缺失或 `payloadOffset` 计算差异而拒绝挂载，请用新可执行文件重新执行 `/init` 生成 v5 容器。
- 创建与读取侧的 `payloadOffset` 计算已统一为"逐字段布局"（不使用结构体 `sizeof`），避免对齐差导致的偏移误差。

### DirectIO 模式与性能优化

#### DirectIO 模式说明

- `/direct` 参数启用 directIO 模式，绕过 Windows 文件系统缓存，直接访问底层加密容器文件。
- **优势**：减少内存拷贝开销，在大文件顺序读写场景下可显著提升性能。
- **注意**：directIO 要求读写偏移和长度必须按扇区对齐；程序会查询 `FileAlignmentInfo` 与卷 `BytesPerSector`，自动取较大者作为对齐单位。

#### EOF 边界处理

- 加密容器的负载区结尾可能不按扇区对齐，导致 directIO 读取文件尾部时失败。
- **自动修复**：程序会检测此类情况并自动回退到缓冲读取模式，确保稳定性。
- 日志中会显示 `[evhd] unbuffered read touches EOF. Falling back to buffered path.` 提示。

#### 性能基准测试

仓库内构建出的 `evhd-bench.exe` 提供独立于 Dokan 的 `Container` 层基准，可用于比较密码学路径开销。完整端到端 I/O 仍建议用 DiskSpd（禁用缓存）跑实际挂载盘：

```powershell
# 顺序读测试（1MB 块，32 队列深度，4 线程，30秒）
diskspd -b1M -d30 -o32 -t4 -r -Sh -Su -c4G M:\benchfile.dat

# 顺序写测试
diskspd -b1M -d30 -o32 -t4 -w100 -Sh -Su -c4G M:\benchfile.dat

# 随机 4K 读测试
diskspd -b4K -d30 -o32 -t4 -r -Sh -Su -c4G M:\benchfile.dat

# 随机 4K 写测试
diskspd -b4K -d30 -o32 -t4 -w100 -Sh -Su -c4G M:\benchfile.dat
```

**性能期望值**（参考）：
- 顺序读写：1-3 GB/s（取决于 CPU 核心数与 AES-NI 性能）
- 随机 4K Q1T1：几十 MB/s
- 随机 4K Q32T16：几百 MB/s

**注意**：CrystalDiskMark 等工具的顺序读数值可能因 Windows 缓存而虚高，建议使用 DiskSpd 的 `-Sh -Su` 参数禁用缓存获得真实结果。如启用 `authBlockSize > 0` 的 payload 认证，会按块产生额外 HMAC 校验开销，请按场景权衡。

### 自检与回归

- `evhd-selftest.exe` 在 `selftest_tmp/` 目录下生成临时 VHD/EVHD/journal，并依次跑：MBR/GPT 写入回读、journal dirty 标志、未提交事务回放、v4 兼容打开、v5 头部 HMAC 篡改、v5 pad HMAC 篡改、v5 journal HMAC 篡改、v5 多线程并发写入、v5 读写一致性。
- 全部场景成功时进程返回 0 并输出 `[selftest] OK`，可由 `ctest -C Release` 在 CI 中触发。

### 故障排查

#### 通用问题

- 启用 `/d` 查看调试日志，关注：
  - `version`、`payloadOffset`、`relocCount`；
  - `kdf salt/nonce/key[0..7]` 指纹是否正常输出；
  - 完整性校验：`integrity check OK` 或具体失败位置（v5 会指明 `header HMAC verification FAILED`、`padHMAC mismatch`、`journal entries/data HMAC verification FAILED` 之一）。
- 若失败：
  - 确认使用最新 `encrypted-vhd-mount.exe` 重新执行 `/init` 生成 v5 容器；
  - 排除磁盘/安全软件对 EVHD 主负载或 sidecar journal 的写入；
  - 检查密码/密钥文件路径与 KDF 方法是否一致。

#### DirectIO 相关问题

- **挂载失败或读取错误**：
  - 检查日志中是否有 `[evhd] readRawPhys fail` 错误（已在新版本修复）。
  - 确认使用最新版本，旧版本在 directIO 模式下可能在文件尾部读取失败。

- **性能不如预期**：
  - 确认已使用 `/direct` 参数启用 directIO 模式。
  - 使用 DiskSpd 而非 CrystalDiskMark 进行基准测试，后者可能受缓存影响。
  - 检查 CPU 是否支持 AES-NI 指令集，影响加解密性能。

- **日志中出现 EOF 回退提示**：
  - `[evhd] unbuffered read touches EOF. Falling back to buffered path.` 是正常行为。
  - 这表明程序正确处理了文件尾部的非对齐读取，不影响功能和整体性能。

## 构建与编码提示

- 如出现 MSVC `C4819` 编码警告，请将源文件保存为 UTF-8（建议无 BOM）。
- 项目对 `dokan2.dll` 启用了 `/DELAYLOAD`：未安装 Dokan v2 时进程不会在加载阶段静默退出，而是给出明确错误。

## 注意事项

- 当前不支持扩展VHD大小（写入超过原始大小将被拒绝）。
- 建议使用足够强度的密码，并妥善备份密钥材料（密码与密钥文件）。一旦遗失或泄露，数据安全不可保证且不可恢复。
- 密钥文件建议使用随机二进制内容，并与密文分开存放；组合方式（密码+密钥文件）可降低单点泄露风险。
- 读写并发已通过文件级互斥保护；如需高并发可进一步引入分块锁策略。
