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
```

### 挂载解密视图

将加密文件通过Dokan挂载为一个虚拟盘，盘内包含一个文件 `decrypted.vhd`，其内容为对加密文件的解密视图：

```powershell
encrypted-vhd-mount.exe /p "YourPassword" c:\path\to\encrypted.evhd M:\
```

- 可选：`/d` 显示Dokan调试日志；`/l` 挂载后打开资源管理器。
- `M:\` 可以是盘符或NTFS文件夹路径。

### 挂载VHD到系统（可选）

挂载完成后，系统或你可以直接使用 `M:\decrypted.vhd` 进行VHD挂载，例如在PowerShell中：

```powershell
Mount-VHD -Path "M:\\decrypted.vhd" -ReadOnly:$false
```

此过程不会生成临时明文文件，所有读写均通过AES-CTR在块级别流式加解密并直写到加密文件。

## 格式说明

EVHD文件头包含：

- magic: `EVHD0001`
- version: 1
- kdfIterations: PBKDF2迭代次数（默认200000）
- originalSize: 明文VHD大小
- salt[16]: PBKDF2盐值
- nonce[16]: AES-CTR IV基

其后为密文负载，按偏移基于CTR计数器进行随机访问解密/加密。

## 注意事项

- 当前不支持扩展VHD大小（写入超过原始大小将被拒绝）。
- 建议使用足够强度的密码，并备份密钥材料（密码）。一旦遗失密码，数据不可恢复。
- 读写并发已通过文件级互斥保护；如需高并发可进一步引入分块锁策略。