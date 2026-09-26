# Hash-Check

Windows 资源管理器哈希校验扩展：右键生成**加密防篡改校验文件**（AES-256-GCM 双容器冗余 + ECC 签名 + 逐条校验值），双击验证，副本损坏自动修复。基于开源 HashCheck 深度定制。

## 目录表

### 根目录

项目主体：COM 入口、哈希生成/验证引擎、加密封装、签名层、构建配置。

| 文件 | 角色 |
|---|---|
| CHashCheck.cpp | COM 服务入口（DLL 生命周期、进程内服务器逻辑） |
| CHashCheck.hpp | COM 服务入口头文件 |
| CHashCheckClassFactory.cpp | COM 类工厂实现 |
| CHashCheckClassFactory.hpp | COM 类工厂头文件 |
| HashCheck.cpp | DLL 主入口、右键菜单集成与宿主对接 |
| HashCheck.def | DLL 导出表（COM 注册所需导出） |
| HashCheck.manifest | UAC / COM 清单 |
| HashCheck.rc | 资源脚本（对话框、图标、版本信息） |
| HashCheckResources.h | 资源 ID 定义 |
| HashCheckTranslations.h | 21 语言字符串 ID 定义（含「损坏」状态串） |
| HashCheckTranslations.rc | 21 语言字符串资源数据 |
| HashCheckUI.h | 验证/生成对话框控件与常量定义 |
| HashCheck.ico | 程序与菜单图标 |
| HashCheck.bmp | 菜单位图资源 |
| HashCheck.sln | Visual Studio 解决方案 |
| HashCheck.vcxproj | 工程文件（x64 + Win32 双平台） |
| HashCheck.vcxproj.filters | 工程文件过滤器分组 |
| HashCheckGlobalDefines.props | 工程公共属性配置 |
| HashCalc.c | 校验文件**生成引擎**：逐条哈希行写出 + 逐条 chk 校验值写出 + 多编码保存 |
| HashCalc.h | 生成引擎头文件 |
| HashSave.cpp | 保存对话框流程与密封（加密+签名）落盘 |
| HashVerify.cpp | 校验文件**验证引擎**：容器解封、双副本修复通道、逐条 chk 定位、TOFU 信任、状态配色 |
| HashProp.c | 文件属性页「校验哈希」标签页 |
| HashCheckCommon.c | 公共上下文与哈希管线基础 |
| HashCheckCommon.h | 公共上下文头文件 |
| HashCheckOptions.c | 选项持久化（注册表读写） |
| HashCheckOptions.h | 选项持久化头文件 |
| Hcenc.c | AES-256-GCM 容器封装：双容器冗余、魔数扫描定位、前缀幸存者盲扫、全 DLL 唯一 SHA-256 |
| Hcenc.h | 容器格式 v2 说明与 API |
| Hcsign.c | ECC 签名层：内置公钥表、KSP 访问、指纹计算 |
| Hcsign.h | 签名层 API 与公钥表 |
| IsSSD.c | SSD 检测（写盘缓冲策略） |
| IsSSD.h | SSD 检测头文件 |
| RegHelpers.c | 注册表读写助手 |
| RegHelpers.h | 注册表助手头文件 |
| SetAppID.c | 任务栏 AppID 设置 |
| SetAppID.h | AppID 头文件 |
| UnicodeHelpers.c | 编码转换（UTF-8 / UTF-16 / ANSI 与探测） |
| UnicodeHelpers.h | 编码转换头文件 |
| globals.h | 全 DLL 公共定义伞 |
| GetHighMSB.h | 最高有效位快速运算工具 |
| version.h | 版本常量 |
| tiny.bmp | 安装器完成页 1×1 占位图（替代 26KB 向导大图） |
| license.txt | 许可证（上游 HashCheck GPL） |
| README.md | 本文件 |
| .gitignore | Git 忽略规则（构建产物/缓存） |

### images/

README 演示截图（右键校验与文件整理功能演示）。

| 文件 | 角色 |
|---|---|
| images/1_校验演示1.png | 校验功能演示截图一 |
| images/2_校验演示2.png | 校验功能演示截图二 |
| images/3_整理演示1.png | 文件整理（重命名）演示截图一 |
| images/4_整理演示2.png | 文件整理（重命名）演示截图二 |
| images/5_优先演示.png | 校验优先级功能演示截图 |

### installer/

NSIS 安装脚本模板；发版时替换版本号后编译。

| 文件 | 角色 |
|---|---|
| installer/Hash-Check_x.x.x.nsi | 安装器模板：license / 默认算法选择 / 安装进度 / 完成页，双 DLL（x64+Win32）注册逻辑，x64/32 系统自适应 |

### libs/

上游哈希算法库与基础容器：全部哈希算法的实现与调度。

| 文件 | 角色 |
|---|---|
| libs/WinHash.cpp | 哈希计算调度层（按用户选择调用各算法） |
| libs/WinHash.h | 调度层头文件 |
| libs/SimpleList.c | 列表容器（校验条目存储） |
| libs/SimpleList.h | 列表容器头文件 |
| libs/SimpleString.c | 字符串容器 |
| libs/SimpleString.h | 字符串容器头文件 |
| libs/Wow64.c | 32 位进程访问 64 位文件系统的重定向助手 |
| libs/Wow64.h | 重定向助手头文件 |
| libs/IsFontAvailable.c | 字体可用性检测 |
| libs/IsFontAvailable.h | 字体检测头文件 |
| libs/BitwiseIntrinsics.h | 位运算 SIMD 工具 |
| libs/WinIntrinsics.h | Windows SIMD 工具 |
| libs/crc32.c | CRC-32 算法 |
| libs/md5.c | MD5 算法 |
| libs/sha1.c | SHA-1 算法 |
| libs/sha2.c | SHA-2 家族（SHA-224/256/384/512） |
| libs/blake2.h | BLAKE2 算法 |
| libs/blake3.h | BLAKE3 算法 |
| libs/sm3.h | SM3 国密算法 |
| libs/xxhash64.h | xxHash64 算法 |
| libs/ripemd160.h | RIPEMD-160 算法 |

### libs/sha3/

SHA-3 / Keccak 算法族（官方参考实现）。

| 文件 | 角色 |
|---|---|
| libs/sha3/KeccakHash.c | Keccak 高层哈希接口 |
| libs/sha3/KeccakHash.h | 高层接口头文件 |
| libs/sha3/KeccakSponge.c | 海绵结构实现 |
| libs/sha3/KeccakSponge.h | 海绵结构头文件 |
| libs/sha3/KeccakSponge.inc | 海绵结构内部包含文件 |
| libs/sha3/KeccakP-1600-opt64.c | Keccak 1600 置换 64 位优化实现 |
| libs/sha3/KeccakP-1600-opt64-config.h | 优化实现配置 |
| libs/sha3/KeccakP-1600-unrolling.macros | 展开宏 |
| libs/sha3/KeccakP-1600-64.macros | 64 位宏 |
| libs/sha3/KeccakP-1600-SnP.h | 置换接口声明 |
| libs/sha3/SnP-Relaned.h | Relaned 置换接口 |
| libs/sha3/align.h | 对齐工具 |
| libs/sha3/brg_endian.h | 字节序工具 |

### signer/

发布签名工具（独立 CLI）：对校验文件做作者域签名。

| 文件 | 角色 |
|---|---|
| signer/hashsign.c | 独立签名工具源码（链接 Hcenc/Hcsign，命令行用法见文件头注释） |

## 使用方法

- **生成**：资源管理器选中文件/文件夹 → 右键 → 「创建校验文件」→ 选择格式（默认 SHA-256）与编码 → 保存后自动加密封签
- **验证**：双击密封的校验文件 → 列表显示逐条比对结果（绿=匹配 / 红=不匹配 / 黄底=缺失 / 蓝底=新增 / 紫底=损坏）
- **损坏定位**：验签失败且能定位到具体条目时弹窗询问是否继续查看；继续则损坏条目紫底「损坏」且不显示可疑校验值
- **自动修复**：密封文件一份副本损坏时（删除、截断、字节损坏），弹窗用完好副本重封还原
- **拒收**：无法识别或验签失败且无法定位 → 「文件已损坏或被篡改 / 可能安装版本不匹配」
- **信任**：他人签名的校验文件首次打开弹 TOFU 询问，信任后静默
- **注意**：密封文件是二进制容器，**不要用文本编辑器编辑**（会导致全档重编码且无法修复）

## 打包命令

```
:: 1. 编译双平台（VS2022 BuildTools）
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe" HashCheck.vcxproj -t:Rebuild -p:Configuration=Release -p:Platform=x64 -p:PlatformToolset=v143 -m
:: Platform=Win32 再来一次

:: 2. 生成安装器（版本号替换后 NSIS 编译）
sed 's/x\.x\.x/1.5.7/g' installer/Hash-Check_x.x.x.nsi > installer/Hash-Check_1.5.7.nsi
cd installer && makensis Hash-Check_1.5.7.nsi
```

构建产物：`Bin\x64\Release\HashCheck.dll`、`Bin\Win32\Release\HashCheck.dll`、安装器 `installer\Hash-Check_<版本>.exe`。
