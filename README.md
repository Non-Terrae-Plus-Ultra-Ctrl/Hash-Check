# Hash-Check

Windows 资源管理器哈希校验扩展：右键生成校验文件、右键校验、双击打开验证窗增删改查。当前形态（1.6.8）= 纯明文无签名无加密 + 逐条 chk 完整性定位 + 增量维护菜单 + 零打扰安装。基于开源 HashCheck（Kai Liu）深度定制。

## 目录表

### 根目录

工程主体：COM 入口、哈希生成/验证引擎、校验文件落盘、构建配置。

| 文件 | 角色 |
|---|---|
| .gitignore | Git 忽略规则（挡构建产物 Bin/Obj、安装包 exe、NSIS 打包暂存 stage 等） |
| CHashCheck.cpp | COM 服务入口（DLL 生命周期、进程内服务器逻辑） |
| CHashCheck.hpp | COM 服务入口头文件 |
| CHashCheckClassFactory.cpp | COM 类工厂实现 |
| CHashCheckClassFactory.hpp | COM 类工厂头文件 |
| HashCheck.cpp | DLL 主入口、右键菜单集成与宿主对接 |
| HashCheck.def | DLL 导出表（COM 注册与 rundll32 唤起验证窗所需导出） |
| HashCheck.manifest | UAC / COM 清单（v6 主题控件） |
| HashCheck.rc | 资源脚本（对话框模板、图标、版本信息；含雅黑 9 号字体定义） |
| HashCheckResources.h | 资源 ID 定义 |
| HashCheckTranslations.h | 21 语言字符串 ID 定义 |
| HashCheckTranslations.rc | 21 语言字符串资源数据 |
| HashCheckUI.h | 验证/生成对话框控件与常量定义 |
| HashCheck.ico | 程序与菜单图标 |
| HashCheck.bmp | 菜单位图资源 |
| HashCheck.sln | Visual Studio 解决方案 |
| HashCheck.vcxproj | 工程文件（x64 + Win32 双平台） |
| HashCheck.vcxproj.filters | 工程文件过滤器分组 |
| HashCheckGlobalDefines.props | 工程公共属性配置 |
| HashCalc.c | 校验文件生成引擎：逐条哈希行 + 逐条 chk 校验值 + 时间戳落盘，多线程逐文件哈希 |
| HashCalc.h | 生成引擎头文件 |
| HashSave.cpp | 保存对话框流程与落盘（chk 行随写；维护保存走 tmp+原位改写） |
| HashVerify.cpp | 验证窗全部逻辑：列表显示、逐条校验、状态配色（相符/不符/缺失/新增/损坏/未验/已变化）、chk 紫底精确定位、维护菜单（添加/移除/检测变化/保存维护）、Ctrl+C 与右键复制、排序、维护期锁 |
| HashProp.c | 文件属性页「校验哈希」标签页 |
| HashCheckCommon.c | 公共上下文与哈希管线基础 |
| HashCheckCommon.h | 公共上下文头文件 |
| HashCheckOptions.c | 选项对话框与持久化（算法选择、注册表读写） |
| HashCheckOptions.h | 选项持久化头文件 |
| Hcenc.c | 纯 SHA-256 单源模块（chk 校验值与哈希计算的公共实现；历史上曾为 AES-256-GCM 加密封装，已瘦身退役） |
| Hcenc.h | SHA-256 模块接口 |
| Hcsign.c | 签名层历史源码（ECC 签名/验签；1.6.x 无签名线已移出构建链，保留备查） |
| Hcsign.h | 签名层历史接口与公钥表 |
| IsSSD.c | SSD 检测（读盘缓冲策略） |
| IsSSD.h | SSD 检测头文件 |
| RegHelpers.c | 注册表读写助手 |
| RegHelpers.h | 注册表助手头文件 |
| SetAppID.c | 任务栏 AppID 设置 |
| SetAppID.h | AppID 头文件 |
| UnicodeHelpers.c | 编码转换（UTF-8 / UTF-16 / ANSI 与探测） |
| UnicodeHelpers.h | 编码转换头文件 |
| globals.h | 全 DLL 公共定义伞 |
| GetHighMSB.h | 最高有效位快速运算工具 |
| version.h | 版本常量（当前 1.6.8） |
| tiny.bmp | 安装器完成页占位图 |
| license.txt | 许可证（上游 HashCheck GPL） |
| README.md | 本文件 |

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

NSIS 安装脚本目录；构建产物 exe 由 .gitignore 挡住不入库。

| 文件 | 角色 |
|---|---|
| installer/Hash-Check_1.6.8.nsi | 1.6.8 现役安装脚本：双 DLL（x64+Win32）落盘注册、rename-dance 挪移被占文件、零弹窗零询问收尾 |
| installer/Hash-Check_x.x.x.nsi | 版本无关模板（发新版：复制 → 替换版本号 → makensis） |
| installer/Hash-Check_1.4.0_pure.nsi | 1.4.0 重建期·纯净版安装脚本（历史形态备查） |
| installer/Hash-Check_1.4.0_emb.nsi | 1.4.0 重建期·独立签名版安装脚本（签名内嵌形态，历史备查） |
| installer/Hash-Check_1.4.0_ext.nsi | 1.4.0 重建期·信封签名版安装脚本（.sig 外置形态，历史备查） |

### libs/

哈希算法库与基础容器：全部算法实现与调度，上游血统原样保留。

| 文件 | 角色 |
|---|---|
| libs/WinHash.cpp | 哈希计算调度层（按用户选择调用各算法） |
| libs/WinHash.h | 调度层头文件 |
| libs/SimpleList.c | 列表容器（校验条目竞技场式紧凑存储） |
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

独立签名工具（历史 CLI）：1.6.x 无签名线不参与构建，保留备查。

| 文件 | 角色 |
|---|---|
| signer/hashsign.c | 独立签名工具源码（命令行用法见文件头注释） |

## 使用方法

- **安装**：运行安装包，全程零弹窗零询问，装完只剩「完成」按钮；被占用的旧版 DLL 由 rename-dance 落盘、下次系统重启自然生效
- **生成**：资源管理器选中文件/文件夹 → 右键 →「哈希」→ 保存校验文件 → 得到明文 `.sha256`：哈希行 + 逐条 chk 行 + 时间戳（VS Code 可直读可手改）
- **验证**：右键校验文件 →「校验」（或双击打开）→ 验证窗逐条对账：相符绿 / 不符红 / 缺失黄 / 新增蓝 / 损坏紫底 / 未验 / 已变化；chk 损坏条目精确定位到行
- **维护**：验证窗右上「维护」菜单——添加文件（多选）/ 添加文件夹（递归）/ 移除选中 / 检测变化（mtime+大小轻检）/ 保存维护（只重算已变化+未验+不符三态，相符不重算，原位改写）
- **复制**：Ctrl+C 或右键复制选中行（文件名+哈希）；点列头排序
- **选项**：右键 →「哈希」→ 选项——算法选择等设置
- **兼容**：可打开 1.4.9+ 带 chk 的旧明文校验文件；旧加密容器格式已随无加密线退役

## 打包命令

```
:: 1. 编译双平台（VS2022 BuildTools；v143 覆盖 v140）
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe" HashCheck.vcxproj -t:Rebuild -p:Configuration=Release -p:Platform=x64 -p:PlatformToolset=v143 -m
:: Platform=Win32 再来一次

:: 2. 生成安装器（NSIS）
cd installer && D:\NSIS\makensis Hash-Check_1.6.8.nsi
```

发新版：复制 `installer/Hash-Check_x.x.x.nsi` 为 `Hash-Check_<版本>.nsi` → 替换版本号 → makensis 编译。

构建产物：`Bin\x64\Release\HashCheck.dll`、`Bin\Win32\Release\HashCheck.dll`、安装器 `installer\Hash-Check_<版本>.exe`。
