/**
 * HashCheckPRO 校验文件「非明文」加密模块（容器格式 v2，1.4.3）
 *
 * 校验文件在签名完成之后整体用 AES-256-GCM 封进二进制容器；打开时先验
 * 魔数、解密，再走签名验证链（见 1.4.3 设计：keyid 双信任域）。
 *
 * 容器格式 v2（18 字节头 + 密文 + 认证标签）：
 *   [0]   5B  魔数 0x89 'H' 'C' 'K' '2'（与 v1 物理区分；首字节非文本）
 *   [5]   1B  keyid（信任域编号：0x00=本机 KSP 域，0x01+=作者域；
 *             与明文层 "; sig=<keyid>:<b64>" 双写互校验，防头被改冒充）
 *   [6]   12B 随机 nonce
 *   [18]  ..  AES-256-GCM 密文（长度 = 明文字节数）
 *   末尾  16B GCM 认证标签（篡改任意一字节解密即失败）
 *
 * 双容器冗余（1.4.2 引入，v2 沿用）：文件 = [容器A][容器B]，两份同明文、
 * 独立随机 nonce 的完整容器，B 起点 = 文件中点（无需额外格式字段）。
 * GCM 流加密保证两份密文互不相关（乱码无顺序、无重复模式）。
 *
 * 旧格式（v1 HCK、明文校验文件）在 1.4.3 一律拒收——零降级路径。
 *
 * 密钥：两段常量 XOR 的 32 字节，编译进 DLL。免口令、免联网、可分享；
 * 定位明确为「非明文外观门槛」：逆向提钥只拿到读明文的能力，篡改会被
 * 签名层拦死，加密层不承担安全职能。
 */

#ifndef __HCENC_H__
#define __HCENC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

/* 容器头里的 keyid（信任域编号） */
#define HCK_KEYID_LOCAL   0x00   /* 本机 KSP 域：右键生成，验证用本机公钥 */
#define HCK_KEYID_AUTHOR1 0x01   /* 作者域：发布级文件，DLL 内置公钥表 */

/* 返回 TRUE = 这是一份本模块 v2 格式的加密容器 */
BOOL WINAPI HcencIsContainer( const BYTE* pbData, DWORD cbData );

/* 1.5.7: 全 DLL 唯一的 SHA-256（逐条 chk 用；HashCalc 保存端与
   HashVerify 验证端同源，防实现漂移）。 */
BOOL WINAPI HcencSha256( const BYTE* pbIn, DWORD cbIn, BYTE out[32] );

/* 读容器头里的 keyid（调用方已确认是容器） */
BYTE WINAPI HcencGetKeyid( const BYTE* pbData, DWORD cbData );

/* 加密：明文字节流 -> v2 容器（keyid 写入头部）。输出缓冲以 malloc 分配，
   末尾多留 4 字节全零（满足 BufferToWStr 的 NULL 终止约定）。*/
BOOL WINAPI HcencEncrypt( BYTE keyid, const BYTE* pbPlain, DWORD cbPlain,
                          PBYTE* ppOut, DWORD* pcbOut );

/* 解密：容器 -> 明文字节流（malloc，尾留 4 字节零）+ 回填 keyid。
   GCM 认证失败（篡改/损坏）返回 FALSE。*/
BOOL WINAPI HcencDecrypt( const BYTE* pbIn, DWORD cbIn,
                          PBYTE* ppOut, DWORD* pcbOut, BYTE* pKeyid );

/* ---------- 双容器冗余 ---------- */

/* 双容器加密：同一明文封两份（独立 nonce、同一 keyid）拼接。 */
BOOL WINAPI HcencEncryptPair( BYTE keyid,
                              const BYTE* pbPlain, DWORD cbPlain,
                              PBYTE* ppOut, DWORD* pcbOut );

/* 判断：中点处也是容器魔数 -> 双容器文件。 */
BOOL WINAPI HcencIsDouble( const BYTE* pbData, DWORD cbData );

/* 双容器的 B 半起点（文件中点）是否是 HCK2 魔数——A 头部被损坏的文件仍可
   据此识别为双容器，走「半幸存修复」路径而不是误报版本不支持（1.4.5）。 */
BOOL WINAPI HcencIsHalfContainer( const BYTE* pbData, DWORD cbData );

/* 全文件扫描第二份容器魔数，返回 B 半起点偏移（找不到返回 0）。
   1.4.8：单字节「增删」造成的错位配对（B 半偏离中点）也能定位——
   两半各自按 GCM 裁决，幸存的半可修复重封回标准几何。
   1.4.10：扫描起点放宽到偏移 1（跳过 A 自己在 0 处的魔数即可）——
   删除头部一段后完好的 B 可能落在 1..33，旧版从 34 起扫会漏看，
   令门禁把本可修复的文件误报成「不支持的校验文件版本」。 */
DWORD WINAPI HcencFindPairSplit( const BYTE* pbData, DWORD cbData );

/* 1.4.10: 前缀幸存者盲扫——A 头魔数完好但 B 魔数被毁、A 边界随删除
   字节数漂移无法从结构推导时，对每个候选终点做一次 GCM 裁决，唯一
   通过者即幸存 A（keyid 回填 A 头值）。O(cb^2) 有界：仅对不超过
   64KB 的文件开启，更大的文件返回 FALSE（维持「损坏」裁决）。
   输出约定与 HcencDecrypt 一致（malloc + 尾留 4 字节零）。 */
BOOL WINAPI HcencScanPrefixContainer( const BYTE* pbData, DWORD cbData,
                                      PBYTE* ppOut, DWORD* pcbOut, BYTE* pKeyid );

/* 解密指定半份（bSecond=FALSE 前半 A / TRUE 后半 B）。 */
BOOL WINAPI HcencDecryptHalf( const BYTE* pbIn, DWORD cbIn, BOOL bSecond,
                              PBYTE* ppOut, DWORD* pcbOut, BYTE* pKeyid );

#ifdef __cplusplus
}
#endif
#endif /* __HCENC_H__ */