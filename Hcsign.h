/**
 * HashCheckPRO 校验文件防篡改签名模块（1.4.3：双信任域 + keyid）
 *
 * 免口令 + 防篡改 + 可分享：
 *   私钥   由 Windows 软件 KSP(MS_KEY_STORAGE_PROVIDER) 生成并存管，
 *           操作系统 DPAPI 包裹 + LSA 隔离进程持有，本程序进程从未接触私钥比特。
 *   签名   生成校验文件时用本机私钥对规范化正文做 ECDSA P-256 签名，免口令。
 *   验签   打开校验文件时按 keyid 路由（本机 KSP 公钥 / DLL 内置作者公钥表），
 *           文件不携带公钥——攻击者自备密钥对重签必然验不过。
 *   不可伪造 没有对应域的私钥无法为篡改后的内容重签 -> 必报
 *           「校验文件损坏或被修改」/「外来签名者」。
 *
 * 明文层结构（签名后整体封入 Hcenc v2 容器，见 Hcenc.h）：
 *   <fileA> <sha256>
 *   ...
 *   ; cn261213020202                         <- 时间戳
 *   ; sig=<keyid:hex>:<base64url(R||S 签名)>  <- 文件尾，keyid 与容器头双写互校验，
 *                                              载荷 = sig 行前全部规范化文本
 *
 * ECDSA P-256 签名 = 64 字节（r||s 各 32）；公钥 = 8 字节头 + 64 字节 (X|Y)。
 * 编译依赖：ncrypt.lib（CNG），libs/sha2.c 提供 SHA-256。
 */

#ifndef __HCSIGN_H__
#define __HCSIGN_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

/* ---------------------------------------------------------------------------
 * 1.4.3 双信任域 + 作者公钥表（keyid 体系）：
 *   keyid=0x00  本机 KSP 域 —— 右键生成的文件，验证端动态取「本机」KSP
 *               公钥验签（复用现有流程）。在别的机器打开这类文件时，本机
 *               公钥与文件签名不匹配 -> 报「外来签名者」。
 *   keyid=0x01+ 作者域 —— 发布级文件，验证端只认下表（编译期写死）。
 *               作者私钥以 BLOB 文件离线冷存（U 盘/发布机），由 HashSign
 *               工具签名；私钥永不进源码库、永不进安装包。
 *   轮换：私钥疑泄露 -> 生成新对 -> 新表追加新 keyid、删除旧 keyid ->
 *   旧文件在新 DLL 上报「签名密钥已撤销」。
 * ------------------------------------------------------------------------- */
typedef struct {
	BYTE   keyid;
	PTSTR  pubB64;
} HCK_AUTHOR_KEY;

/* 当前生效的作者公钥（0x01）。密钥对由 hckeygen 一次性生成。 */
#define HCK_AUTHOR_KEY_01_B64 \
	TEXT("RUNTMSAAAABXA4UdZRgJ7_BX5OTVQbxYhAqtwZl7Yb_vhhFIuC0oCSvQKkiCviw1ufbmGgkdFQ5t04SfoNdQnIj6N4aVMx6q")

/* 公钥表（按 keyid 升序）。撤销 = 从表中删除对应条目并重编 DLL。 */
static const HCK_AUTHOR_KEY HCK_AUTHOR_KEYS[] = {
	{ 0x01, HCK_AUTHOR_KEY_01_B64 },
};
#define HCK_AUTHOR_KEY_COUNT \
	(sizeof(HCK_AUTHOR_KEYS) / sizeof(HCK_AUTHOR_KEYS[0]))

/* 确保本机签名密钥存在。软件 KSP 中命名密钥 HashCheckPRO_Signer，
   不可导出（NCRYPT_EXPORT_POLICY_PROPERTY = 0）。重复调用幂等。 */
BOOL WINAPI HcsignEnsureKey(void);

/* 用本机签名私钥对 pbData(长度 cbData) 的数字摘要(SHA-256)签名。
   ppSigOut 指向 malloc 分配的输出（base64url，无等号填充），调用方 LocalFree；
   失败返回 FALSE。 */
BOOL WINAPI HcsignSign(const BYTE* pbData, DWORD cbData,
                       PTSTR* ppszSigOut);

/* 用指定公钥(pbPub 为 BCRYPT_ECCPUBLIC_BLOB)验证签名。
   pszSigEnc 为 base64url 编码的 64 字节 (r||s)，不区分大小写。
   返回 TRUE=验签通过（内容未篡改且有匹配私钥）。失败返回 FALSE。 */
BOOL WINAPI HcsignVerify(const BYTE* pbData, DWORD cbData,
                         const BYTE* pbPub, DWORD cbPub,
                         PCTSTR pszSigEnc);

/* 导出本机公钥为 base64url（用于 "; pub=" 行）。ppPubEncOut 为 malloc，
   调用方 LocalFree。失败返回 FALSE。 */
BOOL WINAPI HcsignGetPublicKeyB64(PTSTR* ppszPubEncOut);

/* 由 base64url 公钥解码出 BCRYPT_ECCPUBLIC_BLOB。pbPubOut 为 malloc(+4 零尾)，
   调用方 free。失败返回 FALSE。 */
BOOL WINAPI HcsignImportPublicKey(PCTSTR pszPubEnc,
                                  PBYTE* ppbPubOut, DWORD* pcbPubOut);

/* 由公钥 blob 计算指纹：SHA-256(公钥 blob) 的 64 位小写 hex 字符串。
   szOut 需 >= 65 字符。失败返回 FALSE。 */
BOOL WINAPI HcsignFingerprintFromBlob(const BYTE* pbPub, DWORD cbPub,
                                      PTSTR szOut, UINT cchOut);

/* 基64 URL 编码：pbIn -> pszOut(malloc)。无"="填充。调用方 LocalFree。 */
BOOL WINAPI HcsignBase64UrlEncode(const BYTE* pbIn, DWORD cbIn,
                                  PTSTR* ppszOut);

/* 基64 URL 解码：pszIn -> ppbOut(malloc,+4 零尾)+pcbOut。调用方 free。
   允许非 4 的倍数长度（编码无"="填充，残组按位数解码）。失败返回 FALSE。 */
BOOL WINAPI HcsignBase64UrlDecode(PCTSTR pszIn,
                                  PBYTE* ppbOut, DWORD* pcbOut);

#ifdef __cplusplus
}
#endif
#endif /* __HCSIGN_H__ */