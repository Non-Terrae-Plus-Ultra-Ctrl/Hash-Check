/**
 * HashSign —— Hash-Check 1.4.3 作者域发布签名工具
 *
 * 用法（发布机上运行；私钥文件冷存于 U 盘/发布机，绝不进源码库/安装包）：
 *   hashsign <author_priv.key> <keyid 两位十六进制> <校验文件>
 *   例：  hashsign author_priv.key 01 校验-001.sha256
 *
 * 流程（与 DLL 保存链 HashCalcAppendSignature + HashCalcEncryptFile 完全同构）：
 *   1. 读入明文校验文件（BOM/UTF-8/ANSI/UTF-16 自动识别——链接 DLL 的真实现
 *      BufferToWStr，绝不复刻）
 *   2. 导入私钥 -> 导出对应公钥（pub 行与签名密钥必然自洽）
 *   3. 规范化副本（HCNormalizeString——同样是真实现）+ "; pub=<b64>"（规范化形态
 *      \n 行尾拼入载荷）后 SHA-256 + ECDSA P-256 签名（r||s 64 字节）
 *   4. 明文层追加 "; pub=<b64>\r\n" + "; sig=<keyid>:<base64url 签名>\r\n"
 *      （签名载荷 = sig 行前全部，含 pub 行——与 DLL 验证端一致）
 *   5. HcencEncryptPair 封入 HCK2 双容器（同 DLL），keyid 写入容器头
 *   6. 原地覆写目标文件（先写 .tmp 再 MoveFileEx，失败不伤原文件）
 *
 * 输出明文层固定为 UTF-8+BOM（发布格式确定，验证端解码无歧义）。
 *
 * 拒绝：keyid=0x00（本机 KSP 域，发布文件必须用作者域）、keyid 不在 DLL 内置
 * 公钥表（否则验证端只按陌生签名者 TOFU 处理）、目标已是 HCK2 容器、
 * 明文已含 "; sig=" 或 "; pub=" 行。
 *
 * 编译（ASCII 路径，裸 cl 不吃中文路径）：
 *   cl /nologo /utf-8 /O2 /DUNICODE /D_UNICODE /W3 /Fe:hashsign.exe ^
 *      hashsign.c Hcenc.c Hcsign.c UnicodeHelpers.c bcrypt.lib ncrypt.lib
 *   （需同目录有 Hcenc.h Hcsign.h UnicodeHelpers.h libs/BitwiseIntrinsics.h）
 **/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Hcsign.h"
#include "Hcenc.h"
#include "UnicodeHelpers.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

/* ---- 与 Hcsign.c 的 HcsignSha256 相同的 BCrypt SHA-256（签名摘要） ---- */
static BOOL HsSha256(const BYTE* pbIn, DWORD cbIn, BYTE out[32])
{
    BCRYPT_ALG_HANDLE  hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    BOOL bOk = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return FALSE;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0)
        goto done;
    if (BCryptHashData(hHash, (PUCHAR)pbIn, cbIn, 0) != 0)
        goto done;
    bOk = (BCryptFinishHash(hHash, out, 32, 0) == 0);

done:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return bOk;
}

/* ---- 用私钥文件（BCRYPT_ECCPRIVATE_BLOB）做 ECDSA P-256 签名 ----
 * 输出 64 字节 r||s —— 与 HcsignSign 走 NCryptSignHash 产出的 CNG 格式一致
 * （管线测试里有工具签 -> HcsignVerify 的双向验证）。 */
static BOOL HsSignWithBlob(const BYTE* pbKey, DWORD cbKey,
                           const BYTE* pbData, DWORD cbData,
                           BYTE sig[64])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE hash[32];
    DWORD cbSig = 0;
    BOOL bOk = FALSE;

    if (!HsSha256(pbData, cbData, hash))
        return FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) != 0)
        return FALSE;
    if (BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB,
                             &hKey, (PUCHAR)pbKey, cbKey, 0) != 0)
        goto done;
    if (BCryptSignHash(hKey, NULL, hash, sizeof(hash),
                       sig, 64, &cbSig, 0) != 0 || cbSig != 64)
        goto done;
    bOk = TRUE;

done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bOk;
}

/* ---- 从私钥 BLOB 导出对应公钥（BCRYPT_ECCPUBLIC_BLOB，72 字节） ----
 * pub 行与签名密钥必然自洽：公钥由同一把私钥导出，不可能漂移。 */
static BOOL HsExportPubFromBlob(const BYTE* pbKey, DWORD cbKey, BYTE pubOut[72])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    ULONG cbPub = 0;
    BOOL bOk = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) != 0)
        return FALSE;
    if (BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB,
                             &hKey, (PUCHAR)pbKey, cbKey, 0) != 0)
        goto done;
    if (BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB,
                        pubOut, 72, &cbPub, 0) != 0 || cbPub != 72)
        goto done;
    bOk = TRUE;

done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bOk;
}

/* ---- 小工具（全宽字符路径，中文路径安全） ---- */
static unsigned char* read_file(const WCHAR* path, DWORD* pcb)
{
    FILE* f = _wfopen(path, L"rb");
    unsigned char* buf;
    long len;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); len = ftell(f); fseek(f, 0, SEEK_SET);
    buf = (unsigned char*)malloc(len ? len : 1);
    if (len && fread(buf, 1, len, f) != (size_t)len) { fclose(f); free(buf); return NULL; }
    fclose(f); *pcb = (DWORD)len; return buf;
}

static int write_all(const WCHAR* path, const unsigned char* b, DWORD n)
{
    FILE* f = _wfopen(path, L"wb");
    if (!f) return 0;
    if (n && fwrite(b, 1, n, f) != n) { fclose(f); return 0; }
    fclose(f);
    return 1;
}

static int parse_keyid(const char* s, BYTE* out)
{
    BYTE hi, lo;
    if (!s[0] || !s[1] || s[2]) return 0;
    hi = (BYTE)(s[0] <= '9' ? s[0]-'0' : (s[0]|0x20)-'a'+10);
    lo = (BYTE)(s[1] <= '9' ? s[1]-'0' : (s[1]|0x20)-'a'+10);
    if (hi > 15 || lo > 15) return 0;
    *out = (BYTE)(hi * 16 + lo);
    return 1;
}

/* 明文里是否已有签名/公钥行（防重复签名） */
static int has_sig_line(const WCHAR* p)
{
    return wcsstr(p, L"; sig=") != NULL || wcsstr(p, L"; pub=") != NULL;
}

static WCHAR g_wszKeyPath[1024];
static WCHAR g_wszTarget[1024];
static WCHAR g_wszTmp[1024+10];

int main(int argc, char** argv)
{
    BYTE  keyid;
    DWORD cbKey = 0, cbPlain = 0;
    BYTE *pbKey, *pbData;
    PWSTR pszW, pszOriginal;
    UINT  i;
    BOOL  bInTable = FALSE;
    BYTE  sig[64];
    BYTE  pubBlob[72];
    PTSTR pszSigB64 = NULL;
    PTSTR pszPubB64 = NULL;
    PWSTR pszPayload = NULL;
    char *pOut;
    int   cchUtf8, cbUtf8, cbSigLine;
    DWORD cbFinal, cbOut, cbSealed = 0;
    PBYTE pbFinal = NULL, pbSealed = NULL;

    if (argc != 4) {
        printf("用法：hashsign <author_priv.key> <keyid两位十六进制> <校验文件>\n"
               "例：  hashsign author_priv.key 01 校验-001.sha256\n");
        return 1;
    }
    if (!parse_keyid(argv[2], &keyid)) {
        printf("[失败] keyid 必须是两位十六进制（如 01）\n");
        return 1;
    }
    if (keyid == HCK_KEYID_LOCAL) {
        printf("[失败] 0x00 是本机 KSP 域（右键生成专用），发布文件请用 0x01+ 作者域\n");
        return 1;
    }
    for (i = 0; i < HCK_AUTHOR_KEY_COUNT; ++i)
        if (HCK_AUTHOR_KEYS[i].keyid == keyid) { bInTable = TRUE; break; }
    if (!bInTable) {
        printf("[失败] keyid=%02X 不在 DLL 内置公钥表——验证端会报「签名密钥已撤销」。\n"
               "       先把该 keyid 的公钥加入 Hcsign.h 表并重编 DLL，再发布。\n", keyid);
        return 1;
    }

    /* 控制台参数按 ACP 转宽字符（中文路径安全） */
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, g_wszKeyPath, 1024);
    MultiByteToWideChar(CP_ACP, 0, argv[3], -1, g_wszTarget, 1024);
    swprintf(g_wszTmp, 1024+10, L"%ls.hc.tmp", g_wszTarget);

    /* 1. 私钥文件 */
    pbKey = read_file(g_wszKeyPath, &cbKey);
    if (!pbKey || cbKey < 104 || cbKey > 4096) {
        printf("[失败] 读不到私钥文件：%s（应为 104 字节 BCRYPT_ECCPRIVATE_BLOB）\n", argv[1]);
        return 1;
    }

    /* 2. 明文校验文件（尾留 4 字节零给 BufferToWStr） */
    pbData = (PBYTE)read_file(g_wszTarget, &cbPlain);
    if (!pbData) {
        printf("[失败] 读不到校验文件：%s\n", argv[3]);
        return 1;
    }
    {
        PBYTE pb2 = (PBYTE)realloc(pbData, cbPlain + sizeof(DWORD));
        if (!pb2) { free(pbData); return 1; }
        pbData = pb2;
        ZeroMemory(pbData + cbPlain, sizeof(DWORD));
    }

    if (HcencIsContainer(pbData, cbPlain)) {
        printf("[失败] 目标已是 HCK2 加密容器——先准备明文版本再签名\n");
        return 1;
    }

    /* 3. 解码（DLL 真实现）+ 保留未规范化原文用于输出 */
    pszW = BufferToWStr(&pbData, cbPlain);
    if (!pszW) {
        printf("[失败] 无法解码校验文件（编码异常）\n");
        return 1;
    }
    if (has_sig_line(pszW)) {
        printf("[失败] 明文已含 \"; sig=\" 行——请从原始未签名版本重来\n");
        return 1;
    }
    {
        size_t cch = wcslen(pszW);
        pszOriginal = (PWSTR)malloc((cch + 1) * sizeof(WCHAR));
        if (!pszOriginal) return 1;
        memcpy(pszOriginal, pszW, (cch + 1) * sizeof(WCHAR));
    }

    /* 4. 导入私钥 -> 导出对应公钥（pub 行与签名密钥必然自洽） */
    if (!HsExportPubFromBlob(pbKey, cbKey, pubBlob)) {
        printf("[失败] 私钥文件损坏（导出公钥失败？应为 hckeygen 产出的 ECCPRIVATE_BLOB）\n");
        return 1;
    }
    if (!HcsignBase64UrlEncode(pubBlob, 72, &pszPubB64)) {
        printf("[失败] base64url 编码失败\n");
        return 1;
    }

    /* 5. 载荷 = 原文 + "; pub=<b64>\r\n"（原始形态）整体规范化 -> 签名
       （与 DLL 验证端 normalize（sig 行前内容）字节一致。注意 HCNormalizeString
       逐字符替换：\r->\n 保留原 \n，\r\n 会变成 \n\n——绝不能先规范化再拼 \n） */
    {
        size_t cch = wcslen(pszW);
        size_t cchPub = wcslen(pszPubB64);

        pszPayload = (PWSTR)malloc((cch + cchPub + 16) * sizeof(WCHAR));
        if (!pszPayload) return 1;
        memcpy(pszPayload, pszW, cch * sizeof(WCHAR));
        memcpy(pszPayload + cch, L"; pub=", 6 * sizeof(WCHAR));
        memcpy(pszPayload + cch + 6, pszPubB64, cchPub * sizeof(WCHAR));
        pszPayload[cch + 6 + cchPub] = L'\r';
        pszPayload[cch + 7 + cchPub] = L'\n';
        pszPayload[cch + 8 + cchPub] = 0;

        HCNormalizeString(pszPayload);   /* 整体规范化（与验证端一致） */

        if (!HsSignWithBlob(pbKey, cbKey, (const BYTE*)pszPayload,
                            (DWORD)((cch + 8 + cchPub) * sizeof(WCHAR)), sig)) {
            printf("[失败] 签名失败（私钥文件损坏？应为 hckeygen 产出的 ECCPRIVATE_BLOB）\n");
            return 1;
        }
    }
    if (!HcsignBase64UrlEncode(sig, sizeof(sig), &pszSigB64)) {
        printf("[失败] base64url 编码失败\n");
        return 1;
    }

    /* 6. 组装明文层：UTF-8 BOM + 原文 + "; pub=<b64>\r\n" + "; sig=XX:<b64>\r\n" */
    cchUtf8 = WideCharToMultiByte(CP_UTF8, 0, pszOriginal, -1, NULL, 0, NULL, NULL);
    if (cchUtf8 <= 0) return 1;
    cbUtf8 = cchUtf8 - 1;                 /* 去掉结尾 NUL */
    cbSigLine = 6 + 3 + (int)wcslen(pszSigB64) + 2;  /* "; sig=" + "XX:" + b64 + CRLF */
    cbFinal = 3 + (DWORD)cbUtf8
            + (6 + (DWORD)wcslen(pszPubB64) + 2)     /* "; pub=" + b64 + CRLF */
            + (DWORD)cbSigLine;
    pbFinal = (BYTE*)malloc(cbFinal + 4);
    if (!pbFinal) return 1;
    ZeroMemory(pbFinal, cbFinal + 4);
    pOut = (char*)pbFinal;
    pOut[0] = (char)0xEF; pOut[1] = (char)0xBB; pOut[2] = (char)0xBF;
    pOut += 3;
    WideCharToMultiByte(CP_UTF8, 0, pszOriginal, -1, pOut, cchUtf8, NULL, NULL);
    pOut += cbUtf8;
    sprintf(pOut, "; pub=%ls\r\n", pszPubB64);
    pOut += strlen(pOut);
    sprintf(pOut, "; sig=%02X:%ls\r\n", (UINT)keyid, pszSigB64);
    cbOut = 3 + (DWORD)strlen((char*)(pbFinal + 3));   /* BOM 后全部（正文+pub+sig 行），勿重复计 cbUtf8 */

    /* 6. 封双容器（keyid 入头） */
    if (!HcencEncryptPair(keyid, pbFinal, cbOut, &pbSealed, &cbSealed)) {
        printf("[失败] 封装加密容器失败\n");
        return 1;
    }

    /* 7. 原子覆写：.tmp -> MoveFileEx */
    if (!write_all(g_wszTmp, pbSealed, cbSealed)) {
        printf("[失败] 写临时文件失败\n");
        return 1;
    }
    if (!MoveFileExW(g_wszTmp, g_wszTarget, MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileW(g_wszTmp);
        printf("[失败] 覆写目标失败（文件被占用？）：%s\n", argv[3]);
        return 1;
    }

    printf("[OK] 已签名并封装：%s\n", argv[3]);
    printf("     keyid=%02X  明文层 %lu 字节 -> 密封容器 %lu 字节\n",
           (UINT)keyid, (unsigned long)cbOut, (unsigned long)cbSealed);
    printf("     sig=%ls\n", pszSigB64);
    return 0;
}
