/**
 * HashCheckPRO 校验文件防篡改签名模块（1.4.3：双信任域 + keyid 路由原语）
 *
 * 本模块只提供签名/验签原语；信任域路由（keyid -> 用哪把公钥）在
 * HashVerifySignature（见 HashVerify.cpp），密钥体系见 Hcsign.h：
 *   keyid=0x00  本机 KSP 域 —— 右键生成，验证端动态取本机 KSP 公钥
 *               （HcsignGetPublicKeyB64），他机打开报「外来签名者」。
 *   keyid=0x01+ 作者域 —— 发布级文件，验证端只认 Hcsign.h 内置公钥表；
 *               作者私钥以 BLOB 文件离线冷存（hckeygen 生成，HashSign 工具签名），
 *               私钥永不进源码库、永不进安装包。
 *   签名 = ECDSA P-256（r||s 64 字节），载荷 = 规范化正文的 SHA-256。
 *
 * base64url 输出无 "=" 填充，字表用 '-' 与 '_'（RFC 4648 §5，URL 安全）。
 *
 * 依赖：ncrypt.lib + bcrypt.lib（CNG）。
 */

#include "Hcsign.h"

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

#include <bcrypt.h>
#include <ncrypt.h>

/* 命名密钥 */
#define HCSIGN_KEY_NAME    TEXT("HashCheckPRO_Signer")
#define HCSIGN_ALGO        BCRYPT_ECDSA_P256_ALGORITHM   /* == NCRYPT_ECDSA_P256_ALGORITHM */

/* ECDSA P-256 签名 = 64 字节 (r||s) */
#define HCSIGN_SIG_SIZE    64
#define HCSIGN_PUB_HEADER  8                             /* BCRYPT_ECCKEY_BLOB 头 */
#define HCSIGN_PUB_SIZE    (HCSIGN_PUB_HEADER + 64)      /* 公钥 blob 总长 */
#define HCSIGN_HASH_SIZE   32

#define HCSIGN_B64_ALPHATEXT TEXT("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

/*-------------------------------------------------------------------------*\
	内部工具
\*-------------------------------------------------------------------------*/

static BOOL HcsignOpenProvider(NCRYPT_PROV_HANDLE* phProv)
{
	return NCryptOpenStorageProvider(phProv, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS;
}

/* 打开签名私钥（不存在则创建）。返回的 closed 由调用方 NCryptFreeObject。 */
static NCRYPT_KEY_HANDLE HcsignOpenKey(NCRYPT_PROV_HANDLE hProv)
{
	NCRYPT_KEY_HANDLE hKey = 0;
	NTSTATUS st = NCryptOpenKey(hProv, &hKey, HCSIGN_KEY_NAME, 0, 0);

	if (st != ERROR_SUCCESS)
	{
		/* 首次运行：生成密钥 */
		st = NCryptCreatePersistedKey(hProv, &hKey, HCSIGN_ALGO,
		                              HCSIGN_KEY_NAME, 0, 0);
		if (st != ERROR_SUCCESS)
			return 0;

		/* 禁止导出私钥：NCRYPT_EXPORT_POLICY_PROPERTY 置 0 */
		{
			DWORD dwExportPolicy = 0;
			NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY,
			                  (PBYTE)&dwExportPolicy, sizeof(dwExportPolicy), 0);
		}

		st = NCryptFinalizeKey(hKey, 0);
		if (st != ERROR_SUCCESS)
		{
			NCryptFreeObject(hKey);
			return 0;
		}
	}

	return hKey;
}

/* 一次性 SHA-256 -> out[32]，用 BCrypt（避免额外依赖 sha2.c） */
static BOOL HcsignSha256(const BYTE* pbIn, DWORD cbIn, BYTE out[HCSIGN_HASH_SIZE])
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	BOOL bOk = FALSE;

	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
		return FALSE;
	if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0)
		goto cleanup;
	if (BCryptHashData(hHash, (PUCHAR)pbIn, cbIn, 0) != 0)
		goto cleanup;

	bOk = (BCryptFinishHash(hHash, out, HCSIGN_HASH_SIZE, 0) == 0);

cleanup:
	if (hHash) BCryptDestroyHash(hHash);
	if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
	return bOk;
}

/*-------------------------------------------------------------------------*\
	base64url（无填充）
\*-------------------------------------------------------------------------*/

BOOL WINAPI HcsignBase64UrlEncode(const BYTE* pbIn, DWORD cbIn, PTSTR* ppszOut)
{
	static const TCHAR szAlphabet[] = HCSIGN_B64_ALPHATEXT;
	DWORD cbOut = (cbIn + 2) / 3 * 4;   /* 无填充：最后残组字符数另算 */
	DWORD nFull = cbIn / 3;
	DWORD i, o = 0;

	/* 精确长度：满组 4 字符/3 字节；残 1 字节 2 字符，残 2 字节 3 字符 */
	{
		DWORD nRem = cbIn % 3;
		if (nRem == 1) cbOut = nFull * 4 + 2;
		else if (nRem == 2) cbOut = nFull * 4 + 3;
		else cbOut = nFull * 4;
	}

	*ppszOut = (PTSTR)LocalAlloc(LMEM_FIXED, (cbOut + 1) * sizeof(TCHAR));
	if (!*ppszOut)
		return FALSE;

	for (i = 0; i < nFull; ++i)
	{
		DWORD n = ((DWORD)pbIn[3*i] << 16) | ((DWORD)pbIn[3*i+1] << 8) | pbIn[3*i+2];
		(*ppszOut)[o++] = szAlphabet[(n >> 18) & 63];
		(*ppszOut)[o++] = szAlphabet[(n >> 12) & 63];
		(*ppszOut)[o++] = szAlphabet[(n >> 6) & 63];
		(*ppszOut)[o++] = szAlphabet[n & 63];
	}

	{
		DWORD nRem = cbIn - nFull * 3;
		if (nRem == 1)
		{
			DWORD n = (DWORD)pbIn[nFull*3] << 16;
			(*ppszOut)[o++] = szAlphabet[(n >> 18) & 63];
			(*ppszOut)[o++] = szAlphabet[(n >> 12) & 63];
		}
		else if (nRem == 2)
		{
			DWORD n = ((DWORD)pbIn[nFull*3] << 16) | ((DWORD)pbIn[nFull*3+1] << 8);
			(*ppszOut)[o++] = szAlphabet[(n >> 18) & 63];
			(*ppszOut)[o++] = szAlphabet[(n >> 12) & 63];
			(*ppszOut)[o++] = szAlphabet[(n >> 6) & 63];
		}
	}

	(*ppszOut)[o] = 0;
	return TRUE;
}

BOOL WINAPI HcsignBase64UrlDecode(PCTSTR pszIn, PBYTE* ppbOut, DWORD* pcbOut)
{
	/* 反向字表：-1=非法 */
	static signed char s_rgDecode[128] = { -1 };
	static BOOL s_bInit = FALSE;
	DWORD cbIn = (DWORD)lstrlen(pszIn);
	BYTE* pbOut;
	DWORD i, o = 0;
	DWORD dwBuf = 0;
	int nBits = 0;

	if (!s_bInit)
	{
		DWORD j;
		for (j = 0; j < 64; ++j)
		{
			TCHAR ch = HCSIGN_B64_ALPHATEXT[j];
			if (ch < 0x80)
				s_rgDecode[ch] = (signed char)j;
		}
		s_bInit = TRUE;
	}

	if (!pszIn || !cbIn)
		return FALSE;

	pbOut = (BYTE*)malloc(cbIn / 4 * 3 + 4);
	if (!pbOut)
		return FALSE;

	for (i = 0; i < cbIn; ++i)
	{
		TCHAR ch = pszIn[i];
		if ((DWORD)ch >= 0x80 || s_rgDecode[ch] < 0)
		{
			free(pbOut);
			return FALSE;
		}

		dwBuf = (dwBuf << 6) | (DWORD)s_rgDecode[ch];
		nBits += 6;
		if (nBits >= 8)
		{
			nBits -= 8;
			pbOut[o++] = (BYTE)((dwBuf >> nBits) & 0xFF);
		}
	}

	/* 末尾必须无残余不足 6 位的换算；残 4 位/2 位合法（对应 1/2 字节） */
	if (nBits > 4)
	{
		free(pbOut);
		return FALSE;
	}

	/* +4 零尾（供 BufferToWStr / 调用方约定） */
	memset(pbOut + o, 0, 4);

	*ppbOut = pbOut;
	*pcbOut = o;
	return TRUE;
}

/*-------------------------------------------------------------------------*\
	对外 API
\*-------------------------------------------------------------------------*/

BOOL WINAPI HcsignEnsureKey(void)
{
	NCRYPT_PROV_HANDLE hProv = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	BOOL bOk = FALSE;

	if (HcsignOpenProvider(&hProv))
	{
		hKey = HcsignOpenKey(hProv);
		bOk = (hKey != 0);
	}

	if (hKey)  NCryptFreeObject(hKey);
	if (hProv) NCryptFreeObject(hProv);
	return bOk;
}

BOOL WINAPI HcsignSign(const BYTE* pbData, DWORD cbData, PTSTR* ppszSigOut)
{
	NCRYPT_PROV_HANDLE hProv = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	BYTE hash[HCSIGN_HASH_SIZE];
	BYTE sig[HCSIGN_SIG_SIZE];
	DWORD cbSig = 0;
	BOOL bOk = FALSE;

	if (!ppszSigOut)
		return FALSE;
	*ppszSigOut = NULL;

	if (!HcsignSha256(pbData, cbData, hash))
		return FALSE;

	if (!HcsignOpenProvider(&hProv))
		return FALSE;
	hKey = HcsignOpenKey(hProv);
	if (!hKey)
		goto cleanup;

	if (NCryptSignHash(hKey, NULL, hash, HCSIGN_HASH_SIZE,
	                   sig, sizeof(sig), &cbSig, 0) == ERROR_SUCCESS &&
	    cbSig == HCSIGN_SIG_SIZE)
	{
		bOk = HcsignBase64UrlEncode(sig, cbSig, ppszSigOut);
	}

cleanup:
	if (hKey)  NCryptFreeObject(hKey);
	if (hProv) NCryptFreeObject(hProv);
	return bOk;
}

BOOL WINAPI HcsignVerify(const BYTE* pbData, DWORD cbData,
                         const BYTE* pbPub, DWORD cbPub,
                         PCTSTR pszSigEnc)
{
	NCRYPT_PROV_HANDLE hProv = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	BYTE hash[HCSIGN_HASH_SIZE];
	PBYTE pbSig = NULL;
	DWORD cbSig = 0;
	BOOL bOk = FALSE;
	NTSTATUS st;

	if (!pbPub || cbPub != HCSIGN_PUB_SIZE || !pszSigEnc)
		return FALSE;

	if (!HcsignSha256(pbData, cbData, hash))
		return FALSE;

	if (!HcsignBase64UrlDecode(pszSigEnc, &pbSig, &cbSig))
		return FALSE;
	if (cbSig != HCSIGN_SIG_SIZE)
	{
		free(pbSig);
		return FALSE;
	}

	if (!HcsignOpenProvider(&hProv))
	{
		free(pbSig);
		return FALSE;
	}

	/* 导入公钥 blob（BCRYPT_ECCPUBLIC_BLOB）为临时候钥 */
	st = NCryptImportKey(hProv, (NCRYPT_KEY_HANDLE)0, BCRYPT_ECCPUBLIC_BLOB, NULL,
	                     &hKey, (PBYTE)pbPub, cbPub, 0);
	if (st == ERROR_SUCCESS)
	{
		/* NCryptVerifySignature: 成功返回 ERROR_SUCCESS，验签失败返回
		   STATUS_INVALID_SIGNATURE，其余为错误码 */
		st = NCryptVerifySignature(hKey, NULL, hash, HCSIGN_HASH_SIZE,
		                           pbSig, cbSig, 0);
		bOk = (st == ERROR_SUCCESS);
	}

	free(pbSig);
	if (hKey)  NCryptFreeObject(hKey);
	if (hProv) NCryptFreeObject(hProv);
	return bOk;
}

BOOL WINAPI HcsignGetPublicKeyB64(PTSTR* ppszPubEncOut)
{
	NCRYPT_PROV_HANDLE hProv = 0;
	NCRYPT_KEY_HANDLE hKey = 0;
	BYTE pub[HCSIGN_PUB_SIZE];
	DWORD cbPub = 0;
	BOOL bOk = FALSE;

	if (!ppszPubEncOut)
		return FALSE;
	*ppszPubEncOut = NULL;

	if (!HcsignOpenProvider(&hProv))
		return FALSE;
	hKey = HcsignOpenKey(hProv);
	if (!hKey)
		goto cleanup;

	if (NCryptExportKey(hKey, (NCRYPT_KEY_HANDLE)0, BCRYPT_ECCPUBLIC_BLOB, NULL,
	                    pub, sizeof(pub), &cbPub, 0) == ERROR_SUCCESS &&
	    cbPub == HCSIGN_PUB_SIZE)
	{
		bOk = HcsignBase64UrlEncode(pub, cbPub, ppszPubEncOut);
	}

cleanup:
	if (hKey)  NCryptFreeObject(hKey);
	if (hProv) NCryptFreeObject(hProv);
	return bOk;
}

BOOL WINAPI HcsignImportPublicKey(PCTSTR pszPubEnc,
                                  PBYTE* ppbPubOut, DWORD* pcbPubOut)
{
	PBYTE pbPub;
	DWORD cbPub;

	if (!ppbPubOut || !pcbPubOut)
		return FALSE;
	*ppbPubOut = NULL;
	*pcbPubOut = 0;

	if (!HcsignBase64UrlDecode(pszPubEnc, &pbPub, &cbPub))
		return FALSE;

	if (cbPub != HCSIGN_PUB_SIZE)
	{
		free(pbPub);
		return FALSE;
	}

	*ppbPubOut = pbPub;
	*pcbPubOut = cbPub;
	return TRUE;
}

BOOL WINAPI HcsignFingerprintFromBlob(const BYTE* pbPub, DWORD cbPub,
                                      PTSTR szOut, UINT cchOut)
{
	static const TCHAR szHex[] = TEXT("0123456789abcdef");
	BYTE hash[HCSIGN_HASH_SIZE];
	UINT i;

	if (!szOut || cchOut < 65)
		return FALSE;

	if (!HcsignSha256(pbPub, cbPub, hash))
		return FALSE;

	for (i = 0; i < HCSIGN_HASH_SIZE; ++i)
	{
		szOut[2*i]     = szHex[hash[i] >> 4];
		szOut[2*i + 1] = szHex[hash[i] & 15];
	}
	szOut[64] = 0;
	return TRUE;
}