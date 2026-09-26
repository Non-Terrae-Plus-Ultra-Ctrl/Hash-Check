/**
 * HashCheckPRO 校验文件「非明文」加密模块（容器 v2，CNG AES-256-GCM）
 *
 * 见 Hcenc.h 的格式说明。密钥为两段常量 XOR（沿用既有常量）。
 */

/* Standalone-friendly: this unit is also linked into the HashSign release
   tool and the pipeline test harness, so it must not depend on the DLL's
   globals.h umbrella (see signer/hashsign.c). */
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include "Hcenc.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

/* ---------- 容器常量 ---------- */
static const BYTE HCE_MAGIC[5] = { 0x89, 'H', 'C', 'K', '2' };
#define HCE_NONCE_LEN 12
#define HCE_TAG_LEN   16
#define HCE_HEADER_LEN (5 + 1 + HCE_NONCE_LEN)   /* 魔数5 + keyid1 + nonce12 */

/* 内置对称密钥 = A XOR B（防从字符串/十六进制直接抠走） */
static const BYTE HCE_KEY_A[32] = {
	0x5d, 0x35, 0xde, 0xff, 0x90, 0xe8, 0x06, 0x81,
	0x93, 0x45, 0x62, 0xc6, 0x4d, 0xce, 0xce, 0x35,
	0xed, 0x37, 0x25, 0x85, 0x32, 0x85, 0xda, 0x79,
	0xea, 0x35, 0xa0, 0x68, 0xc7, 0x7b, 0x48, 0x0f
};
static const BYTE HCE_KEY_B[32] = {
	0x30, 0x49, 0x72, 0xbd, 0xe5, 0x6d, 0x82, 0x2d,
	0xbe, 0xbc, 0x2a, 0x6c, 0x4c, 0x66, 0xb0, 0xcd,
	0x7a, 0xbf, 0xf4, 0x0f, 0xf6, 0x7c, 0x61, 0x97,
	0x19, 0x62, 0x3d, 0xd6, 0xbe, 0xde, 0x85, 0xc5
};

static void HcencDeriveKey( BYTE key[32] )
{
	UINT i;
	for (i = 0; i < 32; ++i)
		key[i] = HCE_KEY_A[i] ^ HCE_KEY_B[i];
}

/* 1.5.7: 全 DLL 唯一的 SHA-256（1.4.9 起逐条 chk 用）。此前 HashCalc.c 与
   HashVerify.cpp 各持一份逐字节相同的实现——合并到被两者共同链接的本
   单元，省一份体量，更重要的是 chk 双端永远同源、不再可能各自漂移。
   注意：保存链的裁尾在副本上做（1.5.6 修复），与本函数无关。 */
BOOL WINAPI HcencSha256( const BYTE* pbIn, DWORD cbIn, BYTE out[32] )
{
	BCRYPT_ALG_HANDLE  hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	BOOL bOk = FALSE;

	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
		return(FALSE);
	if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0)
		goto done;
	if (BCryptHashData(hHash, (PUCHAR)pbIn, cbIn, 0) != 0)
		goto done;
	bOk = (BCryptFinishHash(hHash, out, 32, 0) == 0);

done:
	if (hHash) BCryptDestroyHash(hHash);
	if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
	return(bOk);
}

/* AES-256-GCM 单次加密/解密。tag 缓冲由调用方提供；解密时传入期望的
   tag 供 CNG 校验（不符返回 FALSE）。 */
static BOOL HcencAesGcm( const BYTE key[32], const BYTE nonce[HCE_NONCE_LEN],
                        const BYTE* pbIn, DWORD cbIn,
                        BYTE* pbOut, BYTE tag[HCE_TAG_LEN], BOOL bEncrypt )
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	ULONG cbResult = 0;
	NTSTATUS st;
	BOOL bOk = FALSE;

	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
		return(FALSE);

	if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
	                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
	                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
		goto done;

	if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
	                               (PUCHAR)key, 32, 0) != 0)
		goto done;

	BCRYPT_INIT_AUTH_MODE_INFO(info);
	info.pbNonce = (PUCHAR)nonce;
	info.cbNonce = HCE_NONCE_LEN;
	info.pbTag   = tag;
	info.cbTag   = HCE_TAG_LEN;

	if (bEncrypt)
		st = BCryptEncrypt(hKey, (PUCHAR)pbIn, cbIn, &info,
		                   NULL, 0, pbOut, cbIn, &cbResult, 0);
	else
		st = BCryptDecrypt(hKey, (PUCHAR)pbIn, cbIn, &info,
		                   NULL, 0, pbOut, cbIn, &cbResult, 0);

	bOk = (st == 0 && cbResult == cbIn);

done:
	if (hKey)  BCryptDestroyKey(hKey);
	if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
	return(bOk);
}

/* ---------- 公共 API ---------- */

BOOL WINAPI HcencIsContainer( const BYTE* pbData, DWORD cbData )
{
	if (!pbData || cbData < HCE_HEADER_LEN + HCE_TAG_LEN)
		return(FALSE);
	return(memcmp(pbData, HCE_MAGIC, 5) == 0);
}

BYTE WINAPI HcencGetKeyid( const BYTE* pbData, DWORD cbData )
{
	if (!HcencIsContainer(pbData, cbData))
		return(0xFF);
	return(pbData[5]);
}

BOOL WINAPI HcencEncrypt( BYTE keyid, const BYTE* pbPlain, DWORD cbPlain,
                          PBYTE* ppOut, DWORD* pcbOut )
{
	BYTE key[32];
	BYTE nonce[HCE_NONCE_LEN];
	BYTE tag[HCE_TAG_LEN];
	BYTE* pbOut;
	DWORD cbOut;

	if (!ppOut || !pcbOut || !pbPlain)
		return(FALSE);

	cbOut = HCE_HEADER_LEN + cbPlain + HCE_TAG_LEN;

	if (BCryptGenRandom(NULL, nonce, sizeof(nonce),
	                    BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		return(FALSE);

	/* 尾部多留 4 字节全零给解密侧的 BufferToWStr 约定 */
	pbOut = (BYTE*)malloc(cbOut + 4);
	if (!pbOut)
		return(FALSE);
	ZeroMemory(pbOut, cbOut + 4);

	HcencDeriveKey(key);
	if (!HcencAesGcm(key, nonce, pbPlain, cbPlain,
	                 pbOut + HCE_HEADER_LEN, tag, TRUE))
	{
		free(pbOut);
		return(FALSE);
	}

	memcpy(pbOut, HCE_MAGIC, 5);
	pbOut[5] = keyid;
	memcpy(pbOut + 6, nonce, sizeof(nonce));
	memcpy(pbOut + HCE_HEADER_LEN + cbPlain, tag, sizeof(tag));

	*ppOut = pbOut;
	*pcbOut = cbOut;
	return(TRUE);
}

BOOL WINAPI HcencDecrypt( const BYTE* pbIn, DWORD cbIn,
                          PBYTE* ppOut, DWORD* pcbOut, BYTE* pKeyid )
{
	BYTE key[32];
	BYTE nonce[HCE_NONCE_LEN];
	BYTE tag[HCE_TAG_LEN];
	BYTE* pbOut;
	DWORD cbPlain;

	if (!ppOut || !pcbOut || !HcencIsContainer(pbIn, cbIn))
		return(FALSE);

	cbPlain = cbIn - HCE_HEADER_LEN - HCE_TAG_LEN;

	pbOut = (BYTE*)malloc(cbPlain + 4);
	if (!pbOut)
		return(FALSE);
	ZeroMemory(pbOut, cbPlain + 4);

	memcpy(nonce, pbIn + 6, sizeof(nonce));
	memcpy(tag, pbIn + HCE_HEADER_LEN + cbPlain, sizeof(tag));

	HcencDeriveKey(key);
	if (!HcencAesGcm(key, nonce, pbIn + HCE_HEADER_LEN, cbPlain,
	                 pbOut, tag, FALSE))
	{
		free(pbOut);
		return(FALSE);
	}

	if (pKeyid)
		*pKeyid = pbIn[5];

	*ppOut = pbOut;
	*pcbOut = cbPlain;
	return(TRUE);
}

/* ---------- 双容器冗余 ----------
   [容器A][容器B]：两份独立随机 nonce 的完整加密，B 起点 = 文件中点。 */

BOOL WINAPI HcencIsDouble( const BYTE* pbData, DWORD cbData )
{
	DWORD cbHalf;

	if (!pbData || (cbData & 1) != 0)
		return(FALSE);

	cbHalf = cbData / 2;
	if (cbHalf < HCE_HEADER_LEN + HCE_TAG_LEN)
		return(FALSE);

	/* Both halves must start with the container magic; A is required, and
	   the midpoint magic is what makes this a PAIR rather than a single
	   container that happens to be even-sized. */
	return(memcmp(pbData, HCE_MAGIC, 5) == 0 &&
	       memcmp(pbData + cbHalf, HCE_MAGIC, 5) == 0);
}

BOOL WINAPI HcencIsHalfContainer( const BYTE* pbData, DWORD cbData )
{
	DWORD cbHalf;

	if (!pbData || (cbData & 1) != 0)
		return(FALSE);

	cbHalf = cbData / 2;
	if (cbHalf < HCE_HEADER_LEN + HCE_TAG_LEN)
		return(FALSE);

	return(memcmp(pbData + cbHalf, HCE_MAGIC, 5) == 0);
}

DWORD WINAPI HcencFindPairSplit( const BYTE* pbData, DWORD cbData )
{
	const BYTE* pb;
	const BYTE* pbEnd;
	const BYTE* pbHit;

	if (!pbData || cbData < 35)
		return(0);

	/* 1.4.10: 从偏移 1 起扫描，只跳过 A 自己在 0 处的魔数。删除头部一段
	   后完好的 B 可能落在 1..33——旧版从 34 起扫会漏看，令门禁把本可
	   修复的文件误报成「不支持的校验文件版本」（识别层盲区）。命中处
	   其后仍容得下一个最小容器（34B）才算数，两半由 GCM 各自裁决。 */
	pb    = pbData + 1;
	pbEnd = pbData + cbData - (HCE_HEADER_LEN + HCE_TAG_LEN);

	while (pb <= pbEnd)
	{
		pbHit = (const BYTE*)memchr(pb, HCE_MAGIC[0],
		                            (size_t)(pbEnd - pb) + 1);

		if (!pbHit)
			return(0);

		if (memcmp(pbHit, HCE_MAGIC, 5) == 0)
			return((DWORD)(pbHit - pbData));

		pb = pbHit + 1;
	}

	return(0);
}

/* 1.4.10: 前缀幸存者盲扫（数据层冗余）。B 的魔数被删除/摧毁但 A 完好
   时，A 的边界无法从结构推导——删除字节数未知，中点与全扫描都没有
   锚点（1.4.5 的「A 独立容器」兜底只对长度未漂移的文件成立）。对每个
   候选终点做一次 GCM 裁决：标签是密码学判决，乱试不可能碰对，唯一
   通过者即幸存 A。为控制 O(cb^2) 成本仅对小文件开启；大文件维持
   「损坏」裁决。算法会话只建一次（alg/key），循环内纯解密。 */
#define HCE_SCAN_MAX (64 * 1024)

BOOL WINAPI HcencScanPrefixContainer( const BYTE* pbData, DWORD cbData,
                                      PBYTE* ppOut, DWORD* pcbOut, BYTE* pKeyid )
{
	BCRYPT_ALG_HANDLE  hAlg = NULL;
	BCRYPT_KEY_HANDLE  hKey = NULL;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	BYTE key[32];
	BYTE nonce[HCE_NONCE_LEN];
	BYTE* pbScratch = NULL;
	BYTE* pbOut = NULL;
	BYTE byKeyid;
	ULONG cbResult = 0;
	NTSTATUS st;
	DWORD e, cbHalf, cbFound = 0;
	UINT uPass;
	BOOL bFound = FALSE;

	if (!ppOut || !pcbOut || !pbData)
		return(FALSE);
	if (cbData < HCE_HEADER_LEN + HCE_TAG_LEN + 1 || cbData > HCE_SCAN_MAX)
		return(FALSE);
	if (memcmp(pbData, HCE_MAGIC, 5) != 0)
		return(FALSE);   /* 扫的是「A 完好在文件头」的形态 */

	HcencDeriveKey(key);

	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
		return(FALSE);
	if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
	                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
	                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
		goto done;
	if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
	                               (PUCHAR)key, 32, 0) != 0)
		goto done;

	pbScratch = (BYTE*)malloc(cbData);
	if (!pbScratch)
		goto done;

	memcpy(nonce, pbData + 6, sizeof(nonce));
	byKeyid = pbData[5];
	cbHalf  = cbData / 2;

	/* 先扫大概率区（B 头处小缺口：A 终点略过中点），再回扫前半
	   （B 残骸比 A 还长的形态）。两段并起来 = 除整份外的全部候选。 */
	for (uPass = 0; uPass < 2 && !bFound; ++uPass)
	{
		DWORD e0 = uPass ? (HCE_HEADER_LEN + HCE_TAG_LEN) : (cbHalf + 1);
		DWORD e1 = uPass ? cbHalf : cbData;

		for (e = e0; e < e1 && !bFound; ++e)
		{
			DWORD cbCt = e - HCE_HEADER_LEN - HCE_TAG_LEN;

			BCRYPT_INIT_AUTH_MODE_INFO(info);
			info.pbNonce = nonce;
			info.cbNonce = HCE_NONCE_LEN;
			info.pbTag   = (PUCHAR)(pbData + e - HCE_TAG_LEN);
			info.cbTag   = HCE_TAG_LEN;

			st = BCryptDecrypt(hKey, (PUCHAR)pbData + HCE_HEADER_LEN,
			                   cbCt, &info, NULL, 0, pbScratch, cbCt,
			                   &cbResult, 0);
			if (st == 0 && cbResult == cbCt)
			{
				bFound = TRUE;
				cbFound = cbCt;
			}
		}
	}

	if (bFound)
	{
		pbOut = (BYTE*)malloc(cbFound + 4);
		if (pbOut)
		{
			ZeroMemory(pbOut, cbFound + 4);
			memcpy(pbOut, pbScratch, cbFound);
		}
	}

done:
	if (pbScratch) free(pbScratch);
	if (hKey)  BCryptDestroyKey(hKey);
	if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);

	if (!bFound || !pbOut)
		return(FALSE);

	*ppOut = pbOut;
	*pcbOut = cbFound;
	if (pKeyid)
		*pKeyid = byKeyid;
	return(TRUE);
}

BOOL WINAPI HcencDecryptHalf( const BYTE* pbIn, DWORD cbIn, BOOL bSecond,
                              PBYTE* ppOut, DWORD* pcbOut, BYTE* pKeyid )
{
	DWORD cbHalf;

	/* 1.4.5: 严格双容器，或 A 头被毁但 B 半魔数完好——都按半份解密，
	   GCM 标签裁决每半好坏（坏半的魔数缺失会在 HcencDecrypt 内被拒）。 */
	if (!HcencIsDouble(pbIn, cbIn) && !HcencIsHalfContainer(pbIn, cbIn))
		return(FALSE);

	cbHalf = cbIn / 2;
	return(HcencDecrypt(pbIn + (bSecond ? cbHalf : 0), cbHalf,
	                    ppOut, pcbOut, pKeyid));
}

BOOL WINAPI HcencEncryptPair( BYTE keyid,
                              const BYTE* pbPlain, DWORD cbPlain,
                              PBYTE* ppOut, DWORD* pcbOut )
{
	BYTE* pbA = NULL;
	BYTE* pbB = NULL;
	DWORD cbA = 0, cbB = 0;
	BYTE* pbOut;
	DWORD cbOut;

	if (!ppOut || !pcbOut || !pbPlain)
		return(FALSE);

	/* Two independent seals with fresh random nonces; the two ciphertexts
	   are unrelated (GCM keystream differs per nonce), so the sealed file
	   shows no ordering or repetition pattern. */
	if (!HcencEncrypt(keyid, pbPlain, cbPlain, &pbA, &cbA))
		return(FALSE);
	if (!HcencEncrypt(keyid, pbPlain, cbPlain, &pbB, &cbB))
	{
		free(pbA);
		return(FALSE);
	}

	/* cbA == cbB by construction (same plaintext -> same container size) */
	cbOut = cbA + cbB;

	pbOut = (BYTE*)malloc(cbOut + 4);
	if (!pbOut)
	{
		free(pbA);
		free(pbB);
		return(FALSE);
	}
	ZeroMemory(pbOut, cbOut + 4);

	memcpy(pbOut, pbA, cbA);
	memcpy(pbOut + cbA, pbB, cbB);
	free(pbA);
	free(pbB);

	*ppOut = pbOut;
	*pcbOut = cbOut;
	return(TRUE);
}