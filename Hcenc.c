/**
 * HashCheck SHA-256 单源模块（1.4.0 纯净版瘦身，2026-10-17 优化三遍）
 *
 * 原文件名 Hcenc.c（历史=容器加密模块），1.4.1 起承担 AES-256-GCM 容器；
 * 1.4.0 纯净版剥离加密层后，本单元仅保留全 DLL 唯一的 SHA-256 实现
 * （文件名沿用避免工程文件改动）。加密容器相关代码已全部移除——
 * 纯净版不生成也不识别加密容器，DLL 内不再携带任何密钥常量。
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
