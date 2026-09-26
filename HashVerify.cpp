/**
 * HashCheck Shell Extension
 * Original work copyright (C) Kai Liu.  All rights reserved.
 * Modified work copyright (C) 2014, 2016 Christopher Gurnee.  All rights reserved.
 * Modified work copyright (C) 2016 Tim Schlueter.  All rights reserved.
 *
 * Please refer to readme.txt for information about this source code.
 * Please refer to license.txt for details about distribution and modification.
 **/

#include "globals.h"
#include <bcrypt.h>
#include "HashCheckCommon.h"
#include "SetAppID.h"
#include "UnicodeHelpers.h"
#include "IsSSD.h"
#include "Hcsign.h"
#include "Hcenc.h"
#include <uxtheme.h>
#include <Strsafe.h>
#include <cassert>
#include <algorithm>
#ifdef USE_PPL
#include <ppl.h>
#include <concurrent_vector.h>
#endif

#define HV_COL_FILENAME 0
#define HV_COL_SIZE     1
#define HV_COL_STATUS   2
#define HV_COL_EXPECTED 3
#define HV_COL_ACTUAL   4
#define HV_COL_FIRST    HV_COL_FILENAME
#define HV_COL_LAST     HV_COL_ACTUAL

#define HV_STATUS_NULL       0
#define HV_STATUS_MATCH      1
#define HV_STATUS_MISMATCH   2
#define HV_STATUS_UNREADABLE 3
#define HV_STATUS_NEW        4
#define HV_STATUS_DAMAGED     5   // 1.4.9: 损坏（逐条 chk 不符）

#define LISTVIEW_EXSTYLES ( LVS_EX_HEADERDRAGDROP | \
                            LVS_EX_FULLROWSELECT  | \
                            LVS_EX_LABELTIP       | \
                            LVS_EX_DOUBLEBUFFER )

// Fix up missing A/W aliases
#ifdef UNICODE
#define LPNMLVDISPINFO LPNMLVDISPINFOW
#define StrCmpLogical StrCmpLogicalW
#else
#define LPNMLVDISPINFO LPNMLVDISPINFOA
#define StrCmpLogical StrCmpIA
#endif

// Due to the stupidity of the x64 compiler, the code emitted for the non-inline
// function is not as efficient as it is on x86
#ifdef _M_IX86
#undef SSChainNCpy2
#define SSChainNCpy2 SSChainNCpy2F
#endif

typedef struct {
	UINT               cMatch;       // number of matches
	UINT               cMismatch;    // number of mismatches
	UINT               cUnreadable;  // number of unreadable files
	UINT               cNew;         // number of newly-added files
} HASHVERIFYPREV, *PHASHVERIFYPREV;

typedef struct {
	INT                iColumn;      // column to sort
	BOOL               bReverse;     // reverse sort?
} HASHVERIFYSORT, *PHASHVERIFYSORT;

typedef struct {
	FILESIZE           filesize;
	PTSTR              pszDisplayName;
	PTSTR              pszExpected;
	INT16              cchDisplayName;
	INT                nListviewIndex;
	BOOL               bBeenSeen;    // has the listview control asked for this item's info yet?
	UINT8              uState;
	UINT8              uStatusID;
	TCHAR              szActual[MAX_DIGEST_STRING_LENGTH];
} HASHVERIFYITEM, *PHASHVERIFYITEM, *PHVITEM, **PPHVITEM;

typedef CONST HASHVERIFYITEM **PPCHVITEM;

typedef struct {
	// Common block (see COMMONCONTEXT)
	WORKERTHREADSTATUS status;       // thread status
	DWORD              dwFlags;      // misc. status flags
	MSGCOUNT           cSentMsgs;    // number update messages sent by the worker
	MSGCOUNT           cHandledMsgs; // number update messages processed by the UI
	HWND               hWnd;         // handle of the dialog window
	HWND               hWndPBTotal;  // cache of the IDC_PROG_TOTAL progress bar handle
	HWND               hWndPBFile;   // cache of the IDC_PROG_FILE progress bar handle
	HANDLE             hThread;      // handle of the worker thread
	HANDLE             hUnpauseEvent;// handle of the event which signals when unpaused
	PFNWORKERMAIN      pfnWorkerMain;// worker function executed by the (non-GUI) thread
	// Members specific to HashVerify
	HWND               hWndList;     // handle of the list
	HSIMPLELIST        hList;        // where we store all the data
	HSIMPLELIST        hNewPaths;    // separately-stored strings for "newly-added" file paths
	PPHVITEM           index;        // index of the items in the list
	PPHVITEM           queue;        // items to hash this run (subset of index)
	UINT               cQueue;       // number of items in queue
	PTSTR              pszPath;      // raw path, set by initial input
	PTSTR              pszFileData;  // raw file data, set by initial input
	HASHVERIFYSORT     sort;         // sort information
	BOOL               bFreshStates; // is our copy of the item states fresh?
	UINT               cTotal;       // total number of files
	UINT               cOrigTotal;   // number of files listed in the manifest (files to hash)
	UINT               cMatch;       // number of matches
	UINT               cMismatch;    // number of mismatches
	UINT               cUnreadable;  // number of unreadable files
	UINT               cMissing;     // manifest files detected as absent from disk up front
	UINT               cNew;         // number of newly-added files
	DWORD              dwStarted;    // GetTickCount() start time
	HASHVERIFYPREV     prev;         // previous update data, used for update coalescing
	UINT               uMaxBatch;    // maximum number of updates to coalesce
    volatile DWORD     whctxFlags;   // WinHash library dwFlags (which checksums to use)
	BYTE               byKeyid;      // 1.4.3: keyid of the container half we decrypted (trust domain)
	BYTE               byKeyidA;     // 1.4.7: keyid in container A's header, raw (surgical-repair evidence)
	BYTE               byKeyidB;     // 1.4.7: keyid in container B's header, raw
	DWORD              cbHalfRaw;    // 1.4.7: half length of the loaded file (surgical repair offset)
	BOOL               bKeyidHeaderDamage; // 1.4.7: a header keyid byte contradicts the sig line -> offer surgical repair
	BOOL               bUnsupportedFormat; // 1.4.3: not an HCK2 container (legacy plaintext / 1.4.1 HCK1) -- rejected, zero downgrade
	BOOL               bForeignSigner; // 1.4.4: unknown signer -> TOFU prompt (non-terminal); file still opens
	BOOL               bSignatureFailed; // ECDSA signature missing/invalid or pub line missing/malformed (tampered)
	BOOL               bHasSignature;    // a valid signature was verified
	BOOL               bDoubleTampered;  // double container: both halves damaged (already reported)
	TCHAR              szForeignFingerprint[80]; // 1.4.4: fingerprint of an untrusted signer (banner, 64 hex + NUL)
	TCHAR              szTimestamp[MAX_STRINGRES];  // "; cn<...>" timestamp embedded in the file
	TCHAR              szStatus[6][MAX_STRINGRES];
	UINT               cDamaged;   // 1.4.9: 逐条 chk 定位到的损坏条目数
} HASHVERIFYCONTEXT, *PHASHVERIFYCONTEXT;



/*============================================================================*\
	Function declarations
\*============================================================================*/

// Data parsing functions
// Locate the signature line ("; sig=" at line start) in the normalized
// file data; returns NULL if none.
static PTSTR FindSigLine( PCTSTR pszData )
{
	const TCHAR *p = pszData;
	const size_t cch = SSLen(TEXT("; sig="));

	for (;;)
	{
		while (*p == TEXT(' '))
			++p;

		if (!*p)
			return(NULL);

		if (*p == TEXT(';') && StrCmpNI(p, TEXT("; sig="), (INT)cch) == 0)
			return((PTSTR)p);

		while (*p && *p != TEXT('\n'))
			++p;
		if (*p == TEXT('\n'))
			++p;
	}
}


// Extract the base64url token following "; <tag>=" on a line.
static BOOL ExtractToken( PCTSTR pszLine, PCTSTR pszPrefix, PTSTR szOut, UINT cchOut )
{
	const TCHAR *p = pszLine + SSLen(pszPrefix);
	UINT i = 0;

	while (*p && *p != TEXT('\n') && *p != TEXT('\r') && *p != TEXT(' ') &&
	       i < cchOut - 1)
		szOut[i++] = *p++;
	szOut[i] = 0;

	return(i > 0);
}


// Locate the public key line ("; pub=" at line start) in the normalized
// file data; returns NULL if none.  1.4.4: restored (the file-internal pub
// is the root of transport-integrity verification for shared files).
static PTSTR FindPubLine( PCTSTR pszData )
{
	const TCHAR *p = pszData;
	const size_t cch = SSLen(TEXT("; pub="));

	for (;;)
	{
		while (*p == TEXT(' '))
			++p;

		if (!*p)
			return(NULL);

		if (*p == TEXT(';') && StrCmpNI(p, TEXT("; pub="), (INT)cch) == 0)
			return((PTSTR)p);

		while (*p && *p != TEXT('\n'))
			++p;
		if (*p == TEXT('\n'))
			++p;
	}
}


// 1.4.4: TrustedSigners registry (TOFU persistence).  Fingerprints of
// signers the user explicitly trusted, stored as values of subkeys under
// HKCU\Software\HashCheck\TrustedSigners.
static BOOL TrustedSignersHas( PCTSTR pszFp )
{
	HKEY   hKey;
	LSTATUS lRet;

	if (!pszFp || !*pszFp)
		return(FALSE);

	lRet = RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("Software\\HashCheck\\TrustedSigners"),
	                    0, KEY_READ, &hKey);
	if (lRet != ERROR_SUCCESS)
		return(FALSE);

	lRet = RegQueryValueEx(hKey, pszFp, NULL, NULL, NULL, NULL);
	RegCloseKey(hKey);
	return(lRet == ERROR_SUCCESS);
}

static VOID TrustedSignersAdd( PCTSTR pszFp )
{
	HKEY  hKey;
	DWORD dwOne = 1;

	if (!pszFp || !*pszFp)
		return;

	if (RegCreateKeyEx(HKEY_CURRENT_USER, TEXT("Software\\HashCheck\\TrustedSigners"),
	                   0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
		return;

	RegSetValueEx(hKey, pszFp, 0, REG_DWORD, (const BYTE*)&dwOne, sizeof(dwOne));
	RegCloseKey(hKey);
}

__forceinline PBYTE WINAPI HashVerifyLoadData( PHASHVERIFYCONTEXT phvctx );
// 1.4.4 分层信任验签（fail-closed + TOFU）：
//   能走到这里的文件必然出自 HCK2 容器（非容器文件已在 HashVerifyLoadData
//   拒收），而保存链必然写过 pub 行与 sig 行——任一缺失即被篡改。
//     1. pub 行/sig 行缺失或畸形              -> bSignatureFailed（损坏，防剥签名）
//     2. sig 行 keyid（GCM+签名保护）为唯一权威；容器头 keyid 与权威不符
//        -> bKeyidHeaderDamage（外科修复：只写回坏的那 1 字节，不再按损坏拒收）
//     3. pub 行公钥解码失败                   -> bSignatureFailed（损坏）
//     4. 用文件内 pub 验签，挂                -> bSignatureFailed（传输途中被篡改）
//     5. 签名者身份分层（验签已过，只影响提示层，不影响打开）：
//          pub == DLL 内置作者公钥            -> 静默（发布级文件，硬信任）
//          pub == 本机 KSP 公钥               -> 静默（本机生成的文件）
//          指纹已在 TrustedSigners 注册表     -> 静默（用户曾点「信任」）
//          其他                              -> bForeignSigner + szForeignFingerprint
//                                               （TOFU 一问：是=信任+静默；否=仍打开+指纹常驻）
static BYTE HexVal( TCHAR c )
{
	if (c >= TEXT('0') && c <= TEXT('9')) return((BYTE)(c - TEXT('0')));
	if (c >= TEXT('A') && c <= TEXT('F')) return((BYTE)(c - TEXT('A') + 10));
	if (c >= TEXT('a') && c <= TEXT('f')) return((BYTE)(c - TEXT('a') + 10));
	return(0xFF);
}

VOID WINAPI HashVerifySignature( PHASHVERIFYCONTEXT phvctx )
{
	PTSTR pszData = phvctx->pszFileData;
	PTSTR pszSig, pszPub;
	TCHAR szSigEnc[MAX_DIGEST_STRING_LENGTH + 96];
	TCHAR szPubEnc[MAX_DIGEST_STRING_LENGTH + 96];
	PBYTE pbPub = NULL;
	DWORD cbPub = 0;
	UINT cbSigned;
	BYTE byHi, byLo, bySigKeyid;

	phvctx->bSignatureFailed = FALSE;
	phvctx->bHasSignature    = FALSE;
	phvctx->bForeignSigner   = FALSE;
	phvctx->szForeignFingerprint[0] = 0;

	if (!pszData)
		return;

	// fail-closed：pub 行与 sig 行都必需（防剥签名）
	pszSig = FindSigLine(pszData);
	pszPub = FindPubLine(pszData);
	if (!pszSig || !pszPub)
	{
		phvctx->bSignatureFailed = TRUE;
		return;
	}

	if (!ExtractToken(pszSig, TEXT("; sig="), szSigEnc, countof(szSigEnc)) ||
	    !ExtractToken(pszPub, TEXT("; pub="), szPubEnc, countof(szPubEnc)))
	{
		phvctx->bSignatureFailed = TRUE;   // 行存在但 token 畸形 = 损坏
		return;
	}

	// 解析 "XX:<b64>" 的 keyid 前缀（1.4.7: sig 行为唯一权威，头 keyid 仅为提示）
	byHi = HexVal(szSigEnc[0]);
	byLo = HexVal(szSigEnc[1]);
	if (byHi == 0xFF || byLo == 0xFF || szSigEnc[2] != TEXT(':'))
	{
		phvctx->bSignatureFailed = TRUE;   // keyid 前缀畸形 = 损坏
		return;
	}
	bySigKeyid = (BYTE)((byHi << 4) | byLo);

	// 1.4.7: sig 行 keyid 在 GCM 密文 + 签名载荷之内（动它必挂签名）——唯一权威。
	// 容器头 keyid 只是外层提示：任一头字节与权威不符 = 头部损坏 -> 外科修复，
	// 不再按「损坏」拒收。信任路由本就按文件内 pub 走（1.4.4），改头冒充得不到
	// 任何东西；sig 行与头全对不上也不可能（sig 行与头同源，同毁走 GCM 拦截）。
	phvctx->bKeyidHeaderDamage =
	    (phvctx->byKeyidA != bySigKeyid || phvctx->byKeyidB != bySigKeyid);

	if (bySigKeyid != phvctx->byKeyid)
		phvctx->byKeyid = bySigKeyid;   // 权威接管（坏字节的写回由 Thread 弹窗完成）

	// pub 行公钥解码（文件内携带公钥——传输完整性的根基）
	if (!HcsignImportPublicKey(szPubEnc, &pbPub, &cbPub))
	{
		phvctx->bSignatureFailed = TRUE;   // pub 畸形 = 损坏
		return;
	}

	// Signed payload = everything up to (not including) the sig line
	// (includes the pub line; identical to what the save chain signed).
	cbSigned = (UINT)(pszSig - pszData) * sizeof(TCHAR);
	if (!HcsignVerify((const BYTE*)pszData, cbSigned, pbPub, cbPub,
	                   szSigEnc + 3))
	{
		free(pbPub);
		phvctx->bSignatureFailed = TRUE;   // 传输途中被篡改
		return;
	}

	// 身份分层（验签已过；只影响提示层，不影响打开）
	{
		BOOL bAuthor = FALSE, bLocal = FALSE;
		UINT i;

		// 作者域：pub == 内置公钥表任一条目（blob 逐字节比对）
		for (i = 0; i < HCK_AUTHOR_KEY_COUNT && !bAuthor; ++i)
		{
			PBYTE pbTbl = NULL;
			DWORD cbTbl = 0;

			if (HcsignImportPublicKey(HCK_AUTHOR_KEYS[i].pubB64, &pbTbl, &cbTbl))
			{
				bAuthor = (cbPub == cbTbl && memcmp(pbPub, pbTbl, cbTbl) == 0);
				free(pbTbl);
			}
		}

		// 本机域：pub == 本机 KSP 公钥
		if (!bAuthor)
		{
			PTSTR pszLocalB64 = NULL;

			if (HcsignGetPublicKeyB64(&pszLocalB64))
			{
				PBYTE pbLocal = NULL;
				DWORD cbLocal = 0;

				if (HcsignImportPublicKey(pszLocalB64, &pbLocal, &cbLocal))
				{
					bLocal = (cbPub == cbLocal && memcmp(pbPub, pbLocal, cbLocal) == 0);
					free(pbLocal);
				}
				LocalFree(pszLocalB64);
			}
		}

		if (bAuthor || bLocal)
		{
			// 静默（发布级 / 本机生成）
		}
		else
		{
			// 已信任签名者（TrustedSigners 注册表）或陌生签名者（TOFU 一问）
			TCHAR szFp[80];

			if (HcsignFingerprintFromBlob(pbPub, cbPub, szFp, countof(szFp)) &&
			    TrustedSignersHas(szFp))
			{
				// 静默（用户曾点「信任」）
			}
			else
			{
				phvctx->bForeignSigner = TRUE;   // Thread 弹 TOFU 一问，指纹条常驻
				StringCchCopy(phvctx->szForeignFingerprint,
				              countof(phvctx->szForeignFingerprint), szFp);
			}
		}
	}

	free(pbPub);
	phvctx->bHasSignature = TRUE;   // 验签已过（身份分层只影响提示层）
}

// Open a sealed checksum file (encrypted container).  Double-container
// layout: [seal A][seal B], same plaintext, independent random nonces.  The
// GCM tag is the natural integrity judge -- the half that decrypts is intact.
//   A and B intact      -> use A silently
//   exactly one intact  -> offer repair: re-seal the good plaintext as a new
//                          pair (with the survivor's keyid) and rewrite the
//                          file, then continue with it
//   both damaged        -> report "tampered" (bDoubleTampered, single dialog)
// 1.4.5: header damage no longer misroutes the verdicts.  A file counts as a
// pair when both halves' magic is intact (strict) OR B's half magic alone
// survives (A's header destroyed) -- GCM judges the halves either way.  In the
// single-container branch a whole-file decrypt failure falls back to "A as a
// standalone container" (in a pair, A's tag sits right before the midpoint),
// so a destroyed B header also reaches the repair path instead of a bare
// "corrupted" verdict.  "Unsupported format" stays reserved for files that
// carry no HCK2 magic at all (zero downgrade).
// 1.4.10: deletion coverage on both layers -- the magic scan now starts at
// offset 1 (a head-section deletion pushes intact B to offsets 1..33, which
// the old offset-34 scan missed and misreported as "unsupported format"),
// and HcencScanPrefixContainer rescues an intact A whose boundary drifted
// off the midpoint when the deletion ate B's magic (no structural anchor
// left to locate it; GCM adjudicates every candidate end).
// On success *ppbRaw/*pcbRaw are replaced with the plaintext (old buffer
// freed); on failure they are NULLed and the verdict flag is set.
static BOOL HashVerifyOpenSealed( PHASHVERIFYCONTEXT phvctx,
                                  PBYTE* ppbRaw, DWORD* pcbRaw )
{
	PBYTE pbRaw = *ppbRaw;
	DWORD cbRaw = *pcbRaw;
	PBYTE pbPlain = NULL, pbOther = NULL;
	DWORD cbPlain = 0, cbOther = 0;
	BYTE byKeyidA = 0xFF, byKeyidB = 0xFF;
	DWORD cbSplit = 0;
	BOOL bAok = FALSE, bBok = FALSE, bPairMode = FALSE;

	/* 配对几何：严格双（两头魔数都在），或 B 半魔数在中点（A 头被毁），
	   或 1.4.8 全文件扫描第二份魔数（单字节增删使 B 半偏离中点）。
	   两半始终由各自的 GCM 标签裁决。 */
	if (HcencIsDouble(pbRaw, cbRaw) || HcencIsHalfContainer(pbRaw, cbRaw))
		cbSplit = cbRaw / 2;
	else
		cbSplit = HcencFindPairSplit(pbRaw, cbRaw);

	if (cbSplit)
	{
		bPairMode = TRUE;
		bAok = HcencDecrypt(pbRaw, cbSplit, &pbPlain, &cbPlain, &byKeyidA);
		bBok = HcencDecrypt(pbRaw + cbSplit, cbRaw - cbSplit,
		                    &pbOther, &cbOther, &byKeyidB);
	}
	else
	{
		/* Single container (e.g. a truncated pair): decrypt the whole file.
		   If that fails, try "A as a standalone container" -- in a pair
		   whose B header was destroyed, A is still complete (its tag sits
		   right before the midpoint), so this reaches the repair path. */
		if (HcencDecrypt(pbRaw, cbRaw, &pbPlain, &cbPlain, &phvctx->byKeyid))
		{
			/* 单容器（截断的双容器等）：无另一份可援，头 keyid 损坏时
			   以 sig 行权威值打开（cbHalfRaw=0 -> 跳过 B 半修复定位） */
			phvctx->byKeyidA = phvctx->byKeyid;
			phvctx->byKeyidB = phvctx->byKeyid;
			phvctx->cbHalfRaw = 0;
			free(pbRaw);
			*ppbRaw = pbPlain;
			*pcbRaw = cbPlain;
			return(TRUE);
		}
		if ((cbRaw & 1) == 0)
			bAok = HcencDecrypt(pbRaw, cbRaw / 2, &pbPlain, &cbPlain,
			                    &byKeyidA);

		/* 1.4.10: B 的魔数被删除/摧毁但 A 完好——A 的边界随删除字节数
		   漂移，中点与魔数全扫描都没有锚点（上面的半份兜底只对长度未
		   漂移的文件成立）。逐候选终点 GCM 裁决（HcencScanPrefixContainer，
		   ≤64KB 有界）：唯一通过者即幸存 A -> 修复通道。 */
		if (!bAok)
			bAok = HcencScanPrefixContainer(pbRaw, cbRaw, &pbPlain,
			                                &cbPlain, &byKeyidA);
	}

	if (bAok && bBok)
	{
		/* Fully intact pair: use the primary copy, keep the file as-is.
		   Half A leads the file, so its keyid is the header keyid.
		   1.4.7: keep both raw header keyids + half length for the
		   surgical keyid repair (see HashVerifySignature). */
		phvctx->byKeyid  = byKeyidA;
		phvctx->byKeyidA = byKeyidA;
		phvctx->byKeyidB = byKeyidB;
		phvctx->cbHalfRaw = cbSplit;
		free(pbOther);
		free(pbRaw);
		*ppbRaw = pbPlain;
		*pcbRaw = cbPlain;
		return(TRUE);
	}

	if (bAok || bBok)
	{
		/* One copy damaged: offer to rebuild the pair from the survivor.
		   The survivor's keyid is authoritative (the damaged copy's
		   header cannot be trusted). */
		PBYTE pbGood = bAok ? pbPlain : pbOther;
		DWORD cbGood = bAok ? cbPlain : cbOther;

		phvctx->byKeyid = bAok ? byKeyidA : byKeyidB;
		phvctx->byKeyidA = phvctx->byKeyid;
		phvctx->byKeyidB = phvctx->byKeyid;
		phvctx->cbHalfRaw = cbSplit;

		if (MessageBox(NULL,
			L"检测到校验文件内容损坏，是否用完好副本尝试修复？",
			NULL, MB_YESNO | MB_ICONQUESTION) == IDYES)
		{
			PBYTE pbNew = NULL;
			DWORD cbNew = 0;

			if (HcencEncryptPair(phvctx->byKeyid, pbGood, cbGood,
			                     &pbNew, &cbNew))
			{
				HANDLE hOut = CreateFile(
					phvctx->pszPath,
					GENERIC_WRITE,
					FILE_SHARE_READ,
					NULL,
					CREATE_ALWAYS,
					FILE_ATTRIBUTE_NORMAL,
					NULL
				);

				if (hOut != INVALID_HANDLE_VALUE)
				{
					DWORD cbWritten;
					BOOL bW = WriteFile(hOut, pbNew, cbNew,
					                    &cbWritten, NULL) &&
					          cbWritten == cbNew;
					CloseHandle(hOut);
					MessageBox(NULL,
						bW ? L"修复成功。" : L"修复失败。",
						NULL,
						bW ? MB_OK | MB_ICONINFORMATION
						   : MB_OK | MB_ICONERROR);
				}
				else
				{
					MessageBox(NULL, L"修复失败。", NULL,
					           MB_OK | MB_ICONERROR);
				}
				free(pbNew);
			}
			else
			{
				MessageBox(NULL, L"修复失败。", NULL,
				           MB_OK | MB_ICONERROR);
			}
		}

		if (pbPlain && pbPlain != pbGood) free(pbPlain);
		if (pbOther && pbOther != pbGood) free(pbOther);
		free(pbRaw);
		*ppbRaw = pbGood;
		*pcbRaw = cbGood;
		return(TRUE);
	}

	/* Neither copy decrypts */
	if (bPairMode)
	{
		/* 1.4.10: 假阳性防线——全扫描定位到的 split 可能只是密文里长得
		   像魔数的随机字节（真单容器 ≥68B 被撞中会被误判成对）。整份
		   解密再试一次：成功 = 真单容器直开；失败 = 真双坏。 */
		if (HcencDecrypt(pbRaw, cbRaw, &pbPlain, &cbPlain,
		                 &phvctx->byKeyid))
		{
			phvctx->byKeyidA = phvctx->byKeyid;
			phvctx->byKeyidB = phvctx->byKeyid;
			phvctx->cbHalfRaw = 0;
			free(pbRaw);
			*ppbRaw = pbPlain;
			*pcbRaw = cbPlain;
			return(TRUE);
		}
	}

	if (pbPlain) free(pbPlain);
	if (pbOther) free(pbOther);
	free(pbRaw);
	*ppbRaw = NULL;

	if (bPairMode)
	{
		/* Pair with both halves damaged */
		phvctx->bDoubleTampered = TRUE;
		MessageBox(NULL,
			L"校验文件被篡改（两份副本均损坏）。",
			NULL, MB_OK | MB_ICONERROR);
	}
	else
	{
		/* Damaged single container (whole-file, half and prefix-scan
		   attempts all failed) */
		phvctx->bSignatureFailed = TRUE;   // -> "校验文件损坏或被修改"
	}
	return(FALSE);
}

__forceinline PBYTE WINAPI HashVerifyLoadData( PHASHVERIFYCONTEXT phvctx );
VOID WINAPI HashVerifyParseData( PHASHVERIFYCONTEXT phvctx );
BOOL WINAPI ValidateHexSequence( PTSTR psz, UINT cch );

// "Newly-added" file detection: walk the directory of the checksum file
// and flag files that exist on disk but are not listed in the manifest
VOID WINAPI HashVerifyScanForNewFiles( PHASHVERIFYCONTEXT phvctx );
VOID WINAPI HashVerifyScanForMissingFiles( PHASHVERIFYCONTEXT phvctx );
VOID WINAPI HashVerifyScanDir( PHASHVERIFYCONTEXT phvctx, PTSTR pszDir, UINT cchDir,
                               UINT cchPrefix, UINT cOrigTotal );
BOOL WINAPI HashVerifyIsPathInList( PHASHVERIFYCONTEXT phvctx, PCTSTR pszPath, UINT cOrigTotal );

// Worker thread
VOID __fastcall HashVerifyWorkerMain( PHASHVERIFYCONTEXT phvctx );
VOID WINAPI HashVerifyStartHashing( PHASHVERIFYCONTEXT phvctx, BOOL bPriority, BOOL bIncludeRest );

// Dialog general
INT_PTR CALLBACK HashVerifyDlgProc( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam );
VOID WINAPI HashVerifyDlgInit( PHASHVERIFYCONTEXT phvctx );

// Dialog status
VOID WINAPI HashVerifyUpdateSummary( PHASHVERIFYCONTEXT phvctx, PHASHVERIFYITEM pItem );

// List management
VOID WINAPI HashVerifyCopySelection( PHASHVERIFYCONTEXT phvctx );
VOID WINAPI HashVerifyCopySelection( PHASHVERIFYCONTEXT phvctx )
{
	INT nIndex = -1;
	UINT cSel = 0;
	UINT cLen = 0, cbAlloc, cchAlloc;
	PTSTR pszBuf, pszWrite;
	UINT i;

	// Count selected items with a non-empty expected hash, and measure text.
	if (phvctx->hWndList == NULL)
		return;

	while ((nIndex = ListView_GetNextItem(phvctx->hWndList, nIndex, LVNI_SELECTED)) != -1)
	{
		if ((UINT)nIndex >= phvctx->cTotal)
			continue;
		PHASHVERIFYITEM pItem = phvctx->index[nIndex];
		if (!pItem->pszExpected || !pItem->pszExpected[0])
			continue;   // no expected checksum; nothing meaningful to copy
		++cSel;
		// Each item = [prefix] name CRLF hash CRLF
		cLen += (UINT)lstrlen(pItem->pszDisplayName) +
		        (UINT)lstrlen(pItem->pszExpected) + 4;   // two CRLFs
	}

	if (cSel == 0)
		return;   // nothing to copy

	// Buffer: numeric prefix "N." per line for multi-selection, then the
	// item text, then the trailing NUL.
	{
		UINT cPrefix = 0;              // chars for the "N." prefix (single: 0)
		if (cSel > 1)
			cPrefix = (UINT)(cSel >= 10 ? 3 : 2);   // "1." = 2, "10." = 3

		cbAlloc = (cLen + cSel * cPrefix + 1) * sizeof(TCHAR);
		cchAlloc = cLen + cSel * cPrefix + 1;
	}

	if (cchAlloc > 0x100000)   // sanity: cap at ~1 MB
		return;

	pszBuf = (PTSTR)malloc(cbAlloc);
	if (!pszBuf)
		return;

	pszWrite = pszBuf;
	nIndex = -1;
	i = 0;

	while ((nIndex = ListView_GetNextItem(phvctx->hWndList, nIndex, LVNI_SELECTED)) != -1)
	{
		UINT cchLeft;

		if ((UINT)nIndex >= phvctx->cTotal)
			continue;
		PHASHVERIFYITEM pItem = phvctx->index[nIndex];
		if (!pItem->pszExpected || !pItem->pszExpected[0])
			continue;

		if (cSel > 1)
		{
			TCHAR szNum[16];
			StringCchPrintf(szNum, countof(szNum), TEXT("%u."), i + 1);
			cchLeft = (UINT)(cchAlloc - (UINT)(pszWrite - pszBuf));
			StringCchCopy(pszWrite, cchLeft, szNum);
			pszWrite += lstrlen(szNum);
		}

		cchLeft = (UINT)(cchAlloc - (UINT)(pszWrite - pszBuf));
		StringCchCopy(pszWrite, cchLeft, pItem->pszDisplayName);
		pszWrite += lstrlen(pItem->pszDisplayName);

		cchLeft = (UINT)(cchAlloc - (UINT)(pszWrite - pszBuf));
		StringCchCopy(pszWrite, cchLeft, TEXT("\r\n"));
		pszWrite += 2;

		cchLeft = (UINT)(cchAlloc - (UINT)(pszWrite - pszBuf));
		StringCchCopy(pszWrite, cchLeft, pItem->pszExpected);
		pszWrite += lstrlen(pItem->pszExpected);

		cchLeft = (UINT)(cchAlloc - (UINT)(pszWrite - pszBuf));
		StringCchCopy(pszWrite, cchLeft, TEXT("\r\n"));
		pszWrite += 2;

		++i;
	}
	*pszWrite = 0;

	// Put it on the clipboard as Unicode text.
	if (OpenClipboard(phvctx->hWnd))
	{
		HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE,
		                    ((UINT)(pszWrite - pszBuf) + 1) * sizeof(TCHAR));
		if (hMem)
		{
			PTSTR pszDst = (PTSTR)GlobalLock(hMem);
			if (pszDst)
			{
				lstrcpy(pszDst, pszBuf);
				GlobalUnlock(hMem);
				EmptyClipboard();
				if (SetClipboardData(CF_UNICODETEXT, hMem))
					hMem = NULL;   // clipboard owns it now
			}
			if (hMem)
				GlobalFree(hMem);
		}
		CloseClipboard();
	}

	free(pszBuf);
}

VOID WINAPI HashVerifyListInfo( PHASHVERIFYCONTEXT phvctx, LPNMLVDISPINFO pdi );
__forceinline LONG_PTR WINAPI HashVerifySetColor( PHASHVERIFYCONTEXT phvctx, LPNMLVCUSTOMDRAW pcd );
__forceinline LONG_PTR WINAPI HashVerifyFindItem( PHASHVERIFYCONTEXT phvctx, LPNMLVFINDITEM pfi );
__forceinline VOID WINAPI HashVerifySortColumn( PHASHVERIFYCONTEXT phvctx, LPNMLISTVIEW plv );
VOID WINAPI HashVerifySortByStatus( PHASHVERIFYCONTEXT phvctx );
__forceinline VOID WINAPI HashVerifyReadStates( PHASHVERIFYCONTEXT phvctx );
__forceinline VOID WINAPI HashVerifySetStates( PHASHVERIFYCONTEXT phvctx );
INT __cdecl HashVerifySortCompare( PHASHVERIFYCONTEXT phvctx, PPCHVITEM ppItemA, PPCHVITEM ppItemB );
__forceinline VOID WINAPI HashVerifyRebuildListIndex( PHASHVERIFYCONTEXT phvctx );



/*============================================================================*\
	Entry points / main functions
\*============================================================================*/

VOID CALLBACK HashVerify_RunDLLW( HWND hWnd, HINSTANCE hInstance,
                                  PWSTR pszCmdLine, INT nCmdShow )
{
	SIZE_T cchPath = SSLenW(pszCmdLine) + 1;
	PTSTR pszPath;

	// HashVerifyThread will try to free the path passed to it, as it expects
	// it to be allocated by malloc; it also expects g_cRefThisDll to be
	// incremented by the caller.

	if (pszPath = (PTSTR)malloc(cchPath * sizeof(TCHAR)))
	{
		if (WStrToTStr(pszCmdLine, pszPath, (UINT)cchPath))
		{
			++g_cRefThisDll;
			HashVerifyThread(pszPath);
		}
		else
		{
			free(pszPath);
		}
	}
}

// 1.5.7: SHA-256 合并到 Hcenc.c（HcencSha256）——chk 双端同源防漂移
#define HashVerifySha256 HcencSha256

// 1.4.9: 行文本（已裁剪、NUL 终止）-> 规范化副本的 SHA-256 -> 64 位小写 hex
static BOOL HashVerifyChkOfLine( PCTSTR pszLine, PTSTR szOut )
{
	static const TCHAR szHex[] = TEXT("0123456789abcdef");
	PTSTR pszCopy;
	BYTE byHash[32];
	size_t cch;
	UINT k;

	if (!pszLine || !szOut)
		return(FALSE);
	cch = SSLen(pszLine);
	if (!cch || cch > 0x8000)
		return(FALSE);
	pszCopy = (PTSTR)malloc((cch + 1) * sizeof(TCHAR));
	if (!pszCopy)
		return(FALSE);
	memcpy(pszCopy, pszLine, (cch + 1) * sizeof(TCHAR));
	HCNormalizeString(pszCopy);
	if (!HashVerifySha256((const BYTE*)pszCopy, (DWORD)(cch * sizeof(TCHAR)), byHash))
	{
		free(pszCopy);
		return(FALSE);
	}
	free(pszCopy);
	for (k = 0; k < 32; ++k)
	{
		szOut[2*k]   = szHex[byHash[k] >> 4];
		szOut[2*k+1] = szHex[byHash[k] & 15];
	}
	szOut[64] = 0;
	return(TRUE);
}

// 1.5.3: SHA-256("") 的十六进制。1.4.9~1.5.2 保存端 bug（取「\n 之后」
// 拿到空行）把每条 chk 都写成了这个值——验证端遇到它视为「无定位器」：
// 不标不计数（等价于没有 chk 行），旧文件打开不再整清单误标。真数据行
// 非空，其 chk 不可能是空串哈希；蓄意写它=主动放弃定位=按无定位器拒收。
static const TCHAR szChkEmptySha[] =
    TEXT("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

// 1.4.9: 逐条定位——数据行的下一行是 "; chk=" 且与本行 chk 不符 = 该条损坏。
// chk 无密钥可重算：蓄意篡改者重算 chk 使本函数返回 0，Thread 据此守门。
static UINT HashVerifyCountDamagedLines( PCTSTR pszData )
{
	UINT cDamaged = 0;
	const TCHAR *p = pszData;

	if (!p)
		return(0);

	while (*p)
	{
		const TCHAR *pszLine = p;
		const TCHAR *pszEnd;
		const TCHAR *pszNext;

		while (*p && *p != TEXT('\n'))
			++p;
		pszEnd = p;
		while (pszEnd > pszLine && (pszEnd[-1] == TEXT('\r') || pszEnd[-1] == TEXT(' ')))
			--pszEnd;
		pszNext = (*p == TEXT('\n')) ? p + 1 : p;

		while (*pszLine == TEXT(' '))
			++pszLine;

		if (*pszLine && *pszLine != TEXT(';') && pszEnd > pszLine)
		{
			const TCHAR *q = pszNext;

			/* 1.5.2: 规范化把行尾 CRLF 变成 \n\n（\r→\n 保留原 \n），
			   每条数据行后都隔着一个空行——配对必须跳过这些规范化伪影
			   空行，否则「下一行是 ; chk=」永远不成立，逐条定位整体失效 */
			while (*q == TEXT(' ') || *q == TEXT('\n'))
				++q;

			if (q[0] == TEXT(';') && _tcsnicmp(q, TEXT("; chk="), 6) == 0)
			{
				TCHAR szExpect[65];
				const TCHAR *r = q + 6;
				int i;

				for (i = 0; i < 64 && *r && *r != TEXT('\n') &&
				     *r != TEXT('\r') && *r != TEXT(' '); ++i)
					szExpect[i] = *r++;
				szExpect[i] = 0;

				/* 1.5.3: 空串哈希指纹（旧版保存端 bug）= 无定位器，跳过 */
				if (i == 64 && lstrcmpi(szExpect, szChkEmptySha) != 0)
				{
					TCHAR szActual[65];
					size_t cch = pszEnd - pszLine;

					if (cch && cch < 0x8000)
					{
						PTSTR pszCopy = (PTSTR)malloc((cch + 1) * sizeof(TCHAR));

						if (pszCopy)
						{
							memcpy(pszCopy, pszLine, cch * sizeof(TCHAR));
							pszCopy[cch] = 0;
							if (HashVerifyChkOfLine(pszCopy, szActual) &&
							    lstrcmpi(szExpect, szActual) != 0)
								++cDamaged;
							free(pszCopy);
						}
					}
				}
			}
		}

		if (!*pszNext)
			break;
		p = pszNext;
	}

	return(cDamaged);
}

DWORD WINAPI HashVerifyThread( PTSTR pszPath )
{
	// We will need to free the memory allocated for the data when done
	PBYTE pbRawData;

	// First, activate our manifest and AddRef our host
	ULONG_PTR uActCtxCookie = ActivateManifest(TRUE);
	ULONG_PTR uHostCookie = HostAddRef();

	// Allocate the context data that will persist across this session
	HASHVERIFYCONTEXT hvctx;

	// It's important that we zero the memory since an initial value of zero is
	// assumed for many of the elements
	ZeroMemory(&hvctx, sizeof(hvctx));

	// Prep the path
	HCNormalizeString(pszPath);
	StrTrim(pszPath, TEXT(" "));
	hvctx.pszPath = pszPath;

	// Load the raw data
	pbRawData = HashVerifyLoadData(&hvctx);

	// 1.4.4 fail-closed verdicts, in priority order.  bDoubleTampered /
	// bUnsupportedFormat / bSignatureFailed are terminal; bForeignSigner is
	// a TOFU prompt after which the file opens either way.
	if (hvctx.bDoubleTampered)
	{
		// 双容器两半全坏：OpenSealed 已弹「校验文件被篡改」，不再重复
	}
	else if (hvctx.bUnsupportedFormat)
	{
		// 无任何 HCK2 魔数（古老格式 / 魔数被篡改毁 / 文本编辑器重编码全灭）：
		// 零降级拒收。与「损坏」弹窗共用一条文案——魔数没了就没有证据区分
		// 「曾是本产品文件」与「从未见过的格式」，分开表述只会误导用户去升级
		MessageBox(NULL, L"文件已损坏或被篡改\r\n可能安装版本不匹配",
		           NULL, MB_OK | MB_ICONERROR);
	}
	else if (hvctx.bSignatureFailed)
	{
		// 1.4.9: 验签挂——逐条 chk 定位损坏条目（意外损坏特征）。
		// chk 能定位 = 继续/退出；chk 全过（蓄意重算）= 整档拒收
		hvctx.cDamaged = HashVerifyCountDamagedLines(hvctx.pszFileData);

		if (hvctx.cDamaged)
		{
			TCHAR szMsg[0x100];

			StringCchPrintf(szMsg, countof(szMsg),
			                L"检测到 %u 条校验记录损坏（其余条目仍可用）。\r\n\r\n是否继续查看？",
			                hvctx.cDamaged);

			if (MessageBox(NULL, szMsg, NULL, MB_YESNO | MB_ICONQUESTION) == IDYES)
				hvctx.bSignatureFailed = FALSE;   // 继续：损坏条紫底「损坏」
			// 点否：用户选择退出，静默关闭
		}
		else
		{
			// pub/sig 行缺失或畸形、GCM 挂或验签挂且无法定位：与「不支持版本」
			// 共用同一弹窗（1.5.5 合并）——用户视角两者都是「这文件坏了」
			MessageBox(NULL, L"文件已损坏或被篡改\r\n可能安装版本不匹配",
			           NULL, MB_OK | MB_ICONERROR);
		}
	}

	if (!hvctx.bDoubleTampered && !hvctx.bUnsupportedFormat && !hvctx.bSignatureFailed)
	{
		// 1.4.7: 头部 keyid 字节损坏（另一份完好即可还原）——外科手术式只写回
		// 坏的那 1 字节（A 半偏移 5；双容器的 B 半偏移 半长+5）。修不修都不影响打开。
		if (hvctx.bKeyidHeaderDamage)
		{
			if (MessageBox(NULL,
				L"检测到校验文件头部标识损坏，是否修复？",
				NULL, MB_YESNO | MB_ICONQUESTION) == IDYES)
			{
				HANDLE hFile = CreateFile(
					hvctx.pszPath,
					GENERIC_READ | GENERIC_WRITE,
					FILE_SHARE_READ,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL
				);
				BOOL bFixed = FALSE;

				if (hFile != INVALID_HANDLE_VALUE)
				{
					LARGE_INTEGER cbSize;

					if (GetFileSizeEx(hFile, &cbSize) && !cbSize.HighPart)
					{
						BYTE           by = hvctx.byKeyid;   // 权威值（sig 行裁决）
						BYTE           buf;
						DWORD          cbIO;
						LARGE_INTEGER  li;

						li.QuadPart = 5;   // A 半 keyid
						SetFilePointerEx(hFile, li, NULL, FILE_BEGIN);
						if (ReadFile(hFile, &buf, 1, &cbIO, NULL) && cbIO == 1 && buf != by)
						{
							SetFilePointerEx(hFile, li, NULL, FILE_BEGIN);
							WriteFile(hFile, &by, 1, &cbIO, NULL);
						}

						if (hvctx.cbHalfRaw &&
						    (DWORD)cbSize.LowPart >= hvctx.cbHalfRaw + 5)
						{
							li.QuadPart = (LONGLONG)hvctx.cbHalfRaw + 5;   // B 半 keyid
							SetFilePointerEx(hFile, li, NULL, FILE_BEGIN);
							if (ReadFile(hFile, &buf, 1, &cbIO, NULL) && cbIO == 1 && buf != by)
							{
								SetFilePointerEx(hFile, li, NULL, FILE_BEGIN);
								WriteFile(hFile, &by, 1, &cbIO, NULL);
							}
						}
						bFixed = TRUE;
					}
					CloseHandle(hFile);
				}
				MessageBox(NULL,
					bFixed ? L"修复成功。" : L"修复失败。",
					NULL,
					bFixed ? MB_OK | MB_ICONINFORMATION : MB_OK | MB_ICONERROR);
			}
			// 点否：仍正常打开（内容与签名均完好）
		}

		// 1.4.4: 陌生签名者 -> TOFU 一问（非终局）：是 = 写入 TrustedSigners，
		// 此后同指纹静默；否 = 仍正常打开，指纹条常驻（分享需求下拒绝=没用）
		if (hvctx.bForeignSigner)
		{
			TCHAR szMsg[0x100];

			StringCchPrintf(szMsg, countof(szMsg),
			                L"此校验文件由其他设备签发（指纹 %s）。\r\n\r\n"
			                L"是否信任该签名者？（信任后同指纹文件不再询问）",
			                hvctx.szForeignFingerprint);

			if (MessageBox(NULL, szMsg, NULL,
			               MB_YESNO | MB_ICONQUESTION) == IDYES)
			{
				TrustedSignersAdd(hvctx.szForeignFingerprint);
				hvctx.bForeignSigner = FALSE;   // 信任 -> 静默（指纹条不显示）
			}
			// 点否：bForeignSigner 保持，指纹条在验证窗口常驻
		}

		if (hvctx.pszFileData && (hvctx.hList = SLCreateEx(TRUE)))
		{
			HashVerifyParseData(&hvctx);

			// Remember how many files came from the manifest itself: only those are
			// hashed.  Files found on disk but absent from the manifest are appended
			// by the scan below and shown as "新增" without being hashed.
			hvctx.cOrigTotal = hvctx.cTotal;

			// Scan the manifest's folder for "newly-added" files
			HashVerifyScanForNewFiles(&hvctx);

			// Flag manifest files that no longer exist on disk as "缺失" up front,
			// so they show as missing the moment the dialog opens (mirrors the
			// "新增" scan above)
			HashVerifyScanForMissingFiles(&hvctx);

			DialogBoxParam(
				g_hModThisDll,
				MAKEINTRESOURCE(IDD_HASHVERF),
				NULL,
				HashVerifyDlgProc,
				(LPARAM)&hvctx
			);

			SLRelease(hvctx.hList);
			if (hvctx.hNewPaths)
				SLRelease(hvctx.hNewPaths);
		}
		else if (*pszPath)
		{
			// Technically, we could reach this point by either having a file read
			// error or a memory allocation error, but I really don't feel like
			// doing separate messages for what are supposed to be rare edge cases.
			TCHAR szFormat[MAX_STRINGRES], szMessage[0x100];
			LoadString(g_hModThisDll, IDS_HV_LOADERROR_FMT, szFormat, countof(szFormat));
			StringCchPrintf(szMessage, countof(szMessage), szFormat, pszPath);
			MessageBox(NULL, szMessage, NULL, MB_OK | MB_ICONERROR);
		}
	}

	free(pbRawData);
	free(pszPath);

	// Clean up the manifest activation and release our host
	DeactivateManifest(uActCtxCookie);
	HostRelease(uHostCookie);

	InterlockedDecrement(&g_cRefThisDll);
	return(0);
}



/*============================================================================*\
	Data parsing functions
\*============================================================================*/

// Returns a single WHEX_CHECK bit for the algorithm implied by a path's
// extension, or 0 if the extension is not a checksum extension (mirrors the
// extension block in HashVerifyParseData).
DWORD WINAPI HashVerifyAlgFromExt( PCTSTR pszPath )
{
	PTSTR pszExt = StrRChr(pszPath, NULL, TEXT('.'));

	if (pszExt)
	{
#define HASH_VERIFY_ALG_op(alg) \
		if (StrCmpI(pszExt, HASH_EXT_##alg) == 0)  return WHEX_CHECK##alg;
		FOR_EACH_HASH(HASH_VERIFY_ALG_op)
#undef HASH_VERIFY_ALG_op
	}

	return(0);
}

PBYTE WINAPI HashVerifyLoadData( PHASHVERIFYCONTEXT phvctx )
{
	PBYTE pbRawData = NULL;
	HANDLE hFile;

	if ((hFile = OpenFileForReading(phvctx->pszPath)) != INVALID_HANDLE_VALUE)
	{
		LARGE_INTEGER cbRawData;
		DWORD cbBytesRead;

		if ( (GetFileSizeEx(hFile, &cbRawData)) &&
		     (pbRawData = (PBYTE)malloc(cbRawData.LowPart + sizeof(DWORD))) &&
		     (ReadFile(hFile, pbRawData, cbRawData.LowPart, &cbBytesRead, NULL)) &&
		     (cbRawData.LowPart == cbBytesRead) )
		{
			// When we allocated a block of memory for the file data, we
			// reserved a DWORD at the end for NULL termination and to serve as
			// the extra buffer needed by IsTextUTF8...
			*((UPDWORD)(pbRawData + cbRawData.LowPart)) = 0;

			// 1.4.5 fail-closed: this build only opens v2 (HCK2) sealed
			// containers.  Legacy plaintext checksum files and 1.4.1-era
			// HCK1 containers are rejected as "unsupported format" -- zero
			// downgrade paths.  Sealed files carry double-container
			// redundancy; a damaged half (or a damaged half header) is
			// repaired from the other half (see HashVerifyOpenSealed).
			if (HcencIsContainer(pbRawData, cbRawData.LowPart) ||
			    HcencIsHalfContainer(pbRawData, cbRawData.LowPart) ||
			    HcencFindPairSplit(pbRawData, cbRawData.LowPart))
			{
				phvctx->byKeyid = HcencGetKeyid(pbRawData, cbRawData.LowPart);
				if (!HashVerifyOpenSealed(phvctx, &pbRawData,
				                          &cbRawData.LowPart))
				{
					CloseHandle(hFile);
					return(NULL);
				}
			}
			else
			{
				phvctx->bUnsupportedFormat = TRUE;
				free(pbRawData);
				CloseHandle(hFile);
				return(NULL);
			}

			// Prepare the data for the parser...
			phvctx->pszFileData = BufferToWStr(&pbRawData, cbRawData.LowPart);
			HCNormalizeString(phvctx->pszFileData);

			// Extract the embedded "; <region><YYYYMMDDHHMMSS>" timestamp, if present
			phvctx->szTimestamp[0] = 0;
			{
				PTSTR pszTs = phvctx->pszFileData;
				while (!phvctx->szTimestamp[0] && (pszTs = StrStrW(pszTs, L"; ")) != NULL)
				{
					PTSTR pszRegion = pszTs + 2;   // skip "; "
					UINT i, cDigit = 0;

					// 2-letter region code, then exactly 14 digits (YYYYMMDDHHMMSS)
					if ( ((pszRegion[0] >= L'A' && pszRegion[0] <= L'Z') ||
					       (pszRegion[0] >= L'a' && pszRegion[0] <= L'z')) &&
					     ((pszRegion[1] >= L'A' && pszRegion[1] <= L'Z') ||
					       (pszRegion[1] >= L'a' && pszRegion[1] <= L'z')) )
					{
						for (i = 2; pszRegion[i] >= L'0' && pszRegion[i] <= L'9'; ++i)
							++cDigit;
						if (cDigit == 14)
						{
							for (i = 0; i < countof(phvctx->szTimestamp) - 1 &&
							                pszRegion[i] && pszRegion[i] != L'\n'; ++i)
								phvctx->szTimestamp[i] = pszRegion[i];
							phvctx->szTimestamp[i] = 0;
						}
					}
					pszTs += 2;   // skip "; " and keep scanning comment lines
				}
			}

			// 1.4.3: selfcheck is gone -- the signature covers the whole
			// payload.  Verify the embedded "; sig=<keyid>:<b64>" line; in a
			// fail-closed world it must exist and must verify.
			HashVerifySignature(phvctx);
		}

		CloseHandle(hFile);
	}

	return(pbRawData);
}

VOID WINAPI HashVerifyParseData( PHASHVERIFYCONTEXT phvctx )
{
	PTSTR pszData = phvctx->pszFileData;  // Points to the next line to process

	UINT cchChecksum;             // Expected length of the checksum in TCHARs
	BOOL bReverseFormat = FALSE;  // TRUE if using SFV's format of putting the checksum last
	BOOL bLinesRemaining = TRUE;  // TRUE if we have not reached the end of the data

	// Try to determine the file type from the extension
	{
		PTSTR pszExt = StrRChr(phvctx->pszPath, NULL, TEXT('.'));

		if (pszExt)
		{
            do  // loops once; only here so there's something to break out of
            {
#define HASH_VERIFY_EXT_TYPE(alg)                           \
                if (StrCmpI(pszExt, HASH_EXT_##alg) == 0)   \
                {                                           \
                    phvctx->whctxFlags = WHEX_CHECK##alg;   \
                    cchChecksum = alg##_DIGEST_LENGTH * 2;  \
                    break;                                  \
                }
                FOR_EACH_HASH(HASH_VERIFY_EXT_TYPE)
            } while (FALSE);

            // Special case for CRC-32
            if (phvctx->whctxFlags == WHEX_CHECKCRC32)
				bReverseFormat = TRUE;
		}
	}

	while (bLinesRemaining)
	{
		PTSTR pszStartOfLine;  // First non-whitespace character of the line
		PTSTR pszEndOfLine;    // Last non-whitespace character of the line
		PTSTR pszChecksum = NULL, pszFileName = NULL;
		INT16 cchPath;         // This INCLUDES the NULL terminator!
		PCTSTR pszChkLine;     // 1.5.2: complete line text for the per-line chk
		                       // (Step 2 advances pszStartOfLine past the checksum --
		                       //  and SFV mode even writes NULs into the line -- so
		                       //  the chk hash is computed HERE in Step 1 while the
		                       //  line is still intact, exactly as HashCalc did)
		TCHAR  szChkActual[65];
		BOOL   bChkReady = FALSE;

		// Step 1: Isolate the current line as a NULL-terminated string
		{
			pszStartOfLine = pszData;

			// Find the end of the line
			while (*pszData && *pszData != TEXT('\n'))
				++pszData;

			// Terminate it if necessary, otherwise flag the end of the data
			if (*pszData)
				*pszData = 0;
			else
				bLinesRemaining = FALSE;

			pszEndOfLine = pszData;

			// Strip spaces from the end of the line...
			while (--pszEndOfLine >= pszStartOfLine && *pszEndOfLine == TEXT(' '))
				*pszEndOfLine = 0;

			// ...and from the start of the line
			while (*pszStartOfLine == TEXT(' '))
				++pszStartOfLine;

			// 1.5.2: freeze the trimmed complete line NOW and hash it while
			// the buffer is still intact -- Step 2 advances pszStartOfLine
			// and SFV mode writes NULs into the line. ~3us/line, one-shot.
			pszChkLine = pszStartOfLine;
			bChkReady  = (*pszChkLine && *pszChkLine != TEXT(';')) &&
			              HashVerifyChkOfLine(pszChkLine, szChkActual);

			// Skip past this line's terminator; point at the remaining data
			++pszData;
		}

		// Step 2a: Parse the line as SFV
		if (bReverseFormat)
		{
			pszEndOfLine -= 7;

			if (pszEndOfLine > pszStartOfLine && ValidateHexSequence(pszEndOfLine, 8))
			{
				pszChecksum = pszEndOfLine;

				// Trim spaces between the checksum and the file name
				while (--pszEndOfLine >= pszStartOfLine && *pszEndOfLine == TEXT(' '))
					*pszEndOfLine = 0;

				// Lines that begin with ';' are comments in SFV
				if (*pszStartOfLine && *pszStartOfLine != TEXT(';'))
					pszFileName = pszStartOfLine;
			}
		}

		// Step 2b: All other file formats
		else
		{
			// If we do not know the type yet, make a stab at detecting it
			if (phvctx->whctxFlags == 0)
			{
				// 32-bit algorithms (8-byte)
				if (ValidateHexSequence(pszStartOfLine, 8))
				{
					cchChecksum = 8;
					phvctx->whctxFlags = WHEX_ALL32;  // WHEX_CHECKCRC32
				}
				// 64-bit algorithms (16-byte)
				else if (ValidateHexSequence(pszStartOfLine, 16))
				{
					cchChecksum = 16;
					phvctx->whctxFlags = WHEX_ALL64;  // WHEX_CHECKXXHASH64
				}
				// 128-bit algorithms (32-byte)
				else if (ValidateHexSequence(pszStartOfLine, 32))
				{
					cchChecksum = 32;
					phvctx->whctxFlags = WHEX_ALL128;  // WHEX_CHECKMD5
				}
				// 160-bit algorithms (40-byte)
				else if (ValidateHexSequence(pszStartOfLine, 40))
				{
					cchChecksum = 40;
					phvctx->whctxFlags = WHEX_ALL160;  // WHEX_CHECKSHA1
				}
				// 224-bit algorithms (56-byte)
				else if (ValidateHexSequence(pszStartOfLine, 56))
				{
					cchChecksum = 56;
					phvctx->whctxFlags = WHEX_ALL224;  // WHEX_CHECKSHA224 | WHEX_CHECKSHA3_224
				}
				// 256-bit algorithms (64-byte)
				else if (ValidateHexSequence(pszStartOfLine, 64))
				{
					cchChecksum = 64;
					phvctx->whctxFlags = WHEX_ALL256;  // SHA256 | SHA3_256 | BLAKE2s | BLAKE3 | SM3
				}
				// 384-bit algorithms (96-byte)
				else if (ValidateHexSequence(pszStartOfLine, 96))
				{
					cchChecksum = 96;
					phvctx->whctxFlags = WHEX_ALL384;  // WHEX_CHECKSHA384 | WHEX_CHECKSHA3_384
				}
				// 512-bit algorithms (128-byte)
				else if (ValidateHexSequence(pszStartOfLine, 128))
				{
					cchChecksum = 128;
					phvctx->whctxFlags = WHEX_ALL512;  // SHA512 | SHA3_512 | BLAKE2b
				}
			}

			// Parse the line
			if ( phvctx->whctxFlags && pszEndOfLine > pszStartOfLine + cchChecksum &&
			     ValidateHexSequence(pszStartOfLine, cchChecksum) )
			{
				pszChecksum = pszStartOfLine;
				pszStartOfLine += cchChecksum + 1;

				// Skip over spaces between the checksum and filename
				while (*pszStartOfLine == TEXT(' '))
					++pszStartOfLine;

				if (*pszStartOfLine)
					pszFileName = pszStartOfLine;
			}
		}

		// Step 3: Do something useful with the results
		if (pszFileName && (cchPath = (INT16)(pszEndOfLine + 2 - pszFileName)) > 1)
		{
			// Since pszEndOfLine points to the character BEFORE the terminator,
			// cchLine == 1 + pszEnd - pszStart, and then +1 for the NULL
			// terminator means that we need to add 2 TCHARs to the length

			// By treating cchPath as INT16 and checking the sign, we ensure
			// that the path does not exceed 32K.

			// Create the new data block
			PHASHVERIFYITEM pItem = (PHASHVERIFYITEM)SLAddItem(phvctx->hList, NULL, sizeof(HASHVERIFYITEM));

			// Abort if we are out of memory
			if (!pItem) break;

			pItem->filesize.ui64 = -1;
			pItem->filesize.sz[0] = 0;
			pItem->pszDisplayName = pszFileName;
			pItem->pszExpected = pszChecksum;
			pItem->cchDisplayName = cchPath;
			pItem->nListviewIndex = phvctx->cTotal;
			pItem->bBeenSeen = FALSE;
			pItem->uStatusID = HV_STATUS_NULL;
			pItem->szActual[0] = 0;

			++phvctx->cTotal;

			// 1.4.9: 下一行是本条的 "; chk=" 注释——不符 = 该条损坏：
			// 紫底「损坏」、哈希列隐藏、不入哈希队列。
			// 1.5.2: 规范化把 CRLF 变 \n\n，pszData 此刻指向的是数据行
			// 终结符后的「空行」——用独立指针跳过伪影空行再判前缀。
			{
				const TCHAR *pszPeek = pszData;

				while (*pszPeek == TEXT(' ') || *pszPeek == TEXT('\n'))
					++pszPeek;

				if (pszPeek[0] == TEXT(';') && _tcsnicmp(pszPeek, TEXT("; chk="), 6) == 0)
				{
					TCHAR szExpect[65];
					const TCHAR *r = pszPeek + 6;
					int i;

					for (i = 0; i < 64 && *r && *r != TEXT('\n') &&
					     *r != TEXT('\r') && *r != TEXT(' '); ++i)
						szExpect[i] = *r++;
					szExpect[i] = 0;

					/* 1.5.3: 空串哈希指纹（旧版保存端 bug）= 无定位器，跳过 */
					if (i == 64 && lstrcmpi(szExpect, szChkEmptySha) != 0)
					{
						if (bChkReady && lstrcmpi(szExpect, szChkActual) != 0)
						{
							pItem->uStatusID = HV_STATUS_DAMAGED;
						}
					}
				}
			}

		} // If the current line was found to be valid

	} // Loop until there are no lines left

	// Build the index
	if ( phvctx->cTotal && (phvctx->index =
	     (PPHVITEM)SLSetContextSize(phvctx->hList, phvctx->cTotal * sizeof(PHVITEM))) )
	{
		SLBuildIndex(phvctx->hList, (PVOID*)phvctx->index);
	}
	else
	{
		phvctx->cTotal = 0;
	}
}

BOOL WINAPI ValidateHexSequence( PTSTR psz, UINT cch )
{
	// Check that the given hex string matches /[0-9A-Fa-f]{cch}\b/, and if it
	// does, convert to lower-case and NULL-terminate it.

	while (cch)
	{
		TCHAR ch = *psz;

		if (ch < TEXT('0'))
		{
			return(FALSE);
		}
		else if (ch > TEXT('9'))
		{
			ch |= 0x20; // Convert to lower-case

			if (ch < TEXT('a') || ch > TEXT('f'))
				return(FALSE);

			*psz = ch;
		}

		++psz;
		--cch;
	}

	if (*psz == 0 || *psz == TEXT('\n') || *psz == TEXT(' '))
	{
		*psz = 0;
		return(TRUE);
	}

	return(FALSE);
}



/*============================================================================*\
	"Newly-added" file detection
\*============================================================================*/

// Returns TRUE if the (relative) path is listed in the manifest, FALSE otherwise.
// Only the first cOrigTotal entries (the files actually parsed from the manifest)
// are consulted, so that files added by the scan itself are never matched.
BOOL WINAPI HashVerifyIsPathInList( PHASHVERIFYCONTEXT phvctx, PCTSTR pszPath, UINT cOrigTotal )
{
	UINT i;

	for (i = 0; i < cOrigTotal; ++i)
	{
		PCTSTR pszA = phvctx->index[i]->pszDisplayName;
		PCTSTR pszB = pszPath;

		// Strip a leading ".\" from either side, as some manifests store it
		if (pszA[0] == TEXT('.') && pszA[1] == TEXT('\\'))
			pszA += 2;
		if (pszB[0] == TEXT('.') && pszB[1] == TEXT('\\'))
			pszB += 2;

		// Compare case-insensitively, treating '/' the same as '\'
		while (*pszA && *pszB)
		{
			TCHAR ca = *pszA, cb = *pszB;
			if (ca == TEXT('/')) ca = TEXT('\\');
			if (cb == TEXT('/')) cb = TEXT('\\');
			if (ca >= TEXT('a') && ca <= TEXT('z')) ca -= TEXT('a') - TEXT('A');
			if (cb >= TEXT('a') && cb <= TEXT('z')) cb -= TEXT('a') - TEXT('A');
			if (ca != cb)
				break;
			++pszA;
			++pszB;
		}
		if (!*pszA && !*pszB)
			return(TRUE);
	}

	return(FALSE);
}

// Walks the directory tree rooted at pszDir (a full path WITHOUT a trailing '\'),
// and appends a "newly-added" item to the list for every file on disk that is NOT
// listed in the checksum manifest.  pszDir is used as a scratch buffer: its length
// (cchDir) grows as subdirectories are entered and shrinks as they are left.
// cchPrefix is the length of the manifest's folder prefix INCLUDING the trailing
// '\', so that pszDir + cchPrefix yields the manifest-relative path.
VOID WINAPI HashVerifyScanDir( PHASHVERIFYCONTEXT phvctx, PTSTR pszDir, UINT cchDir,
                               UINT cchPrefix, UINT cOrigTotal )
{
	HANDLE hFind;
	WIN32_FIND_DATA wfd;

	PTSTR pszAppend = pszDir + cchDir;

	if (cchDir + 3 >= MAX_PATH_BUFFER)
		return;  // Path too long; skip this subtree

	// Build the "dir\*" search pattern
	pszAppend[0] = TEXT('\\');
	pszAppend[1] = TEXT('*');
	pszAppend[2] = 0;

	if ((hFind = FindFirstFile(pszDir, &wfd)) == INVALID_HANDLE_VALUE)
	{
		pszDir[cchDir] = 0;  // restore: back to "dir"
		return;
	}

	do
	{
		// Skip "." and ".."
		if (wfd.cFileName[0] == TEXT('.'))
		{
			if (wfd.cFileName[1] == 0 ||
			    (wfd.cFileName[1] == TEXT('.') && wfd.cFileName[2] == 0))
			{
				continue;
			}
		}

		UINT cchName = (UINT)SSLen(wfd.cFileName);
		if (cchDir + 1 + cchName + 1 >= MAX_PATH_BUFFER)
			continue;

		// Append "\name"; after this the buffer is "dir\name" (NULL-terminated)
		pszAppend[0] = TEXT('\\');
		memcpy(pszAppend + 1, wfd.cFileName, (cchName + 1) * sizeof(TCHAR));
		UINT cchFull = cchDir + 1 + cchName;  // length of "dir\name"

		if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			// Directory: recurse into "dir\name"
			HashVerifyScanDir(phvctx, pszDir, cchFull, cchPrefix, cOrigTotal);
			pszDir[cchDir] = 0;  // restore: back to "dir"
		}
		else
		{
			// File: skip the checksum file itself, then check the manifest
			if (StrCmpI(pszDir, phvctx->pszPath) != 0)
			{
				PCTSTR pszRel = pszDir + cchPrefix;  // path relative to the manifest's folder
				if (!HashVerifyIsPathInList(phvctx, pszRel, cOrigTotal))
				{
					PTSTR pszStored = (PTSTR)SLAddStringI(phvctx->hNewPaths, pszRel);
					if (pszStored)
					{
						PHVITEM pItem = (PHVITEM)SLAddItem(phvctx->hList, NULL, sizeof(HASHVERIFYITEM));
						if (pItem)
						{
							pItem->filesize.ui64 = ((ULONGLONG)wfd.nFileSizeHigh << 32) | wfd.nFileSizeLow;
							StrFormatKBSize(pItem->filesize.ui64, pItem->filesize.sz, countof(pItem->filesize.sz));
							pItem->pszDisplayName = pszStored;
							pItem->pszExpected = TEXT("");   // no expected checksum for a new file
							pItem->cchDisplayName = (INT16)((UINT)SSLen(pszStored) + 1);
							pItem->nListviewIndex = phvctx->cTotal;
							pItem->bBeenSeen = FALSE;
							pItem->uStatusID = HV_STATUS_NEW;
							pItem->szActual[0] = 0;
							++phvctx->cTotal;
							++phvctx->cNew;
						}
					}
				}
			}

			pszDir[cchDir] = 0;  // restore: back to "dir"
		}
	} while (FindNextFile(hFind, &wfd));

	FindClose(hFind);
}

// Entry point for the "newly-added" scan.  Runs after the manifest has been
// parsed, before the dialog is shown: scans the folder that contains the
// checksum file and flags every file that exists on disk but is absent from the
// manifest as "新增" (HV_STATUS_NEW).  The list index is rebuilt afterwards so
// the new items show up in the list view.
VOID WINAPI HashVerifyScanForNewFiles( PHASHVERIFYCONTEXT phvctx )
{
	PTSTR pszSlash;
	UINT cchDir, cchPrefix, cOrigTotal;

	// Only scan when there is at least one manifest entry to compare against,
	// otherwise every file in the folder would show up as "new"
	if (!phvctx->cTotal || !phvctx->index)
		return;

	cOrigTotal = phvctx->cTotal;

	// Determine the folder of the checksum file (excluding the trailing '\')
	pszSlash = StrRChr(phvctx->pszPath, NULL, TEXT('\\'));
	if (!pszSlash)
		return;

	cchDir = (UINT)(pszSlash - phvctx->pszPath);
	cchPrefix = cchDir + 1;  // relative-path prefix = folder length + trailing '\'
	if (cchDir + 2 >= MAX_PATH_BUFFER)
		return;

	// Storage for the new paths (so their display names outlive the scan)
	phvctx->hNewPaths = SLCreate();
	if (!phvctx->hNewPaths)
		return;

	// Build the folder path into a scratch buffer, then walk it
	{
		TCHAR szDir[MAX_PATH_BUFFER];
		memcpy(szDir, phvctx->pszPath, cchDir * sizeof(TCHAR));
		szDir[cchDir] = 0;
		HashVerifyScanDir(phvctx, szDir, cchDir, cchPrefix, cOrigTotal);
	}

	// If any new items were added, grow the index and rebuild it
	if (phvctx->cTotal != cOrigTotal)
	{
		PPHVITEM pIndex = (PPHVITEM)SLSetContextSize(phvctx->hList, phvctx->cTotal * sizeof(PHVITEM));
		if (pIndex)
		{
			phvctx->index = pIndex;
			SLBuildIndex(phvctx->hList, (PVOID*)phvctx->index);
		}
	}
}

// Flags manifest files that are absent from disk as "缺失" (HV_STATUS_UNREADABLE)
// before the dialog is shown, so they display as missing immediately instead of
// only after the worker fails to read them.  Only the first cOrigTotal entries
// (the files parsed from the manifest) are checked.
VOID WINAPI HashVerifyScanForMissingFiles( PHASHVERIFYCONTEXT phvctx )
{
	PTSTR pszSlash;
	UINT cchDir, cchPrefix, i;

	if (!phvctx->cOrigTotal || !phvctx->index)
		return;

	// Determine the folder of the checksum file (excluding the trailing '\')
	pszSlash = StrRChr(phvctx->pszPath, NULL, TEXT('\\'));
	if (!pszSlash)
		return;

	cchDir = (UINT)(pszSlash - phvctx->pszPath);
	cchPrefix = cchDir + 1;  // relative-path prefix = folder length + trailing '\'

	for (i = 0; i < phvctx->cOrigTotal; ++i)
	{
		PHASHVERIFYITEM pItem = phvctx->index[i];
		TCHAR szPath[MAX_PATH_BUFFER];
		SIZE_T cchPrefixUse = cchPrefix;

		// Absolute paths are checked verbatim; relative paths are resolved
		// against the checksum file's folder (mirrors the worker's path build)
		if (pItem->pszDisplayName[0] == TEXT('\\') ||
		    pItem->pszDisplayName[1] == TEXT(':'))
			cchPrefixUse = 0;

		SSChainNCpy2(szPath, phvctx->pszPath, cchPrefixUse,
		             pItem->pszDisplayName, pItem->cchDisplayName);

		if (GetFileAttributes(szPath) == INVALID_FILE_ATTRIBUTES)
		{
			pItem->uStatusID = HV_STATUS_UNREADABLE;
			++phvctx->cUnreadable;
			++phvctx->cMissing;
		}
	}
}



/*============================================================================*\
	Worker thread
\*============================================================================*/

VOID __fastcall HashVerifyWorkerMain( PHASHVERIFYCONTEXT phvctx )
{
	// Note that ALL message communication to and from the main window MUST
	// be asynchronous, or else there may be a deadlock

	// Initialize the path prefix length; used for building the full path
	PTSTR pszPathTail = StrRChr(phvctx->pszPath, NULL, TEXT('\\'));
	SIZE_T cchPathPrefix = (pszPathTail) ? pszPathTail + 1 - phvctx->pszPath : 0;

// Force single-threaded hashing. Parallel hashing (ConcRT/PPL) combined with
    // pause -> cancel is fragile: signaling the pause event wakes every worker
    // thread at once, so they all throw CanceledException simultaneously, which
    // the Concurrency runtime does not handle gracefully and can crash. Serial
    // hashing is reliable and fast enough for a verification tool.
    const bool bMultithreaded = false;

    concurrency::concurrent_vector<void*> vecBuffers;  // unused (single-threaded)
    DWORD dwBufferTlsIndex = TLS_OUT_OF_INDEXES;       // unused (single-threaded)

    PBYTE pbTheBuffer;  // filename/read buffer, used iff not multithreaded
    if (! bMultithreaded)
    {
        pbTheBuffer = (PBYTE)VirtualAlloc(NULL, READ_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);
        if (pbTheBuffer == NULL)
            return;
    }

    // Initialize the progress bar update synchronization vars
    CRITICAL_SECTION updateCritSec;
    volatile ULONGLONG cbCurrentMaxSize = 0;
    if (bMultithreaded)
        InitializeCriticalSection(&updateCritSec);

	// We need to keep track of the thread's execution time so that we can do a
	// sound notification of completion when appropriate
	phvctx->dwStarted = GetTickCount();

    class CanceledException {};

    // concurrency::parallel_for_each(...); only the manifest's own files are hashed
    auto per_file_worker = [&](PHASHVERIFYITEM pItem)
	{
        PBYTE pbBuffer;
#ifdef USE_PPL
        if (bMultithreaded)
        {
            // Allocate or retrieve the already-allocated read buffer for the current thread
            pbBuffer = (PBYTE)TlsGetValue(dwBufferTlsIndex);
            if (pbBuffer == NULL)
            {
                pbBuffer = (PBYTE)VirtualAlloc(NULL, READ_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);
                if (pbBuffer == NULL)
                    throw CanceledException();
                // Cache the read buffer for the current thread
                vecBuffers.push_back(pbBuffer);
                TlsSetValue(dwBufferTlsIndex, pbBuffer);
            }
        }
        else
#endif
            pbBuffer = pbTheBuffer;

		// Part 1: Build the path
		{
			SIZE_T cchPrefix = cchPathPrefix;

			// Do not use the prefix if pszDisplayName is an absolute path
			if ( pItem->pszDisplayName[0] == TEXT('\\') ||
			     pItem->pszDisplayName[1] == TEXT(':') )
			{
				cchPrefix = 0;
			}

			SSChainNCpy2(
                (PTSTR)pbBuffer,
				phvctx->pszPath, cchPrefix,
				pItem->pszDisplayName, pItem->cchDisplayName
			);
		}

		// Part 2: Calculate the checksum(s)
        WHCTXEX whctx;
        WHRESULTEX whres;
        whctx.dwFlags = phvctx->whctxFlags;
        whres.dwFlags = 0;
		WorkerThreadHashFile(
			(PCOMMONCONTEXT)phvctx,
            (PTSTR)pbBuffer,
			&whctx,
			&whres,
            pbBuffer,
			&pItem->filesize,
            pItem->nListviewIndex,
            bMultithreaded ? &updateCritSec : NULL, &cbCurrentMaxSize
#ifdef _TIMED
          , NULL
#endif
        );

        if (phvctx->status == PAUSED)
            WaitForSingleObject(phvctx->hUnpauseEvent, INFINITE);
		if (phvctx->status == CANCEL_REQUESTED)
            throw CanceledException();

		// Part 3: Do something with the results
		if (whres.dwFlags)
		{
            UINT cHashes = 0;
            DWORD dwMatched = 0;
            PTSTR pszActual = NULL;

#define HASH_VERIFY_ONE_HASH_op(alg)                                  \
            if (whres.dwFlags & WHEX_CHECK##alg)                      \
            {                                                         \
                cHashes++;                                            \
                if (! dwMatched)                                      \
                {                                                     \
                    pszActual = whres.szHex##alg;                     \
                    if (StrCmpI(pItem->pszExpected, pszActual) == 0)  \
                        dwMatched = WHEX_CHECK##alg;                  \
                }                                                     \
            }
            FOR_EACH_HASH(HASH_VERIFY_ONE_HASH_op)

            assert(cHashes > 0);  // should always be true since whres.dwFlags > 0
            assert(pszActual);
            if (dwMatched)
            {
                pItem->uStatusID = HV_STATUS_MATCH;
                
                StringCbCopy(pItem->szActual, sizeof(pItem->szActual), pszActual);
                if (cHashes > 1 && phvctx->whctxFlags != dwMatched)
                    phvctx->whctxFlags = dwMatched;
            }
            else
            {
                pItem->uStatusID = HV_STATUS_MISMATCH;
                if (cHashes == 1)
                    StringCbCopy(pItem->szActual, sizeof(pItem->szActual), pszActual);
            }
		}
		else
		{
			pItem->uStatusID = HV_STATUS_UNREADABLE;
		}

		// Part 4: Update the UI
		++phvctx->cSentMsgs;
		PostMessage(phvctx->hWnd, HM_WORKERTHREAD_UPDATE, (WPARAM)phvctx, (LPARAM)pItem);
    };

    try
    {
#ifdef USE_PPL
        if (bMultithreaded)
            concurrency::parallel_for_each(phvctx->queue, phvctx->queue + phvctx->cQueue, per_file_worker);
        else
#endif
            std::for_each(phvctx->queue, phvctx->queue + phvctx->cQueue, per_file_worker);
    }
    catch (CanceledException) {}  // ignore cancellation requests

#ifdef USE_PPL
    if (bMultithreaded)
    {
        for (void* pBuffer : vecBuffers)
            VirtualFree(pBuffer, 0, MEM_RELEASE);
        DeleteCriticalSection(&updateCritSec);
    }
    else
#endif
        VirtualFree(pbTheBuffer, 0, MEM_RELEASE);

	// Play a sound to signal the normal, successful termination of operations,
	// but exempt operations that were nearly instantaneous
	if (phvctx->cTotal && GetTickCount() - phvctx->dwStarted >= 2000)
		MessageBeep(MB_ICONASTERISK);
}

VOID WINAPI HashVerifyStartHashing( PHASHVERIFYCONTEXT phvctx, BOOL bPriority, BOOL bIncludeRest )
{
	UINT i, cTotal2Hash = 0, cQueued = 0;
	PPHVITEM queue;

	// Ignore the click while a batch is already running
	if (phvctx->status == ACTIVE || phvctx->status == PAUSED)
		return;

	// Refresh our copy of the selection states if we need the selected files
	if (bPriority)
		HashVerifyReadStates(phvctx);

	// Count the files to hash this run: unhashed manifest files only ("新增"/NEW
	// files are never hashed). In priority mode, selected files go first; the
	// unselected files are also included when bIncludeRest is set (mid-run
	// reprioritization), so they follow the selected ones.
	for (i = 0; i < phvctx->cOrigTotal; ++i)
	{
		PHASHVERIFYITEM pItem = phvctx->index[i];
		if (pItem->uStatusID != HV_STATUS_NULL)
			continue;
		if (!bPriority || (pItem->uState & LVIS_SELECTED) || bIncludeRest)
			++cTotal2Hash;
	}

	// Nothing selected (or nothing left); signal and do nothing
	if (!cTotal2Hash)
	{
		if (bPriority)
			MessageBeep(MB_ICONEXCLAMATION);
		return;
	}

	queue = (PPHVITEM)malloc(cTotal2Hash * sizeof(PHVITEM));
	if (!queue)
		return;

	// First pass: the selected files (or, in non-priority mode, all unhashed files)
	for (i = 0; i < phvctx->cOrigTotal; ++i)
	{
		PHASHVERIFYITEM pItem = phvctx->index[i];
		if (pItem->uStatusID != HV_STATUS_NULL)
			continue;
		if (bPriority && !(pItem->uState & LVIS_SELECTED))
			continue;
		queue[cQueued++] = pItem;
	}

	// Second pass: the unselected (unhashed) files, only when reprioritizing mid-run
	if (bIncludeRest)
	{
		for (i = 0; i < phvctx->cOrigTotal; ++i)
		{
			PHASHVERIFYITEM pItem = phvctx->index[i];
			if (pItem->uStatusID != HV_STATUS_NULL)
				continue;
			if (pItem->uState & LVIS_SELECTED)
				continue;
			queue[cQueued++] = pItem;
		}
	}

	// Replace any previous queue and start hashing
	free(phvctx->queue);
	phvctx->queue  = queue;
	phvctx->cQueue = cQueued;

	// While hashing, "暂停"/"继续" toggles pause; "优先" is disabled
	SetControlText(phvctx->hWnd, IDC_PAUSE, IDS_HV_PAUSE);
	EnableControl(phvctx->hWnd, IDC_PAUSE, TRUE);
	EnableControl(phvctx->hWnd, IDC_STOP, FALSE);
	// 恢复进度条为正常(绿)：暂停后点「优先」重启会绕过暂停/继续的着色切换
	SetProgressBarPause((PCOMMONCONTEXT)phvctx, PBST_NORMAL);

	// Preserve the overall progress counts across a mid-run restart: the worker
	// thread startup zeroes cSentMsgs/cHandledMsgs, which would otherwise reset
	// the total progress bar to show only the files hashed after a "优先" reprioritization.
	MSGCOUNT cSentMsgs = phvctx->cSentMsgs, cHandledMsgs = phvctx->cHandledMsgs;
	phvctx->hThread = CreateThreadCRT(NULL, phvctx);
	if (!phvctx->hThread)
		WorkerThreadCleanup((PCOMMONCONTEXT)phvctx);
	phvctx->cSentMsgs = cSentMsgs;
	phvctx->cHandledMsgs = cHandledMsgs;
}



/*============================================================================*\
	Dialog general
\*============================================================================*/

INT_PTR CALLBACK HashVerifyDlgProc( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam )
{
	PHASHVERIFYCONTEXT phvctx;

	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			phvctx = (PHASHVERIFYCONTEXT)lParam;

			// Associate the window with the context and vice-versa
			phvctx->hWnd = hWnd;
			SetWindowLongPtr(hWnd, DWLP_USER, (LONG_PTR)phvctx);

			SetAppIDForWindow(hWnd, TRUE);

			HashVerifyDlgInit(phvctx);

			phvctx->pfnWorkerMain = (PFNWORKERMAIN)HashVerifyWorkerMain;

			// Do not auto-start hashing; open in a "standby" state instead.
			// The user selects files and clicks "优先", or clicks "开始" for the rest.
			phvctx->queue  = NULL;
			phvctx->cQueue = 0;
			phvctx->hWndPBTotal = GetDlgItem(hWnd, IDC_PROG_TOTAL);
			phvctx->hWndPBFile  = GetDlgItem(hWnd, IDC_PROG_FILE);

			// Initialize the summary; progress covers only the manifest's files
			SendMessage(phvctx->hWndPBTotal, PBM_SETRANGE32, 0,
			(phvctx->cOrigTotal > phvctx->cMissing + phvctx->cDamaged) ?
				phvctx->cOrigTotal - phvctx->cMissing - phvctx->cDamaged : 0);
			SendMessage(phvctx->hWndPBTotal, PBM_SETPOS, 0, 0);
			HashVerifyUpdateSummary(phvctx, NULL);

			// Standby controls: "开始" (IDC_PAUSE) and "优先" (IDC_STOP)
			SetControlText(hWnd, IDC_PAUSE, IDS_HV_START);
			EnableControl(hWnd, IDC_PAUSE, TRUE);
			EnableControl(hWnd, IDC_STOP, TRUE);

			return(TRUE);
		}

		case WM_DESTROY:
		{
			SetAppIDForWindow(hWnd, FALSE);
			break;
		}

		case WM_ENDSESSION:
        {
            if (wParam == FALSE)  // if TRUE, fall through to WM_CLOSE
                break;
        }
		case WM_CLOSE:
		{
			phvctx = (PHASHVERIFYCONTEXT)GetWindowLongPtr(hWnd, DWLP_USER);
			goto cleanup_and_exit;
		}

		case WM_COMMAND:
		{
			phvctx = (PHASHVERIFYCONTEXT)GetWindowLongPtr(hWnd, DWLP_USER);

			switch (LOWORD(wParam))
			{
				case IDC_PAUSE:
				{
					if (phvctx->status == ACTIVE || phvctx->status == PAUSED)
					{
						WorkerThreadTogglePause((PCOMMONCONTEXT)phvctx);
						// 暂停时允许中途优先，运行时禁用
						EnableControl(phvctx->hWnd, IDC_STOP, phvctx->status == PAUSED);
					}
					else
						HashVerifyStartHashing(phvctx, FALSE, FALSE);  // "开始": hash all
					return(TRUE);
				}

				case IDC_STOP:  // "优先" (算完前) / "整理" (算完后)
				{
					if (phvctx->status == CLEANUP_COMPLETED)
					{
						if (phvctx->cHandledMsgs >= phvctx->cOrigTotal - phvctx->cMissing)
							HashVerifySortByStatus(phvctx);  // 全部算完：整理
						else
							HashVerifyStartHashing(phvctx, TRUE, FALSE);  // 部分算完：再次优先算选中
					}
					else if (phvctx->status == ACTIVE || phvctx->status == PAUSED)
					{
						// 中途优先：停止当前 worker，选中文件插队后重启
						// HCF_RESTARTING 抑制旧 worker 的 DONE 消息，避免与新 worker 竞态
						phvctx->dwFlags |= HCF_RESTARTING;
						WorkerThreadStop((PCOMMONCONTEXT)phvctx);
						WorkerThreadCleanup((PCOMMONCONTEXT)phvctx);
						phvctx->dwFlags &= ~HCF_RESTARTING;
						HashVerifyStartHashing(phvctx, TRUE, TRUE);
					}
					else
					{
						// 待命：只算选中的文件
						HashVerifyStartHashing(phvctx, TRUE, FALSE);
					}
					return(TRUE);
				}

				case IDC_EXIT:
				{
					cleanup_and_exit:
					phvctx->dwFlags |= HCF_EXIT_PENDING;
					WorkerThreadStop((PCOMMONCONTEXT)phvctx);
					WorkerThreadCleanup((PCOMMONCONTEXT)phvctx);
					free(phvctx->queue);
					phvctx->queue = NULL;
					EndDialog(hWnd, 0);
					break;
				}
			}

			break;
		}

		case WM_NOTIFY:
		{
			LPNMHDR pnm = (LPNMHDR)lParam;

			if (pnm && pnm->idFrom == IDC_LIST)
			{
				phvctx = (PHASHVERIFYCONTEXT)GetWindowLongPtr(hWnd, DWLP_USER);

				switch (pnm->code)
				{
						case LVN_KEYDOWN:
						{
							if (((LPNMLVKEYDOWN)lParam)->wVKey == (WPARAM)'C' &&
							    (GetKeyState(VK_CONTROL) < 0))
							{
								HashVerifyCopySelection(phvctx);
								return(TRUE);
							}
							break;
						}

					case LVN_GETDISPINFO:
					{
						HashVerifyListInfo(phvctx, (LPNMLVDISPINFO)lParam);
						return(TRUE);
					}
					case NM_CUSTOMDRAW:
					{
						SetWindowLongPtr(hWnd, DWLP_MSGRESULT, HashVerifySetColor(phvctx, (LPNMLVCUSTOMDRAW)lParam));
						return(TRUE);
					}
					case LVN_ODFINDITEM:
					{
						SetWindowLongPtr(hWnd, DWLP_MSGRESULT, HashVerifyFindItem(phvctx, (LPNMLVFINDITEM)lParam));
						return(TRUE);
					}
					case LVN_COLUMNCLICK:
					{
						HashVerifySortColumn(phvctx, (LPNMLISTVIEW)lParam);
						return(TRUE);
					}
					case LVN_ITEMCHANGED:
					{
						if (((LPNMLISTVIEW)lParam)->uChanged & LVIF_STATE)
							phvctx->bFreshStates = FALSE;
						break;
					}
					case LVN_ODSTATECHANGED:
					{
						phvctx->bFreshStates = FALSE;
						break;
					}
				}
			}

			break;
		}

		case WM_TIMER:
		{
			// Vista: Workaround to fix their buggy progress bar
			KillTimer(hWnd, TIMER_ID_PAUSE);
			phvctx = (PHASHVERIFYCONTEXT)GetWindowLongPtr(hWnd, DWLP_USER);
			if (phvctx->status == PAUSED)
				SetProgressBarPause((PCOMMONCONTEXT)phvctx, PBST_PAUSED);
			return(TRUE);
		}

		case HM_WORKERTHREAD_DONE:
		{
			phvctx = (PHASHVERIFYCONTEXT)wParam;
			WorkerThreadCleanup((PCOMMONCONTEXT)phvctx);

			// Hashing finished. The "开始" button becomes a disabled "完成" label
			// (no further hashing), and the progress bars stay filled/visible.
			if (!(phvctx->dwFlags & HCF_EXIT_PENDING))
			{
				if (phvctx->cHandledMsgs >= phvctx->cOrigTotal - phvctx->cMissing)
				{
					// 全部算完：完成（禁用）+ 整理
					SetControlText(phvctx->hWnd, IDC_PAUSE, IDS_HV_DONE);
					ShowWindow(GetDlgItem(phvctx->hWnd, IDC_PAUSE), SW_SHOW);   // WorkerThreadCleanup 已隐藏，需重新显示
					EnableWindow(GetDlgItem(phvctx->hWnd, IDC_PAUSE), FALSE);   // 禁用但可见
					SetControlText(phvctx->hWnd, IDC_STOP, IDS_HV_SORT);  // 整理
					EnableControl(phvctx->hWnd, IDC_STOP, TRUE);
				}
				else
				{
					// 只算了一部分（如仅优先算了选中文件）：继续 + 优先
					SetControlText(phvctx->hWnd, IDC_PAUSE, IDS_HC_RESUME);
					EnableControl(phvctx->hWnd, IDC_PAUSE, TRUE);
					SetControlText(phvctx->hWnd, IDC_STOP, IDS_HV_PRIORITY);
					EnableControl(phvctx->hWnd, IDC_STOP, TRUE);
				}
				EnableControl(phvctx->hWnd, IDC_PROG_TOTAL, TRUE);
				EnableControl(phvctx->hWnd, IDC_PROG_FILE, TRUE);

				// 强制刷新列表和摘要，确保算完后的状态列与统计都显示出来
				ListView_RedrawItems(phvctx->hWndList, 0, phvctx->cTotal);
				InvalidateRect(phvctx->hWndList, NULL, FALSE);
				HashVerifyUpdateSummary(phvctx, NULL);
			}
			return(TRUE);
		}

		case HM_WORKERTHREAD_UPDATE:
		{
			phvctx = (PHASHVERIFYCONTEXT)wParam;
			++phvctx->cHandledMsgs;
			HashVerifyUpdateSummary(phvctx, (PHASHVERIFYITEM)lParam);
			return(TRUE);
		}

		case HM_WORKERTHREAD_SETSIZE:
		{
			phvctx = (PHASHVERIFYCONTEXT)wParam;
			assert(lParam >= 0 && (UINT)lParam < phvctx->cTotal);
			if (phvctx->index[lParam]->bBeenSeen)
				ListView_RedrawItems(phvctx->hWndList, lParam, lParam);
			return(TRUE);
		}
	}

	return(FALSE);
}

VOID WINAPI HashVerifyDlgInit( PHASHVERIFYCONTEXT phvctx )
{
	HWND hWnd = phvctx->hWnd;
	UINT i;

	// Load strings
	{
		static const UINT16 arStrMap[][2] =
		{
			{ IDC_SUMMARY,          IDS_HV_SUMMARY    },
			{ IDC_MATCH_LABEL,      IDS_HV_MATCH      },
			{ IDC_MISMATCH_LABEL,   IDS_HV_MISMATCH   },
			{ IDC_UNREADABLE_LABEL, IDS_HV_UNREADABLE },
			{ IDC_PENDING_LABEL,    IDS_HV_PENDING    },
			{ IDC_NEW_LABEL,        IDS_HV_NEW        },
			{ IDC_PAUSE,            IDS_HV_START      },
			{ IDC_STOP,             IDS_HV_PRIORITY   },
				{ IDC_TIME_LABEL,       IDS_HV_TIME       }
			};

		for (i = 0; i < countof(arStrMap); ++i)
			SetControlText(hWnd, arStrMap[i][0], arStrMap[i][1]);

		// Show the timestamp embedded in the checksum file
		SetDlgItemText(hWnd, IDC_TIME_RESULTS, phvctx->szTimestamp);
	}

	// 1.4.4: fingerprint banner for untrusted signers (the user chose not to
	// trust in the TOFU prompt) -- stays visible for the whole session
	if (phvctx->szForeignFingerprint[0])
	{
		TCHAR szBanner[160];

		StringCchPrintf(szBanner, countof(szBanner),
		                L"签名者：其他设备（指纹 %s）——请核对来源后再使用",
		                phvctx->szForeignFingerprint);
		SetDlgItemText(hWnd, IDC_FP_BANNER, szBanner);
	}

	// Set the window icon and title
	{
		PTSTR pszFileName = StrRChr(phvctx->pszPath, NULL, TEXT('\\'));

		if (!(pszFileName && *++pszFileName))
			pszFileName = phvctx->pszPath;

		SendMessage(
			hWnd,
			WM_SETTEXT,
			0,
			(LPARAM)pszFileName
		);

		SendMessage(
			hWnd,
			WM_SETICON,
			ICON_BIG, // No need to explicitly set the small icon
			(LPARAM)LoadIcon(g_hModThisDll, MAKEINTRESOURCE(IDI_FILETYPE))
		);
	}

	// Initialize the list box
	{
		typedef struct {
			UINT16 iStringID;
			UINT16 iAlign;
			UINT16 iWidth;
		} COLINFO, *PCOLINFO;

		static const COLINFO arCols[] =
		{
			{ IDS_HV_COL_FILENAME, LVCFMT_LEFT,  245 },
			{ IDS_HV_COL_SIZE,     LVCFMT_RIGHT,  64 },
			{ IDS_HV_COL_STATUS,   LVCFMT_CENTER, 64 },
			{ IDS_HV_COL_EXPECTED, LVCFMT_CENTER,  0 },
			{ IDS_HV_COL_ACTUAL,   LVCFMT_CENTER,  0 },
		};

		// We will be using the list window handle a lot throughout HashVerify,
		// so we should cache it to reduce the number of lookups
		phvctx->hWndList = GetDlgItem(hWnd, IDC_LIST);

		for (i = 0; i < countof(arCols); ++i)
		{
			TCHAR szBuffer[MAX_STRINGRES];
			LVCOLUMN lvc;
			RECT rc;

			LoadString(g_hModThisDll, arCols[i].iStringID, szBuffer, countof(szBuffer));

			rc.left = arCols[i].iWidth;

			if (rc.left == 0)
			{
                if (phvctx->whctxFlags & WHEX_ALL512)
                    rc.left = 512 + 20;
                else if (phvctx->whctxFlags & WHEX_ALL256)
                    rc.left = 256 + 20;
                else if (phvctx->whctxFlags & WHEX_ALL160)
                    rc.left = 160 + 20;
                else if (phvctx->whctxFlags & WHEX_ALL128)
                    rc.left = 128 + 20;
                else if (phvctx->whctxFlags & WHEX_ALL32)
                    rc.left =  32 + 20 + 40;  // extra size to accommodate the header labels
			}

			MapDialogRect(hWnd, &rc);

			lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH;
			lvc.fmt = arCols[i].iAlign;
			lvc.cx = rc.left;
			lvc.pszText = szBuffer;

			ListView_InsertColumn(phvctx->hWndList, i, &lvc);
		}

		ListView_SetExtendedListViewStyle(phvctx->hWndList, LISTVIEW_EXSTYLES);
		ListView_SetItemCount(phvctx->hWndList, phvctx->cTotal);

		// Use the new-fangled list view style for Vista
		if (g_uWinVer >= 0x0600)
			SetWindowTheme(phvctx->hWndList, L"Explorer", NULL);

		phvctx->sort.iColumn = -1;
	}

	// Initialize the status strings
	{
		UINT i;

		for (i = 1; i <= 5; ++i)
		{
			// 1.5.3: DAMAGED 的资源 ID（0x4416）不在这个连续序列里
			// （1.4.9 因 0x4410 与 IDS_HV_NEW 撞号挪走）——连续公式
			// 会把「新增:」按钮串加载进状态列，特判改用真 ID
			LoadString(
				g_hModThisDll,
				(i == HV_STATUS_DAMAGED) ? IDS_HV_STATUS_DAMAGED
				                         : i + (IDS_HV_STATUS_MATCH - 1),
				phvctx->szStatus[i],
				countof(phvctx->szStatus[i])
			);
		}
	}

	// Initialize miscellaneous stuff
	{
		phvctx->uMaxBatch = (phvctx->cTotal < (0x20 << 8)) ? 0x20 : phvctx->cTotal >> 8;
		phvctx->dwStarted = 0;
        phvctx->hThread = NULL;
        phvctx->hUnpauseEvent = NULL;
	}
}



/*============================================================================*\
	Dialog status
\*============================================================================*/

VOID WINAPI HashVerifyUpdateSummary( PHASHVERIFYCONTEXT phvctx, PHASHVERIFYITEM pItem )
{
	HWND hWnd = phvctx->hWnd;
	TCHAR szFormat[MAX_STRINGRES], szBuffer[MAX_STRINGMSG];

	// If this is not the initial update and we are lagging, and our update
	// drought is not TOO long, then we should skip the update...
    UINT cUnhandledMsgs = phvctx->cSentMsgs - phvctx->cHandledMsgs;
    BOOL bUpdateUI = pItem == NULL || cUnhandledMsgs == 0 || cUnhandledMsgs > phvctx->uMaxBatch;

	// Update the list
	if (pItem)
	{
		switch (pItem->uStatusID)
		{
			case HV_STATUS_MATCH:
				++phvctx->cMatch;
				break;
			case HV_STATUS_MISMATCH:
				++phvctx->cMismatch;
				break;
			case HV_STATUS_NEW:
				++phvctx->cNew;
				break;
			default:
				++phvctx->cUnreadable;
		}

		if (pItem->bBeenSeen)
		{
			ListView_RedrawItems(
				phvctx->hWndList,
				pItem->nListviewIndex,
				pItem->nListviewIndex
			);
		}
	}

	// Update the counts and progress bar
	if (bUpdateUI)
	{
		// FormatFractionalResults expects an empty format buffer on the first call
		szFormat[0] = 0;

		if (!pItem || phvctx->prev.cMatch != phvctx->cMatch)
		{
			FormatFractionalResults(szFormat, szBuffer, phvctx->cMatch, phvctx->cTotal);
			SetDlgItemText(hWnd, IDC_MATCH_RESULTS, szBuffer);
		}

		if (!pItem || phvctx->prev.cMismatch != phvctx->cMismatch)
		{
			FormatFractionalResults(szFormat, szBuffer, phvctx->cMismatch, phvctx->cTotal);
			SetDlgItemText(hWnd, IDC_MISMATCH_RESULTS, szBuffer);
		}

		if (!pItem || phvctx->prev.cUnreadable != phvctx->cUnreadable)
		{
			FormatFractionalResults(szFormat, szBuffer, phvctx->cUnreadable, phvctx->cTotal);
			SetDlgItemText(hWnd, IDC_UNREADABLE_RESULTS, szBuffer);
		}

		if (!pItem || phvctx->prev.cNew != phvctx->cNew)
		{
			FormatFractionalResults(szFormat, szBuffer, phvctx->cNew, phvctx->cTotal);
			SetDlgItemText(hWnd, IDC_NEW_RESULTS, szBuffer);
		}

		// Remaining = manifest files that have not been handled yet ("新增" files
		// are already accounted for in cNew and were never hashed)
		FormatFractionalResults(szFormat, szBuffer, phvctx->cOrigTotal - phvctx->cMissing - phvctx->cHandledMsgs, phvctx->cTotal);
		SetDlgItemText(hWnd, IDC_PENDING_RESULTS, szBuffer);

		SendMessage(phvctx->hWndPBTotal, PBM_SETPOS, phvctx->cHandledMsgs, 0);

		// Now that we've updated the UI, update the prev structure
		phvctx->prev.cMatch = phvctx->cMatch;
		phvctx->prev.cMismatch = phvctx->cMismatch;
		phvctx->prev.cUnreadable = phvctx->cUnreadable;
		phvctx->prev.cNew = phvctx->cNew;
	}

	// Update the header
	if (!(phvctx->dwFlags & HVF_HAS_SET_TYPE))
	{
		PCTSTR pszSubtitle = NULL;

		switch (phvctx->whctxFlags)
		{
#define HASH_VERIFY_TITLE_op(alg)  \
			case WHEX_CHECK##alg:  pszSubtitle = HASH_NAME_##alg;  break;
            FOR_EACH_HASH(HASH_VERIFY_TITLE_op)
		}

		if (pszSubtitle)
		{
			LoadString(g_hModThisDll, IDS_HV_SUMMARY, szFormat, countof(szFormat));
#ifndef _TIMED
			StringCchPrintf(szBuffer, countof(szBuffer), TEXT("%s (%s)"), szFormat, pszSubtitle);
			phvctx->dwFlags |= HVF_HAS_SET_TYPE;
#else
            StringCchPrintf(szBuffer, countof(szBuffer), TEXT("%s (%s) - %d ms"), szFormat, pszSubtitle,
                            phvctx->dwStarted ? GetTickCount() - phvctx->dwStarted : 0);
#endif
			SetDlgItemText(hWnd, IDC_SUMMARY, szBuffer);
		}
	}
}



/*============================================================================*\
	List management
\*============================================================================*/

VOID WINAPI HashVerifyListInfo( PHASHVERIFYCONTEXT phvctx, LPNMLVDISPINFO pdi )
{
	if ((UINT)pdi->item.iItem >= phvctx->cTotal)
		return;  // Invalid index; by casting to unsigned, we also catch negatives

	if (pdi->item.mask & LVIF_TEXT)
	{
		PHASHVERIFYITEM pItem = phvctx->index[pdi->item.iItem];

		switch (pdi->item.iSubItem)
		{
			case HV_COL_FILENAME: pdi->item.pszText = pItem->pszDisplayName;              break;
			case HV_COL_SIZE:     pdi->item.pszText = pItem->filesize.sz;                 break;
			case HV_COL_STATUS:   pdi->item.pszText = phvctx->szStatus[pItem->uStatusID]; break;
			case HV_COL_EXPECTED: pdi->item.pszText =
			                      (pItem->uStatusID == HV_STATUS_DAMAGED)
			                      ? (PTSTR)TEXT("")
			                      : pItem->pszExpected;                              break;
			case HV_COL_ACTUAL:   pdi->item.pszText = pItem->szActual;                    break;
			default:              pdi->item.pszText = TEXT("");                           break;
		}
        if (! pItem->bBeenSeen)
            pItem->bBeenSeen = TRUE;
	}

	if (pdi->item.mask & LVIF_IMAGE)
		pdi->item.iImage = I_IMAGENONE;

	// We can (and should) ignore LVIF_STATE
}

LONG_PTR WINAPI HashVerifySetColor( PHASHVERIFYCONTEXT phvctx, LPNMLVCUSTOMDRAW pcd )
{
	switch (pcd->nmcd.dwDrawStage)
	{
		case CDDS_PREPAINT:
			return(CDRF_NOTIFYITEMDRAW);

		case CDDS_ITEMPREPAINT:
		{
			// We need to determine the highlight state during the item stage
			// because this information becomes subitem-specific if we try to
			// retrieve it when we actually need it in the subitem stage

			if (g_uWinVer >= 0x0600 && IsAppThemed())
			{
				// Clear the highlight bit...
				phvctx->dwFlags &= ~HVF_ITEM_HILITE;

				// uItemState is buggy; if LVS_SHOWSELALWAYS is set, uItemState
				// will ALWAYS have the CDIS_SELECTED bit set, regardless of
				// whether the item is actually selected, so a more expensive
				// test for the LVIS_SELECTED bit is needed...
				if ( pcd->nmcd.uItemState & CDIS_HOT ||
				     ListView_GetItemState(pcd->nmcd.hdr.hwndFrom, pcd->nmcd.dwItemSpec, LVIS_SELECTED) )
				{
					phvctx->dwFlags |= HVF_ITEM_HILITE;
				}
			}

			return(CDRF_NOTIFYSUBITEMDRAW);
		}

		case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
		{
			PHASHVERIFYITEM pItem;

			if (pcd->nmcd.dwItemSpec >= phvctx->cTotal)
				break;  // Invalid index

			pItem = phvctx->index[pcd->nmcd.dwItemSpec];

			// By default, we use the default foreground and background colors
			// except when the item is a mismatch or is unreadable, in which
			// case, we change the foreground color
			switch (pItem->uStatusID)
			{
				case HV_STATUS_MISMATCH:
					pcd->clrText = RGB(0xC0, 0x00, 0x00);
					break;

				case HV_STATUS_UNREADABLE:
					pcd->clrText = RGB(0x80, 0x80, 0x80);
					break;

				default:
					pcd->clrText = CLR_DEFAULT;
			}

			pcd->clrTextBk = CLR_DEFAULT;

			// The status column, however, deserves special treatment
			if (pcd->iSubItem == HV_COL_STATUS)
			{
				if (phvctx->dwFlags & HVF_ITEM_HILITE)
				{
					// Vista-style highlighting means that the foreground
					// color can show through, but not the background color
					if (pItem->uStatusID == HV_STATUS_MATCH)
						pcd->clrText = RGB(0x00, 0x80, 0x00);
				}
				else
				{
					switch (pItem->uStatusID)
					{
						case HV_STATUS_MATCH:
							pcd->clrText = RGB(0x00, 0x00, 0x00);
							pcd->clrTextBk = RGB(0x00, 0xE0, 0x00);
							break;

						case HV_STATUS_MISMATCH:
							pcd->clrText = RGB(0xFF, 0xFF, 0xFF);
							pcd->clrTextBk = RGB(0xC0, 0x00, 0x00);
							break;

						case HV_STATUS_UNREADABLE:   // 缺失（1.4.9 深黄底白字）
							pcd->clrText = RGB(0xFF, 0xFF, 0xFF);
							pcd->clrTextBk = RGB(0xC8, 0xA0, 0x00);
							break;

						case HV_STATUS_NEW:          // 新增（1.4.9 钢蓝底白字）
							pcd->clrText = RGB(0xFF, 0xFF, 0xFF);
							pcd->clrTextBk = RGB(0x1E, 0x5E, 0x8C);
							break;

						case HV_STATUS_DAMAGED:      // 损坏（1.4.9 深紫底白字）
							pcd->clrText = RGB(0xFF, 0xFF, 0xFF);
							pcd->clrTextBk = RGB(0x6A, 0x00, 0xA8);
							break;
					}
				}
			}

			break;
		}
	}

	return(CDRF_DODEFAULT);
}

LONG_PTR WINAPI HashVerifyFindItem( PHASHVERIFYCONTEXT phvctx, LPNMLVFINDITEM pfi )
{
	PHASHVERIFYITEM pItem;
	INT cchCompare, iStart = pfi->iStart;
	LONG_PTR i;

	if (pfi->lvfi.flags & (LVFI_PARAM | LVFI_NEARESTXY))
		goto not_found;  // Unsupported search types

	if (!(pfi->lvfi.flags & (LVFI_PARTIAL | LVFI_STRING)))
		goto not_found;  // No valid search type specified

	// According to the documentation, LVFI_STRING without a corresponding
	// LVFI_PARTIAL should match the FULL string, but when the user sends
	// keyboard input (which uses a partial match), the notification does not
	// have the LVFI_PARTIAL flag, so we should just always assume LVFI_PARTIAL
	// INT cchCompare = (pfi->lvfi.flags & LVFI_PARTIAL) ? 0 : 1;
	// cchCompare += SSLen(pfi->lvfi.psz);
	// The above code should have been correct, but it is not...
	cchCompare = (INT)SSLen(pfi->lvfi.psz);

	// Fix out-of-range indices; by casting to unsigned, we also catch negatives
	if ((UINT)iStart > phvctx->cTotal)
		iStart = phvctx->cTotal;

	for (i = iStart; i < (INT)phvctx->cTotal; ++i)
	{
		pItem = phvctx->index[i];
		if (StrCmpNI(pItem->pszDisplayName, pfi->lvfi.psz, cchCompare) == 0)
			return(i);
	}

	if (pfi->lvfi.flags & LVFI_WRAP)
	{
		for (i = 0; i < iStart; ++i)
		{
			pItem = phvctx->index[i];
			if (StrCmpNI(pItem->pszDisplayName, pfi->lvfi.psz, cchCompare) == 0)
				return(i);
		}
	}

	not_found: return(-1);
}

__forceinline VOID WINAPI HashVerifyRebuildListIndex( PHASHVERIFYCONTEXT phvctx )
{
	// 排序后重排了 index 数组，但每个 item 的 nListviewIndex 仍指向旧位置。
	// 该字段同时被 worker 用作 index 下标和 listview 显示行号，必须同步重建，
	// 否则宽限「待命/部分算完也能排序」后，后续哈希会定位到错误行。
	UINT i;
	for (i = 0; i < phvctx->cTotal; ++i)
		phvctx->index[i]->nListviewIndex = (INT)i;
}

VOID WINAPI HashVerifySortColumn( PHASHVERIFYCONTEXT phvctx, LPNMLISTVIEW plv )
{
	if (phvctx->status == ACTIVE || phvctx->status == PAUSED)
		return;  // 计算进行中禁止排序；待命（INACTIVE）与算完（CLEANUP_COMPLETED）均可排

	// Capture the current selection/focus state
	HashVerifyReadStates(phvctx);

	if (phvctx->sort.iColumn != plv->iSubItem)
	{
		// Change to a new column
		phvctx->sort.iColumn = plv->iSubItem;
		phvctx->sort.bReverse = FALSE;
		qsort_s(phvctx->index, phvctx->cTotal, sizeof(PHVITEM), (int(__cdecl*)(void*, const void*, const void*))HashVerifySortCompare, phvctx);
	}
	else if (phvctx->sort.bReverse)
	{
		// Clicking a column thrice in a row reverts to the original file order
		phvctx->sort.iColumn = -1;
		phvctx->sort.bReverse = FALSE;

		// We do need to validate phvctx->index to handle the edge case where
		// the list is really non-empty, but we are treating it as empty because
		// we could not allocate an index (qsort_s uses the given length while
		// SLBuildIndex uses the actual length); this is, admittedly, a very
		// extreme edge case, as it crops up only in an OOM situation where the
		// user tries to click-sort an empty list view!
		if (phvctx->index)
			SLBuildIndex(phvctx->hList, (PVOID*)phvctx->index);
	}
	else
	{
		// Clicking a column twice in a row reverses the order; since we are
		// just reversing the order of an already-sorted column, we can just
		// naively flip the index

		if (phvctx->index)
		{
			PHVITEM pItemTemp;
			PPHVITEM ppItemLow = phvctx->index;
			PPHVITEM ppItemHigh = phvctx->index + phvctx->cTotal - 1;

			while (ppItemHigh > ppItemLow)
			{
				pItemTemp = *ppItemLow;
				*ppItemLow = *ppItemHigh;
				*ppItemHigh = pItemTemp;
				++ppItemLow;
				--ppItemHigh;
			}
		}

		phvctx->sort.bReverse = TRUE;
	}

	// 排序重排 index 后，同步各 item 的列表索引
	HashVerifyRebuildListIndex(phvctx);

	// Restore the selection/focus state
	HashVerifySetStates(phvctx);

	// Update the UI
	{
		HWND hWndHeader = ListView_GetHeader(phvctx->hWndList);
		INT i;

		HDITEM hdi;
		hdi.mask = HDI_FORMAT;

		for (i = HV_COL_FIRST; i <= HV_COL_LAST; ++i)
		{
			Header_GetItem(hWndHeader, i, &hdi);
			hdi.fmt &= ~(HDF_SORTDOWN | HDF_SORTUP);
			if (phvctx->sort.iColumn == i)
				hdi.fmt |= (phvctx->sort.bReverse) ? HDF_SORTDOWN : HDF_SORTUP;
			Header_SetItem(hWndHeader, i, &hdi);
		}

		// Invalidate all items
		ListView_RedrawItems(phvctx->hWndList, 0, phvctx->cTotal);

		// Set a light gray background on the sorted column
		ListView_SetSelectedColumn(
			phvctx->hWndList,
			(phvctx->sort.iColumn != HV_COL_STATUS) ? phvctx->sort.iColumn : -1
		);

		// Unfortunately, the list does not automatically repaint all of the
		// areas affected by SetSelectedColumn, so it is necessary to force a
		// repaint of the list view's visible areas in order to avoid artifacts
		InvalidateRect(phvctx->hWndList, NULL, FALSE);
	}
}

VOID WINAPI HashVerifySortByStatus( PHASHVERIFYCONTEXT phvctx )
{
	// 按状态整理：未算 → 相符 → 不符 → 缺失 → 新增。
	if (!phvctx->index || !phvctx->cTotal)
		return;

	phvctx->sort.iColumn = HV_COL_STATUS;
	phvctx->sort.bReverse = FALSE;

	qsort_s(phvctx->index, phvctx->cTotal, sizeof(PHVITEM),
	        (int(__cdecl*)(void*, const void*, const void*))HashVerifySortCompare, phvctx);

	// 排序重排 index 后，同步各 item 的列表索引
	HashVerifyRebuildListIndex(phvctx);

	// 更新列头排序箭头并重绘列表
	{
		HWND hWndHeader = ListView_GetHeader(phvctx->hWndList);
		INT i;
		HDITEM hdi;
		hdi.mask = HDI_FORMAT;

		for (i = HV_COL_FIRST; i <= HV_COL_LAST; ++i)
		{
			Header_GetItem(hWndHeader, i, &hdi);
			hdi.fmt &= ~(HDF_SORTDOWN | HDF_SORTUP);
			if (i == HV_COL_STATUS)
				hdi.fmt |= HDF_SORTUP;
			Header_SetItem(hWndHeader, i, &hdi);
		}
	}

	ListView_RedrawItems(phvctx->hWndList, 0, phvctx->cTotal);
	InvalidateRect(phvctx->hWndList, NULL, FALSE);
}

VOID WINAPI HashVerifyReadStates( PHASHVERIFYCONTEXT phvctx )
{
	if (!phvctx->bFreshStates)
	{
		UINT i;

		for (i = 0; i < phvctx->cTotal; ++i)
		{
			phvctx->index[i]->uState = ListView_GetItemState(
				phvctx->hWndList,
				i,
				LVIS_FOCUSED | LVIS_SELECTED
			);
		}
	}
}

VOID WINAPI HashVerifySetStates( PHASHVERIFYCONTEXT phvctx )
{
	UINT i;

	// Optimize for the case where most items are unselected
	ListView_SetItemState(phvctx->hWndList, -1, 0, LVIS_FOCUSED | LVIS_SELECTED);

	for (i = 0; i < phvctx->cTotal; ++i)
	{
		if (phvctx->index[i]->uState)
		{
			ListView_SetItemState(
				phvctx->hWndList,
				i,
				phvctx->index[i]->uState,
				LVIS_FOCUSED | LVIS_SELECTED
			);
		}
	}

	phvctx->bFreshStates = TRUE;
}

INT __cdecl HashVerifySortCompare( PHASHVERIFYCONTEXT phvctx, PPCHVITEM ppItemA, PPCHVITEM ppItemB )
{
	PHASHVERIFYITEM pItemA = *(PPHVITEM)ppItemA;
	PHASHVERIFYITEM pItemB = *(PPHVITEM)ppItemB;

	switch (phvctx->sort.iColumn)
	{
		case HV_COL_FILENAME:
			return(StrCmpLogical(pItemA->pszDisplayName, pItemB->pszDisplayName));

		case HV_COL_SIZE:
			return(pItemA->filesize.ui64 < pItemB->filesize.ui64 ? -1 : (pItemA->filesize.ui64 == pItemB->filesize.ui64 ? 0 : 1));

		case HV_COL_STATUS:
		{
			// 排序键：未算=0、相符=1、不符=2、缺失=3、新增=4（下标即 uStatusID）
			static const UINT8 ruSortKey[] = { 0, 1, 2, 3, 4 };
			INT keyA = ruSortKey[pItemA->uStatusID];
			INT keyB = ruSortKey[pItemB->uStatusID];
			return(keyA - keyB);
		}

		case HV_COL_EXPECTED:
			return(StrCmpI(pItemA->pszExpected, pItemB->pszExpected));

		case HV_COL_ACTUAL:
			return(StrCmpI(pItemA->szActual, pItemB->szActual));
	}

	return(0);
}
