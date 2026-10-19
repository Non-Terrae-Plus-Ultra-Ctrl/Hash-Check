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
// 1.6.9: HV_STATUS_DAMAGED(5) 随 chk 功能链铲除——编号 5 空缺留位，历史档兼容不受影响
#define HV_STATUS_STALE       6   // 1.6.3: 已变化（维护轻检 mtime/大小 与基线不符）

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
	ULONGLONG          ftModified;  // 1.6.3: 哈希时刻记录的文件 mtime（维护轻检基线；0=本会话未哈希）
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
	TCHAR              szStatus[7][MAX_STRINGRES];
	BOOL               bMaintLock; // 1.6.3: 维护哈希进行中（防消息泵重入维护流程）
	PPHVITEM           ppIndexOrig; // 1.6.7: 排序前原序快照（列头三连击还原用；维护增删条目即作废）
	UINT               cIndexOrig;  // 1.6.7: 快照条目数
} HASHVERIFYCONTEXT, *PHASHVERIFYCONTEXT;



/*============================================================================*\
	Function declarations
\*============================================================================*/

// Data parsing functions


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

// 1.6.3 增量维护（铁驭令：相符文件不重算，原位维护校验清单）
VOID WINAPI HashVerifyMaintainMenu( PHASHVERIFYCONTEXT phvctx );

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
		{
			// 1.6.7 修复：按最大序号位数动态预留——原版写死 3，≥100 选时
			// 「100.」=4 欠账 1 字符/行，截断后 pszWrite 仍按源长推进=堆越界写
			UINT n = cSel;
			cPrefix = 1;               // 句点
			while (n) { ++cPrefix; n /= 10; }
		}

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
	SIZE_T cchPath;
	PTSTR pszPath;

	// 1.4.0 优化三遍 #1：无参调用曾直接 SSLenW(NULL) 崩溃（2026-10-17
	// rundll32 实测实锤）——空参改弹用法说明而不是崩。
	if (!pszCmdLine || !*pszCmdLine)
	{
		MessageBox(NULL,
			L"用法：rundll32 HashCheck.dll,HashVerify_RunDLLW <校验文件路径>",
			NULL, MB_OK | MB_ICONINFORMATION);
		return;
	}

	cchPath = SSLenW(pszCmdLine) + 1;

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

			// 1.4.0 rebuild: 明文校验文件——不做任何容器探测/解密，
			// 直接交给下方文本解析。加密容器（HCK2 魔数）在此形态下
			// 会因无法解析而判损坏，符合 1.4.0 时代的边界语义。

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

			// 1.4.0 纯净版：无签名层——不验签（校验文件可自由编辑）。
		}

		CloseHandle(hFile);
	}

	return(pbRawData);
}

VOID WINAPI HashVerifyParseData( PHASHVERIFYCONTEXT phvctx )
{
	PTSTR pszData = phvctx->pszFileData;  // Points to the next line to process

	UINT cchChecksum = 0;          // Expected length of the checksum in TCHARs
	                              // （1.4.0 优化三遍：初始化消 C4701 静态盲区；逻辑本自洽——whctxFlags 短路保护）
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

			// 1.6.9: chk 功能链已铲除——数据行后的 "; chk=" 注释行静默跳过
			//（不校验不显示不报错），1.4.9+/1.6.x 旧带 chk 文件照常打开校验。
			// 规范化把 CRLF 变 \n\n，pszData 此刻指向数据行终结符后的伪影
			// 空行——先跳过再判前缀（1.5.2 管线沿用）。
			{
				const TCHAR *pszPeek = pszData;

				while (*pszPeek == TEXT(' ') || *pszPeek == TEXT('\n'))
					++pszPeek;

				if (pszPeek[0] == TEXT(';') && _tcsnicmp(pszPeek, TEXT("; chk="), 6) == 0)
				{
					while (*pszPeek && *pszPeek != TEXT('\n'))
						++pszPeek;
					pszData = (PTSTR)(*pszPeek ? pszPeek + 1 : pszPeek);
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

		// 1.6.3：路径快照——pbBuffer 同时充当读取缓冲，哈希一开跑路径就被文件内容
		// 冲掉；维护 mtime 基线必须从快照读（否则 GetFileAttributesExW 拿到的是乱码路径）
		TCHAR szPathSnapshot[MAX_PATH];
		StringCchCopy(szPathSnapshot, countof(szPathSnapshot), (PCTSTR)pbBuffer);

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

		// 1.6.3 维护轻检基线：记录哈希时刻的 mtime（维护 stat 对比即知文件动过没）
		{
			WIN32_FILE_ATTRIBUTE_DATA fad;
			if (GetFileAttributesExW(szPathSnapshot, GetFileExInfoStandard, &fad))
				pItem->ftModified = ((ULONGLONG)fad.ftLastWriteTime.dwHighDateTime << 32)
				                   |  fad.ftLastWriteTime.dwLowDateTime;
		}

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

/*============================================================================*\
		1.6.3 增量维护——添加/移除/轻检/原位保存（相符文件一字节不碰）
\*============================================================================*/

// 消息泵：同步哈希期间让窗口和进度条保持活性（bMaintLock 防递归进维护流程）
static VOID HashVerifyMaintPump( PHASHVERIFYCONTEXT phvctx )
{
	MSG msg;
	phvctx->bMaintLock = TRUE;
	while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	phvctx->bMaintLock = FALSE;
}

// 同步算一个文件（算法沿用清单 whctxFlags）
static BOOL HashVerifyMaintHashOne( PHASHVERIFYCONTEXT phvctx, PCTSTR pszFullPath,
                                    WHRESULTEX *pwhres, PFILESIZE pfs )
{
	WHCTXEX whctx;
	HANDLE hFile;
	PBYTE pBuffer;
	ULONGLONG cbFileSize, cbRead = 0;
	DWORD cbBufferRead = 0;
	BOOL bRet = FALSE;

	ZeroMemory(pwhres, sizeof(*pwhres));
	ZeroMemory(&whctx, sizeof(whctx));
	whctx.dwFlags   = phvctx->whctxFlags;
	whctx.uCaseMode = WHFMT_LOWERCASE;

	pBuffer = (PBYTE)malloc(READ_BUFFER_SIZE);
	if (!pBuffer)
		return(FALSE);
	if ((hFile = OpenFileForReading(pszFullPath)) != INVALID_HANDLE_VALUE)
	{
		if (GetFileSizeEx(hFile, (PLARGE_INTEGER)&cbFileSize))
		{
			WHInitEx(&whctx);
			do
			{
				if (!ReadFile(hFile, pBuffer, READ_BUFFER_SIZE, &cbBufferRead, NULL))
				{
					cbBufferRead = 0;
					break;
				}
				WHUpdateEx(&whctx, pBuffer, cbBufferRead);
				cbRead += cbBufferRead;
				HashVerifyMaintPump(phvctx);   // 每读一块泵一次消息
			} while (cbBufferRead == READ_BUFFER_SIZE);
			WHFinishEx(&whctx, pwhres);
			if (cbRead != cbFileSize)
				pwhres->dwFlags = 0;   // 读不全=结果作废
			else
			{
				bRet = (pwhres->dwFlags != 0);
				if (bRet && pfs)
				{
					pfs->ui64 = cbFileSize;
					StrFormatKBSize(cbFileSize, pfs->sz, countof(pfs->sz));
				}
			}
		}
		CloseHandle(hFile);
	}
	free(pBuffer);
	return(bRet);
}

// 从 whres 取本会话算法对应的 hex 结果
static PTSTR HashVerifyMaintResultHex( WHRESULTEX *pwhres )
{
	PTSTR psz = NULL;
#define MAINT_HEX_op(alg) \
	if (!psz && (pwhres->dwFlags & WHEX_CHECK##alg)) psz = pwhres->szHex##alg;
	FOR_EACH_HASH(MAINT_HEX_op)
#undef MAINT_HEX_op
	return(psz);
}

// 清单目录前缀长（含尾反斜杠）
static UINT HashVerifyDirPrefixLen( PHASHVERIFYCONTEXT phvctx )
{
	PCTSTR pszSlash = StrRChr(phvctx->pszPath, NULL, TEXT('\\'));
	return(pszSlash ? (UINT)(pszSlash - phvctx->pszPath + 1) : 0);
}

// 显示名 -> 全路径（绝对名直用；相对名拼清单目录）
static VOID HashVerifyBuildFullPath( PHASHVERIFYCONTEXT phvctx, PHASHVERIFYITEM pItem,
                                     PTSTR pszBuf, UINT cchBuf )
{
	UINT cchPrefix = HashVerifyDirPrefixLen(phvctx);

	if (pItem->pszDisplayName[0] == TEXT('\\') || pItem->pszDisplayName[1] == TEXT(':'))
	{
		StringCchCopy(pszBuf, cchBuf, pItem->pszDisplayName);
		return;
	}
	if (cchPrefix && cchPrefix < cchBuf)
	{
		StringCchCopy(pszBuf, cchBuf, phvctx->pszPath);
		pszBuf[cchPrefix] = 0;
		StringCchCat(pszBuf, cchBuf, pItem->pszDisplayName);
	}
	else
		StringCchCopy(pszBuf, cchBuf, pItem->pszDisplayName);
}

// 1.6.7 原序快照：列头三连击「还原原序」不再重走竞技场（SLBuildIndex 无界写案）——
// 首次进入排序态前存一份显示序，还原即回放；维护增删条目后作废（下次首排时重存）
static VOID HashVerifyOrigSnapshotFree( PHASHVERIFYCONTEXT phvctx )
{
	if (phvctx->ppIndexOrig)
	{
		free(phvctx->ppIndexOrig);
		phvctx->ppIndexOrig = NULL;
	}
	phvctx->cIndexOrig = 0;
}

// 索引视图扩缩（SLSetContextSize 换块不保内容——先暂存再重拷）
static BOOL HashVerifyIndexResize( PHASHVERIFYCONTEXT phvctx, UINT cNew )
{
	PHVITEM *ppTemp = NULL;
	PPHVITEM pNew;
	UINT cCopy;

	if (phvctx->cTotal && phvctx->index)
	{
		ppTemp = (PHVITEM *)malloc(phvctx->cTotal * sizeof(PHVITEM));
		if (!ppTemp)
			return(FALSE);
		memcpy(ppTemp, phvctx->index, phvctx->cTotal * sizeof(PHVITEM));
	}
	pNew = (PPHVITEM)SLSetContextSize(phvctx->hList, cNew * sizeof(PHVITEM));
	if (!pNew)
	{
		free(ppTemp);
		return(FALSE);
	}
	phvctx->index = pNew;
	cCopy = (phvctx->cTotal < cNew) ? phvctx->cTotal : cNew;
	if (ppTemp)
	{
		memcpy(phvctx->index, ppTemp, cCopy * sizeof(PHVITEM));
		free(ppTemp);
	}
	return(TRUE);
}

// 添加单条（跳过已收录；块内嵌 [item][名][哈希]，竞技场同生共死）
static BOOL HashVerifyMaintAddPath( PHASHVERIFYCONTEXT phvctx, PCTSTR pszFull, UINT *pcAdded )
{
	TCHAR szFull[MAX_PATH];
	TCHAR szName[MAX_PATH];
	PTSTR pszHex;
	PHASHVERIFYITEM pItem;
	UINT i, cbName, cbHex;
	WHRESULTEX whres;
	WIN32_FILE_ATTRIBUTE_DATA fad;
	FILESIZE fs;

	StringCchCopy(szFull, countof(szFull), pszFull);

	// 校验文件自身不入册
	if (StrCmpI(szFull, phvctx->pszPath) == 0)
		return(TRUE);

	// 相对显示名（清单同目录起算；目录之外用绝对名）
	{
		UINT cchPrefix = HashVerifyDirPrefixLen(phvctx);
		if (cchPrefix && _tcsnicmp(szFull, phvctx->pszPath, cchPrefix - 1) == 0 &&
		    szFull[cchPrefix - 1] == TEXT('\\'))
			StringCchCopy(szName, countof(szName), szFull + cchPrefix);
		else
			StringCchCopy(szName, countof(szName), szFull);
	}

	// 已收录跳过
	for (i = 0; i < phvctx->cTotal; ++i)
		if (StrCmpI(phvctx->index[i]->pszDisplayName, szName) == 0)
			return(TRUE);

	// 哈希（同步+泵消息）
	if (!HashVerifyMaintHashOne(phvctx, szFull, &whres, &fs))
		return(FALSE);
	pszHex = HashVerifyMaintResultHex(&whres);
	if (!pszHex)
		return(FALSE);

	cbName = ((UINT)lstrlen(szName) + 1) * sizeof(TCHAR);
	cbHex  = ((UINT)lstrlen(pszHex)  + 1) * sizeof(TCHAR);
	pItem  = (PHASHVERIFYITEM)SLAddItem(phvctx->hList, NULL,
	                                    sizeof(HASHVERIFYITEM) + cbName + cbHex);
	if (!pItem)
		return(FALSE);
	ZeroMemory(pItem, sizeof(HASHVERIFYITEM));
	pItem->pszDisplayName = (PTSTR)(pItem + 1);
	memcpy(pItem->pszDisplayName, szName, cbName);
	pItem->pszExpected = (PTSTR)((PBYTE)(pItem + 1) + cbName);
	memcpy(pItem->pszExpected, pszHex, cbHex);
	pItem->cchDisplayName = (INT16)(lstrlen(szName) + 1);
	pItem->filesize = fs;
	pItem->uStatusID = HV_STATUS_MATCH;   // 哈希即所得
	StringCbCopy(pItem->szActual, sizeof(pItem->szActual), pszHex);
	if (GetFileAttributesExW(szFull, GetFileExInfoStandard, &fad))
		pItem->ftModified = ((ULONGLONG)fad.ftLastWriteTime.dwHighDateTime << 32)
		                  |  fad.ftLastWriteTime.dwLowDateTime;

	if (!HashVerifyIndexResize(phvctx, phvctx->cTotal + 1))
		return(FALSE);
	pItem->nListviewIndex = (INT)phvctx->cTotal;
	phvctx->index[phvctx->cTotal] = pItem;
	++phvctx->cTotal;
	++phvctx->cOrigTotal;
	++(*pcAdded);

	HashVerifyOrigSnapshotFree(phvctx);   // 1.6.7：条目集已变——原序快照作废（下次首排重存）
	ListView_SetItemCount(phvctx->hWndList, phvctx->cTotal);
	return(TRUE);
}

// 文件夹递归收割（跳过隐藏/系统/重解析点）
static VOID HashVerifyMaintWalk( PHASHVERIFYCONTEXT phvctx, PCTSTR pszDir, UINT *pcAdded )
{
	TCHAR szPattern[MAX_PATH];
	TCHAR szSub[MAX_PATH];
	WIN32_FIND_DATA fd;
	HANDLE hFind;

	StringCchPrintf(szPattern, countof(szPattern), TEXT("%s\\*"), pszDir);
	hFind = FindFirstFile(szPattern, &fd);
	if (hFind == INVALID_HANDLE_VALUE)
		return;
	do
	{
		if (fd.cFileName[0] == TEXT('.'))
			continue;
		if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (fd.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
				continue;
			StringCchPrintf(szSub, countof(szSub), TEXT("%s\\%s"), pszDir, fd.cFileName);
			HashVerifyMaintWalk(phvctx, szSub, pcAdded);
		}
		else
		{
			if (fd.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
				continue;
			StringCchPrintf(szSub, countof(szSub), TEXT("%s\\%s"), pszDir, fd.cFileName);
			HashVerifyMaintAddPath(phvctx, szSub, pcAdded);
		}
	} while (FindNextFile(hFind, &fd));
	FindClose(hFind);
}

// 多选文件对话框 -> 逐个添加
static UINT HashVerifyMaintAddFilesDlg( PHASHVERIFYCONTEXT phvctx )
{
	PTSTR pszBuf, pszWalk;
	OPENFILENAME ofn;
	UINT cAdded = 0;

	pszBuf = (PTSTR)malloc(32768 * sizeof(TCHAR));
	if (!pszBuf)
		return(0);
	pszBuf[0] = 0;
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner   = phvctx->hWnd;
	ofn.lpstrFile   = pszBuf;
	ofn.nMaxFile    = 32768;
	ofn.Flags       = OFN_ALLOWMULTISELECT | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
	if (GetOpenFileName(&ofn))
	{
		if (!pszBuf[lstrlen(pszBuf) + 1])
		{
			// 单选：缓冲=完整路径
			HashVerifyMaintAddPath(phvctx, pszBuf, &cAdded);
		}
		else
		{
			// 多选：缓冲=目录+'\0'+文件1+'\0'+…+'\0\0'
			TCHAR szDir[MAX_PATH];
			StringCchCopy(szDir, countof(szDir), pszBuf);
			pszWalk = pszBuf + lstrlen(pszBuf) + 1;
			while (*pszWalk)
			{
				TCHAR szFull[MAX_PATH];
				StringCchPrintf(szFull, countof(szFull), TEXT("%s\\%s"), szDir, pszWalk);
				HashVerifyMaintAddPath(phvctx, szFull, &cAdded);
				pszWalk += lstrlen(pszWalk) + 1;
			}
		}
	}
	free(pszBuf);
	return(cAdded);
}

// 文件夹浏览（shell32 的老派对话框——零 COM 依赖）
static BOOL HashVerifyMaintBrowseFolder( HWND hWnd, PTSTR pszDir, UINT cchDir )
{
	BROWSEINFOW bi;
	LPITEMIDLIST pidl;
	BOOL bRet = FALSE;

	ZeroMemory(&bi, sizeof(bi));
	bi.hwndOwner = hWnd;
	bi.lpszTitle  = L"选择要收录的文件夹（递归添加，已收录自动跳过）";
	bi.ulFlags    = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
	pidl = SHBrowseForFolderW(&bi);
	if (pidl)
	{
		if (SHGetPathFromIDListW(pidl, pszDir))
			bRet = TRUE;
		ILFree(pidl);
	}
	return(bRet);
}

// 移除选中行（索引视图压缩；竞技场 write-once，死块滞留无害）
static UINT HashVerifyMaintRemoveSel( PHASHVERIFYCONTEXT phvctx )
{
	UINT cSel = 0, cOrig, i, j;
	PHVITEM *ppTemp;
	PBOOL pbDel;
	INT nIndex = -1;

	while ((nIndex = ListView_GetNextItem(phvctx->hWndList, nIndex, LVNI_SELECTED)) != -1)
		++cSel;
	if (!cSel || cSel > phvctx->cTotal)
		return(0);

	pbDel = (PBOOL)malloc(phvctx->cTotal * sizeof(BOOL));
	if (!pbDel)
		return(0);
	ZeroMemory(pbDel, phvctx->cTotal * sizeof(BOOL));
	nIndex = -1;
	while ((nIndex = ListView_GetNextItem(phvctx->hWndList, nIndex, LVNI_SELECTED)) != -1)
	{
		if ((UINT)nIndex >= phvctx->cTotal)
			continue;
		pbDel[nIndex] = TRUE;
		// 1.6.7：随删同步状态计数（原版不动——「相符 N/总数 M」分母变分子不变+待验下溢巨数）
		switch (phvctx->index[nIndex]->uStatusID)
		{
			case HV_STATUS_MATCH:       if (phvctx->cMatch)      --phvctx->cMatch;      break;
			case HV_STATUS_MISMATCH:    if (phvctx->cMismatch)   --phvctx->cMismatch;   break;
			case HV_STATUS_UNREADABLE:  if (phvctx->cUnreadable) --phvctx->cUnreadable; break;
			case HV_STATUS_NEW:         if (phvctx->cNew)        --phvctx->cNew;        break;
			default: break;
		}
	}

	ppTemp = (PHVITEM *)malloc(phvctx->cTotal * sizeof(PHVITEM));
	if (!ppTemp)
	{
		free(pbDel);
		return(0);
	}
	memcpy(ppTemp, phvctx->index, phvctx->cTotal * sizeof(PHVITEM));
	cOrig = phvctx->cTotal;

	if (!HashVerifyIndexResize(phvctx, cOrig - cSel))
	{
		free(ppTemp);
		free(pbDel);
		return(0);
	}
	for (i = 0, j = 0; i < cOrig; ++i)
	{
		if (pbDel[i])
			continue;
		phvctx->index[j++] = ppTemp[i];
	}
	free(ppTemp);
	free(pbDel);

	phvctx->cTotal = cOrig - cSel;
	phvctx->cOrigTotal = (phvctx->cOrigTotal > cSel) ? phvctx->cOrigTotal - cSel : 0;

	// 队列作废（维护只在待命态开放）
	free(phvctx->queue);
	phvctx->queue = NULL;
	phvctx->cQueue = 0;

	for (i = 0; i < phvctx->cTotal; ++i)
		phvctx->index[i]->nListviewIndex = (INT)i;
	ListView_SetItemCount(phvctx->hWndList, phvctx->cTotal);
	HashVerifyOrigSnapshotFree(phvctx);   // 1.6.7：条目集已变——原序快照作废（下次首排重存）
	HashVerifyUpdateSummary(phvctx, NULL);
	InvalidateRect(phvctx->hWndList, NULL, FALSE);
	return(cSel);
}

// 轻量检测：mtime/大小 vs 哈希时刻基线
static UINT HashVerifyMaintDetect( PHASHVERIFYCONTEXT phvctx )
{
	UINT i, cStale = 0;

	for (i = 0; i < phvctx->cTotal; ++i)
	{
		PHASHVERIFYITEM pItem = phvctx->index[i];
		WIN32_FILE_ATTRIBUTE_DATA fad;
		TCHAR szFull[MAX_PATH];
		ULONGLONG ftNow;

		if (!pItem->pszExpected || !pItem->pszExpected[0])
			continue;
		if (!pItem->ftModified)
			continue;   // 本会话没哈希过（无基线）——保存时统一重算
		HashVerifyBuildFullPath(phvctx, pItem, szFull, countof(szFull));
		if (!GetFileAttributesExW(szFull, GetFileExInfoStandard, &fad))
			continue;   // 缺失交给保存阶段裁决
		ftNow = ((ULONGLONG)fad.ftLastWriteTime.dwHighDateTime << 32)
		      |   fad.ftLastWriteTime.dwLowDateTime;
		if (ftNow != pItem->ftModified ||
		    (((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow) != pItem->filesize.ui64)
		{
			pItem->uStatusID = HV_STATUS_STALE;
			pItem->szActual[0] = 0;
			++cStale;
		}
	}
	InvalidateRect(phvctx->hWndList, NULL, FALSE);
	return(cStale);
}

// 1.7.0 右键「添加」：重算单个 NEW 行的哈希写入期望值 → 行态变 MATCH。
// 就地替换 pszExpected（竞技场节点内指针重指向新 hex 缓冲，write-once 不变量保持）。
static UINT HashVerifyCtxAddSel( PHASHVERIFYCONTEXT phvctx )
{
	INT nIndex = -1;
	UINT cDone = 0, cFailed = 0;

	while ((nIndex = ListView_GetNextItem(phvctx->hWndList, nIndex, LVNI_SELECTED)) != -1)
	{
		PHASHVERIFYITEM pItem;
		TCHAR szFull[MAX_PATH];
		WIN32_FILE_ATTRIBUTE_DATA fad;
		WHRESULTEX whres;
		FILESIZE fs;
		PTSTR pszHex;
		UINT cbHex;
		PTSTR pszNew;

		if ((UINT)nIndex >= phvctx->cTotal)
			continue;
		pItem = phvctx->index[nIndex];
		if (!pItem || pItem->uStatusID != HV_STATUS_NEW)
			continue;   // 只作用于新增行
		HashVerifyBuildFullPath(phvctx, pItem, szFull, countof(szFull));
		if (!HashVerifyMaintHashOne(phvctx, szFull, &whres, &fs))
		{
			++cFailed;
			continue;   // 行内报错不中断
		}
		pszHex = HashVerifyMaintResultHex(&whres);
		if (!pszHex)
		{
			++cFailed;
			continue;
		}
		cbHex = ((UINT)lstrlen(pszHex) + 1) * sizeof(TCHAR);
		pszNew = (PTSTR)SLAddItem(phvctx->hList, NULL, cbHex);
		if (!pszNew)
		{
			++cFailed;
			continue;
		}
		memcpy(pszNew, pszHex, cbHex);
		pItem->pszExpected = pszNew;
		pItem->filesize = fs;
		StringCbCopy(pItem->szActual, sizeof(pItem->szActual), pszHex);
		// mtime 基线随收录落地（漏记=后续「检测变化」对该行永久失明）
		if (GetFileAttributesExW(szFull, GetFileExInfoStandard, &fad))
			pItem->ftModified = ((ULONGLONG)fad.ftLastWriteTime.dwHighDateTime << 32)
			                  |  fad.ftLastWriteTime.dwLowDateTime;
		if (pItem->uStatusID == HV_STATUS_NEW && phvctx->cNew)
			--phvctx->cNew;
		++phvctx->cMatch;
		pItem->uStatusID = HV_STATUS_MATCH;
		++cDone;
	}
	if (cDone)
	{
		HashVerifyOrigSnapshotFree(phvctx);
		HashVerifyUpdateSummary(phvctx, NULL);
		InvalidateRect(phvctx->hWndList, NULL, FALSE);
	}
	return(cFailed ? (cDone | 0x8000) : cDone);
}

// 1.7.0 右键「更新」：重算单个 MISMATCH 行哈希覆写期望值+mtime/大小基线
// → 行态变 MATCH（存疑不给——轻检嫌疑态先重算落地再谈）。
static UINT HashVerifyCtxUpdateSel( PHASHVERIFYCONTEXT phvctx )
{
	INT nIndex = -1;
	UINT cDone = 0, cFailed = 0;

	while ((nIndex = ListView_GetNextItem(phvctx->hWndList, nIndex, LVNI_SELECTED)) != -1)
	{
		PHASHVERIFYITEM pItem;
		TCHAR szFull[MAX_PATH];
		WIN32_FILE_ATTRIBUTE_DATA fad;
		WHRESULTEX whres;
		FILESIZE fs;
		PTSTR pszHex;

		if ((UINT)nIndex >= phvctx->cTotal)
			continue;
		pItem = phvctx->index[nIndex];
		if (!pItem || pItem->uStatusID != HV_STATUS_MISMATCH)
			continue;   // 只作用于不符行
		HashVerifyBuildFullPath(phvctx, pItem, szFull, countof(szFull));
		if (!HashVerifyMaintHashOne(phvctx, szFull, &whres, &fs))
		{
			++cFailed;
			continue;
		}
		pszHex = HashVerifyMaintResultHex(&whres);
		if (!pszHex)
		{
			++cFailed;
			continue;
		}
		/* 等长原位覆写（1.6.7 维护保存同款）；短旧档塞不下走新节点兜底 */
		if ((UINT)lstrlen(pszHex) <= (UINT)lstrlen(pItem->pszExpected))
		{
			StringCbCopy(pItem->pszExpected,
			             ((UINT)lstrlen(pItem->pszExpected) + 1) * sizeof(TCHAR),
			             pszHex);
		}
		else
		{
			UINT cbHex = ((UINT)lstrlen(pszHex) + 1) * sizeof(TCHAR);
			PTSTR pszNew = (PTSTR)SLAddItem(phvctx->hList, NULL, cbHex);
			if (!pszNew)
			{
				++cFailed;
				continue;
			}
			memcpy(pszNew, pszHex, cbHex);
			pItem->pszExpected = pszNew;
		}
		pItem->filesize = fs;
		StringCbCopy(pItem->szActual, sizeof(pItem->szActual), pszHex);
		if (GetFileAttributesExW(szFull, GetFileExInfoStandard, &fad))
			pItem->ftModified = ((ULONGLONG)fad.ftLastWriteTime.dwHighDateTime << 32)
			                  |  fad.ftLastWriteTime.dwLowDateTime;
		if (pItem->uStatusID == HV_STATUS_MISMATCH && phvctx->cMismatch)
			--phvctx->cMismatch;
		++phvctx->cMatch;
		pItem->uStatusID = HV_STATUS_MATCH;
		++cDone;
	}
	if (cDone)
	{
		HashVerifyOrigSnapshotFree(phvctx);
		HashVerifyUpdateSummary(phvctx, NULL);
		InvalidateRect(phvctx->hWndList, NULL, FALSE);
	}
	return(cFailed ? (cDone | 0x8000) : cDone);
}

// 保存维护：重算 变化/未验 条目 + 原位改写（temp+替换，绝不出半档）
static BOOL HashVerifyMaintSave( PHASHVERIFYCONTEXT phvctx )
{
	UINT i, cNeed = 0, cRehash = 0, cMissing = 0, cDropped = 0, cWrote = 0;
	UINT cchTotal = 64;
	TCHAR szRegion[3];
	TCHAR szLine[MAX_PATH_BUFFER];   // 1.6.7：原 MAX_PATH+80 偏小（SHA-512 128+2+长名>344 截断=chk 对残行计算）——按原版写手规格放大
	TCHAR szFull[MAX_PATH];
	PTSTR pszText;
	SYSTEMTIME st;
	PSTR pszUtf8;
	BOOL bRet = FALSE;

	// 第 1 轮：清点容量与缺失（cNeed=清点数；cRehash 只留给第 2 轮实算数，防双计）
	for (i = 0; i < phvctx->cTotal; ++i)
	{
		PHASHVERIFYITEM pItem = phvctx->index[i];
		WIN32_FILE_ATTRIBUTE_DATA fad;

		if (!pItem->pszExpected || !pItem->pszExpected[0])
			continue;   // 无期望哈希（损坏行）不入档
		HashVerifyBuildFullPath(phvctx, pItem, szFull, countof(szFull));
		if (!GetFileAttributesExW(szFull, GetFileExInfoStandard, &fad))
		{
			++cMissing;
			// 1.6.7 修复：答「保留」时缺失行仍要组稿——清点轮必须预留其容量
			//（原版在累加前 continue=零预留，全缺失清单 StringCchCat 静默截断=半档）
			cchTotal += (UINT)lstrlen(pItem->pszExpected) +
			            (UINT)lstrlen(pItem->pszDisplayName) + 420;
			continue;
		}
		// 需重算的：已变化 / 本会话未验证 / 验证不符
		if (pItem->uStatusID == HV_STATUS_STALE ||
		    pItem->uStatusID == HV_STATUS_NULL   ||
		    pItem->uStatusID == HV_STATUS_MISMATCH)
			++cNeed;
		cchTotal += (UINT)lstrlen(pItem->pszExpected) + (UINT)lstrlen(pItem->pszDisplayName) + 420;
	}
	if (!cWrote && !phvctx->cTotal)
	{
		MessageBox(phvctx->hWnd, TEXT("清单为空，无可保存条目。"), NULL, MB_OK | MB_ICONINFORMATION);
		return(FALSE);
	}
	if (cMissing)
	{
		TCHAR szMsg[0x100];
		StringCchPrintf(szMsg, countof(szMsg),
		                TEXT("检测到 %u 个文件已不存在。\r\n\r\n是=从清单移除；否=保留原条目。"), cMissing);
		if (MessageBox(phvctx->hWnd, szMsg, NULL, MB_YESNO | MB_ICONQUESTION) == IDYES)
			cDropped = 1;
	}

	pszText = (PTSTR)malloc(cchTotal * sizeof(TCHAR));
	if (!pszText)
		return(FALSE);
	pszText[0] = 0;

	// 第 2 轮：重算 + 组稿（"<hash>  <name>\r\n"——1.6.9 chk 行随功能链铲除不再随写）
	for (i = 0; i < phvctx->cTotal; ++i)
	{
		PHASHVERIFYITEM pItem = phvctx->index[i];
		WIN32_FILE_ATTRIBUTE_DATA fad;
		ULONGLONG ftNow;
		BOOL bNeedHash;

		if (!pItem->pszExpected || !pItem->pszExpected[0])
			continue;
		HashVerifyBuildFullPath(phvctx, pItem, szFull, countof(szFull));
		if (!GetFileAttributesExW(szFull, GetFileExInfoStandard, &fad))
		{
			if (cDropped)
				continue;   // 用户裁决：缺失行不写
			// 1.6.7：缺失但用户裁决保留的行原样组稿（1.6.9 起纯哈希行）
			StringCchPrintf(szLine, countof(szLine), TEXT("%s  %s"),
			                pItem->pszExpected, pItem->pszDisplayName);
			StringCchCat(pszText, cchTotal, szLine);
			StringCchCat(pszText, cchTotal, TEXT("\r\n"));
			++cWrote;
			continue;   // 保留原条目
		}
		ftNow = ((ULONGLONG)fad.ftLastWriteTime.dwHighDateTime << 32)
		      |   fad.ftLastWriteTime.dwLowDateTime;
		bNeedHash = (pItem->uStatusID == HV_STATUS_STALE) ||
		           (pItem->uStatusID == HV_STATUS_NULL)   ||
		           (pItem->uStatusID == HV_STATUS_MISMATCH) ||
		           (pItem->ftModified && pItem->ftModified != ftNow);
		if (bNeedHash)
		{
			WHRESULTEX whres;
			FILESIZE fs;
			if (HashVerifyMaintHashOne(phvctx, szFull, &whres, &fs))
			{
				PTSTR pszHex = HashVerifyMaintResultHex(&whres);
				if (pszHex)
				{
					// 1.6.7 修复：原方案 SLAddItem 裸串节点破坏「竞技场节点数==cTotal」
					// 不变量——列头三连击还原原序走 SLBuildIndex 无界写=堆越界+类型
					// 混淆；改为等长哈希原位覆写 pszExpected（同算法 SHA-256 65 TCHAR
					// 等长，零新节点）；异常短旧档塞不下的兜底才走加节点（快照还原已
					// 使竞技场遍历不再发生，兜底无害）
					if ((UINT)lstrlen(pszHex) <= (UINT)lstrlen(pItem->pszExpected))
					{
						StringCbCopy(pItem->pszExpected,
						             ((UINT)lstrlen(pItem->pszExpected) + 1) * sizeof(TCHAR),
						             pszHex);
						pItem->filesize = fs;
						pItem->ftModified = ftNow;
						pItem->uStatusID = HV_STATUS_MATCH;
						StringCbCopy(pItem->szActual, sizeof(pItem->szActual), pszHex);
						++cRehash;   // 实算数（清点数走 cNeed，互不掺和）
					}
					else
					{
						UINT cbHex = ((UINT)lstrlen(pszHex) + 1) * sizeof(TCHAR);
						PTSTR pszNew = (PTSTR)SLAddItem(phvctx->hList, NULL, cbHex);
						if (pszNew)
						{
							memcpy(pszNew, pszHex, cbHex);
							pItem->pszExpected = pszNew;
							pItem->filesize = fs;
							pItem->ftModified = ftNow;
							pItem->uStatusID = HV_STATUS_MATCH;
							StringCbCopy(pItem->szActual, sizeof(pItem->szActual), pszHex);
							++cRehash;
						}
					}
				}
			}
		}
		StringCchPrintf(szLine, countof(szLine), TEXT("%s  %s"),
		                pItem->pszExpected, pItem->pszDisplayName);
		StringCchCat(pszText, cchTotal, szLine);
		StringCchCat(pszText, cchTotal, TEXT("\r\n"));
		++cWrote;
	}

	// 尾行时间戳：region 沿用原文件前 2 字，缺省 cn
	szRegion[0] = 0;
	if (((phvctx->szTimestamp[0] >= TEXT('A') && phvctx->szTimestamp[0] <= TEXT('Z')) ||
	     (phvctx->szTimestamp[0] >= TEXT('a') && phvctx->szTimestamp[0] <= TEXT('z'))) &&
	    ((phvctx->szTimestamp[1] >= TEXT('A') && phvctx->szTimestamp[1] <= TEXT('Z')) ||
	     (phvctx->szTimestamp[1] >= TEXT('a') && phvctx->szTimestamp[1] <= TEXT('z'))))
	{
		szRegion[0] = phvctx->szTimestamp[0];
		szRegion[1] = phvctx->szTimestamp[1];
		szRegion[2] = 0;
	}
	else
		StringCchCopy(szRegion, countof(szRegion), TEXT("cn"));
	GetLocalTime(&st);
	StringCchPrintf(szLine, countof(szLine),
	                TEXT("; %s%04u%02u%02u%02u%02u%02u\r\n"), szRegion,
	                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	StringCchCat(pszText, cchTotal, szLine);

	// UTF-8 落盘：.tmp 写全 -> 原位替换（保命铁律：绝不出半档）
	{
		TCHAR szTmp[MAX_PATH + 8];
		HANDLE hOut;
		UINT cchText = (UINT)lstrlen(pszText);

		pszUtf8 = (PSTR)malloc((size_t)cchText * 3 + 16);
		if (!pszUtf8)
		{
			free(pszText);
			return(FALSE);
		}
		WStrToUTF8(pszText, pszUtf8, (UINT)((size_t)cchText * 3 + 16));
		StringCchCopy(szTmp, countof(szTmp), phvctx->pszPath);
		StringCchCat(szTmp, countof(szTmp), TEXT(".tmp"));
		hOut = CreateFile(szTmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hOut != INVALID_HANDLE_VALUE)
		{
			DWORD cbWrite = (DWORD)lstrlenA(pszUtf8), cbWritten;
			if (WriteFile(hOut, pszUtf8, cbWrite, &cbWritten, NULL) && cbWritten == cbWrite)
			{
				CloseHandle(hOut);
				hOut = INVALID_HANDLE_VALUE;
				if (MoveFileEx(szTmp, phvctx->pszPath, MOVEFILE_REPLACE_EXISTING))
					bRet = TRUE;
				else
					DeleteFile(szTmp);
			}
			if (hOut != INVALID_HANDLE_VALUE)
				CloseHandle(hOut);
		}
		free(pszUtf8);
	}
	free(pszText);

	if (bRet)
	{
		// 界面收口：时间戳条更新 + 摘要 + 列表重绘
		GetLocalTime(&st);
		StringCchPrintf(phvctx->szTimestamp, countof(phvctx->szTimestamp),
		                TEXT("%s%04u%02u%02u%02u%02u%02u"), szRegion,
		                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		HashVerifyUpdateSummary(phvctx, NULL);
		InvalidateRect(phvctx->hWndList, NULL, FALSE);
		{
			TCHAR szMsg[0x100];
			StringCchPrintf(szMsg, countof(szMsg),
			                TEXT("维护完成：共 %u 条已写回（其中重算 %u）。"), cWrote, cRehash);
			MessageBox(phvctx->hWnd, szMsg, NULL, MB_OK | MB_ICONINFORMATION);
		}
	}
	else
		MessageBox(phvctx->hWnd, TEXT("写盘失败，原文件未改动。"), NULL, MB_OK | MB_ICONERROR);
	return(bRet);
}

// 维护主入口：右上角按钮 -> 弹出菜单
VOID WINAPI HashVerifyMaintainMenu( PHASHVERIFYCONTEXT phvctx )
{
	HMENU hMenu;
	RECT rc;
	INT cmd;
	TCHAR szMsg[0x100];
	UINT c = 0;

	if (phvctx->bMaintLock)
		return;
	if (phvctx->status == ACTIVE || phvctx->status == PAUSED)
	{
		MessageBox(phvctx->hWnd, TEXT("校验正在进行，请等完成后再维护。"),
		           NULL, MB_OK | MB_ICONINFORMATION);
		return;
	}

	GetWindowRect(GetDlgItem(phvctx->hWnd, IDC_MAINTAIN), &rc);
	hMenu = CreatePopupMenu();
	AppendMenu(hMenu, MF_STRING, 1, TEXT("添加文件…"));
	AppendMenu(hMenu, MF_STRING, 2, TEXT("添加文件夹…"));
	AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
	AppendMenu(hMenu, MF_STRING, 3, TEXT("移除选中行"));
	AppendMenu(hMenu, MF_STRING, 4, TEXT("检测变化（mtime/大小）"));
	AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
	AppendMenu(hMenu, MF_STRING, 5, TEXT("保存维护（重算变化，原位改写）"));
	cmd = TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
	                     rc.left, rc.bottom, 0, phvctx->hWnd, NULL);
	DestroyMenu(hMenu);

	switch (cmd)
	{
		case 1:
			c = HashVerifyMaintAddFilesDlg(phvctx);
			HashVerifyUpdateSummary(phvctx, NULL);
			InvalidateRect(phvctx->hWndList, NULL, FALSE);
			StringCchPrintf(szMsg, countof(szMsg), TEXT("已添加 %u 个文件。"), c);
			MessageBox(phvctx->hWnd, szMsg, NULL, MB_OK | MB_ICONINFORMATION);
			break;

		case 2:
		{
			TCHAR szDir[MAX_PATH];
			if (HashVerifyMaintBrowseFolder(phvctx->hWnd, szDir, countof(szDir)))
			{
				HashVerifyMaintWalk(phvctx, szDir, &c);
				HashVerifyUpdateSummary(phvctx, NULL);
				InvalidateRect(phvctx->hWndList, NULL, FALSE);
				StringCchPrintf(szMsg, countof(szMsg), TEXT("已添加 %u 个文件。"), c);
				MessageBox(phvctx->hWnd, szMsg, NULL, MB_OK | MB_ICONINFORMATION);
			}
			break;
		}

		case 3:
			c = HashVerifyMaintRemoveSel(phvctx);
			StringCchPrintf(szMsg, countof(szMsg),
			               c ? TEXT("已移除 %u 条。") : TEXT("未选中任何行。"), c);
			MessageBox(phvctx->hWnd, szMsg, NULL, MB_OK | (c ? MB_ICONINFORMATION : MB_ICONWARNING));
			break;

		case 4:
			c = HashVerifyMaintDetect(phvctx);
			StringCchPrintf(szMsg, countof(szMsg),
			               c ? TEXT("检测到 %u 条存疑（紫底）。") : TEXT("未发现存疑条目。"), c);
			MessageBox(phvctx->hWnd, szMsg, NULL, MB_OK | MB_ICONINFORMATION);
			break;

		case 5:
			HashVerifyMaintSave(phvctx);
			break;
	}
}

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
			//（1.6.9: cDamaged 随 chk 铲除——进度基线=原始-缺失）
			SendMessage(phvctx->hWndPBTotal, PBM_SETRANGE32, 0,
			(phvctx->cOrigTotal > phvctx->cMissing) ?
				phvctx->cOrigTotal - phvctx->cMissing : 0);
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
			// 1.6.7 修复：维护同步哈希的泵会派发本消息——照常清理=对话框返回即释放
			// 竞技场，而维护循环仍持 phvctx 在用（UAF）；拒关等维护收尾（秒级窗口）
			if (phvctx && phvctx->bMaintLock)
				break;
			goto cleanup_and_exit;
		}

		case WM_COMMAND:
		{
			phvctx = (PHASHVERIFYCONTEXT)GetWindowLongPtr(hWnd, DWLP_USER);

			// 1.6.7：维护同步哈希泵消息期间——开始/整理一律拒入
			// （防 worker 与维护循环并发写条目=竞态脏数据）
			if (phvctx && phvctx->bMaintLock &&
			    (LOWORD(wParam) == IDC_PAUSE || LOWORD(wParam) == IDC_STOP))
				break;

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

				case IDC_MAINTAIN:  // 1.6.3: 维护（右上角）
				{
					HashVerifyMaintainMenu(phvctx);
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
					HashVerifyOrigSnapshotFree(phvctx);   // 1.6.7: 快照配平释放
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

						case NM_RCLICK:  // 1.6.3: 右键菜单（复制的第二通道，不依赖列表焦点）
						        // 1.7.0: 状态项动态追加——按选中集并集显示，
						        // 每个操作只作用于自己适用的行（grilling 定案）
						{
							HMENU hmCtx = CreatePopupMenu();
							INT nCmd, nScan;
							POINT pt;
							BOOL bHasNew = FALSE, bHasInBook = FALSE, bHasMismatch = FALSE;
							UINT cSel = 0;

							/* 收集选中集状态并集 */
							nScan = -1;
							while ((nScan = ListView_GetNextItem(phvctx->hWndList, nScan, LVNI_SELECTED)) != -1)
							{
								UINT uStatus;
								++cSel;
								if ((UINT)nScan >= phvctx->cTotal)
									continue;
								uStatus = phvctx->index[nScan]->uStatusID;
								if (uStatus == HV_STATUS_NEW)
									bHasNew = TRUE;
								else
									bHasInBook = TRUE;   // 册内态（含缺失/未验/存疑）
								if (uStatus == HV_STATUS_MISMATCH)
									bHasMismatch = TRUE;
							}
							// 1.6.7 竞态锁延伸：维护哈希中（HashOne 消息泵）只留复制/全选，
							// 状态操作禁入——防泵分发重入改条目
							if (phvctx->bMaintLock)
								bHasNew = bHasInBook = bHasMismatch = FALSE;

							AppendMenu(hmCtx, MF_STRING, 1, TEXT("复制所选（名字+哈希）"));
							AppendMenu(hmCtx, MF_STRING, 2, TEXT("全选"));
							if (cSel && (bHasNew || bHasInBook))
								AppendMenu(hmCtx, MF_SEPARATOR, 0, NULL);
							if (bHasNew)
								AppendMenu(hmCtx, MF_STRING, 3, TEXT("添加（重算入册）"));
							if (bHasInBook)
								AppendMenu(hmCtx, MF_STRING, 4, TEXT("删除（移出清单）"));
							if (bHasMismatch)
								AppendMenu(hmCtx, MF_STRING, 5, TEXT("更新（以现在为准）"));

							GetCursorPos(&pt);
							nCmd = TrackPopupMenu(hmCtx, TPM_RETURNCMD | TPM_RIGHTBUTTON,
							                      pt.x, pt.y, 0, hWnd, NULL);
							DestroyMenu(hmCtx);
							if (nCmd == 1)
								HashVerifyCopySelection(phvctx);
							else if (nCmd == 2)
							{
								INT nItem = -1;
								LVITEM lvi;
								ZeroMemory(&lvi, sizeof(lvi));
								lvi.state = LVIS_SELECTED;
								lvi.stateMask = LVIS_SELECTED;
								while ((nItem = ListView_GetNextItem(phvctx->hWndList, nItem, 0)) != -1)
									ListView_SetItemState(phvctx->hWndList, nItem, LVIS_SELECTED, LVIS_SELECTED);
							}
							else if (nCmd == 3)
							{
								UINT cRes = HashVerifyCtxAddSel(phvctx);
								if (cRes & 0x8000)
									MessageBox(hWnd,
										TEXT("部分文件哈希失败，未能全部收录。"),
										NULL, MB_OK | MB_ICONWARNING);
							}
							else if (nCmd == 4)
							{
								// 定案：只删册内行——新增行先取消选中（无条目可删），
								// 再复用维护移除（内存态行立即消失；盘上文件绝不碰，协议三）
								INT nDrop = -1;
								while ((nDrop = ListView_GetNextItem(phvctx->hWndList, nDrop, LVNI_SELECTED)) != -1)
								{
									if ((UINT)nDrop >= phvctx->cTotal ||
									    phvctx->index[nDrop]->uStatusID == HV_STATUS_NEW)
										ListView_SetItemState(phvctx->hWndList, nDrop, 0, LVIS_SELECTED);
								}
								HashVerifyMaintRemoveSel(phvctx);
							}
							else if (nCmd == 5)
							{
								UINT cRes = HashVerifyCtxUpdateSel(phvctx);
								if (cRes & 0x8000)
									MessageBox(hWnd,
										TEXT("部分文件哈希失败，未能全部更新。"),
										NULL, MB_OK | MB_ICONWARNING);
							}
							return(TRUE);
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
		UINT iStatus;  // 1.4.0 优化三遍：消 C4456 遮蔽（原 i 遮蔽外层同名循环变量）

		// 1.6.9: DAMAGED（5）随 chk 铲除——编号 5 空缺，循环跳过
		for (iStatus = 1; iStatus <= 6; ++iStatus)
		{
			if (iStatus == 5)
				continue;
			// 1.7.0: 存疑资源化（21 语言，Translations IDS_HV_STATUS_STALE）
			if (iStatus == HV_STATUS_STALE)
			{
				LoadString(
					g_hModThisDll,
					IDS_HV_STATUS_STALE,
					phvctx->szStatus[iStatus],
					countof(phvctx->szStatus[iStatus])
				);
				continue;
			}
			LoadString(
				g_hModThisDll,
				iStatus + (IDS_HV_STATUS_MATCH - 1),
				phvctx->szStatus[iStatus],
				countof(phvctx->szStatus[iStatus])
			);
		}
	}

	// Initialize miscellaneous stuff
	{
		phvctx->uMaxBatch = (phvctx->cTotal < (0x20 << 8)) ? 0x20 : phvctx->cTotal >> 8;
		phvctx->dwStarted = 0;
        phvctx->hThread = NULL;
        phvctx->hUnpauseEvent = NULL;
		phvctx->bMaintLock = FALSE;
		phvctx->ppIndexOrig = NULL;   // 1.6.7: 原序快照（首排前懒存，维护增删即作废）
		phvctx->cIndexOrig = 0;

		// 1.6.5: 维护按钮（右上角）——1.6.3 可拉拽布局已按铁驭令回档拆除
		SetWindowTextW(GetDlgItem(phvctx->hWnd, IDC_MAINTAIN), L"维护");
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
		// 1.6.7：维护移除条目后 cHandledMsgs 可能超过剩余账目——钳零防 UINT 下溢显巨数
		{
			UINT cPending = (phvctx->cOrigTotal > phvctx->cMissing + phvctx->cHandledMsgs)
			              ? (phvctx->cOrigTotal - phvctx->cMissing - phvctx->cHandledMsgs)
			              : 0;
			FormatFractionalResults(szFormat, szBuffer, cPending, phvctx->cTotal);
		}
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
			case HV_COL_EXPECTED: pdi->item.pszText = pItem->pszExpected;                break;
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

						// 1.6.9: HV_STATUS_DAMAGED 着色分支随 chk 铲除


						case HV_STATUS_STALE:        // 存疑（1.7.2 收敛为状态列紫底白字，与黄缺失/蓝新增同惯例；1.7.0 曾整行紫）
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
	if (phvctx->status == ACTIVE || phvctx->status == PAUSED || phvctx->bMaintLock)
		return;  // 计算进行中禁止排序；待命（INACTIVE）与算完（CLEANUP_COMPLETED）均可排；
		         // 1.6.7：维护同步哈希中同样禁排（排序与维护循环并发写条目=竞态）

	// Capture the current selection/focus state
	HashVerifyReadStates(phvctx);

	if (phvctx->sort.iColumn != plv->iSubItem)
	{
		// 1.6.7：从未排序态进入排序态时存原序快照（三连击还原的依据）
		if (phvctx->sort.iColumn == -1 && !phvctx->ppIndexOrig && phvctx->cTotal && phvctx->index)
		{
			phvctx->ppIndexOrig = (PPHVITEM)malloc(phvctx->cTotal * sizeof(PHVITEM));
			if (phvctx->ppIndexOrig)
			{
				memcpy(phvctx->ppIndexOrig, phvctx->index, phvctx->cTotal * sizeof(PHVITEM));
				phvctx->cIndexOrig = phvctx->cTotal;
			}
		}

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

		// 1.6.7 修复：原版 SLBuildIndex 从竞技场无界重建——维护重算串节点/移除死块破坏
		// 「节点数==cTotal」不变量=越界写+串块被当条目解引用；改走首排前快照回放；
		// 快照缺失或过期（维护增删条目后）=保持现状序，绝不碰竞技场
		if (phvctx->ppIndexOrig && phvctx->index &&
		    phvctx->cIndexOrig == phvctx->cTotal)
			memcpy(phvctx->index, phvctx->ppIndexOrig, phvctx->cTotal * sizeof(PHVITEM));
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
			// 排序键（下标即 uStatusID）：未算=0、相符=1、不符=2、无法读=3、新增=4、
			// 5=空缺（DAMAGED 已铲）、存疑=6——1.6.7 修复：原 5 格数组装不下越界读
			// 1.6.9: DAMAGED(5) 随 chk 铲除——键位 5 永不被访问（uStatusID 不再产生 5）
			static const UINT8 ruSortKey[] = { 0, 1, 2, 3, 4, 5, 6 };
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
