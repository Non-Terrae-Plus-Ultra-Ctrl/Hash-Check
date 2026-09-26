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
#include "HashCheckCommon.h"
#include "HashCalc.h"
#include "UnicodeHelpers.h"
#include "Hcenc.h"
#include "libs/WinHash.h"
#include <Strsafe.h>
#include <stdlib.h>
#include <bcrypt.h>

// 1.4.9: bcrypt 已由 Hcsign.c 的 #pragma comment 链接


// Due to the stupidity of the x64 compiler, the code emitted for the non-inline
// function is not as efficient as it is on x86
#ifdef _M_IX86
#undef SSChainNCpy2
#define SSChainNCpy2 SSChainNCpy2F
#endif



/*============================================================================*\
	Function declarations
\*============================================================================*/

// Path processing
VOID WINAPI HashCalcWalkDirectory( PHASHCALCCONTEXT phcctx, PTSTR pszPath, UINT cchPath );
__forceinline BOOL WINAPI IsSpecialDirectoryName( PCTSTR pszPath );
__forceinline BOOL WINAPI IsDoubleSlashPath( PCTSTR pszPath );

// Save helpers
__forceinline VOID WINAPI HashCalcSetSavePrefix( PHASHCALCCONTEXT phcctx, PTSTR pszSave );
static BOOL WINAPI HashCalcWriteCommentLine( PHASHCALCCONTEXT phcctx, PCTSTR pszComment );
static BOOL WINAPI HashCalcWriteSignatureHeader( PHASHCALCCONTEXT phcctx );



// 1.5.7: SHA-256 合并到 Hcenc.c（HcencSha256）——chk 双端同源防漂移
#define HashCalcSha256 HcencSha256

/*============================================================================*\
	Path processing
\*============================================================================*/

BOOL WINAPI HashCalcPrepare( PHASHCALCCONTEXT phcctx )
{
	PTSTR pszPrev = NULL;
	PTSTR pszCurrent, pszCurrentEnd;
	UINT cbCurrent, cchCurrent;

	SLReset(phcctx->hListRaw);

	while (pszCurrent = SLGetDataAndStepEx(phcctx->hListRaw, &cbCurrent))
	{
		pszCurrentEnd = BYTEADD(pszCurrent, cbCurrent);
		cchCurrent = cbCurrent / sizeof(TCHAR) - 1;

		// Get rid of the trailing slash if there is one
		if (cchCurrent && *(pszCurrentEnd - 1) == TEXT('\\'))
		{
			*(--pszCurrentEnd) = 0;
			--cchCurrent;
			cbCurrent -= sizeof(TCHAR);
		}

		if (pszPrev == NULL)
		{
			// Initialize the cchPrefix (and cchMax) for the first time; since
			// we have stripped away the trailing slash (if there was one), we
			// are guaranteed that cchPrefix < cchCurrent for the first run,
			// and that cchPrefix < cchPrev for all other iterations

			PTSTR pszTail = StrRChr(pszCurrent, pszCurrentEnd, TEXT('\\'));

			if (pszTail)
				phcctx->cchPrefix = (UINT)(pszTail - pszCurrent) + 1;
			else
				phcctx->cchPrefix = 0;

			// For "\\" paths, we cannot cut off any of the first two slashes
			if (phcctx->cchPrefix == 2 && IsDoubleSlashPath(pszCurrent))
				phcctx->cchPrefix = 0;

			phcctx->cchMax = cchCurrent;
		}
		else
		{
			// Or, just update cchPrefix

			UINT i, j = 0, k = 0;

			for (i = 0; i < cchCurrent && i < phcctx->cchPrefix; ++i)
			{
				if (pszCurrent[i] != pszPrev[i])
					break;

				if (pszCurrent[i] == TEXT('\\'))
				{
					j = i + 1;
					++k;
				}
			}

			// For "\\" paths, we cannot cut off any of the first two slashes
			if (cchCurrent >= 2 && IsDoubleSlashPath(pszCurrent) && k < 3)
				phcctx->cchPrefix = 0;
			else
				phcctx->cchPrefix = j;
		}

		if (cchCurrent && phcctx->hList)
		{
			// Finally, we can do the actual work that's needed!

			if (GetFileAttributes(pszCurrent) & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (cchCurrent < MAX_PATH_BUFFER - 2)
				{
					memcpy(phcctx->scratch.sz, pszCurrent, cbCurrent);
					HashCalcWalkDirectory(phcctx, phcctx->scratch.sz, cchCurrent);
				}
			}
			else
			{
				PHASHCALCITEM pItem = SLAddItem(phcctx->hList, NULL, sizeof(HASHCALCITEM) + cbCurrent);

				if (pItem)
				{
                    pItem->results.dwFlags = 0;
					pItem->cchPath = cchCurrent;
					memcpy(pItem->szPath, pszCurrent, cbCurrent);

					if (phcctx->cchMax < cchCurrent)
						phcctx->cchMax = cchCurrent;

					++phcctx->cTotal;
				}
			}
		}

        if (phcctx->status == PAUSED)
            WaitForSingleObject(phcctx->hUnpauseEvent, INFINITE);
        if (phcctx->status == CANCEL_REQUESTED)
			return(FALSE);

		pszPrev = pszCurrent;
	}
    return(TRUE);
}

VOID WINAPI HashCalcWalkDirectory( PHASHCALCCONTEXT phcctx, PTSTR pszPath, UINT cchPath )
{
	HANDLE hFind;
	WIN32_FIND_DATA finddata;

	PTSTR pszPathAppend = pszPath + cchPath;
	*pszPathAppend = TEXT('\\');
	SSCpy2Ch(++pszPathAppend, TEXT('*'), 0);

	if ((hFind = FindFirstFile(pszPath, &finddata)) == INVALID_HANDLE_VALUE)
		return;

	do
	{
		// Add 1 to the length since we are also going to count the slash that
		// was added at the end of the directory
		UINT cchLeaf = (UINT)SSLen(finddata.cFileName) + 1;
		UINT cchNew = cchPath + cchLeaf;

        if (phcctx->status == PAUSED)
            WaitForSingleObject(phcctx->hUnpauseEvent, INFINITE);
		if (phcctx->status == CANCEL_REQUESTED)
			break;

		if ( (!(finddata.dwFileAttributes & FILE_ATTRIBUTE_OFFLINE)) &&
		     (cchNew < MAX_PATH_BUFFER - 2) )
		{
			SSChainNCpy(pszPathAppend, finddata.cFileName, cchLeaf);

			if (finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				// Directory: Recurse
				if (!IsSpecialDirectoryName(finddata.cFileName))
					HashCalcWalkDirectory(phcctx, pszPath, cchNew);
			}
			else
			{
				// File: Add to the list
				UINT cbPathBuffer = (cchNew + 1) * sizeof(TCHAR);
				PHASHCALCITEM pItem = SLAddItem(phcctx->hList, NULL, sizeof(HASHCALCITEM) + cbPathBuffer);

				if (pItem)
				{
                    pItem->results.dwFlags = 0;
					pItem->cchPath = cchNew;
					memcpy(pItem->szPath, pszPath, cbPathBuffer);

					if (phcctx->cchMax < cchNew)
						phcctx->cchMax = cchNew;

					++phcctx->cTotal;
				}
			}
		}

	} while (FindNextFile(hFind, &finddata));

	FindClose(hFind);
}

BOOL WINAPI IsSpecialDirectoryName( PCTSTR pszPath )
{
	// TRUE if name is "." or ".."

	#ifdef UNICODE
	return(
		(*((UPDWORD)pszPath) == WCHARS2DWORD(L'.', 0)) ||
		(*((UPDWORD)pszPath) == WCHARS2DWORD(L'.', L'.') && pszPath[2] == 0)
	);
	#else
	return(
		(*((UPWORD)pszPath) == CHARS2WORD('.', 0)) ||
		(*((UPWORD)pszPath) == CHARS2WORD('.', '.') && pszPath[2] == 0)
	);
	#endif
}

BOOL WINAPI IsDoubleSlashPath( PCTSTR pszPath )
{
	// TRUE if string starts with "\\"

	#ifdef UNICODE
	return(*((UPDWORD)pszPath) == WCHARS2DWORD(L'\\', L'\\'));
	#else
	return(*((UPWORD)pszPath) == CHARS2WORD('\\', '\\'));
	#endif
}



/*============================================================================*\
	Save dialog
\*============================================================================*/

VOID WINAPI HashCalcInitSave( PHASHCALCCONTEXT phcctx )
{
	HWND hWnd = phcctx->hWnd;

	// We can use the extended portion of the scratch buffer for the file name
	PTSTR pszFile = (PTSTR)phcctx->scratch.ext;

	// Default result value
	phcctx->hFileOut = INVALID_HANDLE_VALUE;

	// Load settings
	phcctx->opt.dwFlags = HCOF_FILTERINDEX | HCOF_SAVEENCODING;
	OptionsLoad(&phcctx->opt);

	// Initialize the struct for the first time, if needed
	if (phcctx->ofn.lStructSize == 0)
	{
		phcctx->ofn.lStructSize = sizeof(phcctx->ofn);
		phcctx->ofn.hwndOwner = hWnd;
		phcctx->ofn.lpstrFilter = HASH_FILE_FILTERS;
		phcctx->ofn.nFilterIndex = phcctx->opt.dwFilterIndex;
		phcctx->ofn.lpstrFile = pszFile;
		phcctx->ofn.nMaxFile = MAX_PATH_BUFFER + 10;
		phcctx->ofn.Flags = OFN_DONTADDTORECENT | OFN_NOCHANGEDIR | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
		phcctx->ofn.lpstrDefExt = TEXT("");

		// Set the initial file name: localized base ("校验"/"Verify") +
		// sequence number + hash extension (e.g. 校验-001.sha256).
		// Skip sequence numbers whose file already exists.
		{
			PTSTR pszOrigPath;
			TCHAR szBase[MAX_STRINGRES];
			UINT uSeq;

			SLReset(phcctx->hListRaw);
			pszOrigPath = SLGetDataAndStep(phcctx->hListRaw);

			LoadString(g_hModThisDll, IDS_HS_SAVE_BASENAME, szBase, countof(szBase));

			for (uSeq = 1; ; ++uSeq)
			{
				TCHAR szName[MAX_STRINGMSG];

				StringCchPrintf(
					szName, countof(szName),
					TEXT("%s-%03u%s"),
					szBase, uSeq,
					g_szHashExtsTab[phcctx->ofn.nFilterIndex - 1]
				);

				// Directory prefix + generated name
				SSChainNCpy2(
					pszFile,
					pszOrigPath, phcctx->cchPrefix,
					szName, countof(szName)
				);

				if (!PathFileExists(pszFile))
					break;
			}
		}
	}

	// We should also do a sanity check to make sure that the filter index
	// is set to a valid value since we depend on that to determine the format
	if ( GetSaveFileName(&phcctx->ofn) &&
	     phcctx->ofn.nFilterIndex &&
		 phcctx->ofn.nFilterIndex <= NUM_HASHES)
	{
		// Save the filter in the user's preferences
		if (phcctx->opt.dwFilterIndex != phcctx->ofn.nFilterIndex)
		{
			phcctx->opt.dwFilterIndex = phcctx->ofn.nFilterIndex;
			phcctx->opt.dwFlags = HCOF_FILTERINDEX;
			OptionsSave(&phcctx->opt);
		}

		// Extension fixup: Correct the extension to match the selected
		// type, but only if the extension was one of the 5 in the list
		if (phcctx->ofn.nFileExtension)
		{
			PTSTR pszExt = pszFile + phcctx->ofn.nFileExtension - 1;

#define HASH_EXT_CMP_OR_op(alg) StrCmpI(pszExt, HASH_EXT_##alg) == 0 ||
			if (FOR_EACH_HASH(HASH_EXT_CMP_OR_op) FALSE)  // the FALSE is to ignore the last trailing ||
			{
				if (StrCmpI(pszExt, g_szHashExtsTab[phcctx->ofn.nFilterIndex - 1]))
					SSCpy(pszExt, g_szHashExtsTab[phcctx->ofn.nFilterIndex - 1]);
			}
		}

		// Adjust the file paths for the output path, if necessary
		HashCalcSetSavePrefix(phcctx, pszFile);

		// Open the file for output
		phcctx->hFileOut = CreateFile(
			pszFile,
			FILE_APPEND_DATA | DELETE,
			FILE_SHARE_READ,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		if (phcctx->hFileOut != INVALID_HANDLE_VALUE)
		{
			// The actual format will be set when HashCalcWriteResult is called
			phcctx->szFormat[0] = 0;

			if (phcctx->opt.dwSaveEncoding == 1)
			{
				// Write the BOM for UTF-16LE
				WCHAR BOM = 0xFEFF;
				DWORD cbWritten;
				WriteFile(phcctx->hFileOut, &BOM, sizeof(WCHAR), &cbWritten, NULL);
			}

			// Provision file signing: make sure the local signing key
			// exists up front.  The signature itself is appended by
			// HashCalcAppendSignature() after all lines are in.
			HashCalcWriteSignatureHeader(phcctx);
		}
		else
		{
			TCHAR szMessage[MAX_STRINGMSG];
			LoadString(g_hModThisDll, IDS_HC_SAVE_ERROR, szMessage, countof(szMessage));
			MessageBox(hWnd, szMessage, NULL, MB_OK | MB_ICONERROR);
		}
	}
}

VOID WINAPI HashCalcSetSaveFormat( PHASHCALCCONTEXT phcctx )
{
	// Set szFormat if necessary
	if (phcctx->szFormat[0] == 0)
	{
		// Did I ever mention that I hate SFV?
		// The reason we tracked cchMax was because of this idiotic format
		if (phcctx->ofn.nFilterIndex == 1)
		{
			StringCchPrintf(
				phcctx->szFormat,
				countof(phcctx->szFormat),
				TEXT("%%-%ds %%s\r\n"),
				phcctx->cchMax - phcctx->cchAdjusted
			);
		}
		else
		{
			SSStaticCpy(phcctx->szFormat, TEXT("%s *%s\r\n"));
		}
	}
}

BOOL WINAPI HashCalcWriteResult( PHASHCALCCONTEXT phcctx, PHASHCALCITEM pItem )
{
	PCTSTR pszHash;                     // will be pointed to the hash name
    WCHAR szWbuffer[MAX_PATH_BUFFER];   // wide-char buffer
    CHAR  szAbuffer[MAX_PATH_BUFFER];   // narrow-char buffer
#ifdef UNICODE
#   define szTbuffer szWbuffer
#else
#   define szTbuffer szAbuffer
#endif
    PTSTR szTbufferAppend = szTbuffer;  // current end of the buffer used to build output
    size_t cchLine = MAX_PATH_BUFFER;   // starts off as count of remaining TCHARS in the buffer
    PVOID pvLine;                       // will be pointed to the buffer to write out
    size_t cbLine;                      // will be line length in bytes, EXCLUDING nul terminator
    BOOL bRetval = TRUE;
    TCHAR szChkBody[72];                // 1.4.9: "chk=<64 hex>" per-line integrity
    BOOL bWriteChk = FALSE;

	// If the checksum to save isn't present in the results
    if (! ((1 << (phcctx->ofn.nFilterIndex - 1)) & pItem->results.dwFlags))
    {
        // Start with a commented-out error message - "; UNREADABLE:"
        WCHAR szUnreadable[MAX_STRINGRES];
        LoadString(g_hModThisDll, IDS_HV_STATUS_UNREADABLE, szUnreadable, MAX_STRINGRES);
        StringCchPrintfEx(szTbufferAppend, cchLine, &szTbufferAppend, &cchLine, 0, TEXT("; %s:\r\n"), szUnreadable);

        // We'll still output a hash, but it will be all 0's, that way Verify will indicate an mismatch
        HashCalcClearInvalid(&pItem->results, TEXT('0'));
        bRetval = FALSE;
    }

	// Translate the filter index to a hash
	switch (phcctx->ofn.nFilterIndex)
	{
#define HASH_INDEX_TO_RESULTS_op(alg) \
        case alg:  pszHash = pItem->results.szHex##alg;  break;
        FOR_EACH_HASH(HASH_INDEX_TO_RESULTS_op)
		default: return(FALSE);
	}

	// Format the line
	#define HashCalcFormat(a, b) StringCchPrintfEx(szTbufferAppend, cchLine, &szTbufferAppend, &cchLine, 0, phcctx->szFormat, a, b)
	(phcctx->ofn.nFilterIndex == 1) ?
		HashCalcFormat(pItem->szPath + phcctx->cchAdjusted, pszHash) : // SFV
		HashCalcFormat(pszHash, pItem->szPath + phcctx->cchAdjusted);  // everything else
	#undef HashCalcFormat

#ifdef _TIMED
    StringCchPrintfEx(szTbufferAppend, cchLine, NULL, &cchLine, 0,
                      _T("; Elapsed: %d ms\r\n"), pItem->dwElapsed);
#endif

	// 1.4.9/1.5.6: 逐条 chk——数据行 = 本块最后一个 '\n' 之后（UNREADABLE
	// 前置注释行在它前面）；裁尾必须在「副本」上做。1.5.3 曾直接在
	// szTbuffer 本体上裁尾，把数据行的 \r\n 行尾从写盘内容里裁丢——数据行
	// 与 chk 注释行连成一体，验证端把 "; chk=..." 当文件名的一部分，整清单
	// 「缺失/新增」无法校验。1.4.9 的原始病（取「\n 之后」拿到行尾 NUL，
	// chk 全是空串哈希）由「先裁尾再取行」解决，此处只是把裁尾搬到副本。
	{
		PTSTR pszLast;
		PTSTR pScan;
		PTSTR pszCopy;
		size_t cchBuf, cchLast;

		cchBuf = SSLen(szTbuffer);
		pszCopy = (PTSTR)malloc((cchBuf + 1) * sizeof(TCHAR));

		if (pszCopy)
		{
			BYTE byHash[32];

			memcpy(pszCopy, szTbuffer, (cchBuf + 1) * sizeof(TCHAR));
			while (cchBuf && (pszCopy[cchBuf-1] == TEXT('\r') ||
			                  pszCopy[cchBuf-1] == TEXT('\n') ||
			                  pszCopy[cchBuf-1] == TEXT(' ')))
				pszCopy[--cchBuf] = 0;

			pszLast = pszCopy;
			for (pScan = pszCopy; *pScan; ++pScan)
			{
				if (*pScan == TEXT('\n'))
					pszLast = pScan + 1;
			}

			cchLast = SSLen(pszLast);
			if (cchLast && cchLast <= 0x8000)
			{
				HCNormalizeString(pszLast);

				if (HashCalcSha256((const BYTE*)pszLast,
				                   (DWORD)(cchLast * sizeof(TCHAR)), byHash))
				{
					static const TCHAR szHex[] = TEXT("0123456789abcdef");
					UINT k;

					SSCpy(szChkBody, TEXT("chk="));
					for (k = 0; k < 32; ++k)
					{
						szChkBody[4 + 2*k]     = szHex[byHash[k] >> 4];
						szChkBody[4 + 2*k + 1] = szHex[byHash[k] & 15];
					}
					szChkBody[68] = 0;
					bWriteChk = TRUE;
				}
			}

			free(pszCopy);
		}
	}

	cchLine = MAX_PATH_BUFFER - cchLine;  // from now on cchLine is the line length in bytes, EXCLUDING nul terminator
	if (cchLine > 0)
	{
		// Convert to the correct encoding
		switch (phcctx->opt.dwSaveEncoding)
		{
			case 0:
			{
				// UTF-8
				#ifdef UNICODE
				cbLine = WStrToUTF8(szWbuffer, szAbuffer, MAX_PATH_BUFFER) - 1;
				#else
				         AStrToWStr(szAbuffer, szWbuffer, MAX_PATH_BUFFER));
				cbLine = WStrToUTF8(szWbuffer, szAbuffer, MAX_PATH_BUFFER)) - 1;
				#endif

				pvLine = szAbuffer;
				break;
			}

			case 1:
			{
				// UTF-16
				#ifndef UNICODE
				cchLine = AStrToWStr(szAbuffer, szWbuffer, MAX_PATH_BUFFER) - 1;
				#endif

				cbLine = cchLine * sizeof(WCHAR);
				pvLine = szWbuffer;
				break;
			}

			case 2:
			{
				// ANSI
				#ifdef UNICODE
				cbLine = WStrToAStr(szWbuffer, szAbuffer, MAX_PATH_BUFFER) - 1;
				#else
				cbLine = cchLine;
				#endif

				pvLine = szAbuffer;
				break;
			}

			default: return(FALSE);
		}

		if (cbLine > 0)
		{
			INT cbWritten;
			WriteFile(phcctx->hFileOut, pvLine, (DWORD)cbLine, &cbWritten, NULL);
			if (cbLine != cbWritten) return(FALSE);

			// 1.4.9: 数据行成功写出 -> 紧跟本条 chk 注释行
			if (bWriteChk && !HashCalcWriteCommentLine(phcctx, szChkBody))
				return(FALSE);
		}
		else return(FALSE);
	}
	else return(FALSE);

	return(bRetval);
}

// Append a "; <comment>" line to the file, in the file's save encoding.
// The content is ASCII so UTF-8 and ANSI output are identical.
static BOOL WINAPI HashCalcWriteCommentLine( PHASHCALCCONTEXT phcctx, PCTSTR pszComment )
{
	TCHAR szLine[MAX_DIGEST_STRING_LENGTH + 16];
#ifndef UNICODE
	WCHAR szW[MAX_DIGEST_STRING_LENGTH + 16];
#endif
	CHAR  szA[(MAX_DIGEST_STRING_LENGTH + 16) * 3];
	PVOID pvLine;
	size_t cbLine;

	StringCchPrintf(szLine, countof(szLine), TEXT("; %s\r\n"), pszComment);

	switch (phcctx->opt.dwSaveEncoding)
	{
		case 1: // UTF-16
			cbLine = SSLen(szLine) * sizeof(TCHAR);
			pvLine = szLine;
			break;

		case 2: // ANSI
#ifdef UNICODE
			cbLine = WStrToAStr(szLine, szA, countof(szA)) - 1;
#else
			cbLine = SSLen(szLine);
			memcpy(szA, szLine, cbLine);
#endif
			pvLine = szA;
			break;

		default: // UTF-8
#ifdef UNICODE
			cbLine = WStrToUTF8(szLine, szA, countof(szA)) - 1;
#else
			cbLine = AStrToWStr(szLine, szW, countof(szW)) - 1;
			cbLine = WStrToUTF8(szW, szA, countof(szA)) - 1;
#endif
			pvLine = szA;
			break;
	}

	if (cbLine == 0)
		return(FALSE);

	{
		DWORD cbWritten;
		return(WriteFile(phcctx->hFileOut, pvLine, (DWORD)cbLine, &cbWritten, NULL) &&
		       cbWritten == (DWORD)cbLine);
	}
}


// Append the "; <region><YYYYMMDDHHMMSS>" timestamp line to the checksum file.
VOID WINAPI HashCalcAppendTimestamp( PHASHCALCCONTEXT phcctx )
{
	SYSTEMTIME st;
	TCHAR szRegion[MAX_STRINGRES];
	TCHAR szTime[MAX_STRINGRES];   // region(2) + 14 digits + NUL

	// Region = the system "Country or region" (GetUserDefaultGeoName, Win10+),
	// else the format locale country (GetLocaleInfo), else "cn"; lowercased.
	szRegion[0] = 0;
	{
		HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
		typedef int(WINAPI* PFN_GUDGN)(PWSTR, int);
		PFN_GUDGN pfnGeo = (PFN_GUDGN)GetProcAddress(hKernel32, "GetUserDefaultGeoName");
		if (pfnGeo)
			pfnGeo(szRegion, countof(szRegion));
	}
	if (!szRegion[0])
	{
		if (!GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, szRegion, countof(szRegion)))
			szRegion[0] = 0;
	}
	if (!szRegion[0])
		SSCpy(szRegion, TEXT("cn"));
	CharLowerBuff(szRegion, (DWORD)SSLen(szRegion));

	GetLocalTime(&st);
	StringCchPrintf(szTime, countof(szTime), TEXT("%s%04u%02u%02u%02u%02u%02u"),
	                szRegion,
	                (UINT)st.wYear, (UINT)st.wMonth, (UINT)st.wDay,
	                (UINT)st.wHour, (UINT)st.wMinute, (UINT)st.wSecond);

	HashCalcWriteCommentLine(phcctx, szTime);
}


// Provision signing for a new checksum file (called from HashCalcInitSave,
// right after the BOM).  1.4.4: the file carries a pub= line (the local KSP
// public key, written by HashCalcAppendSignature) and a sig= line; the
// verifier verifies with the in-file pub and layers signer identity
// (author table / local KSP / TrustedSigners / TOFU).  selfcheck stays
// removed (1.4.3).  Here we only make sure the local signing key exists;
// the signature itself is appended by HashCalcAppendSignature at the end.
// Returns TRUE if signing is provisioned; FALSE if the key could not
// be created (HashCalcEncryptFile then aborts the save, fail-closed).
static BOOL WINAPI HashCalcWriteSignatureHeader( PHASHCALCCONTEXT phcctx )
{
	if (!HcsignEnsureKey())
		return FALSE;

	phcctx->bSignEnabled = TRUE;
	return TRUE;
}

// Sign the just-finished checksum file: re-read its raw contents, decode and
// normalize them exactly as the verifier will, sign that normalized text with
// the per-user signing key (ECDSA P-256, SHA-256 inside HcsignSign), and
// append the "; sig=<keyid>:<base64url signature>" line.  The signature
// covers every line that came before it (the hash lines and the timestamp)
// so any tampering invalidates the signature.
VOID WINAPI HashCalcAppendSignature( PHASHCALCCONTEXT phcctx )
{
	HANDLE hFile;
	LARGE_INTEGER cbSize;
	DWORD cbLen, cbRead;
	PBYTE pbData;
	PWSTR pszW;
	PTSTR pszSig = NULL;

	if (!phcctx->bSignEnabled)
		return;   // no pub= header (key unavailable); leave the file plain

	if ((hFile = OpenFileForReading(phcctx->ofn.lpstrFile)) == INVALID_HANDLE_VALUE)
		return;

	if (!GetFileSizeEx(hFile, &cbSize) || cbSize.HighPart)
	{
		CloseHandle(hFile);
		return;
	}

	cbLen = cbSize.LowPart;

	if (!(pbData = (PBYTE)malloc(cbLen + sizeof(DWORD))))
	{
		CloseHandle(hFile);
		return;
	}

	if (cbLen && (!ReadFile(hFile, pbData, cbLen, &cbRead, NULL) || cbRead != cbLen))
	{
		free(pbData);
		CloseHandle(hFile);
		return;
	}

	CloseHandle(hFile);

	// Null-terminate the buffer for the decoder (mirrors HashVerifyLoadData)
	*((UPDWORD)(pbData + cbLen)) = 0;

	if (!(pszW = BufferToWStr(&pbData, cbLen)))
	{
		free(pbData);
		return;
	}

	// 1.4.4: pub 行回归——签名载荷 = 「原文 + "; pub=<b64>\r\n"」（原始形态）整体
	// 规范化后的结果，与验证端 normalize（sig 行前内容）字节一致。
	// 注意：HCNormalizeString 逐字符替换（\r->\n 保留原 \n），\r\n 会变成 \n\n——
	// 所以载荷必须先拼原始 \r\n 形态再整体规范化，绝不能先规范化再拼 \n。
	// 任一步失败 -> bSignEnabled 置 FALSE -> HashCalcEncryptFile 删文件（fail-closed）。
	{
		PTSTR pszPub = NULL;

		if (HcsignGetPublicKeyB64(&pszPub))
		{
			size_t cch = SSLen(pszW);
			PWSTR pszPayload = (PWSTR)malloc((cch + SSLen(pszPub) + 16) * sizeof(TCHAR));

			if (pszPayload)
			{
				memcpy(pszPayload, pszW, cch * sizeof(TCHAR));
				memcpy(pszPayload + cch, TEXT("; pub="), 6 * sizeof(TCHAR));
				cch += 6;
				memcpy(pszPayload + cch, pszPub, SSLen(pszPub) * sizeof(TCHAR));
				cch += SSLen(pszPub);
				pszPayload[cch++] = TEXT('\r');
				pszPayload[cch++] = TEXT('\n');
				pszPayload[cch]   = 0;

				HCNormalizeString(pszPayload);   /* 整体规范化（与验证端一致） */

				if (HcsignSign((const BYTE*)pszPayload, (DWORD)(cch * sizeof(TCHAR)), &pszSig))
				{
					TCHAR szComment[(MAX_DIGEST_STRING_LENGTH + 16) + 32];

					// pub 行（本机 KSP 公钥——接收方用它验签，传输完整性的根基）
					StringCchPrintf(szComment, countof(szComment), TEXT("pub=%s"), pszPub);
					HashCalcWriteCommentLine(phcctx, szComment);

					// sig 行带 keyid（与容器头双写互校验，1.4.3 保留）。
					// NOTE: %02X (hex) -- the verifier parses the prefix as hex,
					// and the writer/reader must agree byte-for-byte.
					StringCchPrintf(szComment, countof(szComment), TEXT("sig=%02X:%s"),
					                (UINT)HCK_KEYID_LOCAL, pszSig);
					HashCalcWriteCommentLine(phcctx, szComment);
				}
				else
					phcctx->bSignEnabled = FALSE;   // fail-closed

				free(pszPayload);
			}
			else
				phcctx->bSignEnabled = FALSE;   // fail-closed
		}
		else
			phcctx->bSignEnabled = FALSE;   // fail-closed（EncryptFile 删文件）

		if (pszPub)
			LocalFree(pszPub);
	}
	if (pszSig)
		LocalFree(pszSig);

	free(pbData);
}

// Seal the just-finished checksum file into the encrypted container: read the
// whole plaintext file back (data lines + timestamp + signature), encrypt it
// with the built-in AES-256-GCM key (see Hcenc.c), and overwrite
// the file with the container.  The on-disk file becomes non-plaintext; the
// verifier detects the container magic and decrypts before parsing.  On any
// failure the file is deleted -- never leave an unencrypted checksum file
// behind.  hFileOut is closed first (its sharing mode forbids a second
// write handle); the later close by the caller sees INVALID and is a no-op.
VOID WINAPI HashCalcEncryptFile( PHASHCALCCONTEXT phcctx )
{
	HANDLE hFile, hOut;
	LARGE_INTEGER cbSize;
	DWORD cbRead, cbWritten;
	PBYTE pbPlain = NULL;
	PBYTE pbEnc = NULL;
	DWORD cbEnc = 0;
	BOOL bOk = FALSE;

	// 1.4.3 fail-closed: an unsigned checksum file would be REJECTED by the
	// verifier of this build (sealed files must carry a "; sig=" line), so if
	// signing could not be provisioned, never write the file at all.
	if (!phcctx->bSignEnabled)
	{
		MessageBox(NULL, L"签名密钥不可用，已取消保存校验文件。",
		           NULL, MB_OK | MB_ICONERROR);
		goto fail_nofile;
	}

	if (phcctx->hFileOut != INVALID_HANDLE_VALUE)
	{
		CloseHandle(phcctx->hFileOut);
		phcctx->hFileOut = INVALID_HANDLE_VALUE;
	}

	if ((hFile = OpenFileForReading(phcctx->ofn.lpstrFile)) == INVALID_HANDLE_VALUE)
		goto fail;

	if (!GetFileSizeEx(hFile, &cbSize) || cbSize.HighPart)
	{
		CloseHandle(hFile);
		goto fail;
	}

	pbPlain = (PBYTE)malloc(cbSize.LowPart ? cbSize.LowPart : 1);
	if (!pbPlain)
	{
		CloseHandle(hFile);
		goto fail;
	}

	if (cbSize.LowPart &&
	    (!ReadFile(hFile, pbPlain, cbSize.LowPart, &cbRead, NULL) ||
	     cbRead != cbSize.LowPart))
	{
		CloseHandle(hFile);
		goto fail;
	}
	CloseHandle(hFile);

	// 1.4.2: seal twice with independent random nonces -> [seal A][seal B]
	// (double-container redundancy).  1.4.3: the keyid (local-machine KSP
	// trust domain) is written into each container header; the verifier
	// cross-checks it against the "; sig=XX:" prefix (see Hcenc.h).
	if (!HcencEncryptPair(HCK_KEYID_LOCAL, pbPlain, cbSize.LowPart,
	                      &pbEnc, &cbEnc))
		goto fail;

	hOut = CreateFile(
		phcctx->ofn.lpstrFile,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hOut == INVALID_HANDLE_VALUE)
		goto fail;

	bOk = WriteFile(hOut, pbEnc, cbEnc, &cbWritten, NULL) &&
	      cbWritten == cbEnc;
	CloseHandle(hOut);

	if (bOk)
	{
		free(pbPlain);
		free(pbEnc);
		return;
	}

fail:
	if (pbPlain) free(pbPlain);
	if (pbEnc)   free(pbEnc);
	DeleteFile(phcctx->ofn.lpstrFile);
	MessageBox(NULL, L"加密校验文件失败，已删除输出文件。",
	           NULL, MB_OK | MB_ICONERROR);
	return;

fail_nofile:
	// !bSignEnabled path: close the still-open plaintext output handle and
	// delete the file -- never leave an unsigned plaintext behind.
	if (phcctx->hFileOut != INVALID_HANDLE_VALUE)
	{
		CloseHandle(phcctx->hFileOut);
		phcctx->hFileOut = INVALID_HANDLE_VALUE;
	}
	DeleteFile(phcctx->ofn.lpstrFile);
}

VOID WINAPI HashCalcClearInvalid( PWHRESULTEX pwhres, WCHAR cInvalid )
{
#ifdef UNICODE
#   define _tmemset wmemset
#else
#   define _tmemset memset
#endif

#define HASH_CLEAR_INVALID_op(alg)                                                \
    if (! (pwhres->dwFlags & WHEX_CHECK##alg))                                    \
    {                                                                             \
        _tmemset(pwhres->szHex##alg, cInvalid, countof(pwhres->szHex##alg) - 1);  \
        pwhres->szHex##alg[countof(pwhres->szHex##alg) - 1] = L'\0';              \
    }
    FOR_EACH_HASH(HASH_CLEAR_INVALID_op)
}

// This can only succeed on Windows Vista and later;
// returns FALSE on failure
BOOL WINAPI HashCalcDeleteFileByHandle(HANDLE hFile)
{
    if (hFile == INVALID_HANDLE_VALUE)
        return(FALSE);

    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    if (hKernel32 == NULL)
        return(FALSE);

    typedef BOOL(WINAPI* PFN_SFIBH)(_In_ HANDLE, _In_ FILE_INFO_BY_HANDLE_CLASS, _In_ LPVOID, _In_ DWORD);
    PFN_SFIBH pfnSetFileInformationByHandle = (PFN_SFIBH)GetProcAddress(hKernel32, "SetFileInformationByHandle");
    if (pfnSetFileInformationByHandle == NULL)
        return(FALSE);

    FILE_DISPOSITION_INFO fdi;
    fdi.DeleteFile = TRUE;
    return(pfnSetFileInformationByHandle(hFile, FileDispositionInfo, &fdi, sizeof(fdi)));
}

VOID WINAPI HashCalcSetSavePrefix( PHASHCALCCONTEXT phcctx, PTSTR pszSave )
{
	// We have to be careful here about case sensitivity since we are now
	// working with a user-provided path instead of a system-provided path...

	// We want to build new paths without resorting to using "..", as that is
	// ugly, fragile (often more so than absolute paths), and not to mention,
	// complicated to calculate.  This means that relative paths will be used
	// only for paths within the same line of ancestry.

	BOOL bMultiSel;
	PTSTR pszOrig;
	PTSTR pszTail;

	// First, grab one of the original paths to work with
	SLReset(phcctx->hListRaw);
	pszOrig = SLGetDataAndStep(phcctx->hListRaw);
	bMultiSel = SLCheck(phcctx->hListRaw);

	// Unfortunately, we also have to contend with the possibility that one of
	// these paths may be in short name format (e.g., if the user navigates to
	// %TEMP% on a NT 5.x system)
	{
		// The scratch buffer's sz members are large enough for us
		PTSTR pszOrigLong = (PTSTR)phcctx->scratch.szW;
		PTSTR pszSaveLong = (PTSTR)phcctx->scratch.szA;

		// Copy original path to scratch and terminate
		pszTail = SSChainNCpy(pszOrigLong, pszOrig, phcctx->cchPrefix);
		pszTail[0] = 0;

		// Copy output path to scratch and terminate
		pszTail = SSChainNCpy(pszSaveLong, pszSave, phcctx->ofn.nFileOffset);
		pszTail[0] = 0;

		// Normalize both paths to LFN
		GetLongPathName(pszOrigLong, pszOrigLong, MAX_PATH_BUFFER);
		GetLongPathName(pszSaveLong, pszSaveLong, MAX_PATH_BUFFER);

		// We will only handle the case where they are the same, to prevent our
		// re-prefixing from messing up the base behavior; it is not worth the
		// trouble to account for LFN for all cases--just let it fall through
		// to an absolute path.
		if (StrCmpNI(pszOrigLong, pszSaveLong, MAX_PATH_BUFFER) == 0)
		{
			phcctx->cchAdjusted = phcctx->cchPrefix;
			return;
		}
	}

	if (pszTail = StrRChr(pszSave, NULL, TEXT('\\')))
	{
		phcctx->cchAdjusted = (UINT)(pszTail - pszSave) + 1;

		if (phcctx->cchAdjusted <= phcctx->cchPrefix)
		{
			if (StrCmpNI(pszOrig, pszSave, phcctx->cchAdjusted) == 0)
			{
				// If the ouput prefix is the same as or a parent of the input
				// prefix...

				if (!(IsDoubleSlashPath(pszSave) && phcctx->cchAdjusted < 3))
					return;
			}
		}
		else if (!bMultiSel)
		{
			// We will make an exception for the case where the user selects
			// a single directory from the Shell and then saves the output in
			// that directory...

			BOOL bEqual;

			*pszTail = 0;
			bEqual = StrCmpNI(pszOrig, pszSave, phcctx->cchAdjusted) == 0;
			*pszTail = TEXT('\\');

			if (bEqual) return;
		}
	}

	// If we have reached this point, we need to use an absolute path

	if ( pszSave[1] == TEXT(':') && phcctx->cchPrefix > 2 &&
	     StrCmpNI(pszOrig, pszSave, 2) == 0 )
	{
		// Omit drive letter
		phcctx->cchAdjusted = 2;
	}
	else
	{
		// Full absolute path
		phcctx->cchAdjusted = 0;
	}
}



/*============================================================================*\
	Progress bar
\*============================================================================*/

VOID WINAPI HashCalcTogglePrep( PHASHCALCCONTEXT phcctx, BOOL bState )
{
	DWORD dwStyle = (DWORD)GetWindowLongPtr(phcctx->hWndPBTotal, GWL_STYLE);

	if (bState)
	{
		dwStyle &= ~PBS_SMOOTH;
		dwStyle |= PBS_MARQUEE;
		phcctx->dwFlags |= HCF_MARQUEE;
	}
	else
	{
		dwStyle |= PBS_SMOOTH;
		dwStyle &= ~PBS_MARQUEE;
		phcctx->dwFlags &= ~HCF_MARQUEE;
	}

	SetWindowLongPtr(phcctx->hWndPBTotal, GWL_STYLE, dwStyle);
	SendMessage(phcctx->hWndPBTotal, PBM_SETMARQUEE, bState, MARQUEE_INTERVAL);

	if (!bState)
		SendMessage(phcctx->hWndPBTotal, PBM_SETRANGE32, 0, phcctx->cTotal);
}
