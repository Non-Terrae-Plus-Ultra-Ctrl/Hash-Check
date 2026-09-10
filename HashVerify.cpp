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
#include "SetAppID.h"
#include "UnicodeHelpers.h"
#include "IsSSD.h"
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
	TCHAR              szStatus[5][MAX_STRINGRES];
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

// List management
__forceinline VOID WINAPI HashVerifyListInfo( PHASHVERIFYCONTEXT phvctx, LPNMLVDISPINFO pdi );
__forceinline LONG_PTR WINAPI HashVerifySetColor( PHASHVERIFYCONTEXT phvctx, LPNMLVCUSTOMDRAW pcd );
__forceinline LONG_PTR WINAPI HashVerifyFindItem( PHASHVERIFYCONTEXT phvctx, LPNMLVFINDITEM pfi );
__forceinline VOID WINAPI HashVerifySortColumn( PHASHVERIFYCONTEXT phvctx, LPNMLISTVIEW plv );
VOID WINAPI HashVerifySortByStatus( PHASHVERIFYCONTEXT phvctx );
__forceinline VOID WINAPI HashVerifyReadStates( PHASHVERIFYCONTEXT phvctx );
__forceinline VOID WINAPI HashVerifySetStates( PHASHVERIFYCONTEXT phvctx );
INT __cdecl HashVerifySortCompare( PHASHVERIFYCONTEXT phvctx, PPCHVITEM ppItemA, PPCHVITEM ppItemB );



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

			// Prepare the data for the parser...
			phvctx->pszFileData = BufferToWStr(&pbRawData, cbRawData.LowPart);
			HCNormalizeString(phvctx->pszFileData);
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
			SendMessage(phvctx->hWndPBTotal, PBM_SETRANGE32, 0, phvctx->cOrigTotal - phvctx->cMissing);
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
			{ IDC_STOP,             IDS_HV_PRIORITY   }
		};

		for (i = 0; i < countof(arStrMap); ++i)
			SetControlText(hWnd, arStrMap[i][0], arStrMap[i][1]);
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

		for (i = 1; i <= 4; ++i)
		{
			LoadString(
				g_hModThisDll,
				i + (IDS_HV_STATUS_MATCH - 1),
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
			case HV_COL_EXPECTED: pdi->item.pszText = pItem->pszExpected;                 break;
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

				case HV_STATUS_NEW:
					pcd->clrText = RGB(0x00, 0x00, 0xC0);
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

						case HV_STATUS_UNREADABLE:
							pcd->clrText = RGB(0x00, 0x00, 0x00);
							pcd->clrTextBk = RGB(0xFF, 0xE0, 0x00);
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

VOID WINAPI HashVerifySortColumn( PHASHVERIFYCONTEXT phvctx, LPNMLISTVIEW plv )
{
	if (phvctx->status != CLEANUP_COMPLETED)
		return;  // Sorting is available only after the worker is done

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
	// 按状态整理：相符 → 不符 → 缺失 → 新增（待检测排最后）。
	if (!phvctx->index || !phvctx->cTotal)
		return;

	phvctx->sort.iColumn = HV_COL_STATUS;
	phvctx->sort.bReverse = FALSE;

	qsort_s(phvctx->index, phvctx->cTotal, sizeof(PHVITEM),
	        (int(__cdecl*)(void*, const void*, const void*))HashVerifySortCompare, phvctx);

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
			// 排序键：相符=0、不符=1、缺失=2、新增=3、待检测=4（下标即 uStatusID）
			static const UINT8 ruSortKey[] = { 4, 0, 1, 2, 3 };
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
