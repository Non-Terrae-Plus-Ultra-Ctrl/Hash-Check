/**
 * Windows Hashing/Checksumming Library
 * Last modified: 2016/02/21
 * Original work copyright (C) Kai Liu.  All rights reserved.
 * Modified work copyright (C) 2014, 2016 Christopher Gurnee.  All rights reserved.
 * Modified work copyright (C) 2016 Tim Schlueter.  All rights reserved.
 *
 * This is a wrapper for the CRC32, MD5, SHA1, SHA2-256, and SHA2-512
 * algorithms.
 **/

#ifndef __WINHASH_H__
#define __WINHASH_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <tchar.h>
#include "sha3/KeccakHash.h"
#include "BitwiseIntrinsics.h"
#include "blake2.h"
#include "blake3.h"
#include "sm3.h"
#include "ripemd160.h"
#include "xxhash64.h"

#if _MSC_VER >= 1600 && !defined(NO_PPL)
#define USE_PPL
#endif

typedef CONST BYTE *PCBYTE;

#define CRLF _T("\r\n")
#define CCH_CRLF 2

/**
 * Returns the offset of a member in a struct such that:
 * type * t; &t->member == ((BYTE *) t) + FINDOFFSET(type, member)
 */
#define FINDOFFSET(type,member) (&(((type *) 0)->member))

/**
 * Apply a macro for every hash algorithm
 * @param   op      A macro to perform on every hash algorithm
 */
#define FOR_EACH_HASH(op)   op(CRC32)   \
                            op(MD5)     \
                            op(SHA1)    \
                            op(SHA256)  \
                            op(SHA512)  \
                            op(SHA3_256)\
                            op(SHA3_512)\
                            op(SHA224)  \
                            op(SHA384)  \
                            op(SHA3_224)\
                            op(SHA3_384)\
                            op(BLAKE2b) \
                            op(BLAKE2s) \
                            op(BLAKE3)  \
                            op(SM3)     \
                            op(SHAKE128)\
                            op(SHAKE256)\
                            op(RIPEMD160)\
                            op(XXHASH64)
// In approximate order from longest to shortest compute time
#define FOR_EACH_HASH_R(op) op(SHA512)  \
                            op(SHA256)  \
                            op(SHA3_512)\
                            op(SHA3_256)\
                            op(SHA1)    \
                            op(CRC32)   \
                            op(MD5)     \
                            op(SHA384)  \
                            op(BLAKE2b) \
                            op(SHA3_384)\
                            op(SHA224)  \
                            op(BLAKE2s) \
                            op(BLAKE3)  \
                            op(SM3)     \
                            op(SHA3_224)\
                            op(SHAKE128)\
                            op(SHAKE256)\
                            op(RIPEMD160)\
                            op(XXHASH64)

/**
 * Some constants related to the hash algorithms
 */

// Hash algorithms
enum hash_algorithm {
    CRC32 = 1,
    MD5,
    SHA1,
    SHA256,
    SHA512,
    SHA3_256,
    SHA3_512,
    SHA224,
    SHA384,
    SHA3_224,
    SHA3_384,
    BLAKE2b,
    BLAKE2s,
    BLAKE3,
    SM3,
    SHAKE128,
    SHAKE256,
    RIPEMD160,
    XXHASH64
};
#define NUM_HASHES XXHASH64

// The default hash algorithm to use when creating a checksum file
#define DEFAULT_HASH_ALGORITHM SHA256
// and when viewing checksums in the explorer file propery sheet
// (if this is changed, also update the test in HashProp.cs)
#define DEFAULT_HASH_ALGORITHMS (WHEX_CHECKCRC32 | WHEX_CHECKSHA1 | WHEX_CHECKSHA256 | WHEX_CHECKSHA512)

// Bitwise representation of the hash algorithms
#define WHEX_CHECKCRC32     (1UL << (CRC32  - 1))
#define WHEX_CHECKMD5       (1UL << (MD5    - 1))
#define WHEX_CHECKSHA1      (1UL << (SHA1   - 1))
#define WHEX_CHECKSHA256    (1UL << (SHA256 - 1))
#define WHEX_CHECKSHA512    (1UL << (SHA512 - 1))
#define WHEX_CHECKSHA3_256  (1UL << (SHA3_256 - 1))
#define WHEX_CHECKSHA3_512  (1UL << (SHA3_512 - 1))
#define WHEX_CHECKSHA224    (1UL << (SHA224 - 1))
#define WHEX_CHECKSHA384    (1UL << (SHA384 - 1))
#define WHEX_CHECKSHA3_224  (1UL << (SHA3_224 - 1))
#define WHEX_CHECKSHA3_384  (1UL << (SHA3_384 - 1))
#define WHEX_CHECKBLAKE2b   (1UL << (BLAKE2b - 1))
#define WHEX_CHECKBLAKE2s   (1UL << (BLAKE2s - 1))
#define WHEX_CHECKBLAKE3    (1UL << (BLAKE3 - 1))
#define WHEX_CHECKSM3       (1UL << (SM3 - 1))
#define WHEX_CHECKSHAKE128  (1UL << (SHAKE128 - 1))
#define WHEX_CHECKSHAKE256  (1UL << (SHAKE256 - 1))
#define WHEX_CHECKRIPEMD160 (1UL << (RIPEMD160 - 1))
#define WHEX_CHECKXXHASH64  (1UL << (XXHASH64 - 1))
#define WHEX_CHECKLAST      WHEX_CHECKXXHASH64

// Bitwise representation of the hash algorithms, by digest length (in bits)
#define WHEX_ALL            ((1UL << NUM_HASHES) - 1)
#define WHEX_ALL32          WHEX_CHECKCRC32
#define WHEX_ALL64          WHEX_CHECKXXHASH64
#define WHEX_ALL128         WHEX_CHECKMD5
#define WHEX_ALL160         (WHEX_CHECKSHA1 | WHEX_CHECKRIPEMD160)
#define WHEX_ALL224         (WHEX_CHECKSHA224 | WHEX_CHECKSHA3_224)
#define WHEX_ALL256         (WHEX_CHECKSHA256 | WHEX_CHECKSHA3_256 | WHEX_CHECKBLAKE2s | WHEX_CHECKBLAKE3 | WHEX_CHECKSM3 | WHEX_CHECKSHAKE128 | WHEX_CHECKSHAKE256)
#define WHEX_ALL384         (WHEX_CHECKSHA384 | WHEX_CHECKSHA3_384)
#define WHEX_ALL512         (WHEX_CHECKSHA512 | WHEX_CHECKSHA3_512 | WHEX_CHECKBLAKE2b)

// The block lengths of the hash algorithms, if required below
#define MD5_BLOCK_LENGTH            64
#define SHA1_BLOCK_LENGTH           64
#define SHA224_BLOCK_LENGTH         64
#define SHA256_BLOCK_LENGTH         64
#define SHA384_BLOCK_LENGTH         128
#define SHA512_BLOCK_LENGTH         128

// The digest lengths of the hash algorithms
#define CRC32_DIGEST_LENGTH         4
#define MD5_DIGEST_LENGTH           16
#define SHA1_DIGEST_LENGTH          20
#define SHA224_DIGEST_LENGTH        28
#define SHA256_DIGEST_LENGTH        32
#define SHA384_DIGEST_LENGTH        48
#define SHA512_DIGEST_LENGTH        64
#define SHA3_256_DIGEST_LENGTH      32
#define SHA3_512_DIGEST_LENGTH      64
#define SHA3_224_DIGEST_LENGTH      28
#define SHA3_384_DIGEST_LENGTH      48
#define BLAKE2b_DIGEST_LENGTH       64
#define BLAKE2s_DIGEST_LENGTH       32
#define BLAKE3_DIGEST_LENGTH        32
#define SM3_DIGEST_LENGTH           32
#define SHAKE128_DIGEST_LENGTH      32
#define SHAKE256_DIGEST_LENGTH      32
#define RIPEMD160_DIGEST_LENGTH     20
#define XXHASH64_DIGEST_LENGTH      8
#define MAX_DIGEST_LENGTH           SHA512_DIGEST_LENGTH

// The minimum string length required to hold the hex digest strings
#define CRC32_DIGEST_STRING_LENGTH  (CRC32_DIGEST_LENGTH  * 2 + 1)
#define MD5_DIGEST_STRING_LENGTH    (MD5_DIGEST_LENGTH    * 2 + 1)
#define SHA1_DIGEST_STRING_LENGTH   (SHA1_DIGEST_LENGTH   * 2 + 1)
#define SHA224_DIGEST_STRING_LENGTH (SHA224_DIGEST_LENGTH * 2 + 1)
#define SHA256_DIGEST_STRING_LENGTH (SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA384_DIGEST_STRING_LENGTH (SHA384_DIGEST_LENGTH * 2 + 1)
#define SHA512_DIGEST_STRING_LENGTH (SHA512_DIGEST_LENGTH * 2 + 1)
#define SHA3_256_DIGEST_STRING_LENGTH (SHA3_256_DIGEST_LENGTH * 2 + 1)
#define SHA3_512_DIGEST_STRING_LENGTH (SHA3_512_DIGEST_LENGTH * 2 + 1)
#define SHA3_224_DIGEST_STRING_LENGTH (SHA3_224_DIGEST_LENGTH * 2 + 1)
#define SHA3_384_DIGEST_STRING_LENGTH (SHA3_384_DIGEST_LENGTH * 2 + 1)
#define BLAKE2b_DIGEST_STRING_LENGTH (BLAKE2b_DIGEST_LENGTH * 2 + 1)
#define BLAKE2s_DIGEST_STRING_LENGTH (BLAKE2s_DIGEST_LENGTH * 2 + 1)
#define BLAKE3_DIGEST_STRING_LENGTH (BLAKE3_DIGEST_LENGTH * 2 + 1)
#define SM3_DIGEST_STRING_LENGTH (SM3_DIGEST_LENGTH * 2 + 1)
#define SHAKE128_DIGEST_STRING_LENGTH (SHAKE128_DIGEST_LENGTH * 2 + 1)
#define SHAKE256_DIGEST_STRING_LENGTH (SHAKE256_DIGEST_LENGTH * 2 + 1)
#define RIPEMD160_DIGEST_STRING_LENGTH (RIPEMD160_DIGEST_LENGTH * 2 + 1)
#define XXHASH64_DIGEST_STRING_LENGTH (XXHASH64_DIGEST_LENGTH * 2 + 1)
#define MAX_DIGEST_STRING_LENGTH    SHA512_DIGEST_STRING_LENGTH

// Hash file extensions
#define HASH_EXT_CRC32          _T(".sfv")
#define HASH_EXT_MD5            _T(".md5")
#define HASH_EXT_SHA1           _T(".sha1")
#define HASH_EXT_SHA256         _T(".sha256")
#define HASH_EXT_SHA512         _T(".sha512")
#define HASH_EXT_SHA3_256       _T(".sha3-256")
#define HASH_EXT_SHA3_512       _T(".sha3-512")
#define HASH_EXT_SHA224         _T(".sha224")
#define HASH_EXT_SHA384         _T(".sha384")
#define HASH_EXT_SHA3_224       _T(".sha3-224")
#define HASH_EXT_SHA3_384       _T(".sha3-384")
#define HASH_EXT_BLAKE2b        _T(".blake2b")
#define HASH_EXT_BLAKE2s        _T(".blake2s")
#define HASH_EXT_BLAKE3         _T(".blake3")
#define HASH_EXT_SM3            _T(".sm3")
#define HASH_EXT_SHAKE128       _T(".shake128")
#define HASH_EXT_SHAKE256       _T(".shake256")
#define HASH_EXT_RIPEMD160      _T(".ripemd160")
#define HASH_EXT_XXHASH64       _T(".xxh64")

// Table of supported Hash file extensions, plus .asc
extern LPCTSTR g_szHashExtsTab[NUM_HASHES + 1];

// Hash names
#define HASH_NAME_CRC32         _T("CRC-32")
#define HASH_NAME_MD5           _T("MD5")
#define HASH_NAME_SHA1          _T("SHA-1")
#define HASH_NAME_SHA256        _T("SHA-256")
#define HASH_NAME_SHA512        _T("SHA-512")
#define HASH_NAME_SHA3_256      _T("SHA3-256")
#define HASH_NAME_SHA3_512      _T("SHA3-512")
#define HASH_NAME_SHA224        _T("SHA-224")
#define HASH_NAME_SHA384        _T("SHA-384")
#define HASH_NAME_SHA3_224      _T("SHA3-224")
#define HASH_NAME_SHA3_384      _T("SHA3-384")
#define HASH_NAME_BLAKE2b       _T("BLAKE2b")
#define HASH_NAME_BLAKE2s       _T("BLAKE2s")
#define HASH_NAME_BLAKE3        _T("BLAKE3")
#define HASH_NAME_SM3           _T("SM3")
#define HASH_NAME_SHAKE128      _T("SHAKE-128")
#define HASH_NAME_SHAKE256      _T("SHAKE-256")
#define HASH_NAME_RIPEMD160     _T("RIPEMD-160")
#define HASH_NAME_XXHASH64      _T("xxHash64")

// Right-justified Hash names
#define HASH_RNAME_CRC32        _T("  CRC-32")
#define HASH_RNAME_MD5          _T("     MD5")
#define HASH_RNAME_SHA1         _T("   SHA-1")
#define HASH_RNAME_SHA256       _T(" SHA-256")
#define HASH_RNAME_SHA512       _T(" SHA-512")
#define HASH_RNAME_SHA3_256     _T("SHA3-256")
#define HASH_RNAME_SHA3_512     _T("SHA3-512")
#define HASH_RNAME_SHA224       _T(" SHA-224")
#define HASH_RNAME_SHA384       _T(" SHA-384")
#define HASH_RNAME_SHA3_224     _T("SHA3-224")
#define HASH_RNAME_SHA3_384     _T("SHA3-384")
#define HASH_RNAME_BLAKE2b      _T(" BLAKE2b")
#define HASH_RNAME_BLAKE2s      _T(" BLAKE2s")
#define HASH_RNAME_BLAKE3       _T("  BLAKE3")
#define HASH_RNAME_SM3          _T("     SM3")
#define HASH_RNAME_SHAKE128     _T("SHAKE128")
#define HASH_RNAME_SHAKE256     _T("SHAKE256")
#define HASH_RNAME_RIPEMD160    _T("RIPEMD160")
#define HASH_RNAME_XXHASH64     _T("xxHash64")

// Hash OPENFILENAME filters, E.G. "MD5 (*.md5)\0*.md5\0"
#define HASH_FILTER_op(alg)     HASH_NAME_##alg _T(" (*")   \
                                HASH_EXT_##alg  _T(")\0*")  \
                                HASH_EXT_##alg  _T("\0")

// All OPENFILENAME filters together as one big string
#define HASH_FILE_FILTERS       FOR_EACH_HASH(HASH_FILTER_op)

// Hash results strings (colon aligned).
// E.g. "    MD5: "
#define HASH_RESULT_op(alg)     HASH_RNAME_##alg _T(": ")

/**
 * Structures used by the system libraries
 **/

typedef struct {
	UINT32 state[4];
	UINT64 count;
	BYTE buffer[MD5_BLOCK_LENGTH];
	BYTE result[MD5_DIGEST_LENGTH];
} MD5_CTX, *PMD5_CTX;

typedef struct {
	UINT32 state[5];
	UINT64 count;
	BYTE buffer[SHA1_BLOCK_LENGTH];
	BYTE result[SHA1_DIGEST_LENGTH];
} SHA1_CTX, *PSHA1_CTX;

typedef struct _SHA2_CTX {
	union {
		UINT32	st32[8];
		UINT64	st64[8];
	} state;
	UINT64 bitcount[2];
	BYTE buffer[SHA512_BLOCK_LENGTH];
	BYTE result[SHA512_DIGEST_LENGTH];
} SHA2_CTX, *PSHA2_CTX;


UINT32 crc32( UINT32 uInitial, PCBYTE pbIn, UINT cbIn );

void MD5Init( PMD5_CTX pContext );
void MD5Update( PMD5_CTX pContext, PCBYTE pbIn, UINT cbIn );
void MD5Final( PMD5_CTX pContext );

void SHA1Init( PSHA1_CTX pContext );
void SHA1Update( PSHA1_CTX pContext, PCBYTE pbIn, UINT cbIn );
void SHA1Final( PSHA1_CTX pContext );

void SHA224Init( PSHA2_CTX pContext );
#define SHA224Update SHA256Update
void SHA224Final( PSHA2_CTX pContext );

void SHA256Init( PSHA2_CTX pContext );
void SHA256Update( PSHA2_CTX pContext, PCBYTE pbIn, UINT cbIn );
void SHA256Final( PSHA2_CTX pContext );

void SHA384Init( PSHA2_CTX pContext );
#define SHA384Update SHA512Update
void SHA384Final( PSHA2_CTX pContext );

void SHA512Init( PSHA2_CTX pContext );
void SHA512Update( PSHA2_CTX pContext, PCBYTE pbIn, UINT cbIn );
void SHA512Final( PSHA2_CTX pContext );

/**
 * Structures used by our consistency wrapper layer
 **/

typedef union {
	UINT32 state;
	BYTE result[CRC32_DIGEST_LENGTH];
} WHCTXCRC32, *PWHCTXCRC32;

#define  WHCTXMD5  MD5_CTX
#define PWHCTXMD5 PMD5_CTX

#define  WHCTXSHA1  SHA1_CTX
#define PWHCTXSHA1 PSHA1_CTX

#define  WHCTXSHA256  SHA2_CTX
#define PWHCTXSHA256 PSHA2_CTX

#define  WHCTXSHA512  SHA2_CTX
#define PWHCTXSHA512 PSHA2_CTX

typedef struct {
    Keccak_HashInstance state;
    BYTE result[SHA3_256_DIGEST_LENGTH];
} WHCTXSHA3_256, *PWHCTXSHA3_256;

typedef struct {
    Keccak_HashInstance state;
    BYTE result[SHA3_512_DIGEST_LENGTH];
} WHCTXSHA3_512, *PWHCTXSHA3_512;

#define  WHCTXSHA224  SHA2_CTX
#define PWHCTXSHA224 PSHA2_CTX

#define  WHCTXSHA384  SHA2_CTX
#define PWHCTXSHA384 PSHA2_CTX

typedef struct {
    Keccak_HashInstance state;
    BYTE result[SHA3_224_DIGEST_LENGTH];
} WHCTXSHA3_224, *PWHCTXSHA3_224;

typedef struct {
    Keccak_HashInstance state;
    BYTE result[SHA3_384_DIGEST_LENGTH];
} WHCTXSHA3_384, *PWHCTXSHA3_384;

#define  WHCTXBLAKE2b   blake2b_ctx
#define PWHCTXBLAKE2b  blake2b_ctx*
#define  WHCTXBLAKE2s   blake2s_ctx
#define PWHCTXBLAKE2s  blake2s_ctx*
#define  WHCTXBLAKE3    blake3_ctx
#define PWHCTXBLAKE3   blake3_ctx*
#define  WHCTXSM3       SM3_CTX
#define PWHCTXSM3      SM3_CTX*

typedef struct {
    Keccak_HashInstance state;
    BYTE result[SHAKE128_DIGEST_LENGTH];
} WHCTXSHAKE128, *PWHCTXSHAKE128;

typedef struct {
    Keccak_HashInstance state;
    BYTE result[SHAKE256_DIGEST_LENGTH];
} WHCTXSHAKE256, *PWHCTXSHAKE256;

#define  WHCTXRIPEMD160  ripemd160_ctx
#define PWHCTXRIPEMD160 ripemd160_ctx*
#define  WHCTXXXHASH64   xxhash64_ctx
#define PWHCTXXXHASH64  xxhash64_ctx*

/**
 * Wrapper layer functions to ensure a more consistent interface
 **/

#define  WHAPI  __fastcall

__inline void WHAPI WHInitCRC32( PWHCTXCRC32 pContext )
{
	pContext->state = 0;
}

__inline void WHAPI WHUpdateCRC32( PWHCTXCRC32 pContext, PCBYTE pbIn, UINT cbIn )
{
	pContext->state = crc32(pContext->state, pbIn, cbIn);
}

__inline void WHAPI WHFinishCRC32( PWHCTXCRC32 pContext )
{
	pContext->state = SwapV32(pContext->state);
}

#define WHInitMD5 MD5Init
#define WHUpdateMD5 MD5Update
#define WHFinishMD5 MD5Final

#define WHInitSHA1 SHA1Init
#define WHUpdateSHA1 SHA1Update
#define WHFinishSHA1 SHA1Final

#define WHInitSHA256 SHA256Init
#define WHUpdateSHA256 SHA256Update
#define WHFinishSHA256 SHA256Final

#define WHInitSHA512 SHA512Init
#define WHUpdateSHA512 SHA512Update
#define WHFinishSHA512 SHA512Final

__inline void WHAPI WHInitSHA3_256( PWHCTXSHA3_256 pContext )
{
    Keccak_HashInitialize_SHA3_256(&pContext->state);
}

__inline void WHAPI WHUpdateSHA3_256( PWHCTXSHA3_256 pContext, PCBYTE pbIn, UINT cbIn)
{
    Keccak_HashUpdate(&pContext->state, pbIn, cbIn * 8);
}

__inline void WHAPI WHFinishSHA3_256( PWHCTXSHA3_256 pContext )
{
    Keccak_HashFinal(&pContext->state, pContext->result);
}

__inline void WHAPI WHInitSHA3_512(PWHCTXSHA3_512 pContext)
{
    Keccak_HashInitialize_SHA3_512(&pContext->state);
}

__inline void WHAPI WHUpdateSHA3_512(PWHCTXSHA3_512 pContext, PCBYTE pbIn, UINT cbIn)
{
    Keccak_HashUpdate(&pContext->state, pbIn, cbIn * 8);
}

__inline void WHAPI WHFinishSHA3_512(PWHCTXSHA3_512 pContext)
{
    Keccak_HashFinal(&pContext->state, pContext->result);
}

#define WHInitSHA224 SHA224Init
#define WHUpdateSHA224 SHA224Update
#define WHFinishSHA224 SHA224Final

#define WHInitSHA384 SHA384Init
#define WHUpdateSHA384 SHA384Update
#define WHFinishSHA384 SHA384Final

__inline void WHAPI WHInitSHA3_224( PWHCTXSHA3_224 pContext )
{
    Keccak_HashInitialize_SHA3_224(&pContext->state);
}

__inline void WHAPI WHUpdateSHA3_224( PWHCTXSHA3_224 pContext, PCBYTE pbIn, UINT cbIn )
{
    Keccak_HashUpdate(&pContext->state, pbIn, cbIn * 8);
}

__inline void WHAPI WHFinishSHA3_224( PWHCTXSHA3_224 pContext )
{
    Keccak_HashFinal(&pContext->state, pContext->result);
}

__inline void WHAPI WHInitSHA3_384( PWHCTXSHA3_384 pContext )
{
    Keccak_HashInitialize_SHA3_384(&pContext->state);
}

__inline void WHAPI WHUpdateSHA3_384( PWHCTXSHA3_384 pContext, PCBYTE pbIn, UINT cbIn )
{
    Keccak_HashUpdate(&pContext->state, pbIn, cbIn * 8);
}

__inline void WHAPI WHFinishSHA3_384( PWHCTXSHA3_384 pContext )
{
    Keccak_HashFinal(&pContext->state, pContext->result);
}

__inline void WHAPI WHInitBLAKE2b( PWHCTXBLAKE2b pContext )
{
    blake2b_init(pContext);
}

__inline void WHAPI WHUpdateBLAKE2b( PWHCTXBLAKE2b pContext, PCBYTE pbIn, UINT cbIn )
{
    blake2b_update(pContext, pbIn, cbIn);
}

__inline void WHAPI WHFinishBLAKE2b( PWHCTXBLAKE2b pContext )
{
    blake2b_final(pContext);
}

__inline void WHAPI WHInitBLAKE2s( PWHCTXBLAKE2s pContext )
{
    blake2s_init(pContext);
}

__inline void WHAPI WHUpdateBLAKE2s( PWHCTXBLAKE2s pContext, PCBYTE pbIn, UINT cbIn )
{
    blake2s_update(pContext, pbIn, cbIn);
}

__inline void WHAPI WHFinishBLAKE2s( PWHCTXBLAKE2s pContext )
{
    blake2s_final(pContext);
}

__inline void WHAPI WHInitBLAKE3( PWHCTXBLAKE3 pContext )
{
    blake3_init(pContext);
}

__inline void WHAPI WHUpdateBLAKE3( PWHCTXBLAKE3 pContext, PCBYTE pbIn, UINT cbIn )
{
    blake3_update(pContext, pbIn, cbIn);
}

__inline void WHAPI WHFinishBLAKE3( PWHCTXBLAKE3 pContext )
{
    blake3_final(pContext);
}

__inline void WHAPI WHInitSM3( PWHCTXSM3 pContext )
{
    SM3Init(pContext);
}

__inline void WHAPI WHInitSHAKE128( PWHCTXSHAKE128 pContext )
{
    Keccak_HashInitialize_SHAKE128(&pContext->state);
}

__inline void WHAPI WHUpdateSHAKE128( PWHCTXSHAKE128 pContext, PCBYTE pbIn, UINT cbIn )
{
    Keccak_HashUpdate(&pContext->state, pbIn, cbIn * 8);
}

__inline void WHAPI WHFinishSHAKE128( PWHCTXSHAKE128 pContext )
{
    Keccak_HashFinal(&pContext->state, pContext->result);
    Keccak_HashSqueeze(&pContext->state, pContext->result, SHAKE128_DIGEST_LENGTH * 8);
}

__inline void WHAPI WHInitSHAKE256( PWHCTXSHAKE256 pContext )
{
    Keccak_HashInitialize_SHAKE256(&pContext->state);
}

__inline void WHAPI WHUpdateSHAKE256( PWHCTXSHAKE256 pContext, PCBYTE pbIn, UINT cbIn )
{
    Keccak_HashUpdate(&pContext->state, pbIn, cbIn * 8);
}

__inline void WHAPI WHFinishSHAKE256( PWHCTXSHAKE256 pContext )
{
    Keccak_HashFinal(&pContext->state, pContext->result);
    Keccak_HashSqueeze(&pContext->state, pContext->result, SHAKE256_DIGEST_LENGTH * 8);
}

__inline void WHAPI WHInitRIPEMD160( PWHCTXRIPEMD160 pContext )
{
    ripemd160_init(pContext);
}

__inline void WHAPI WHUpdateRIPEMD160( PWHCTXRIPEMD160 pContext, PCBYTE pbIn, UINT cbIn )
{
    ripemd160_update(pContext, pbIn, cbIn);
}

__inline void WHAPI WHFinishRIPEMD160( PWHCTXRIPEMD160 pContext )
{
    ripemd160_final(pContext);
}

__inline void WHAPI WHInitXXHASH64( PWHCTXXXHASH64 pContext )
{
    xxh64_init(pContext);
}

__inline void WHAPI WHUpdateXXHASH64( PWHCTXXXHASH64 pContext, PCBYTE pbIn, UINT cbIn )
{
    xxh64_update(pContext, pbIn, cbIn);
}

__inline void WHAPI WHFinishXXHASH64( PWHCTXXXHASH64 pContext )
{
    xxh64_final(pContext);
}

__inline void WHAPI WHUpdateSM3( PWHCTXSM3 pContext, PCBYTE pbIn, UINT cbIn )
{
    SM3Update(pContext, pbIn, cbIn);
}

__inline void WHAPI WHFinishSM3( PWHCTXSM3 pContext )
{
    SM3Final(pContext);
}

/**
 * WH*To* hex string conversion functions: These require WinHash.cpp
 **/

#define WHAPI __fastcall

#define WHFMT_UPPERCASE 0x00
#define WHFMT_LOWERCASE 0x20

BOOL WHAPI WHHexToByte( PTSTR pszSrc, PBYTE pbDest, UINT cchHex );
PTSTR WHAPI WHByteToHex( PBYTE pbSrc, PTSTR pszDest, UINT cchHex, UINT8 uCaseMode );

/**
 * WH*Ex functions: These require WinHash.cpp
 **/

typedef struct {
    TCHAR szHexCRC32[CRC32_DIGEST_STRING_LENGTH];
    TCHAR szHexMD5[MD5_DIGEST_STRING_LENGTH];
    TCHAR szHexSHA1[SHA1_DIGEST_STRING_LENGTH];
    TCHAR szHexSHA256[SHA256_DIGEST_STRING_LENGTH];
    TCHAR szHexSHA512[SHA512_DIGEST_STRING_LENGTH];
    TCHAR szHexSHA3_256[SHA3_256_DIGEST_STRING_LENGTH];
    TCHAR szHexSHA3_512[SHA3_512_DIGEST_STRING_LENGTH];
    TCHAR szHexSHA224[SHA224_DIGEST_STRING_LENGTH];
    TCHAR szHexSHA384[SHA384_DIGEST_STRING_LENGTH];
    TCHAR szHexSHA3_224[SHA3_224_DIGEST_STRING_LENGTH];
    TCHAR szHexSHA3_384[SHA3_384_DIGEST_STRING_LENGTH];
    TCHAR szHexBLAKE2b[BLAKE2b_DIGEST_STRING_LENGTH];
    TCHAR szHexBLAKE2s[BLAKE2s_DIGEST_STRING_LENGTH];
    TCHAR szHexBLAKE3[BLAKE3_DIGEST_STRING_LENGTH];
    TCHAR szHexSM3[SM3_DIGEST_STRING_LENGTH];
    TCHAR szHexSHAKE128[SHAKE128_DIGEST_STRING_LENGTH];
    TCHAR szHexSHAKE256[SHAKE256_DIGEST_STRING_LENGTH];
    TCHAR szHexRIPEMD160[RIPEMD160_DIGEST_STRING_LENGTH];
    TCHAR szHexXXHASH64[XXHASH64_DIGEST_STRING_LENGTH];
    DWORD dwFlags;
} WHRESULTEX, *PWHRESULTEX;

// Align all the hash contexts to avoid false sharing (of L1/2 cache lines in multi-core systems)
typedef struct {
	__declspec(align(64)) WHCTXCRC32  ctxCRC32;
	__declspec(align(64)) WHCTXMD5    ctxMD5;
	__declspec(align(64)) WHCTXSHA1   ctxSHA1;
	__declspec(align(64)) WHCTXSHA256 ctxSHA256;
	__declspec(align(64)) WHCTXSHA512 ctxSHA512;
	__declspec(align(64)) WHCTXSHA3_256 ctxSHA3_256;
	__declspec(align(64)) WHCTXSHA3_512 ctxSHA3_512;
	__declspec(align(64)) WHCTXSHA224   ctxSHA224;
	__declspec(align(64)) WHCTXSHA384   ctxSHA384;
	__declspec(align(64)) WHCTXSHA3_224 ctxSHA3_224;
	__declspec(align(64)) WHCTXSHA3_384 ctxSHA3_384;
	__declspec(align(64)) WHCTXBLAKE2b  ctxBLAKE2b;
	__declspec(align(64)) WHCTXBLAKE2s  ctxBLAKE2s;
	__declspec(align(64)) WHCTXBLAKE3   ctxBLAKE3;
	__declspec(align(64)) WHCTXSM3      ctxSM3;
	__declspec(align(64)) WHCTXSHAKE128 ctxSHAKE128;
	__declspec(align(64)) WHCTXSHAKE256 ctxSHAKE256;
	__declspec(align(64)) WHCTXRIPEMD160 ctxRIPEMD160;
	__declspec(align(64)) WHCTXXXHASH64  ctxXXHASH64;
	DWORD dwFlags;
	UINT8 uCaseMode;
} WHCTXEX, *PWHCTXEX;


VOID WHAPI WHInitEx( PWHCTXEX pContext );
VOID WHAPI WHUpdateEx( PWHCTXEX pContext, PCBYTE pbIn, UINT cbIn );
VOID WHAPI WHFinishEx( PWHCTXEX pContext, PWHRESULTEX pResults );

#ifdef __cplusplus
}
#endif

#endif
