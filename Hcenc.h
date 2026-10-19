/**
 * HashCheck SHA-256 单源模块头（1.4.0 纯净版瘦身，2026-10-17 优化三遍）
 *
 * 历史上本文件定义 AES-256-GCM 容器格式（v2）与全部加密接口；1.4.0
 * 纯净版剥离加密层后仅保留 SHA-256 单源接口。文件名沿用避免工程改动。
 */

#ifndef __HCENC_H__
#define __HCENC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

/* 1.5.7: 全 DLL 唯一的 SHA-256（逐条 chk 用；HashCalc 保存端与
   HashVerify 验证端同源，防实现漂移）。 */
BOOL WINAPI HcencSha256( const BYTE* pbIn, DWORD cbIn, BYTE out[32] );

#ifdef __cplusplus
}
#endif
#endif /* __HCENC_H__ */
