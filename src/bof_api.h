/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Minimal BOF and Dynamic Function Resolution declarations used by
 * firefoxdump. This file was written specifically for this project and does
 * not incorporate the TrustedSec CS-Situational-Awareness-BOF support files
 * that appeared in earlier revisions.
 */
#pragma once

#include <windows.h>
#include <stddef.h>
#include <stdarg.h>

#ifdef BOF

typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} datap;

#define CALLBACK_OUTPUT 0x00

DECLSPEC_IMPORT void BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT char* BeaconDataExtract(datap* parser, int* size);
DECLSPEC_IMPORT void BeaconOutput(int type, char* data, int length);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE heap, DWORD flags, SIZE_T bytes);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE heap, DWORD flags, LPVOID memory);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR fileName);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR moduleName);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR fileName);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE module, LPCSTR procName);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(HMODULE module);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(
    LPCSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition,
    DWORD flagsAndAttributes,
    HANDLE templateFile);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(HANDLE file, LPDWORD fileSizeHigh);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(
    HANDLE file,
    LPVOID buffer,
    DWORD bytesToRead,
    LPDWORD bytesRead,
    LPOVERLAPPED overlapped);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE object);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR fileName, LPWIN32_FIND_DATAA findData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindNextFileA(HANDLE findFile, LPWIN32_FIND_DATAA findData);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FindClose(HANDLE findFile);

DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void* left, const void* right, size_t count);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void* destination, const void* source, size_t count);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void* destination, int value, size_t count);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char* left, const char* right);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char* left, const char* right);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char* string);
DECLSPEC_IMPORT int __cdecl MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arguments);

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define intFree(memory) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (memory))

#define BOF_MAX_OUTPUT_RECORD (1024U * 1024U)
#define BOF_MAX_TOTAL_OUTPUT  (8U * 1024U * 1024U)

static SIZE_T bofOutputBytes = 0;
static BOOL bofOutputLimited = FALSE;
static BOOL bofOversizedReported = FALSE;

static void bof_output_reset(void) {
    bofOutputBytes = 0;
    bofOutputLimited = FALSE;
    bofOversizedReported = FALSE;
}

static void bof_printf(const char* format, ...) {
    static const char oversized[] = "[!] Output record exceeds the 1 MiB safety limit\n";
    static const char limited[] = "[!] Total output reached the 8 MiB safety limit; further records suppressed\n";
    char* output;
    int length;
    int written;
    va_list arguments;

    va_start(arguments, format);
    length = MSVCRT$vsnprintf(NULL, 0, format, arguments);
    va_end(arguments);

    if (length <= 0) {
        return;
    }
    if ((SIZE_T)length > BOF_MAX_OUTPUT_RECORD) {
        if (!bofOversizedReported) {
            BeaconOutput(CALLBACK_OUTPUT, (char*)oversized, (int)(sizeof(oversized) - 1));
            bofOversizedReported = TRUE;
        }
        return;
    }
    if (bofOutputLimited || (SIZE_T)length > BOF_MAX_TOTAL_OUTPUT - bofOutputBytes) {
        if (!bofOutputLimited) {
            BeaconOutput(CALLBACK_OUTPUT, (char*)limited, (int)(sizeof(limited) - 1));
            bofOutputLimited = TRUE;
        }
        return;
    }

    output = (char*)intAlloc((SIZE_T)length + 1);
    if (!output) {
        return;
    }
    va_start(arguments, format);
    written = MSVCRT$vsnprintf(output, (SIZE_T)length + 1, format, arguments);
    va_end(arguments);
    if (written >= 0 && written <= length) {
        BeaconOutput(CALLBACK_OUTPUT, output, written);
        bofOutputBytes += (SIZE_T)written;
    }
    MSVCRT$memset(output, 0, (SIZE_T)length + 1);
    intFree(output);
}

#define SafeAppend(...) bof_printf(__VA_ARGS__)

#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KERNEL32$GetFileAttributesA GetFileAttributesA
#define KERNEL32$GetModuleHandleA GetModuleHandleA
#define KERNEL32$LoadLibraryA LoadLibraryA
#define KERNEL32$GetProcAddress GetProcAddress
#define KERNEL32$FreeLibrary FreeLibrary
#define KERNEL32$CreateFileA CreateFileA
#define KERNEL32$GetFileSize GetFileSize
#define KERNEL32$ReadFile ReadFile
#define KERNEL32$CloseHandle CloseHandle
#define KERNEL32$FindFirstFileA FindFirstFileA
#define KERNEL32$FindNextFileA FindNextFileA
#define KERNEL32$FindClose FindClose
#define MSVCRT$memcmp memcmp
#define MSVCRT$memcpy memcpy
#define MSVCRT$memset memset
#define MSVCRT$strcmp strcmp
#define MSVCRT$_stricmp _stricmp
#define MSVCRT$strlen strlen
#define intAlloc(size) calloc(1, (size))
#define intFree(memory) free((memory))
#define bof_output_reset() ((void)0)
#define SafeAppend(...) printf(__VA_ARGS__)

#endif
