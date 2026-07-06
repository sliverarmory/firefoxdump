# Firefox Dump BOF

A Beacon Object File (BOF) for Cobalt Strike that extracts saved passwords and cookies from Mozilla Firefox profiles.

## Features

- **Password Extraction**: Decrypts saved passwords from `logins.json` (modern) and `signons.sqlite` (legacy)
- **Cookie Extraction**: Extracts cookies from `cookies.sqlite`
- **NSS Decryption**: Uses Firefox's NSS libraries for password decryption
- **Multi-Profile Support**: Enumerates and processes all Firefox profiles
- **Key Database Support**: Works with both `key4.db` (modern) and `key3.db` (legacy)
- **x86/x64 Support**: Compiled for both architectures

## Usage

### Load in Cobalt Strike

```
 cobaltstrike > Cobalt Strike > Script Manager > Load > firefoxdump.cna
```

### Commands

| Command | Description |
|---------|-------------|
| `firefoxdump` | Extract passwords only (default) |
| `firefoxdump /all` | Extract passwords and cookies |
| `firefoxdump /cookies` | Extract cookies only |

### Examples

```
beacon> firefoxdump
[*] Extracting Firefox Data from All Profiles
================================
[+] Found 2 Firefox profile(s)

[*] Processing Profile: C:\Users\user\AppData\Roaming\Mozilla\Firefox\Profiles\abc123.default
[*] Key database: key4.db (modern)

[+] Saved Passwords (logins.json):
================================
URL: https://example.com | Username: user@example.com | Password: secretpass123
URL: https://github.com | Username: developer | Password: mygithubpass

[+] Found 2 password entries

[*] Completed processing 2 profile(s)
```

## Compilation

### Prerequisites

- MinGW-w64 cross compiler (`x86_64-w64-mingw32-gcc` and `i686-w64-mingw32-gcc`)
- Make

### Build

```bash
make
```

This will compile:
- `firefoxdump.x64.o` (64-bit BOF)
- `firefoxdump.x86.o` (32-bit BOF)

Compiled files are output to the `bin/` directory.

### Manual Compilation

```bash
# 64-bit
x86_64-w64-mingw32-gcc -o bin/firefoxdump.x64.o -I src/common -Os -c src/entry.c -DBOF

# 32-bit
i686-w64-mingw32-gcc -o bin/firefoxdump.x86.o -I src/common -Os -c src/entry.c -DBOF
```

## How It Works

1. **Profile Discovery**: Enumerates Firefox profiles from `%APPDATA%\Mozilla\Firefox\Profiles\`
   - If running as SYSTEM/Admin, searches all user profiles under `C:\Users\`
   - Otherwise, searches only the current user's profile

2. **Key Database Detection**: Checks for `key4.db` (modern) or `key3.db` (legacy)

3. **NSS Loading**: Loads Firefox's NSS libraries from the Firefox installation directory
   - Searches common installation paths (`Program Files`, `Program Files (x86)`)
   - Loads dependencies: `mozglue.dll`, `nssutil3.dll`, `nspr4.dll`, etc.

4. **Password Decryption**:
   - Reads `logins.json` (modern Firefox) or `signons.sqlite` (legacy)
   - Decrypts using `PK11SDR_Decrypt` from NSS

5. **Cookie Extraction**:
   - Reads `cookies.sqlite`
   - Decrypts encrypted cookie values using NSS

## Technical Details

### Supported Firefox Versions

- Firefox 75+ (key4.db, logins.json)
- Legacy Firefox versions (key3.db, signons.sqlite)

### Files Accessed

| File | Purpose |
|------|---------|
| `key4.db` | Modern key database |
| `key3.db` | Legacy key database |
| `logins.json` | Modern password storage |
| `signons.sqlite` | Legacy password storage |
| `cookies.sqlite` | Cookie storage |

### Dependencies

- `winsqlite3.dll` (Windows built-in) - For SQLite operations
- Firefox NSS libraries - For password decryption

## OPSEC Considerations

- Loads Firefox DLLs into beacon process memory
- Accesses user profile directories
- Reads sensitive credential files
- Uses `CryptUnprotectData` for DPAPI operations

## MITRE ATT&CK

- **T1555.003** - Credentials from Web Browsers

## Credits

Based on the [CS-Situational-Awareness-BOF](https://github.com/trustedsec/cs-situational-awareness-bof) collection by TrustedSec.

Firefox decryption logic inspired by [firefox_decrypt](https://github.com/unode/firefox_decrypt/).

## License

MIT License

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before using this tool.
