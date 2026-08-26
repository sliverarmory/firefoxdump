#!/usr/bin/env python3
"""Verify a Minisign signature and its byte-exact embedded manifest."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
from pathlib import Path
import shutil
import subprocess
import tarfile


def fail(message: str) -> None:
    raise ValueError(message)


def compact_public_key(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2 or not lines[1].startswith("RW"):
        fail("public-key file must contain a compact Minisign key on line 2")
    key = lines[1]
    try:
        decoded = base64.b64decode(key, validate=True)
    except binascii.Error as error:
        fail(f"public key is not strict base64: {error}")
    if len(decoded) != 42 or decoded[:2] != b"Ed":
        fail("public key is not a Minisign EdDSA public key")
    return key


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key-file", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()

    for path in (args.archive, args.signature, args.public_key_file):
        if not path.is_file():
            parser.error(f"missing input file: {path}")
    expected_signature = args.archive.name.removesuffix(".tar.gz") + ".minisig"
    if args.signature.name != expected_signature:
        fail(f"signature must be named {expected_signature}")

    public_key = compact_public_key(args.public_key_file)
    minisign = shutil.which("minisign")
    if minisign is None:
        parser.error("minisign is required")
    verification = subprocess.run(
        [
            minisign,
            "-V",
            "-P",
            public_key,
            "-m",
            str(args.archive),
            "-x",
            str(args.signature),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if verification.returncode != 0:
        fail((verification.stderr or verification.stdout).strip())

    signature_lines = args.signature.read_text(encoding="utf-8").rstrip("\r\n").splitlines()
    if len(signature_lines) != 4 or not signature_lines[2].startswith("trusted comment: "):
        fail("signature must contain one canonical four-line trusted comment")
    encoded_manifest = signature_lines[2].removeprefix("trusted comment: ")
    try:
        trusted_manifest = base64.b64decode(encoded_manifest, validate=True)
    except binascii.Error as error:
        fail(f"trusted comment is not strict base64: {error}")

    with tarfile.open(args.archive, "r:gz") as tar:
        manifest_file = tar.extractfile("./extension.json")
        if manifest_file is None:
            fail("archive does not contain ./extension.json")
        archived_manifest = manifest_file.read()
    if trusted_manifest != archived_manifest:
        fail("trusted-comment bytes do not exactly equal ./extension.json")
    manifest = json.loads(archived_manifest.decode("utf-8"))
    if manifest.get("version") != args.tag:
        fail("trusted manifest version does not match the release tag")

    print(f"OK: signature and byte-exact trusted manifest verified for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
