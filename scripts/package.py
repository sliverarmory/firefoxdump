#!/usr/bin/env python3
"""Build the deterministic FirefoxDump Sliver Armory archive."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_BASENAME = "firefoxdump"
SOURCE_ARTIFACTS = {
    "firefoxdump.x64.o": ROOT / "bin/firefoxdump.x64.o",
    "firefoxdump.x86.o": ROOT / "bin/firefoxdump.x86.o",
}
STATIC_FILES = ("LICENSE", "NOTICE")
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
MAX_TRUSTED_COMMENT_BYTES = 4000


def source_epoch() -> int:
    configured = os.environ.get("SOURCE_DATE_EPOCH")
    if configured:
        epoch = int(configured)
    else:
        result = subprocess.run(
            ["git", "show", "-s", "--format=%ct", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        epoch = int(result.stdout.strip())
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must not be negative")
    return epoch


def staged_manifest(tag: str) -> bytes:
    source = (ROOT / "extension.json").read_bytes()
    text = source.decode("utf-8")
    updated, count = re.subn(
        r'("version"\s*:\s*)"v0\.0\.0"',
        rf'\g<1>"{tag}"',
        text,
        count=1,
    )
    if count != 1:
        raise ValueError("source extension.json must contain exactly one v0.0.0 version")

    original_json = json.loads(text)
    staged_json = json.loads(updated)
    original_json["version"] = tag
    if staged_json != original_json:
        raise ValueError("staging changed extension.json fields other than version")
    encoded = updated.encode("utf-8")
    trusted_comment_size = len(base64.b64encode(encoded))
    if trusted_comment_size > MAX_TRUSTED_COMMENT_BYTES:
        raise ValueError(
            "staged extension.json exceeds the safe Minisign trusted-comment limit: "
            f"{trusted_comment_size} > {MAX_TRUSTED_COMMENT_BYTES} base64 bytes"
        )
    return encoded


def write_archive(archive: Path, staged: dict[str, bytes], epoch: int) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.unlink(missing_ok=True)
    with archive.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=epoch) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tarfile.USTAR_FORMAT,
            ) as tar:
                for name in sorted(staged):
                    data = staged[name]
                    info = tarfile.TarInfo(name=f"./{name}")
                    info.size = len(data)
                    info.mtime = epoch
                    info.mode = 0o644
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    tar.addfile(info, io.BytesIO(data))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "release")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    if not TAG_RE.fullmatch(args.tag):
        parser.error("--tag must have the exact form vMAJOR.MINOR.PATCH")

    if not args.skip_build:
        (ROOT / "bin").mkdir(exist_ok=True)
        subprocess.run(["make"], cwd=ROOT, check=True)

    staged: dict[str, bytes] = {"extension.json": staged_manifest(args.tag)}
    for output_name, source_path in SOURCE_ARTIFACTS.items():
        if not source_path.is_file() or source_path.stat().st_size == 0:
            raise FileNotFoundError(f"missing or empty build output: {source_path}")
        staged[output_name] = source_path.read_bytes()
    for name in STATIC_FILES:
        source_path = ROOT / name
        if not source_path.is_file() or source_path.stat().st_size == 0:
            raise FileNotFoundError(f"missing or empty package file: {source_path}")
        staged[name] = source_path.read_bytes()

    archive = args.output_dir.resolve() / f"{ARTIFACT_BASENAME}.tar.gz"
    write_archive(archive, staged, source_epoch())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    print(f"archive={archive}")
    print(f"sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
