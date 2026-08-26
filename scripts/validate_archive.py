#!/usr/bin/env python3
"""Validate the FirefoxDump Armory archive and its BOF objects."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile


REPO_URL = "https://github.com/sliverarmory/firefoxdump"
PACKAGE_NAME = "firefoxdump"
ARTIFACTS = {
    "firefoxdump.x64.o": ("amd64", "i386:x86-64", "go"),
    "firefoxdump.x86.o": ("386", "i386", "_go"),
}
EXPECTED_MEMBERS = {
    "./extension.json",
    "./firefoxdump.x64.o",
    "./firefoxdump.x86.o",
    "./LICENSE",
    "./NOTICE",
}
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
MAX_TRUSTED_COMMENT_BYTES = 4000


def fail(message: str) -> None:
    raise ValueError(message)


def inspect_object(data: bytes, name: str, architecture: str, symbol: str, objdump: str) -> None:
    with tempfile.TemporaryDirectory(prefix="armory-bof-inspect-") as directory:
        path = Path(directory) / name
        path.write_bytes(data)
        headers = subprocess.run(
            [objdump, "-f", str(path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        observed_arch = re.search(r"^architecture:\s*([^,]+),", headers, re.MULTILINE)
        if observed_arch is None or observed_arch.group(1) != architecture:
            fail(f"{name} is not a {architecture} COFF object according to objdump")

        symbols = subprocess.run(
            [objdump, "-t", str(path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        entrypoint = re.search(
            rf"^\[\s*\d+\]\(sec\s+([1-9][0-9]*)\).*?\(scl\s+2\).*?\s{re.escape(symbol)}\s*$",
            symbols,
            re.MULTILINE,
        )
        if entrypoint is None:
            fail(f"{name} does not define the external BOF symbol {symbol}")
        section = entrypoint.group(1)
        if re.search(
            rf"^\[\s*\d+\]\(sec\s+{re.escape(section)}\).*?\s\.text\s*$",
            symbols,
            re.MULTILINE,
        ) is None:
            fail(f"{name}: {symbol} is not defined in the .text code section")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--inspect-objects", action="store_true")
    args = parser.parse_args()

    if not TAG_RE.fullmatch(args.tag):
        parser.error("--tag must have the exact form vMAJOR.MINOR.PATCH")
    if not args.archive.is_file():
        parser.error("--archive must name a readable file")

    objdump = None
    if args.inspect_objects:
        objdump = (
            shutil.which("x86_64-w64-mingw32-objdump")
            or shutil.which("i686-w64-mingw32-objdump")
            or shutil.which("llvm-objdump")
        )
        if objdump is None:
            parser.error("--inspect-objects requires a COFF-capable objdump")

    with tarfile.open(args.archive, "r:gz") as tar:
        members = tar.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            fail("archive contains duplicate paths")
        if set(names) != EXPECTED_MEMBERS:
            fail(
                "archive allowlist mismatch; expected "
                + repr(sorted(EXPECTED_MEMBERS))
                + ", got "
                + repr(sorted(names))
            )
        mtimes = {member.mtime for member in members}
        if len(mtimes) != 1:
            fail("archive members do not share one deterministic timestamp")
        for member in members:
            pure = PurePosixPath(member.name)
            if not member.isfile() or member.name.startswith("/") or ".." in pure.parts:
                fail(f"unsafe or non-regular archive member: {member.name}")
            if member.size == 0:
                fail(f"empty archive member: {member.name}")
            if member.mode != 0o644:
                fail(f"unexpected mode on archive member: {member.name}")
            if (member.uid, member.gid, member.uname, member.gname) != (0, 0, "root", "root"):
                fail(f"unexpected ownership metadata on archive member: {member.name}")

        manifest_member = tar.extractfile("./extension.json")
        if manifest_member is None:
            fail("cannot read ./extension.json")
        manifest_bytes = manifest_member.read()
        if len(base64.b64encode(manifest_bytes)) > MAX_TRUSTED_COMMENT_BYTES:
            fail("extension.json exceeds the safe Minisign trusted-comment limit")
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        expected_top = {
            "name",
            "package_name",
            "version",
            "extension_author",
            "original_author",
            "repo_url",
            "commands",
        }
        if set(manifest) != expected_top:
            fail("extension.json has unexpected or missing top-level fields")
        if manifest["name"] != PACKAGE_NAME or manifest["package_name"] != PACKAGE_NAME:
            fail("unexpected package identity")
        if manifest["version"] != args.tag:
            fail("manifest version does not match tag")
        if manifest["extension_author"] != "Sliver Armory":
            fail("unexpected extension_author")
        if manifest["original_author"] != "mrrobot1o1":
            fail("unexpected original_author")
        if manifest["repo_url"] != REPO_URL:
            fail("unexpected repo_url")

        commands = manifest["commands"]
        if not isinstance(commands, list) or len(commands) != 1:
            fail("manifest must contain exactly one command")
        command = commands[0]
        expected_command_keys = {
            "command_name",
            "help",
            "long_help",
            "entrypoint",
            "bof_executor",
            "init",
            "arguments",
            "files",
        }
        if set(command) != expected_command_keys:
            fail("firefoxdump command has unexpected or missing fields")
        if command["command_name"] != "firefoxdump":
            fail("unexpected command_name")
        if not isinstance(command["help"], str) or not command["help"].strip():
            fail("command help must be nonempty")
        if not isinstance(command["long_help"], str) or not command["long_help"].strip():
            fail("command long_help must be nonempty")
        if command["entrypoint"] != "go":
            fail("entrypoint must be go")
        if command["bof_executor"] != "reflektor":
            fail("bof_executor must be reflektor")
        if command["init"] != "":
            fail("init must be empty")
        if command["arguments"] != [
            {
                "name": "mode",
                "type": "string",
                "desc": "Extraction mode: omit for passwords, set --mode /all for passwords and cookies, or --mode /cookies for cookies only.",
                "optional": True,
                "default": "",
                "choices": ["/all", "/cookies"],
            }
        ]:
            fail("unexpected mode argument contract")

        expected_files = [
            {"os": "windows", "arch": "amd64", "path": "firefoxdump.x64.o"},
            {"os": "windows", "arch": "386", "path": "firefoxdump.x86.o"},
        ]
        if command["files"] != expected_files:
            fail("unexpected target or artifact mappings")

        if objdump is not None:
            for artifact, (_sliver_arch, architecture, symbol) in ARTIFACTS.items():
                artifact_member = tar.extractfile(f"./{artifact}")
                if artifact_member is None:
                    fail(f"cannot read {artifact}")
                inspect_object(
                    artifact_member.read(),
                    artifact,
                    architecture,
                    symbol,
                    objdump,
                )

    print(f"OK: {args.archive.name} is the expected Reflektor package for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
