#!/usr/bin/env python3
"""Check the common binding versions and print the shared tag version."""

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]


def read_toml(path):
    return tomllib.loads((ROOT / path).read_text())


def python_version(version):
    """Map the common SemVer version to Python's canonical PEP 440 spelling."""
    number = r"(?:0|[1-9][0-9]*)"
    match = re.fullmatch(
        rf"({number}\.{number}\.{number})(?:-(alpha|beta|rc|preview)\.({number}))?",
        version,
    )
    if not match:
        raise ValueError(
            "FFI versions must be MAJOR.MINOR.PATCH, optionally followed by "
            "-alpha.N, -beta.N, -rc.N, or -preview.N"
        )
    base, phase, sequence = match.groups()
    if phase is None:
        return base
    phase = {"alpha": "a", "beta": "b", "rc": "rc", "preview": "rc"}[phase]
    return f"{base}{phase}{sequence}"


def check_versions(tag=None):
    ffi = read_toml("payjoin-ffi/Cargo.toml")
    version = ffi["package"]["version"]
    python = python_version(version)
    core = read_toml("payjoin/Cargo.toml")["package"]["version"]
    full = f"{version}+payjoin-{core}"
    js = json.loads((ROOT / "payjoin-ffi/javascript/package.json").read_text())
    dart = re.search(
        r"^version: ([^\s]+)$",
        (ROOT / "payjoin-ffi/dart/pubspec.yaml").read_text(),
        re.M,
    )
    csharp = ET.parse(ROOT / "payjoin-ffi/csharp/Payjoin.csproj").findtext(".//Version")
    dependency = ffi["dependencies"]["payjoin"]
    requirement = dependency if isinstance(dependency, str) else dependency["version"]
    # Match check-invariants.sh's comparison of Cargo's ^ and = requirements.
    requirement = requirement.removeprefix("^").removeprefix("=").strip()
    checks = [
        ("FFI core dependency", requirement, core),
        (
            "Python",
            read_toml("payjoin-ffi/python/pyproject.toml")["project"]["version"],
            python,
        ),
        ("JavaScript", js["version"], version),
        ("JavaScript releaseTag", js["releaseTag"], full),
        ("Dart", dart.group(1) if dart else None, full),
        ("C#", csharp, full),
    ]
    if tag is not None:
        checks.append(("Release tag", tag, f"payjoin-ffi-{full}"))
    for name, actual, expected in checks:
        if actual != expected:
            raise ValueError(f"{name}: expected {expected}, found {actual}")
    return full


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--tag", help="Require this exact shared release tag")
    mode.add_argument("--python-version", help="Print a common version in PEP 440 form")
    args = parser.parse_args()
    try:
        if args.python_version is not None:
            print(python_version(args.python_version))
        else:
            print(check_versions(args.tag))
    except (ValueError, KeyError, OSError, ET.ParseError) as error:
        sys.exit(f"bindings-version: {error}")


if __name__ == "__main__":
    main()
