"""Resolve repository files used to compile the configured product binary."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


class ScopeError(Exception):
    pass


INPUT_FIELDS = ("GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles",
                "HFiles", "FFiles", "SFiles", "SwigFiles", "SwigCXXFiles", "SysoFiles", "EmbedFiles")


def load_targets(path):
    data = json.loads(path.read_text())
    entries, tags, platforms = data["entrypoints"], data["tags"], data["platforms"]
    if not all(isinstance(value, list) for value in (entries, tags, platforms)):
        raise ScopeError("Product target fields must be lists")
    if not all(isinstance(value, str) for value in [*entries, *tags]):
        raise ScopeError("Product entrypoints and tags must be strings")
    if not entries or not platforms:
        raise ScopeError("Product entrypoints and release platforms must be configured")
    for entry in entries:
        if not entry.startswith("./") or ".." in Path(entry).parts or not re.fullmatch(r"\./[\w/.-]+", entry):
            raise ScopeError("Unsafe product entrypoint")
    if any(not re.fullmatch(r"[\w.]+", tag) for tag in tags):
        raise ScopeError("Invalid product build tag")
    for platform in platforms:
        if not isinstance(platform, dict) or any(not isinstance(value, str) for value in platform.values()):
            raise ScopeError("Release platform settings must be string mappings")
        if not {"GOOS", "GOARCH", "CGO_ENABLED"} <= platform.keys():
            raise ScopeError("Incomplete release platform")
        if any(key not in {"GOOS", "GOARCH", "GOARM", "CGO_ENABLED"}
               or not re.fullmatch(r"[\w.]+", value) for key, value in platform.items()):
            raise ScopeError("Invalid release platform")
    return data


def json_objects(text):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        value, offset = decoder.raw_decode(text, offset)
        yield value


def discover_files(root, targets, allow_missing=False):
    root = root.resolve()
    if allow_missing and (not (root / "go.mod").exists()
                          or not any((root / entry).is_dir() for entry in targets["entrypoints"])):
        return set()
    selected = set()
    module_text = (root / "go.mod").read_text() if (root / "go.mod").exists() else ""
    version = re.search(r"(?m)^go\s+(\d+)\.(\d+)", module_text)
    use_vendor = bool((root / "vendor/modules.txt").is_file() and version
                      and tuple(map(int, version.groups())) >= (1, 14))
    for platform in targets["platforms"]:
        environment = {**os.environ, **platform, "GOFLAGS": "", "GOWORK": "off",
                       "GOENV": "off", "GOTOOLCHAIN": "local"}
        environment.setdefault("GOCACHE", str(Path(tempfile.gettempdir()) / "security-go-cache"))
        command = ["go", "list", "-mod=vendor" if use_vendor else "-mod=readonly", "-deps", "-json", "-tags", ",".join(targets["tags"]),
                   "--", *targets["entrypoints"]]
        result = subprocess.run(command, cwd=root, env=environment, capture_output=True)
        if result.returncode:
            raise ScopeError(f"Go build-input discovery failed for {platform['GOOS']}/{platform['GOARCH']}; "
                             "check product entrypoints, module dependencies and build tags")
        roots = 0
        for package in json_objects(result.stdout.decode()):
            if package.get("Error") or package.get("DepsErrors") or package.get("Incomplete"):
                raise ScopeError("Go reported an incomplete product dependency graph")
            if not package.get("DepOnly", False):
                if package.get("Name") != "main":
                    raise ScopeError("Product entrypoint must build a main package")
                roots += 1
            directory = Path(package["Dir"]).resolve()
            try:
                directory.relative_to(root)
            except ValueError:
                # Dependency modules outside the repository are not source
                # owned by this repository. Vendored tracked inputs are kept.
                continue
            for field in INPUT_FIELDS:
                for name in package.get(field, []):
                    source = (directory / name).resolve()
                    try:
                        relative = source.relative_to(root)
                    except ValueError:
                        raise ScopeError("Product input escapes the repository snapshot")
                    if not source.is_file():
                        raise ScopeError("Product build input is missing")
                    selected.add(relative.as_posix())
        if roots != len(targets["entrypoints"]):
            raise ScopeError("Go did not resolve every product entrypoint")
    return selected
