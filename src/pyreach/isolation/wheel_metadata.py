"""Dynamic discovery of top-level importable modules from wheel and package metadata."""

from __future__ import annotations

import csv
from pathlib import Path


def discover_wheel_top_level_modules(package_dir: Path) -> set[str]:
    """Discover importable top-level module/package names from wheel dist-info metadata.

    Inspection order:
    1. *.dist-info/top_level.txt (PEP 376 standard)
    2. *.dist-info/RECORD (PEP 376 standard file manifest)
    3. Directory inspection for packages / modules in sdist/unpacked root
    """
    top_levels: set[str] = set()

    if not package_dir.exists() or not package_dir.is_dir():
        return top_levels

    # 1. Inspect *.dist-info/top_level.txt
    for dist_info in package_dir.glob("*.dist-info"):
        tl_file = dist_info / "top_level.txt"
        if tl_file.exists():
            try:
                for line in tl_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    name = line.strip()
                    if name and not name.startswith("#"):
                        top_levels.add(name)
            except Exception:
                pass
        if top_levels:
            return top_levels

    # 2. Fall back to *.dist-info/RECORD
    for dist_info in package_dir.glob("*.dist-info"):
        rec_file = dist_info / "RECORD"
        if rec_file.exists():
            try:
                with open(rec_file, "r", encoding="utf-8", errors="ignore") as f:
                    for row in csv.reader(f):
                        if not row:
                            continue
                        file_path = row[0].replace("\\", "/")
                        parts = file_path.split("/")
                        first = parts[0]
                        if first.endswith((".dist-info", ".data")):
                            continue
                        if len(parts) > 1 and parts[-1].endswith((".py", ".so", ".pyd")):
                            top_levels.add(first)
                        elif first.endswith((".py", ".so", ".pyd")):
                            top_levels.add(first.split(".")[0])
            except Exception:
                pass
        if top_levels:
            return top_levels

    # 3. Fallback: inspect root directory for packages (__init__.py) or standalone modules
    try:
        for item in package_dir.iterdir():
            if item.name.startswith((".", "_")) and item.name != "__init__.py":
                continue
            if item.name.endswith(".dist-info"):
                continue
            if item.is_dir():
                if (item / "__init__.py").exists() or any(item.glob("*.py")):
                    top_levels.add(item.name)
            elif item.suffix in (".py", ".so", ".pyd"):
                top_levels.add(item.stem)
    except Exception:
        pass

    return top_levels
