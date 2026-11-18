"""Unified diff parser that filters non-code files and maps hunks to pre-fix line ranges."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ChangedHunk:
    """A single changed hunk within a file diff."""

    old_start: int
    old_length: int
    new_start: int
    new_length: int
    hunk_text: str
    changed_pre_lines: tuple[int, ...]  # Pre-fix line numbers modified or deleted


@dataclass
class FileDiff:
    """Diff for a single file containing its modified hunks."""

    old_path: str
    new_path: str
    is_deleted: bool = False
    is_new: bool = False
    is_renamed: bool = False
    hunks: list[ChangedHunk] = field(default_factory=list)


IGNORED_PATH_PATTERNS = [
    r"(^|/)(tests?|testing)/",
    r"(^|/)docs?/",
    r"(^|/)\.github/",
    r"(^|/)\.tox/",
    r"test_.*\.py$",
    r".*_test\.py$",
    r"\.(md|rst|txt|html|yml|yaml|toml|ini|cfg)$",
    r"(^|/)(changelog|readme|license|notice|authors)(\.|$)",
]

HUNK_HEADER_REGEX = re.compile(
    r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@"
)


def should_ignore_file(path: str) -> bool:
    """Return True if path points to tests, documentation, configs, or non-Python files."""
    cleaned = path.replace("\\", "/").strip()
    if cleaned.startswith("a/") or cleaned.startswith("b/"):
        cleaned = cleaned[2:]
    if not cleaned.endswith(".py"):
        return True
    for pattern in IGNORED_PATH_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE):
            return True
    return False


def parse_unified_diff(diff_text: str) -> list[FileDiff]:
    """Parse unified diff text into a list of FileDiff objects, skipping tests and docs."""
    file_diffs: list[FileDiff] = []
    lines = diff_text.splitlines()
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]

        # Look for file boundary: "diff --git a/path b/path"
        if line.startswith("diff --git "):
            parts = line.split()
            old_p = parts[2][2:] if len(parts) > 2 and parts[2].startswith("a/") else ""
            new_p = parts[3][2:] if len(parts) > 3 and parts[3].startswith("b/") else ""
            i += 1

            is_deleted = False
            is_new = False
            is_renamed = False

            while i < n and not lines[i].startswith("diff --git ") and not lines[i].startswith("@@"):
                header_line = lines[i]
                if header_line.startswith("deleted file mode"):
                    is_deleted = True
                elif header_line.startswith("new file mode"):
                    is_new = True
                elif header_line.startswith("rename from"):
                    is_renamed = True
                elif header_line.startswith("--- "):
                    raw = header_line[4:].strip()
                    if raw.startswith("a/"):
                        old_p = raw[2:]
                elif header_line.startswith("+++ "):
                    raw = header_line[4:].strip()
                    if raw.startswith("b/"):
                        new_p = raw[2:]
                i += 1

            target_path = old_p or new_p
            if should_ignore_file(target_path):
                # Skip all lines of this file diff until the next diff --git
                while i < n and not lines[i].startswith("diff --git "):
                    i += 1
                continue

            current_fd = FileDiff(
                old_path=old_p,
                new_path=new_p,
                is_deleted=is_deleted,
                is_new=is_new,
                is_renamed=is_renamed,
            )

            # Parse hunks for this file
            while i < n and not lines[i].startswith("diff --git "):
                hunk_line = lines[i]
                match = HUNK_HEADER_REGEX.match(hunk_line)
                if match:
                    old_start = int(match.group(1))
                    old_count = int(match.group(2)) if match.group(2) is not None else 1
                    new_start = int(match.group(3))
                    new_count = int(match.group(4)) if match.group(4) is not None else 1

                    hunk_text_lines = [hunk_line]
                    i += 1

                    changed_pre_lines: list[int] = []
                    curr_old_line = old_start

                    while i < n and not lines[i].startswith("diff --git ") and not lines[i].startswith("@@"):
                        body_line = lines[i]
                        hunk_text_lines.append(body_line)
                        if body_line.startswith("-"):
                            changed_pre_lines.append(curr_old_line)
                            curr_old_line += 1
                        elif body_line.startswith("+"):
                            # Addition: if no deletions in hunk yet, record the insertion line in old file
                            if not changed_pre_lines:
                                changed_pre_lines.append(max(1, curr_old_line))
                        elif body_line.startswith(" "):
                            curr_old_line += 1
                        i += 1

                    if not changed_pre_lines:
                        changed_pre_lines.append(old_start)

                    hunk = ChangedHunk(
                        old_start=old_start,
                        old_length=old_count,
                        new_start=new_start,
                        new_length=new_count,
                        hunk_text="\n".join(hunk_text_lines),
                        changed_pre_lines=tuple(sorted(set(changed_pre_lines))),
                    )
                    current_fd.hunks.append(hunk)
                else:
                    i += 1

            file_diffs.append(current_fd)
        else:
            i += 1

    return file_diffs
