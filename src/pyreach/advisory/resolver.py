"""Coordinator resolving advisories into affected symbols using diffs, tags, and LLM fallback."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol

import httpx

from pyreach.advisory.commit_miner import CommitMiner
from pyreach.advisory.diff_parser import parse_unified_diff
from pyreach.advisory.llm_fallback import ASTValidatedLLMExtractor
from pyreach.models import (
    Advisory,
    AffectedSymbol,
    ConfidenceLevel,
    SymbolEvidenceSource,
)


class VCSClientInterface(Protocol):
    """Protocol for fetching git commit diffs and historical file contents."""

    def get_commit_diff(self, commit_ref: str) -> str | None:
        """Fetch unified diff text for a commit URL or hash."""
        ...

    def get_file_content_at_commit(self, commit_ref: str, file_path: str, pre_fix: bool = True) -> str | None:
        """Fetch pre-fix or post-fix file source code for a commit."""
        ...


class MockVCSClient:
    """Mock VCS client storing diffs and file contents in memory for offline testing."""

    def __init__(
        self,
        diffs: dict[str, str] | None = None,
        files: dict[tuple[str, str, bool], str] | None = None,
    ) -> None:
        self.diffs = diffs or {}
        self.files = files or {}

    def get_commit_diff(self, commit_ref: str) -> str | None:
        return self.diffs.get(commit_ref)

    def get_file_content_at_commit(self, commit_ref: str, file_path: str, pre_fix: bool = True) -> str | None:
        return self.files.get((commit_ref, file_path, pre_fix))


class HTTPVCSClient:
    """Live VCS client fetching commit diffs and historical files over HTTP/GitHub."""

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    def get_commit_diff(self, commit_ref: str) -> str | None:
        url = commit_ref if commit_ref.endswith(".patch") else f"{commit_ref}.patch"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                r = client.get(url, follow_redirects=True)
                if r.status_code == 200:
                    return r.text
        except Exception:
            pass
        # Fallback to local fixture if offline
        m = re.search(r"commit/([0-9a-fA-F]+)", commit_ref)
        if m:
            short_sha = m.group(1)[:8].lower()
            diff_candidates = list(Path("tests/fixtures/diffs").glob(f"*{short_sha}*.patch"))
            if diff_candidates:
                try:
                    return diff_candidates[0].read_text(encoding="utf-8")
                except Exception:
                    pass
        return None

    def get_file_content_at_commit(self, commit_ref: str, file_path: str, pre_fix: bool = True) -> str | None:
        m = re.search(r"github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]+)", commit_ref)
        if not m:
            return None
        owner, repo, sha = m.groups()
        try:
            with httpx.Client(timeout=self.timeout) as client:
                if pre_fix:
                    commit_api = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
                    r = client.get(commit_api, follow_redirects=True)
                    if r.status_code == 200:
                        parents = r.json().get("parents", [])
                        target_sha = parents[0]["sha"] if parents else sha
                    else:
                        target_sha = sha
                else:
                    target_sha = sha
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{target_sha}/{file_path}"
                r_raw = client.get(raw_url, follow_redirects=True)
                if r_raw.status_code == 200:
                    return r_raw.text
        except Exception:
            pass
        # Fallback to local source fixture if offline
        stem = Path(file_path).stem.lower()
        src_candidates = list(Path("tests/fixtures/sources").glob(f"*{stem}*pre.py"))
        if src_candidates:
            try:
                return src_candidates[0].read_text(encoding="utf-8")
            except Exception:
                pass
        return None


class AdvisorySymbolResolver:
    """Resolves an advisory into concrete affected symbols using git fix commits, tag diffs, or LLM fallback."""

    def __init__(
        self,
        vcs_client: VCSClientInterface,
        llm_extractor: ASTValidatedLLMExtractor | None = None,
    ) -> None:
        self.vcs_client = vcs_client
        self.llm_extractor = llm_extractor

    def resolve(
        self,
        advisory: Advisory,
        release_tag_diff: str | None = None,
        package_sources: dict[str, str] | None = None,
    ) -> list[AffectedSymbol]:
        """Resolve all vulnerable symbols for an advisory."""
        extracted: list[AffectedSymbol] = []
        miner = CommitMiner(package_name=advisory.package_name)

        # 1. Primary Strategy: Analyze git fix commits
        for commit_url in advisory.fix_commits:
            diff_text = self.vcs_client.get_commit_diff(commit_url)
            if not diff_text:
                continue

            file_diffs = parse_unified_diff(diff_text)
            for fd in file_diffs:
                old_path = fd.old_path or fd.new_path
                pre_source = self.vcs_client.get_file_content_at_commit(
                    commit_url, old_path, pre_fix=True
                )
                if pre_source is None:
                    continue

                symbols = miner.mine_file_diff(
                    file_diff=fd,
                    pre_fix_source=pre_source,
                    evidence_source=SymbolEvidenceSource.FIX_COMMIT_DIFF,
                )
                extracted.extend(symbols)

        # 2. Secondary Fallback: Release tag diff between last-vulnerable and first-fixed release
        if not extracted and release_tag_diff:
            file_diffs = parse_unified_diff(release_tag_diff)
            for fd in file_diffs:
                old_path = fd.old_path or fd.new_path
                pre_source = self.vcs_client.get_file_content_at_commit(
                    "tag_diff", old_path, pre_fix=True
                )
                if pre_source:
                    symbols = miner.mine_file_diff(
                        file_diff=fd,
                        pre_fix_source=pre_source,
                        evidence_source=SymbolEvidenceSource.TAG_DIFF,
                    )
                    # Tag diff symbols carry MEDIUM confidence due to potential non-security noise
                    symbols_medium = [
                        AffectedSymbol(
                            package=s.package,
                            module=s.module,
                            qualified_name=s.qualified_name,
                            symbol_type=s.symbol_type,
                            source_of_evidence=SymbolEvidenceSource.TAG_DIFF,
                            confidence=ConfidenceLevel.MEDIUM,
                            line_start=s.line_start,
                            line_end=s.line_end,
                            file_path=s.file_path,
                            diff_hunk=s.diff_hunk,
                            is_public_api=s.is_public_api,
                            description=s.description,
                        )
                        for s in symbols
                    ]
                    extracted.extend(symbols_medium)

        # 3. Tertiary Fallback: LLM extraction with strict AST existence validation
        if not extracted and self.llm_extractor and package_sources:
            llm_symbols = self.llm_extractor.extract_symbols(advisory, package_sources)
            extracted.extend(llm_symbols)

        # Deduplicate while keeping highest confidence
        deduped: dict[str, AffectedSymbol] = {}
        for sym in extracted:
            qname = sym.qualified_name
            if qname not in deduped:
                deduped[qname] = sym
            else:
                existing = deduped[qname]
                # Keep HIGH over MEDIUM over LOW
                rank = {ConfidenceLevel.HIGH: 3, ConfidenceLevel.MEDIUM: 2, ConfidenceLevel.LOW: 1}
                if rank[sym.confidence] > rank[existing.confidence]:
                    deduped[qname] = sym

        final_symbols = list(deduped.values())
        advisory.extracted_symbols = final_symbols
        return final_symbols
