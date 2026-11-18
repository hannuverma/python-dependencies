"""Advisory ingestion and symbol extraction pipeline."""

from pyreach.advisory.commit_miner import CommitMiner
from pyreach.advisory.diff_parser import ChangedHunk, FileDiff, parse_unified_diff
from pyreach.advisory.llm_fallback import ASTValidatedLLMExtractor, LLMExtractorInterface
from pyreach.advisory.osv_client import HTTPOSVClient, OfflineOSVClient, OSVClientInterface
from pyreach.advisory.resolver import AdvisorySymbolResolver, VCSClientInterface

__all__ = [
    "ChangedHunk",
    "FileDiff",
    "parse_unified_diff",
    "OSVClientInterface",
    "HTTPOSVClient",
    "OfflineOSVClient",
    "CommitMiner",
    "LLMExtractorInterface",
    "ASTValidatedLLMExtractor",
    "VCSClientInterface",
    "AdvisorySymbolResolver",
]
