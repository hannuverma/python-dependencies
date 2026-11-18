"""Docker-based sandbox execution runner with network isolation, read-only mounts, and resource caps."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SandboxConfig:
    """Resource and isolation configuration for the Docker sandbox."""

    base_image: str = "python:3.11-slim-bookworm"
    memory_limit: str = "2g"
    cpu_limit: str = "2.0"
    timeout_seconds: int = 120
    user_uid: str = "1000:1000"
    network_mode: str = "none"  # No network during analysis


class DockerSandboxRunner:
    """Wrapper that constructs and runs hermetic Docker execution commands."""

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self.config = config or SandboxConfig()

    @staticmethod
    def is_docker_available() -> bool:
        """Check if docker binary is installed and the daemon is reachable."""
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return False
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0
        except Exception:
            return False

    def build_run_command(
        self,
        project_dir: Path,
        advisory_ids: list[str],
        output_dir: Path | None = None,
    ) -> list[str]:
        """Construct the exact isolated Docker execution command line."""
        resolved_proj = project_dir.resolve()
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            self.config.network_mode,
            "--read-only",
            "--memory",
            self.config.memory_limit,
            "--cpus",
            self.config.cpu_limit,
            "--user",
            self.config.user_uid,
            "-v",
            f"{resolved_proj}:/project:ro",  # Read-only mount of analyzed code
        ]

        if output_dir:
            resolved_out = output_dir.resolve()
            cmd.extend(["-v", f"{resolved_out}:/output:rw"])

        cmd.extend([
            "-w",
            "/project",
            self.config.base_image,
            "pyreach",
            "scan",
            "/project",
            "--advisories",
            *advisory_ids,
        ])

        if output_dir:
            cmd.extend(["--out", "/output"])

        return cmd

    def run(
        self,
        project_dir: Path,
        advisory_ids: list[str],
        output_dir: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Execute the scan inside Docker container or raise RuntimeError if Docker is unavailable."""
        if not self.is_docker_available():
            raise RuntimeError(
                "Docker daemon is not available on this host. Sandbox run cannot proceed against real Docker."
            )

        cmd = self.build_run_command(project_dir, advisory_ids, output_dir)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.config.timeout_seconds,
        )
