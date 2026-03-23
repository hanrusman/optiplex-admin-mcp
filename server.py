#!/usr/bin/env python3
"""
optiplex-admin-mcp: Safe, controlled MCP access to Han's Optiplex homelab.

Design principles:
  - Read operations are always safe and always available.
  - Write operations are strictly limited to: git pull, docker compose up -d,
    docker compose restart <name>, docker compose build + up.
  - Destructive operations (rm, down, volume deletion, exec shell) are NEVER exposed.
  - Secrets are filtered from all output before returning.
"""

import asyncio
import json
import os
import re
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, field_validator, ConfigDict

# ---------------------------------------------------------------------------
# Server init
# ---------------------------------------------------------------------------

mcp = FastMCP("optiplex_admin_mcp")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STACKS_DIR: str = os.environ.get("STACKS_DIR", "/stacks")

# Regex for safe container/service names (Docker naming rules)
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$")

# Pattern to detect secret-looking env var keys
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api[_\-]?key|auth|credential|private[_\-]?key)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------


def _validate_name(value: str, label: str = "name") -> str:
    """Validate a container or service name against the safe name regex."""
    if not _NAME_RE.match(value):
        raise ValueError(
            f"Invalid {label}: {value!r}. "
            "Must start with alphanumeric and contain only letters, digits, _, ., -"
        )
    return value


def _redact_secrets(data: object) -> object:
    """Recursively redact secret-looking values in dicts/lists."""
    if isinstance(data, dict):
        return {
            k: "[REDACTED]"
            if isinstance(v, str) and _SECRET_KEY_RE.search(k)
            else _redact_secrets(v)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [_redact_secrets(item) for item in data]
    return data


def _redact_compose_line(line: str) -> str:
    """Redact secret-looking values in a single YAML line (key: value)."""
    if ":" not in line:
        return line
    key, _, _ = line.partition(":")
    if _SECRET_KEY_RE.search(key.strip()):
        return f"{key}: [REDACTED]"
    return line


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------


async def _run(
    cmd: list[str],
    cwd: Optional[str] = None,
    timeout: int = 60,
) -> tuple[int, str, str]:
    """Execute a command and return (returncode, stdout, stderr).

    Never uses shell=True. All commands are constructed from fixed strings
    plus validated user input — never from raw user strings.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return proc.returncode, stdout_bytes.decode(errors="replace"), stderr_bytes.decode(errors="replace")
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"


def _fmt(returncode: int, stdout: str, stderr: str, label: str) -> str:
    """Format subprocess output into a human-readable result string."""
    combined = (stdout + "\n" + stderr).strip()
    if returncode == 0:
        return combined or f"[{label}] completed successfully (no output)"
    return f"[{label}] failed (exit {returncode}):\n{combined}"


# ---------------------------------------------------------------------------
# Input models
# ---------------------------------------------------------------------------


class ContainerInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    container: str = Field(
        ...,
        description="Container name or ID (e.g., 'nginx', 'homeassistant', 'abc123def456')",
    )

    @field_validator("container")
    @classmethod
    def validate_container(cls, v: str) -> str:
        return _validate_name(v, "container name")


class ServiceInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    service: str = Field(
        ...,
        description="Compose service name (e.g., 'homeassistant', 'nginx', 'vaultwarden')",
    )

    @field_validator("service")
    @classmethod
    def validate_service(cls, v: str) -> str:
        return _validate_name(v, "service name")


class DockerLogsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    container: str = Field(
        ...,
        description="Container name or ID to fetch logs from",
    )
    lines: int = Field(
        default=50,
        description="Number of recent log lines to return (1–500)",
        ge=1,
        le=500,
    )

    @field_validator("container")
    @classmethod
    def validate_container(cls, v: str) -> str:
        return _validate_name(v, "container name")


class GitLogInput(BaseModel):
    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    lines: int = Field(
        default=10,
        description="Number of recent commits to show (1–100)",
        ge=1,
        le=100,
    )


# ---------------------------------------------------------------------------
# READ-ONLY TOOLS
# ---------------------------------------------------------------------------


@mcp.tool(
    name="optiplex_docker_ps",
    annotations={
        "title": "List Running Docker Containers",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def optiplex_docker_ps() -> str:
    """List all running Docker containers with status, health, uptime, and ports.

    Runs `docker ps` with a formatted table showing container ID, name, image,
    status (including health check state), and exposed ports.

    Returns:
        str: Formatted table of running containers. Returns only running containers
             (use optiplex_stack_status for stopped containers too).

    Examples:
        - Use when: "What containers are currently running?"
        - Use when: "Is homeassistant healthy?"
        - Don't use when: You also want stopped containers (use optiplex_stack_status)
    """
    rc, out, err = await _run([
        "docker", "ps",
        "--format", "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
    ])
    return _fmt(rc, out, err, "docker ps")


@mcp.tool(
    name="optiplex_docker_logs",
    annotations={
        "title": "Get Container Logs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def optiplex_docker_logs(params: DockerLogsInput) -> str:
    """Get recent log output from a Docker container (both stdout and stderr).

    Fetches the last N lines of logs with timestamps. Useful for diagnosing
    errors, startup issues, or checking recent activity.

    Args:
        params (DockerLogsInput):
            - container (str): Container name or ID (e.g., 'nginx', 'homeassistant')
            - lines (int): Number of tail lines to return, 1–500 (default: 50)

    Returns:
        str: Recent log lines with timestamps, or an error message if the container
             does not exist or cannot be reached.

    Examples:
        - Use when: "Show me the last 100 lines from homeassistant"
        - Use when: "Why is vaultwarden crashing?" -> check logs first
    """
    rc, out, err = await _run([
        "docker", "logs",
        "--tail", str(params.lines),
        "--timestamps",
        params.container,
    ])
    # docker logs sends container stdout → subprocess stdout, container stderr → subprocess stderr
    # Both are useful log output, so combine them
    combined = (out + err).strip()
    if rc == 0:
        return combined or f"[docker logs {params.container}] No log output"
    return f"[docker logs {params.container}] failed (exit {rc}):\n{combined}"


@mcp.tool(
    name="optiplex_docker_stats",
    annotations={
        "title": "Container Resource Usage",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def optiplex_docker_stats() -> str:
    """Get a one-shot snapshot of CPU, memory, and network usage for all running containers.

    Runs `docker stats --no-stream` to get current resource utilization without
    streaming. Shows CPU%, memory used/limit/%, network I/O, and block I/O.

    Returns:
        str: Formatted table with per-container resource usage. Snapshot only — not live.

    Examples:
        - Use when: "Which container is using the most CPU?"
        - Use when: "How much memory is homeassistant using?"
    """
    rc, out, err = await _run([
        "docker", "stats", "--no-stream",
        "--format",
        "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}",
    ])
    return _fmt(rc, out, err, "docker stats")


@mcp.tool(
    name="optiplex_docker_inspect",
    annotations={
        "title": "Inspect Container Configuration",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def optiplex_docker_inspect(params: ContainerInput) -> str:
    """Inspect a container's full configuration: image, mounts, networks, env vars, restart policy, etc.

    Secrets are automatically redacted: any environment variable whose key contains
    'password', 'token', 'key', 'secret', 'auth', or similar is replaced with [REDACTED].

    Args:
        params (ContainerInput):
            - container (str): Container name or ID to inspect

    Returns:
        str: JSON-formatted container config with secrets redacted, or error message.

    Examples:
        - Use when: "What image is homeassistant running?"
        - Use when: "What volumes does nginx have mounted?"
        - Don't use when: You want logs (use optiplex_docker_logs)
    """
    rc, out, err = await _run(["docker", "inspect", params.container])
    if rc != 0:
        return _fmt(rc, out, err, f"docker inspect {params.container}")
    try:
        data = json.loads(out)
        filtered = _redact_secrets(data)
        return json.dumps(filtered, indent=2)
    except json.JSONDecodeError:
        return out.strip()


@mcp.tool(
    name="optiplex_stack_status",
    annotations={
        "title": "Full Stack Overview (running + stopped)",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def optiplex_stack_status() -> str:
    """Get a full overview of all services: running, stopped, and unhealthy.

    Combines two views:
      1. `docker ps -a` — all containers including stopped ones, with health status
      2. `docker compose ps` — compose-aware view from the stacks directory

    Returns:
        str: Two-section report. First shows all containers with status,
             second shows the compose perspective.

    Examples:
        - Use when: "Give me a full health overview of the homelab"
        - Use when: "Are there any stopped or unhealthy containers?"
        - Use when: Starting a diagnostic session
    """
    rc1, out1, err1 = await _run([
        "docker", "ps", "-a",
        "--format", "table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}",
    ])
    rc2, out2, err2 = await _run(
        ["docker", "compose", "ps"],
        cwd=STACKS_DIR,
    )

    return "\n".join([
        "## All Containers (docker ps -a)",
        _fmt(rc1, out1, err1, "docker ps -a"),
        "",
        "## Compose Stack Status (docker compose ps)",
        _fmt(rc2, out2, err2, "docker compose ps"),
    ])


@mcp.tool(
    name="optiplex_git_status",
    annotations={
        "title": "Git Status of /opt/stacks",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,  # Fetches from remote
    },
)
async def optiplex_git_status() -> str:
    """Check the git status of /opt/stacks: uncommitted changes, branch, ahead/behind origin.

    Runs both `git status -sb` (short branch format) and `git fetch --dry-run`
    to detect any pending remote changes without actually applying them.

    Returns:
        str: Two sections — local status (branch + changes) and remote status
             (any upstream commits not yet pulled). Reports "up to date" if clean.

    Examples:
        - Use when: "Are there uncommitted changes in the stacks repo?"
        - Use when: "Is the stacks repo behind origin?" -> check before deploy
        - Always run before optiplex_deploy to understand what will change
    """
    rc1, out1, err1 = await _run(["git", "-C", STACKS_DIR, "status", "-sb"])
    rc2, out2, err2 = await _run(
        ["git", "-C", STACKS_DIR, "fetch", "--dry-run"],
        timeout=30,
    )

    sections = [
        "## Git Status (/opt/stacks)",
        _fmt(rc1, out1, err1, "git status"),
        "",
    ]
    remote_output = (out2 + err2).strip()
    if remote_output:
        sections += ["## Pending Remote Changes (git fetch --dry-run)", remote_output]
    else:
        sections.append("## Remote: up to date (nothing to fetch)")

    return "\n".join(sections)


@mcp.tool(
    name="optiplex_git_log",
    annotations={
        "title": "Git Log of /opt/stacks",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def optiplex_git_log(params: GitLogInput) -> str:
    """Show recent git commit history of /opt/stacks.

    Args:
        params (GitLogInput):
            - lines (int): Number of commits to show, 1–100 (default: 10)

    Returns:
        str: Git log with short hash, date, author, and commit message — one line per commit.

    Examples:
        - Use when: "What changed in the stacks repo recently?"
        - Use when: "Who last modified the homelab config?"
    """
    rc, out, err = await _run([
        "git", "-C", STACKS_DIR, "log",
        f"-{params.lines}",
        "--pretty=format:%h  %ad  %an  %s",
        "--date=short",
    ])
    return _fmt(rc, out, err, "git log")


@mcp.tool(
    name="optiplex_disk_usage",
    annotations={
        "title": "Disk Space Overview",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def optiplex_disk_usage() -> str:
    """Show disk space: filesystem mounts (df -h) and Docker image/volume usage (docker system df).

    Returns:
        str: Two sections:
          1. Filesystem overview: all mounts with size, used, available, and percent
          2. Docker disk usage: images, containers, volumes, build cache sizes

    Examples:
        - Use when: "Is the disk getting full?"
        - Use when: "How much space are Docker images taking?"
        - Use when: "Why is /var/lib/docker large?"
    """
    rc1, out1, err1 = await _run(["df", "-h"])
    rc2, out2, err2 = await _run(["docker", "system", "df"])

    return "\n".join([
        "## Filesystem Usage (df -h)",
        _fmt(rc1, out1, err1, "df -h"),
        "",
        "## Docker Disk Usage (docker system df)",
        _fmt(rc2, out2, err2, "docker system df"),
    ])


@mcp.tool(
    name="optiplex_read_compose",
    annotations={
        "title": "Read Service docker-compose.yml",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def optiplex_read_compose(params: ServiceInput) -> str:
    """Read the docker-compose.yml for a specific service subdirectory in /opt/stacks.

    Searches for compose files in /opt/stacks/<service>/ in priority order:
    docker-compose.yml → docker-compose.yaml → compose.yml → compose.yaml.
    Falls back to the root /opt/stacks/ compose file if no subdirectory match.

    Lines whose key contains secret-like terms (password, token, key, secret, etc.)
    are redacted before returning.

    Args:
        params (ServiceInput):
            - service (str): Subdirectory name within /opt/stacks (e.g., 'homeassistant')

    Returns:
        str: File path header + compose file contents with secrets redacted,
             or an error message if not found.

    Examples:
        - Use when: "Show me the compose config for vaultwarden"
        - Use when: "What ports does nginx expose?" -> read its compose file
        - Don't use when: You need live container config (use optiplex_docker_inspect)
    """
    stacks_path = Path(STACKS_DIR)
    candidates = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ]

    # First: look in service subdirectory
    for filename in candidates:
        compose_file = stacks_path / params.service / filename
        if compose_file.exists():
            content = compose_file.read_text(errors="replace")
            redacted = "\n".join(_redact_compose_line(line) for line in content.splitlines())
            return f"# {compose_file}\n\n{redacted}"

    # Fallback: root-level compose
    for filename in candidates:
        compose_file = stacks_path / filename
        if compose_file.exists():
            content = compose_file.read_text(errors="replace")
            redacted = "\n".join(_redact_compose_line(line) for line in content.splitlines())
            return f"# {compose_file} (root stacks compose — service '{params.service}' may be defined here)\n\n{redacted}"

    return (
        f"No docker-compose file found for service '{params.service}' in {STACKS_DIR}. "
        f"Available candidates checked: {', '.join(candidates)} in both "
        f"{STACKS_DIR}/{params.service}/ and {STACKS_DIR}/."
    )


# ---------------------------------------------------------------------------
# CONTROLLED WRITE TOOLS
# ---------------------------------------------------------------------------


@mcp.tool(
    name="optiplex_deploy",
    annotations={
        "title": "Deploy Stack (git pull + compose up -d)",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,  # Contacts git remote
    },
)
async def optiplex_deploy() -> str:
    """Run the standard homelab deployment: git pull origin main, then docker compose up -d.

    This is the ONLY operation that updates the full running stack. It does NOT:
      - run docker compose down
      - delete volumes or networks
      - remove containers

    Steps performed:
      1. git -C /opt/stacks pull origin main
      2. docker compose -f /opt/stacks/docker-compose.yml up -d

    If git pull fails (e.g., merge conflict, network error), compose up is skipped.

    Returns:
        str: Combined output from both steps, with clear section headers.
             Note: May take 30–300 seconds if Docker images need to be pulled.

    Examples:
        - Use when: "Deploy the latest changes from the repo"
        - Use when: "I just pushed to main, update the homelab"
        - Run optiplex_git_status first to understand what will change
    """
    results: list[str] = []

    # Step 1: git pull
    results.append("## Step 1: git pull origin main")
    rc1, out1, err1 = await _run(
        ["git", "-C", STACKS_DIR, "pull", "origin", "main"],
        timeout=120,
    )
    results.append(_fmt(rc1, out1 + err1, "", "git pull"))

    if rc1 != 0:
        results.append("\n⚠️  git pull failed — docker compose up skipped to avoid deploying stale state.")
        return "\n".join(results)

    # Step 2: docker compose up -d
    results.append("\n## Step 2: docker compose up -d")
    rc2, out2, err2 = await _run(
        ["docker", "compose", "up", "-d"],
        cwd=STACKS_DIR,
        timeout=300,
    )
    results.append(_fmt(rc2, out2 + err2, "", "docker compose up -d"))

    return "\n".join(results)


@mcp.tool(
    name="optiplex_restart",
    annotations={
        "title": "Restart a Single Container",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def optiplex_restart(params: ContainerInput) -> str:
    """Gracefully restart a single container using docker compose restart.

    Stops and restarts the named service without affecting any other containers.
    Does NOT rebuild the image. Does NOT run docker compose down.

    Args:
        params (ContainerInput):
            - container (str): Compose service/container name to restart

    Returns:
        str: Output from docker compose restart, or error message.

    Examples:
        - Use when: "Restart homeassistant without affecting anything else"
        - Use when: A container is hung and needs a gentle restart
        - Don't use when: You want to apply new code (use optiplex_rebuild or optiplex_deploy)
    """
    rc, out, err = await _run(
        ["docker", "compose", "restart", params.container],
        cwd=STACKS_DIR,
        timeout=60,
    )
    return _fmt(rc, out + err, "", f"docker compose restart {params.container}")


@mcp.tool(
    name="optiplex_rebuild",
    annotations={
        "title": "Rebuild and Restart a Service",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def optiplex_rebuild(params: ServiceInput) -> str:
    """Rebuild a service's Docker image from scratch (--no-cache) and restart it.

    Steps performed:
      1. docker compose build --no-cache <service>  — fresh build, ignores layer cache
      2. docker compose up -d <service>              — start the rebuilt service

    If build fails, step 2 is skipped (existing running container is untouched).

    This does NOT:
      - affect other running containers
      - remove volumes or persistent data
      - run docker compose down

    Args:
        params (ServiceInput):
            - service (str): Compose service name to rebuild

    Returns:
        str: Combined build + up output with section headers.
             Warning: --no-cache means full image rebuild. May take several minutes.

    Examples:
        - Use when: "Rebuild the nginx container with a fresh image"
        - Use when: Changes to a Dockerfile need to be applied
        - Don't use when: You just need a restart (use optiplex_restart — much faster)
    """
    results: list[str] = []

    # Step 1: Build with no cache
    results.append(f"## Step 1: docker compose build --no-cache {params.service}")
    rc1, out1, err1 = await _run(
        ["docker", "compose", "build", "--no-cache", params.service],
        cwd=STACKS_DIR,
        timeout=600,
    )
    results.append(_fmt(rc1, out1 + err1, "", f"docker compose build {params.service}"))

    if rc1 != 0:
        results.append(f"\n⚠️  Build failed — docker compose up skipped. Existing container is unchanged.")
        return "\n".join(results)

    # Step 2: Start the rebuilt service
    results.append(f"\n## Step 2: docker compose up -d {params.service}")
    rc2, out2, err2 = await _run(
        ["docker", "compose", "up", "-d", params.service],
        cwd=STACKS_DIR,
        timeout=120,
    )
    results.append(_fmt(rc2, out2 + err2, "", f"docker compose up -d {params.service}"))

    return "\n".join(results)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="sse")
