# optiplex-admin-mcp

Safe, controlled MCP access to Han's Optiplex homelab. Runs alongside `lippershey-mcp` on the Optiplex.

## Design principles

| Category | Rule |
|---|---|
| **Read operations** | Always safe, always allowed |
| **Write operations** | Strictly limited: `git pull` + `docker compose up/restart/build` only |
| **Destructive operations** | Never exposed (`rm`, `down`, volume deletion, `exec` shell) |
| **Secrets** | Filtered from all output before returning |
| **Command execution** | `subprocess` with hardcoded commands — no `shell=True`, no user-supplied shell strings |

## Tools

### Read-only

| Tool | Description |
|---|---|
| `optiplex_docker_ps` | List running containers (status, health, ports) |
| `optiplex_docker_logs` | Tail logs from a container (1–500 lines) |
| `optiplex_docker_stats` | CPU/memory/network snapshot per container |
| `optiplex_docker_inspect` | Full container config (secrets redacted) |
| `optiplex_stack_status` | All containers including stopped, plus compose ps |
| `optiplex_git_status` | Branch, uncommitted changes, ahead/behind origin |
| `optiplex_git_log` | Recent commit history (1–100 commits) |
| `optiplex_disk_usage` | `df -h` + `docker system df` |
| `optiplex_read_compose` | Read a service's docker-compose.yml (secrets redacted) |

### Controlled write

| Tool | What it runs | What it never does |
|---|---|---|
| `optiplex_deploy` | `git pull origin main` → `docker compose up -d` | `down`, `rm`, volume ops |
| `optiplex_restart` | `docker compose restart <container>` | Affects other containers |
| `optiplex_rebuild` | `docker compose build --no-cache <service>` → `docker compose up -d <service>` | Removes volumes or other services |

## Deployment on Optiplex

```bash
# Clone the repo
cd /opt
git clone https://github.com/hanrusman/optiplex-admin-mcp.git

# Build and start
cd /opt/optiplex-admin-mcp
docker compose up -d --build
```

The server listens on **port 8421** (host) → 8000 (container).

## Registering in Claude Desktop

Add to `~/.claude/claude_desktop_config.json` (or equivalent):

```json
{
  "mcpServers": {
    "optiplex-admin": {
      "url": "http://<optiplex-ip>:8421/mcp"
    }
  }
}
```

## Security model

```
Claude  ──MCP──►  optiplex-admin-mcp container
                       │
                       ├── Python whitelist (hardcoded allowed commands only)
                       │
                       ├── Docker socket :ro (prevents socket file replacement)
                       │
                       ├── read_only: true (container filesystem immutable)
                       │
                       ├── no-new-privileges, ALL caps dropped
                       │
                       └── /stacks :rw (git pull only — no raw file write MCP tools)
```

**What is NOT exposed:**
- No `docker compose down` or `docker rm`
- No volume deletion
- No `.env` or secrets files
- No network modification
- No shell/exec access into containers
- No raw file write tools

## Local development

```bash
pip install mcp[cli]
python server.py
# Server starts at http://localhost:8000
```

Test with MCP Inspector:
```bash
npx @modelcontextprotocol/inspector http://localhost:8000/mcp
```
