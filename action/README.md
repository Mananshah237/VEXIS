# VEXIS Security Scan — GitHub Action

AI-powered vulnerability scanning with cross-file taint analysis and LLM-powered exploit reasoning, directly in your CI/CD pipeline.

## Usage

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  vexis-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: VEXIS Security Scan
        uses: mananshah237/vexis-action@v1
        with:
          api-url: https://vexis-api.railway.app
          api-key: ${{ secrets.VEXIS_API_KEY }}
          severity-threshold: high
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-url` | ✓ | — | VEXIS API base URL |
| `api-key` | ✓ | — | Your VEXIS API key (from /settings) |
| `severity-threshold` | — | `high` | Fail if findings at this severity or above (`critical`, `high`, `medium`, `low`) |
| `scan-path` | — | `.` | Path to scan relative to repo root |
| `languages` | — | `python,javascript` | Comma-separated languages to scan |
| `timeout` | — | `300` | Max seconds to wait for scan completion |

## Outputs

| Output | Description |
|--------|-------------|
| `scan-id` | The VEXIS scan ID |
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high findings |
| `report-url` | URL to the full scan report |

## What VEXIS detects

- **CWE-89** SQL Injection (f-strings, concatenation, ORM raw queries)
- **CWE-78** OS Command Injection (subprocess shell=True, os.system, eval)
- **CWE-22** Path Traversal (os.path.join bypass, send_file, open)
- **CWE-1336** SSTI (render_template_string, Jinja2)
- **CWE-918** SSRF (requests, httpx, urllib with user input)
- **CWE-502** Insecure Deserialization (pickle, yaml.load, marshal)
- **CWE-79** Cross-Site Scripting
- **CWE-601** Open Redirect
- **CWE-117** Log Injection
- **CWE-90** LDAP Injection
- **CWE-611** XXE
- **CWE-362** Race Condition / TOCTOU
- **CWE-287** Authentication Bypass
- Cross-file taint tracking (Semgrep cannot do this)
- Attack chain discovery

## Getting your API key

1. Log in to your VEXIS instance with GitHub OAuth
2. Go to **Settings**
3. Click **Generate API Key**
4. Add it as a GitHub secret: `VEXIS_API_KEY`

## Advanced: scan only changed files

```yaml
- name: VEXIS Scan (src/ only)
  uses: mananshah237/vexis-action@v1
  with:
    api-url: ${{ vars.VEXIS_API_URL }}
    api-key: ${{ secrets.VEXIS_API_KEY }}
    scan-path: src/
    severity-threshold: critical   # only fail on critical
```

## Annotations

VEXIS emits GitHub PR annotations for every finding — you'll see inline code comments on the
exact lines where vulnerabilities were detected, with CWE IDs and confidence scores.

## Self-hosted VEXIS

Point `api-url` at your own deployment:

```yaml
api-url: https://your-vexis-instance.example.com
```

See [DEPLOY.md](../DEPLOY.md) for deployment instructions.
