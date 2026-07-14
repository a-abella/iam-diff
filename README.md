# role-diff

Diff the **functional IAM access** of two AWS roles or managed policies.

Collapses the union of all inline and attached policies on each role into a
canonical `{principal → {resource → {actions}}}` map, then produces a
colorized side-by-side diff with `[+]` / `[-]` markers.

## Installation

```bash
uv sync
uv pip install -e .
```

## Usage

```
role-diff [OPTIONS] LEFT RIGHT
```

`LEFT` and `RIGHT` may each be:
- An IAM **role name** — `MyRole`
- An IAM **role ARN** — `arn:aws:iam::123456789012:role/MyRole`
- A **managed policy ARN** — `arn:aws:iam::123456789012:policy/MyPolicy`

### Examples

```bash
# Compare two roles using the default credential chain
role-diff DevRole ProdRole

# Explicit AWS profile and region
role-diff --profile staging --region us-west-2 DevRole ProdRole

# Hide context lines; show only additions and removals
role-diff --no-context DevRole ProdRole

# Skip principals/resources with no differences
role-diff --only-changed DevRole ProdRole

# Disable ANSI color (e.g. for piping to a file)
role-diff --no-color DevRole ProdRole | tee diff.txt

# Compare a role against a standalone managed policy
role-diff MyRole arn:aws:iam::123456789012:policy/ReadOnlyAccess
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No differences found |
| `1`  | Differences exist (useful in CI) |

## Options

| Flag | Description |
|------|-------------|
| `--profile PROFILE` | AWS CLI named profile (both sides) |
| `--region REGION`   | AWS region (both sides) |
| `--no-context`      | Hide unchanged action lines |
| `--only-changed`    | Skip principals/resources with no diff |
| `--no-color`        | Disable ANSI color |
| `-v / --verbose`    | Enable debug logging |
| `--version`         | Show version and exit |

## How it works

1. **Fetch** — All inline policies and attached managed policies for the role
   are retrieved via the AWS IAM API using boto3.
2. **Normalize** — Each policy statement is parsed into `(principal, resource,
   action, effect)` tuples. The full union of all statements is collapsed into
   an `AccessMap`. Deny always wins over Allow (standard IAM evaluation).
3. **Diff** — The two `AccessMap`s are compared. For each `(principal,
   resource)` pair the symmetric difference of net-allowed actions is
   rendered with `[+]` (right-only) and `[-]` (left-only) markers.

> **Note:** `NotAction` and `NotResource` statements are preserved verbatim
> rather than enumerated against the full AWS action namespace.  They are
> surfaced in the diff output so you can inspect them manually.

## Development

```bash
# Run tests
uv run pytest

# Lint
uv run ruff check src/ tests/

# Type-check
uv run pyrefly check
```

## Toolchain

| Tool | Purpose |
|------|---------|
| [uv](https://github.com/astral-sh/uv) | Package manager |
| [ruff](https://github.com/astral-sh/ruff) | Linter & formatter |
| [pytest](https://pytest.org) | Testing |
| [pyrefly](https://github.com/facebook/pyrefly) | Type checker |