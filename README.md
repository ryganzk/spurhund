# Spurhund

Spurhund scans source for hardcoded secrets, credentials, and policy violations. It is meant to run on a single file, across a repository, on staged Git changes, and as a pre-commit or CI check.

A finding is reported only after a rule's prefix, regular expression, value exclusions, and Shannon-entropy floor all match. Reported tokens are masked.

## Install

Requires Python 3.10 or newer.

```bash
pip install .
```

For local development, including pytest and ruff:

```bash
pip install -e ".[dev]"
```

The console script is `spurhund`.

## Initialize a repository

From the repository root:

```bash
spurhund init
```

This writes `.spurhund-rules.yml` when it is missing, and merges patterns from `.gitignore` into `settings.ignore_paths`. Running it again only adds ignore patterns that are not already listed.

`scan-repo` and `scan-staged` create that file automatically if it is absent. `scan-file` expects it to exist already.

## Scan

Every scan command uses the same exit codes:

| Code | Meaning |
| --- | --- |
| `0` | The scan finished and found nothing, including an empty diff or no matching files. |
| `1` | The scan finished and found secrets or policy violations. |
| `2` | The scan did not finish: missing or invalid config, unreadable path, git error, or invalid flags. |

When `GITHUB_ACTIONS` is `true`, each finding is also printed as a workflow annotation (`::error file=…,line=…,title={rule_id}::…`) so GitHub shows it on the pull request diff. Pass `--github-annotations` to emit those lines outside Actions. `scan-ci` still falls back to a full tree scan when the commit range cannot be produced; that scan uses the same exit codes.

```bash
# One file
spurhund scan-file path/to/file.py

# Every text file under the repository, skipping ignore paths and binaries
spurhund scan-repo .

# Added lines in the Git index only
spurhund scan-staged .

# Added lines in a pull-request range (merge base of base...head)
spurhund scan-ci --base-ref origin/main --head-ref HEAD
```

`scan-repo` walks the tree, skips paths in `settings.ignore_paths`, and skips files whose first 8 KiB contain a null byte. `scan-staged` reads `git diff --cached` and checks only lines being added. `scan-ci` reads `git diff <base>...<head>` and checks those added lines at their line numbers in the new file. Paths in `settings.ignore_paths` are skipped. If the range cannot be produced, `scan-ci` scans the whole tree instead.

Each command accepts `--config` when the rules file is not `.spurhund-rules.yml` in the working directory.

A clean run prints a confirmation. A dirty run prints a table with severity, rule id, `file:line`, entropy, and a masked token.

## Pre-commit

[`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml) publishes a hook that runs `spurhund scan-staged` on every commit. After this repository is tagged, other projects can use it:

```yaml
repos:
  - repo: https://github.com/OWNER/spurhund
    rev: v0.1.0
    hooks:
      - id: spurhund
```

Replace `OWNER` and `rev` with the GitHub account and tag you publish.

This checkout's [`.pre-commit-config.yaml`](.pre-commit-config.yaml) is a local hook. It calls `.venv/bin/spurhund` from this tree because the package is not installed from a remote tag yet:

```bash
pip install -e .
pre-commit install
```

Stage a change and commit. The hook scans the index and blocks the commit when it finds a match.

## Continuous integration

Install the package and fetch the base branch, then scan the pull-request range. `scan-ci` does not need a staged index:

```yaml
- name: Scan pull request changes
  run: |
    pip install .
    git fetch origin main
    spurhund scan-ci --base-ref origin/main --head-ref HEAD
```

A missing base ref, such as a shallow clone that never fetched `origin/main`, falls back to `spurhund scan-repo`. Use `spurhund scan-staged .` only in a job that has already staged the diff you want checked.

## Ignore paths

Repository-wide exclusions live in `settings.ignore_paths`. Patterns are globs (`dist/**`, `*.lock`). A directory entry matches that directory and everything under it.

```bash
spurhund ignore add "dist/**"
spurhund ignore remove "dist/**"
spurhund ignore list
```

`spurhund init` also imports `.gitignore`. A leading `/` is dropped, and a trailing `/` is expanded so the directory and its contents are both ignored. Re-run `init` after `.gitignore` changes if you want those new entries copied in.

The default rules file already skips `.git/`, virtualenvs, `node_modules/`, `vendor/`, lockfiles, images, PDFs, and `.pyc` files.

## Rules

Rules are entries under `rules` in `.spurhund-rules.yml`. Built-in rules:

| Rule | Severity | What it matches |
| --- | --- | --- |
| `sec-github-pat` | CRITICAL | GitHub personal access tokens (`ghp_…`, `github_pat_…`) |
| `sec-generic-key` | HIGH | An assignment to a name containing `key`, `secret`, `token`, `auth`, or `cred`, whose quoted value is 24–64 characters and high entropy |

A line is checked in order:

1. Skip the line when it contains `spurhund:ignore`.
2. Skip the rule when the file matches that rule's `path_excludes`.
3. Require one of `prefixes` to appear on the line, when prefixes are set.
4. Apply `regex_pattern`. `capture_group` selects the secret (`0` is the whole match).
5. Drop the match when it matches any `exclude_values` pattern.
6. Drop the match when its Shannon entropy is below `min_entropy`.

If several rules hit the same token on one line, Spurhund keeps the highest severity (`CRITICAL` and `BLOCKER`, then `HIGH`, `MEDIUM`, `LOW`).

Example rule:

```yaml
- id: sec-aws-access-key
  name: AWS Access Key ID
  severity: HIGH
  prefixes:
    - AKIA
  regex_pattern: 'AKIA[0-9A-Z]{16}'
  min_entropy: 3.0
  capture_group: 0
  exclude_values: []
  path_excludes:
    - "**/tests/fixtures/**"
```

`path_excludes` applies to that rule only. `settings.ignore_paths` applies to every rule. `exclude_values` are regular expressions matched against the captured secret. The generic-key rule uses this to skip values that look like `mock`, `dummy`, or `placeholder`.

## Suppress a line

Put `spurhund:ignore` on the line. The whole line is skipped:

```python
real_key = "dGVzdF9zZWNyZXRfa2V5X2Zvcl90ZXN0aW5nXzEyMzQ="  # spurhund:ignore
```

Prefer a path exclusion or a tighter rule when the same false positive shows up in many files.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

`pytest` runs the suite and writes a coverage report. Missing lines are listed in the terminal. The same report is written to `htmlcov/index.html`.
