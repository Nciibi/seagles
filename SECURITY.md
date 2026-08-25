# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue,
please report it privately.

**Do not** report security vulnerabilities through public GitHub issues.

Instead, please email: security@seagles.io

You should receive a response within 48 hours. If you don't, follow up to
ensure we received your report.

We ask that you allow us 90 days to release a fix before publicly disclosing
the vulnerability.

## Disclosure Policy

When we receive a security bug report, we will:

1. Confirm receipt within 48 hours
2. Assess severity and impact within 5 business days
3. Develop and test a fix
4. Release a security patch and disclose the vulnerability

## Scope

The following are in scope:

- The Go backend (`/backend`)
- The React frontend (`/frontend`)
- The firmware analyzer (`/firmware-analyzer`)
- Infrastructure configuration (`/k8s`, `docker-compose.yml`)
- CI/CD pipelines (`.github/workflows/`)

Out of scope: dependencies with known CVEs that have available patches.
