# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Versions below `1.0.0` may change without notice.

## [Unreleased]

## [0.1.0-preview.0] - 2026-10-13

First public preview. Not security-attested.

### Added
- `@kalahroudi/bulkhead-core`: tenant resolution from the hostname only, a tenant-scoped Durable Object SQLite handle, and a route gate that refuses to start any route without a declared policy.
- `@kalahroudi/bulkhead-auth`: per-tenant users, sessions and API keys with roles and permissions, immediate revocation on role change, disable and logout, API-key role capping, a same-origin check on cookie writes, and login throttling per email.
- `@kalahroudi/bulkhead-spec`: the rule catalog with its formats and linters.
- `@kalahroudi/bulkhead-verify`: a black-box verifier with probes for tenant isolation and authentication, a self-check that catches its own seeded bugs, and the `bulkhead-verify` command.
- A demo Worker app and a tested quickstart.

### Known limits
- No encryption of sensitive fields at rest, no billing, no tenant provisioning (the first owner is claimed with a bootstrap secret), no password reset, email verification, MFA or SSO.
- `bulkhead-verify run` needs probe-contract routes that only the demo app exposes today.
