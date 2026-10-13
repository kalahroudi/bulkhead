# Contributing

Thanks for looking. Bulkhead is a preview, so the most useful contributions are bug reports, missing probes, and anything that makes the quickstart fail for you.

1. Open an issue first for anything larger than a fix.
2. Write the failing check first: a verifier probe for behaviour that leaks, a unit test for anything else.
3. Run `pnpm install && pnpm gate` before pushing. `pnpm gate:release` also packs the packages and installs them into a clean project.
4. Security issues go through private vulnerability reporting, not issues (see `SECURITY.md`).

Licensed under Apache-2.0.
