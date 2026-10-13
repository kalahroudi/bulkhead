# Security policy

Bulkhead is a preview (0.x). A green verify report means no known leak paths, not proof that none exist. It has not been independently audited.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). Include what you did, what you expected, what happened, and the rule from the `@kalahroudi/bulkhead-spec` catalog it breaks if you know it.

## Response window

- Acknowledgement within 3 business days.
- Initial assessment within 10 business days.
- A fix or mitigation plan after assessment; coordinated disclosure by agreement.

## Scope

Anything that breaks tenant isolation, authorization, session or API-key handling, or the guarantees the verifier claims to check. Known gaps are listed in the README and under "Known limits" in the CHANGELOG; reports about those are welcome but are not new vulnerabilities.
