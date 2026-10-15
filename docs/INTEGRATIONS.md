# Integrations and scanner capabilities

Inspected 2026-10-14 UTC. These are source capabilities, not proof of execution. No external integration was activated as part of the audit.

| Integration | Mode | Requirements | Current boundary |
| --- | --- | --- | --- |
| Built-in safe checks | Execute | Approved exact-host scope/window/profile | HTTP headers, cookie flags, security.txt, DNS resolution, TLS certificate; public pinned destination or managed training target |
| Nmap | Execute and XML import | Installed `NMAP_BINARY` for execution; approved scope | TCP connect only, web ports 80/443/8080/8443, fixed flags, no scripts or exploits |
| Nuclei | JSON/JSONL import | Real scanner-authored report, approved scope | No Nuclei process execution |
| Semgrep | JSON import | `results` schema | Source findings normalized, not independently confirmed |
| Trivy | JSON import | `Results` with vulnerability entries | Does not imply full IaC/secrets/SBOM import coverage |
| OWASP ZAP | JSON import | `site` with alert arrays | No active ZAP execution |
| Anthropic Claude | Optional remote interpretation | `requirements-ai.txt`, `ANTHROPIC_API_KEY`, `CLAUDE_MODEL` | SDK lazy import, request timeout; stored project findings/history sent; raw evidence excluded |
| Generic webhooks | Internal helper only | No supported management workflow yet | HMAC signing and retries exist; unsafe to expose until DNS pinning, secrets and durable delivery are addressed |

Imports are limited to 2 MB text and 2,000 normalized findings. Exact supported variants live in `backend/importers.py`; unsupported variants must fail clearly. Imported observations are labeled unverified and asset association is declared by the uploader. An open port is informational, not a vulnerability by itself.

`GET /api/capabilities` reports configured availability, not provider health or successful execution. Nmap presence is a binary lookup, and an AI key alone does not prove that the optional SDK, account balance or selected model works.

## Future adapter contract

New adapters must define supported target/report types, validation, required scope/roles, execution versus import mode, version detection, normalized findings, timeouts, cancellation, bounded output, audit logs and synthetic fixtures. Executable tools require sandboxed workers and restricted egress. Keep tool-specific semantics rather than flattening every observation into a verified vulnerability.

OpenAPI, Schemathesis, Gitleaks, Checkov, Prowler, MobSF, OSV/NVD/EPSS/KEV enrichment, ticketing, chat notifications, email, SIEM and OpenTelemetry are backlog items. No credentials or paid integrations should be activated implicitly. Core operation must remain available without any AI provider.

## Assessment findings export API

Authenticated users with organization read permission can download JSON or CSV from `/api/assessments/{assessment_id}/findings/export?format=json` (or `csv`). The endpoint verifies assessment ownership, returns at most 5,000 findings as a complete dataset, and rejects larger datasets instead of truncating. JSON schema version 1 includes source/verification labels; CSV text prefixes that could trigger spreadsheet formulas are escaped. Exports are audited. These are private authenticated downloads, not share links.
