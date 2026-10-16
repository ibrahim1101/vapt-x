# Integrations and scanner capabilities

Updated 2026-10-16 UTC. Import adapters accept scanner-authored assertions; no external scanner/provider is activated by importing a report. Current acceptance evidence is recorded in the feature matrix.

| Integration | Mode | Requirements | Current boundary |
| --- | --- | --- | --- |
| Built-in safe checks | Execute | Approved exact-host scope/window/profile | HTTP headers, cookie flags, security.txt, DNS resolution, TLS certificate; public pinned destination or managed training target |
| Nmap | Execute and XML import | Installed `NMAP_BINARY` for execution; approved scope | TCP connect only, web ports 80/443/8080/8443, fixed flags, no scripts or exploits |
| Nuclei | JSON/JSONL import | Real scanner-authored report, approved scope | No Nuclei process execution |
| Semgrep | JSON import | `results` schema | Source findings normalized, not independently confirmed |
| Trivy | JSON import | `Results` with `Vulnerabilities`, `Misconfigurations` and `Secrets` | Failed configuration checks and secret candidates; PASS/EXCEPTION omitted; no execution or automatic remediation |
| Prowler | ASFF JSON import | Prowler product/generator identifiers, failed compliance and resource records | ASFF array or Security Hub Findings wrapper; passed/muted/archived/resolved/suppressed records omitted; no cloud credentials or active checks |
| Gitleaks / Checkov | JSON import | Rule/location or failed-check records | Secret matches and code/raw reports omitted; assertions remain unverified |
| OpenAPI / CycloneDX / SPDX | JSON inventory import | Supported API/package schemas | Inventory only; no external references fetched or vulnerabilities inferred |
| OWASP ZAP | JSON import | `site` with alert arrays | No active ZAP execution |
| Anthropic Claude | Optional remote interpretation | `requirements-ai.txt`, `ANTHROPIC_API_KEY`, `CLAUDE_MODEL` | SDK lazy import, request timeout; stored project findings/history sent; raw evidence excluded |
| Generic webhooks | Opt-in signed delivery | Explicit configuration and encryption key | Pinned HTTPS, encrypted destination/secret, bounded retries and leased outbox; no atomic domain/outbox transaction |

Imports are limited to 2 MB text and 2,000 normalized findings. Exact supported variants live in `backend/importers.py`; unsupported variants must fail clearly. Imported observations are labeled unverified and asset association is declared by the uploader. An open port is informational, not a vulnerability by itself.

`GET /api/capabilities` reports configured availability, not provider health or successful execution. Nmap presence is a binary lookup, and an AI key alone does not prove that the optional SDK, account balance or selected model works.

## Future adapter contract

New adapters must define supported target/report types, validation, required scope/roles, execution versus import mode, version detection, normalized findings, timeouts, cancellation, bounded output, audit logs and synthetic fixtures. Executable tools require sandboxed workers and restricted egress. Keep tool-specific semantics rather than flattening every observation into a verified vulnerability.

Schemathesis execution, MobSF, native ticket/chat adapters, SIEM and OpenTelemetry remain backlog items. Cached OSV/NVD/EPSS/KEV facts and optional TLS identity mail workflows are implemented; see the feature matrix. No credentials or paid integrations should be activated implicitly. Core operation must remain available without any AI provider.

## Assessment findings export API

Authenticated users with organization read permission can download JSON or CSV from `/api/assessments/{assessment_id}/findings/export?format=json` (or `csv`). The endpoint verifies assessment ownership, returns at most 5,000 findings as a complete dataset, and rejects larger datasets instead of truncating. JSON schema version 1 includes source/verification labels; CSV text prefixes that could trigger spreadsheet formulas are escaped. Exports are audited. These are private authenticated downloads, not share links.

## Cloud/configuration import contract

Prowler support targets its `json-asff` exporter, not OCSF, CSV or arbitrary cloud-provider JSON. Every emitted resource retains account, region, resource type and source finding ID as scanner metadata; ASFF severity is scanner-provided. The selected VAPT-X asset is an uploader-declared association and is not inferred from the cloud ARN. Duplicate rule/account/region/resource observations within an assessment reuse existing findings. Existing scopes must explicitly permit `prowler`; no old scope permissions are expanded.

Trivy retains its vulnerability normalization and adds FAIL misconfigurations and secret rule/location candidates. Configuration code/message excerpts/traces and secret code/Match values are excluded; known Match strings repeated in retained text are redacted across the normalized report. Line ranges are validated, and mixed report types share the 2,000-finding cap. PASS/EXCEPTION configuration records do not become vulnerabilities. Raw Trivy and Prowler reports are now omitted from stored jobs, as already done for Gitleaks/Checkov. Cloud tags/details are omitted. This is data minimization, not a general-purpose secret detector: retained scanner-authored descriptions, identifiers and locations may still be sensitive. Previously stored raw reports are unchanged.

Source contracts: [Prowler ASFF exporter](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/outputs/asff/asff.py), [Trivy report types](https://pkg.go.dev/github.com/aquasecurity/trivy/pkg/types), [Trivy secret/location types](https://pkg.go.dev/github.com/aquasecurity/trivy@v0.76.0/pkg/fanal/types). Synthetic fixtures cover supported subsets, not every upstream version or output variant.
