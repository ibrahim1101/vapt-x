# Integrations and scanner capabilities

Updated 2026-10-16 UTC. Import adapters accept scanner-authored assertions; no external scanner/provider is activated by importing a report. Current acceptance evidence is recorded in the feature matrix.

| Integration | Mode | Requirements | Current boundary |
| --- | --- | --- | --- |
| Built-in safe checks | Execute | Approved exact-host scope/window/profile | HTTP headers, cookie flags, security.txt, DNS resolution, TLS certificate; public pinned destination or managed training target |
| Nmap | Execute and XML import | Installed `NMAP_BINARY` for execution; approved scope | TCP connect only, web ports 80/443/8080/8443, fixed flags, no scripts or exploits |
| Nuclei | JSON/JSONL import | Real scanner-authored report, approved scope | No Nuclei process execution |
| Semgrep | JSON import | `results` schema | Source findings normalized, not independently confirmed |
| Trivy | JSON import | `Results` with `Vulnerabilities`, `Misconfigurations` and `Secrets` | Failed configuration checks and secret candidates; PASS/EXCEPTION omitted; no execution or automatic remediation |
| MobSF | Android static JSON import | `package_name`, `code_analysis.findings` and `manifest_analysis.manifest_findings` | Rule/location and manifest assertions only; no APK upload, dynamic analysis, iOS or complete report-section coverage |
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

Schemathesis execution, MobSF iOS/dynamic/remaining sections, native ticket/chat adapters, SIEM and OpenTelemetry remain backlog items. Cached OSV/NVD/EPSS/KEV facts and optional TLS identity mail workflows are implemented; see the feature matrix. No credentials or paid integrations should be activated implicitly. Core operation must remain available without any AI provider.

## Assessment findings export API

Authenticated users with organization read permission can download JSON or CSV from `/api/assessments/{assessment_id}/findings/export?format=json` (or `csv`). The endpoint verifies assessment ownership, returns at most 5,000 findings as a complete dataset, and rejects larger datasets instead of truncating. JSON schema version 1 includes source/verification labels; CSV text prefixes that could trigger spreadsheet formulas are escaped. Exports are audited. These are private authenticated downloads, not share links.

## Cloud/configuration import contract

Prowler support targets its `json-asff` exporter, not OCSF, CSV or arbitrary cloud-provider JSON. Every emitted resource retains account, region, resource type and source finding ID as scanner metadata; ASFF severity is scanner-provided. The selected VAPT-X asset is an uploader-declared association and is not inferred from the cloud ARN. Duplicate rule/account/region/resource observations within an assessment reuse existing findings. Existing scopes must explicitly permit `prowler`; no old scope permissions are expanded.

Trivy retains its vulnerability normalization and adds FAIL misconfigurations and secret rule/location candidates. Configuration code/message excerpts/traces and secret code/Match values are excluded; known Match strings repeated in retained text are redacted across the normalized report. Line ranges are validated, and mixed report types share the 2,000-finding cap. PASS/EXCEPTION configuration records do not become vulnerabilities. Raw Trivy and Prowler reports are now omitted from stored jobs, as already done for Gitleaks/Checkov. Cloud tags/details are omitted. This is data minimization, not a general-purpose secret detector: retained scanner-authored descriptions, identifiers and locations may still be sensitive. Previously stored raw reports are unchanged.

Source contracts: [Prowler ASFF exporter](https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/outputs/asff/asff.py), [Trivy report types](https://pkg.go.dev/github.com/aquasecurity/trivy/pkg/types), [Trivy secret/location types](https://pkg.go.dev/github.com/aquasecurity/trivy@v0.76.0/pkg/fanal/types). Synthetic fixtures cover supported subsets, not every upstream version or output variant.

## MobSF Android static import contract

The `mobsf` format accepts the Android static report context with code findings keyed by rule and file-to-comma-separated-line mappings, plus manifest findings containing rule/severity/title/description/component fields. Mobile package/version/location provenance is shown in finding details. Code warnings normalize to medium; secure/good checks are omitted. Multiple files and manifest components retain distinct fingerprints; canonical line lists keep repeat imports stable. Raw reports, code, strings, extracted URLs, permissions inventories and root secret lists are not retained. This does not guarantee that retained rule descriptions or paths are free of sensitive text. The same 2 MB/2,000-finding limits and scope/project/role checks apply. `mobile` and `cloud` asset kinds are report-association labels and do not enable additional execution or imply complete discovery.

Supported source structure: [Android report context](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/StaticAnalyzer/views/android/db_interaction.py), [suppression wrappers](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/StaticAnalyzer/views/common/suppression.py), [source location formatting](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/StaticAnalyzer/views/sast_engine.py). iOS, dynamic reports, certificate/network/binary sections and old unwrapped variants remain unsupported; unknown top-level/nested schemas fail validation. Importing selected sections does not claim complete MobSF report coverage.

## Structured scanner facts

Trivy vulnerability imports retain package name/ecosystem/path, installed/fixed version strings, CWE identifiers, safe HTTP(S) reference URLs and vendor CVSS V3/V40 entries. Nuclei classification imports retain explicit CVE/CWE identifiers, CVSS metrics/score and references. CVSS 3.0/3.1/4.0 vector metric names, values, mandatory fields and duplicates are validated; v4 metric order is enforced. Supplied scores must be finite 0–10 with at most one decimal; missing scores remain absent. Scores and vectors are source assertions: consistency is not recalculated, and scanner severity/verification is not overwritten. No score is derived from a version string, package presence or vector. Version strings are not ordered, evaluated against affected ranges or treated as verified fixes.

Finding details show these facts separately from cached public intelligence and analyst decisions. Reports preserve them and import provenance in source snapshots; technical/remediation PDFs include supplied package/scoring details. JSON exports add typed fact fields; CSV adds the same columns with JSON encoding for structured values. Schema version 1 remains compatible through additive fields. Previously generated report snapshots remain immutable and unchanged. References are deduplicated/bounded and filtered to HTTP(S) without credentials; the server never fetches them.

Vector rules: [FIRST CVSS 3.1 specification](https://www.first.org/cvss/v3.1/specification-document), [FIRST CVSS 4.0 specification](https://www.first.org/cvss/v4.0/specification-document). Trivy field contract: [trivy-db CVSS types](https://github.com/aquasecurity/trivy-db/blob/main/pkg/types/types.go). Malformed supplied scoring metadata fails the import before job/finding writes; unsupported CVSS v2 data is not normalized into v3/v4.

## Cross-scanner correlation candidates

`GET /api/findings/{finding_id}/correlations` returns complete matching counts and stable 25-row server pages (maximum 100 requested, offset up to 1,000,000). The source finding must be readable; candidates require the exact stored asset and project, a different scanner and at least one common normalized `cve_ids` value. Literal title/scanner/assessment search cannot broaden those predicates. Historical assessments and all analyst statuses remain visible as separate observations. Results include only selected metadata and shared CVEs, not descriptions, raw output, notes or evidence. An organization/project/asset/CVE multikey index supports lookup.

The finding modal exposes these candidates without merge, resolution, confidence promotion or severity changes. This is a narrow candidate signal, not general cross-scanner equivalence, package applicability or attack-path analysis. Findings without valid normalized CVE identifiers have no candidates; old text-only identifiers are not backfilled or inferred by this endpoint. Project admission and token read scopes remain enforced.
