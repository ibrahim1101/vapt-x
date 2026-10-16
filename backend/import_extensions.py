"""Bounded import-only cloud and configuration observations, never execution."""
from importers import finding, _array, _object, _text, _required, SEVERITIES


def _line(value, label):
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 2_147_483_647:
        raise ValueError(f"Invalid {label} line number")
    return value


def _severity(value, label):
    value = _required(value, label).lower()
    if value == 'informational':
        value = 'info'
    if value not in SEVERITIES:
        raise ValueError(f"Invalid {label}")
    return value


def prowler_findings(payload, append):
    # Prowler's json-asff export is an array. Also accept Security Hub's wrapper.
    entries = payload.get('Findings') if isinstance(payload, dict) else payload
    for item in _array(entries, 'Prowler ASFF findings'):
        item = _object(item, 'Prowler ASFF finding')
        generator = _required(item.get('GeneratorId'), 'Prowler GeneratorId')
        product = _required(item.get('ProductArn'), 'Prowler ProductArn')
        if not generator.startswith('prowler-') or not product.endswith(':product/prowler/prowler'):
            raise ValueError('Expected Prowler ASFF product and generator identifiers')
        status = _required(_object(item.get('Compliance'), 'Prowler Compliance').get('Status'), 'Prowler Compliance.Status')
        if status not in {'PASSED', 'FAILED', 'WARNING', 'NOT_AVAILABLE'}:
            raise ValueError('Invalid Prowler compliance status')
        record = _text(item.get('RecordState'), 'Prowler RecordState', 'ACTIVE')
        if record not in {'ACTIVE', 'ARCHIVED'}:
            raise ValueError('Invalid Prowler record state')
        workflow = _text(_object(item.get('Workflow', {}), 'Prowler Workflow').get('Status'), 'Prowler Workflow.Status', 'NEW')
        if workflow not in {'NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED'}:
            raise ValueError('Invalid Prowler workflow status')
        if status != 'FAILED' or record == 'ARCHIVED' or workflow in {'RESOLVED', 'SUPPRESSED'}:
            continue
        identity = _required(item.get('Id'), 'Prowler Id')
        account = _required(item.get('AwsAccountId'), 'Prowler AwsAccountId')
        severity = _severity(_object(item.get('Severity'), 'Prowler Severity').get('Label'), 'Prowler Severity.Label')
        title = _required(item.get('Title'), 'Prowler Title')
        description = _text(item.get('Description'), 'Prowler Description')
        recommendation = _object(_object(item.get('Remediation', {}), 'Prowler Remediation').get('Recommendation', {}), 'Prowler Recommendation')
        remediation = _text(recommendation.get('Text'), 'Prowler Recommendation.Text', 'Review the cloud policy and apply the vendor-recommended mitigation.')
        resources = _array(item.get('Resources'), 'Prowler Resources')
        if not 1 <= len(resources) <= 100:
            raise ValueError('Prowler finding requires 1 to 100 resources')
        for resource in resources:
            resource = _object(resource, 'Prowler resource')
            target = _required(resource.get('Id'), 'Prowler resource Id')
            region = _text(resource.get('Region'), 'Prowler resource Region')
            kind = _text(resource.get('Type'), 'Prowler resource Type')
            row = finding(title, severity, f'{generator}:{account}:{region}', target,
                description + '\nImported cloud policy failure; not independently verified.', remediation)
            row.update(finding_type='cloud_configuration', severity_source='scanner',
                import_metadata={'format':'prowler-asff', 'source_id':identity[:1000],
                    'account_id':account[:100], 'region':region[:100], 'resource_type':kind[:200], 'scanner_status':status})
            append(row)


def trivy_extras(data, append):
    matches = set()
    for group in _array(data['Results'], 'Trivy Results', nullable=True):
        group = _object(group, 'Trivy result')
        target = _text(group.get('Target'), 'Trivy Target')
        for item in _array(group.get('Misconfigurations', []), 'Trivy Misconfigurations', nullable=True):
            item = _object(item, 'Trivy misconfiguration')
            status = _required(item.get('Status'), 'Trivy misconfiguration Status')
            if status not in {'FAIL', 'PASS', 'EXCEPTION'}:
                raise ValueError('Invalid Trivy misconfiguration status')
            if status != 'FAIL':
                continue
            rule = _required(item.get('ID') or item.get('AVDID'), 'Trivy misconfiguration ID')
            cause = _object(item.get('CauseMetadata', {}), 'Trivy CauseMetadata')
            start = _line(cause.get('StartLine', 0), 'Trivy configuration start')
            end = _line(cause.get('EndLine', start), 'Trivy configuration end')
            if end < start:
                raise ValueError('Invalid Trivy configuration line range')
            resource = _text(cause.get('Resource'), 'Trivy configuration Resource')
            row = finding(_text(item.get('Title'), 'Trivy configuration Title', rule),
                _severity(item.get('Severity'), 'Trivy configuration Severity'), f'misconfig:{rule}:{resource}:{start}',
                f'{target}:{start}' if start else target,
                _text(item.get('Description'), 'Trivy configuration Description') + '\nImported configuration failure. Code, message excerpts and traces are omitted.',
                _text(item.get('Resolution'), 'Trivy configuration Resolution', 'Review the configuration policy and apply the recommended mitigation.'))
            row.update(finding_type='misconfiguration', severity_source='scanner',
                import_metadata={'format':'trivy-json', 'scanner_status':'FAIL', 'start_line':start, 'end_line':end, 'resource':resource[:1000]})
            append(row)
        for item in _array(group.get('Secrets', []), 'Trivy Secrets', nullable=True):
            item = _object(item, 'Trivy secret')
            rule = _required(item.get('RuleID'), 'Trivy secret RuleID')
            start = _line(item.get('StartLine', 0), 'Trivy secret start')
            end = _line(item.get('EndLine', start), 'Trivy secret end')
            if end < start:
                raise ValueError('Invalid Trivy secret line range')
            match = _text(item.get('Match'), 'Trivy secret Match')
            if match:
                matches.add(match)
            row = finding(f'Trivy secret candidate · {rule}', _severity(item.get('Severity'), 'Trivy secret Severity'),
                f'secret:{rule}:{start}', f'{target}:{start}' if start else target,
                'Imported Trivy secret candidate. Match, code excerpts and raw report are omitted. Credential validity is not verified.',
                'Review the source location, revoke exposed credentials if confirmed, and remove them from source/history.')
            row.update(cve_ids=[], cwe_ids=[], finding_type='secret', severity_source='scanner',
                import_metadata={'format':'trivy-json', 'start_line':start, 'end_line':end})
            append(row)
    return sorted(matches, key=len, reverse=True)


def redact_known(value, matches):
    if isinstance(value, str):
        for match in matches:
            value = value.replace(match, '[REDACTED]')
        return value
    if isinstance(value, list):
        return [redact_known(item, matches) for item in value]
    if isinstance(value, dict):
        return {key:redact_known(item, matches) for key,item in value.items()}
    return value
