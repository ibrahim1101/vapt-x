"""Selected Android static JSON report sections; no APK processing or execution."""
import json
from importers import finding, _array, _object, _text, _required


def _severity(value):
    value = _required(value, 'MobSF severity').lower()
    if value in {'secure', 'good'}:
        return None
    mapped = {'warning':'medium', 'info':'info', 'high':'high', 'critical':'critical', 'medium':'medium', 'low':'low'}
    if value not in mapped:
        raise ValueError('Invalid MobSF severity')
    return mapped[value]


def _lines(value):
    value = _required(value, 'MobSF file lines')
    if len(value) > 5000:
        raise ValueError('Maximum MobSF line list length is 5,000 characters')
    numbers = value.split(',')
    if len(numbers) > 1000 or any(not part.isascii() or not part.isdigit() or not 1 <= int(part) <= 2_147_483_647 for part in numbers):
        raise ValueError('MobSF file lines must be comma-separated positive integers')
    return ','.join(str(n) for n in sorted({int(part) for part in numbers}))


def mobsf_findings(payload, append):
    data = _object(payload, 'MobSF Android static report')
    package = _required(data.get('package_name'), 'MobSF Android package_name')
    version = _text(data.get('version'), 'MobSF version')
    code = _object(data.get('code_analysis'), 'MobSF code_analysis')
    manifest = _object(data.get('manifest_analysis'), 'MobSF manifest_analysis')
    for rule, item in _object(code.get('findings'), 'MobSF code findings').items():
        rule = _required(rule, 'MobSF code rule')
        item = _object(item, 'MobSF code finding')
        metadata = _object(item.get('metadata'), 'MobSF code metadata')
        severity = _severity(metadata.get('severity'))
        files = _object(item.get('files'), 'MobSF code files')
        if severity is None:
            continue
        description = _text(metadata.get('description'), 'MobSF code description', rule)
        cwe = _text(metadata.get('cwe'), 'MobSF code CWE')
        for path, lines in files.items():
            path = _required(path, 'MobSF file path')
            lines = _lines(lines)
            row = finding(description, severity, f'code:{rule}', f'{package}:{path}:{lines}',
                description + '\n' + cwe + '\nImported static code assertion. Source excerpts, URLs, strings and secrets are omitted.',
                'Review the referenced mobile source locations and MobSF rule guidance; verify the issue before remediation.')
            row.update(finding_type='mobile_code', severity_source='scanner',
                import_metadata={'format':'mobsf-android-json','package_name':package[:300], 'scanner_version':version[:100],
                    'file_path':path[:1000], 'line_numbers':lines})
            append(row)
    for item in _array(manifest.get('manifest_findings'), 'MobSF manifest findings'):
        item = _object(item, 'MobSF manifest finding')
        rule = _required(item.get('rule'), 'MobSF manifest rule')
        severity = _severity(item.get('severity'))
        if severity is None:
            continue
        title = _required(item.get('title'), 'MobSF manifest title')
        description = _text(item.get('description'), 'MobSF manifest description')
        components = _array(item.get('component', []), 'MobSF manifest components')
        if len(components) > 50 or any(isinstance(v, bool) or not isinstance(v, (str,int)) or len(str(v)) > 1000 for v in components):
            raise ValueError('Invalid MobSF manifest component list')
        identity = json.dumps(components, separators=(',', ':'))
        row = finding(title, severity, f'manifest:{rule}:{identity}', f'{package}:AndroidManifest.xml',
            description + '\nImported manifest assertion; not independently verified.',
            'Review the referenced Android manifest configuration and verify the issue before changing permissions or exported components.')
        row.update(finding_type='mobile_manifest', severity_source='scanner',
            import_metadata={'format':'mobsf-android-json','package_name':package[:300], 'scanner_version':version[:100],
                'file_path':'AndroidManifest.xml', 'component':', '.join(str(v) for v in components)})
        append(row)
