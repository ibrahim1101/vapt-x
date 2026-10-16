"""Disposable CI restore verification, never a production backup utility.

No database-name/archive/key arguments are accepted. All data and keys are synthetic.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit
import uuid

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from pymongo import MongoClient
from pymongo.errors import PyMongoError

PREFIX = 'vaptx_restore_test_'


def validate_environment(env):
    if env.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('This drill runs only in an isolated GitHub Actions job')
    uri = env.get('RESTORE_TEST_URI', '')
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except ValueError:
        raise ValueError('Invalid disposable test URI') from None
    if (parsed.scheme != 'mongodb' or parsed.hostname not in {'127.0.0.1', 'localhost', '::1'}
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {'', '/'} or parsed.query or parsed.fragment
            or port is None or not 1 <= port <= 65535 or '%' in uri
            or any(ord(c) <= 32 for c in uri)):
        raise ValueError('Use a single unauthenticated loopback MongoDB URI with port and no database/options')
    container = env.get('RESTORE_TEST_CONTAINER', '')
    if not re.fullmatch(r'[0-9a-f]{64}', container):
        raise ValueError('Expected the exact disposable CI MongoDB container ID')
    return uri, port, container


def database_names():
    token = uuid.uuid4().hex
    return PREFIX + token + '_source', PREFIX + token + '_restored'


def validate_name(name):
    if not re.fullmatch(PREFIX + r'[0-9a-f]{32}_(?:source|restored)', name):
        raise ValueError('Refusing a non-generated drill namespace')


def command(container, operation, source, restored):
    validate_name(source)
    validate_name(restored)
    if source == restored:
        raise ValueError('Source and destination must differ')
    base = ['docker', 'exec'] + (['-i'] if operation == 'restore' else []) + [container]
    if operation == 'dump':
        return base + ['mongodump', '--host=127.0.0.1', '--port=27017', '--db=' + source, '--archive', '--gzip']
    if operation != 'restore':
        raise ValueError('Unknown drill operation')
    return base + ['mongorestore', '--host=127.0.0.1', '--port=27017', '--archive', '--gzip',
                   '--nsInclude=' + source + '.*', '--nsFrom=' + source + '.*', '--nsTo=' + restored + '.*', '--stopOnError']


def run_tool(argv, **streams):
    # No shell, text conversion or archive bytes in logs. Diagnostic stderr is not printed.
    result = subprocess.run(argv, stderr=subprocess.PIPE, timeout=120, check=False, **streams)
    if result.returncode:
        raise RuntimeError('Disposable MongoDB tool failed; archive/key contents suppressed')
    return result


def validate_container(container, port):
    result = run_tool(['docker', 'inspect', container], stdout=subprocess.PIPE)
    info = json.loads(result.stdout)[0]
    bindings = info.get('NetworkSettings', {}).get('Ports', {}).get('27017/tcp') or []
    if (info.get('Id') != container or info.get('Config', {}).get('Image') != 'mongo:7'
            or not info.get('State', {}).get('Running')
            or not any(str(port) == row.get('HostPort') for row in bindings)):
        raise ValueError('Container must be the running mongo:7 CI service on the declared port')


def cleanup_owned(client, names, owner):
    failed = False
    for name in names:
        validate_name(name)
        try:
            if client[name].drill_owner.find_one({'_id': owner, 'synthetic': True}):
                client.drop_database(name)
        except PyMongoError:
            # Still attempt the other owned namespace if one lookup/drop fails.
            # Service teardown remains the final cleanup boundary.
            failed = True
    if failed:
        raise RuntimeError('Disposable namespace cleanup failed; CI service teardown required') from None


def verify_fixture(database, owner, evidence, saved_key):
    if database.drill_owner.find_one({'_id': owner, 'synthetic': True}) is None:
        raise AssertionError('Restore ownership marker missing')
    finding = database.findings.find_one({'_id': 'fixture-finding'})
    if not finding or finding['verification'] != 'imported-unverified' or finding['org_id'] != 'synthetic-org':
        raise AssertionError('Finding provenance did not restore')
    item = database.evidence.find_one({'_id': 'fixture-evidence'})
    chunks = list(database.evidence_chunks.find({'evidence_id': 'fixture-evidence'}).sort('index', 1))
    restored = b''.join(base64.b64decode(row['data'], validate=True) for row in chunks)
    if restored != evidence or hashlib.sha256(restored).hexdigest() != item['sha256']:
        raise AssertionError('Evidence bytes/checksum did not restore')
    # Simulate retrieving the previous encryption key after process/key-ring replacement.
    recovered = MultiFernet([Fernet(Fernet.generate_key()), Fernet(saved_key)])
    for collection, field, expected in (
        ('users', 'mfa_secret', b'SYNTHETIC-MFA-SECRET-NOT-AN-ACCOUNT'),
        ('webhooks', 'encrypted_configuration', b'{"secret":"synthetic-webhook-key","url":"https://fixture.invalid/"}'),
    ):
        ciphertext = database[collection].find_one({'_id': 'fixture'})[field].encode()
        try:
            Fernet(Fernet.generate_key()).decrypt(ciphertext)
        except InvalidToken:
            pass
        else:
            raise AssertionError('Unrelated encryption key unexpectedly worked')
        if recovered.decrypt(ciphertext) != expected:
            raise AssertionError('Recovered key did not decrypt restored synthetic material')
    indexes = database.evidence_chunks.index_information()
    if not indexes.get('fixture_chunks', {}).get('unique'):
        raise AssertionError('Unique chunk index did not restore')


def main():
    uri, port, container = validate_environment(os.environ)
    validate_container(container, port)
    source, restored = database_names()
    owner = uuid.uuid4().hex
    client = MongoClient(uri, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000, socketTimeoutMS=10000)
    names = []
    try:
        client.admin.command('ping')
        existing = set(client.list_database_names())
        if source in existing or restored in existing:
            raise RuntimeError('Generated namespace collision; no databases changed')
        # Marker is created in both empty namespaces before invoking external tools.
        # It permits exact-owned cleanup even if restoration fails midway.
        for name in (source, restored):
            client[name].drill_owner.insert_one({'_id': owner, 'synthetic': True})
            names.append(name)
        db = client[source]
        db.findings.insert_one({'_id': 'fixture-finding', 'org_id': 'synthetic-org', 'verification': 'imported-unverified', 'severity': 'info'})
        evidence = b'Synthetic restore fixture only.\n' * 100
        db.evidence.insert_one({'_id': 'fixture-evidence', 'sha256': hashlib.sha256(evidence).hexdigest(), 'size': len(evidence)})
        db.evidence_chunks.create_index([('evidence_id', 1), ('index', 1)], unique=True, name='fixture_chunks')
        for index, offset in enumerate(range(0, len(evidence), 1024)):
            db.evidence_chunks.insert_one({'evidence_id': 'fixture-evidence', 'index': index, 'data': base64.b64encode(evidence[offset:offset + 1024]).decode()})
        key = Fernet.generate_key()
        encrypt = Fernet(key).encrypt
        db.users.insert_one({'_id': 'fixture', 'mfa_secret': encrypt(b'SYNTHETIC-MFA-SECRET-NOT-AN-ACCOUNT').decode()})
        db.webhooks.insert_one({'_id': 'fixture', 'encrypted_configuration': encrypt(b'{"secret":"synthetic-webhook-key","url":"https://fixture.invalid/"}').decode()})
        with tempfile.TemporaryDirectory(prefix='vaptx-restore-drill-') as folder:
            key_path = Path(folder) / 'synthetic.key'
            archive = Path(folder) / 'synthetic.archive.gz'
            with key_path.open('xb') as handle:
                os.chmod(key_path, 0o600)
                handle.write(key)
            # Exclude the source ownership collection: destination already has its own marker.
            dump = command(container, 'dump', source, restored) + ['--excludeCollection=drill_owner']
            with archive.open('xb') as output:
                os.chmod(archive, 0o600)
                run_tool(dump, stdout=output)
            if not archive.stat().st_size:
                raise AssertionError('Dump archive is empty')
            with archive.open('rb') as input_file:
                run_tool(command(container, 'restore', source, restored), stdin=input_file, stdout=subprocess.DEVNULL)
            del key, encrypt
            verify_fixture(client[restored], owner, evidence, key_path.read_bytes())
            verify_fixture(client[source], owner, evidence, key_path.read_bytes())
        print('PASS: synthetic documents, evidence checksum, unique index and encrypted secret key recovery verified')
    finally:
        try:
            cleanup_owned(client, names, owner)
        finally:
            client.close()


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 1:
        raise SystemExit('No arguments accepted; this is a disposable CI-only drill')
    main()
