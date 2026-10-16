# Disposable backup/restore verification

`scripts/verify_restore.py` is a **CI verification drill**, not production backup tooling. The new `Disposable restore drill` workflow is pending its first successful run; guard tests alone do not prove a restore.

## What it verifies

An isolated `mongo:7` Actions service receives synthetic findings, evidence chunks/checksums, a unique index, and Fernet-encrypted synthetic MFA/webhook material. The script creates two UUID-named `vaptx_restore_test_*` databases. `mongodump --archive --gzip` writes binary output to a private temporary archive. `mongorestore --archive --gzip` reads that file via stdin, includes only the generated source namespace and remaps it to the newly generated destination using `--nsFrom`/`--nsTo`.

After restore the script verifies actual finding provenance, reconstructed evidence bytes/SHA-256, the unique index, and decryption using a recovered previous encryption key in a new key ring. An unrelated key must fail. It also checks the source fixture remains intact. The source/destination ownership markers permit cleanup only of exact generated databases created by this run. Temporary archive/key files are deleted; nothing is uploaded. GitHub destroys the service container on failure/job completion.

Command behavior follows official MongoDB documentation: [mongodump archive/stdout and gzip](https://www.mongodb.com/docs/database-tools/mongodump/) and [mongorestore archive/stdin, gzip and namespace remapping](https://www.mongodb.com/docs/database-tools/mongorestore/).

## Safety boundary

The script accepts no CLI arguments, database names, archive paths or key inputs. It requires GitHub Actions, an exact 64-character service container ID and a single unauthenticated loopback URI with explicit port and no database/query/fragment. Remote, authenticated, replica-list and SRV URIs are rejected. Docker inspection must match the running `mongo:7` service and published port. It never reads application `.env`, uses production credentials, runs a shell, passes `--drop`, or removes unrelated databases. All tool invocations use argument lists and binary file handles.

Configuration is supplied only by `.github/workflows/restore.yml`: `RESTORE_TEST_URI` and `RESTORE_TEST_CONTAINER`. The workflow installs the pinned backend requirements, checks them, runs guard regressions and then the drill. Do not repurpose it by weakening guards or feeding customer archives. Run guard tests without services using:

```sh
.venv/bin/python -m unittest discover -s scripts -p test_verify_restore.py
```

## What this does not establish

A successful small synthetic drill proves the exercised dump/restore/key-decryption mechanics. It does not establish production backup completeness, point-in-time recovery/oplog consistency, authenticated replica-set restoration, object-storage retention, secure offsite key custody, real MFA enrollment recovery, app restart/login after restoration, or recovery objectives. Production plans still need data classification, encryption/access policy, retention/deletion, restore ownership, version compatibility, key rotation and a separate approved operational procedure. Database backup without the appropriate MFA/webhook encryption keys cannot recover those encrypted secrets.
