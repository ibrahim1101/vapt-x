"""Opt-in real Mongo atomic authentication budget regression."""
import os
import subprocess
import sys
import textwrap
import unittest


@unittest.skipUnless(os.environ.get('MONGO_TEST_URL'), 'Set MONGO_TEST_URL to a disposable MongoDB server')
class AuthRateLimitPersistenceTests(unittest.TestCase):
    def test_parallel_claims_fixed_windows_and_separate_budgets(self):
        code = textwrap.dedent('''
            import asyncio, os, uuid
            from datetime import datetime, timedelta, timezone
            from unittest.mock import patch
            from motor.motor_asyncio import AsyncIOMotorClient
            from fastapi import HTTPException
            database = 'vaptx_rate_test_' + uuid.uuid4().hex
            os.environ.update(MONGO_URL=os.environ['MONGO_TEST_URL'], DB_NAME=database,
                JWT_SECRET='integration-only-' * 4, ADMIN_EMAIL='owner@example.com',
                ADMIN_PASSWORD='integration-only-password', FRONTEND_URL='http://localhost:3000',
                INTERNAL_API_URL='http://127.0.0.1:8001', NMAP_BINARY='nmap', VAPTX_LOCAL_HTTP='1')
            import auth
            async def run():
                client = AsyncIOMotorClient(os.environ['MONGO_TEST_URL'], serverSelectionTimeoutMS=5000)
                db = client[database]
                # Future deterministic clock prevents TTL cleanup racing assertions.
                instant = (datetime.now(timezone.utc) + timedelta(days=1)).replace(hour=0, minute=1, second=0, microsecond=0)
                try:
                    with patch.object(auth, 'db', db), patch.object(auth, 'now', return_value=instant) as clock:
                        await auth.seed_admin()
                        indexes = await db.auth_rate_limits.index_information()
                        assert indexes['expires_at_1']['expireAfterSeconds'] == 0
                        outcomes = await asyncio.gather(*[
                            auth.charge_auth_attempt('login', 'synthetic@example.com')
                            for _ in range(20)
                        ], return_exceptions=True)
                        assert sum(result is None for result in outcomes) == 10, outcomes
                        rejected = [result for result in outcomes if isinstance(result, HTTPException)]
                        assert len(rejected) == 10 and all(result.status_code == 429 for result in rejected), outcomes
                        assert all(0 < int(result.headers['Retry-After']) <= 900 for result in rejected)
                        assert (await db.auth_rate_limits.find_one({}))['count'] == 20
                        await auth.charge_auth_attempt('login', 'another@example.com')
                        await auth.charge_auth_attempt('password-change', 'synthetic@example.com')
                        clock.return_value = instant + timedelta(minutes=15)
                        await auth.charge_auth_attempt('login', 'synthetic@example.com')
                        assert await db.auth_rate_limits.count_documents({}) == 4
                finally:
                    await client.drop_database(database)
                    client.close()
            asyncio.run(run())
        ''')
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
