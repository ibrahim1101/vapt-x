"""Atomic password-check budgets across concurrent requests and fixed windows."""
import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
import test_auth_rotation  # standalone test environment before importing auth
import auth
from fastapi import HTTPException, Response
from pymongo.errors import DuplicateKeyError

START = datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc)


class AtomicBuckets:
    def __init__(self):
        self.rows = {}
        self.lock = asyncio.Lock()

    async def find_one_and_update(self, query, update, **kwargs):
        await asyncio.sleep(0)
        async with self.lock:
            key = query['_id']
            if key not in self.rows:
                if not kwargs.get('upsert'):
                    return None
                self.rows[key] = {'_id': key, 'count': 0, **update['$setOnInsert']}
            self.rows[key]['count'] += update['$inc']['count']
            return deepcopy(self.rows[key])


class AuthRateLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_twenty_parallel_logins_allow_only_ten_password_checks(self):
        buckets = AtomicBuckets()
        db = SimpleNamespace(auth_rate_limits=buckets, users=SimpleNamespace(
            find_one=AsyncMock(return_value={'_id': 'alice', 'password_hash': 'hash'})))
        with patch.object(auth, 'db', db), patch.object(auth, 'now', return_value=START), patch.object(auth, 'verify_password', return_value=False) as verify:
            results = await asyncio.gather(*[
                auth.login(auth.Credentials(email='Alice@example.com', password='wrong-password'), Response())
                for _ in range(20)
            ], return_exceptions=True)
        self.assertTrue(all(isinstance(result, HTTPException) for result in results))
        self.assertEqual(sum(result.status_code == 401 for result in results), 10)
        self.assertEqual(sum(result.status_code == 429 for result in results), 10)
        self.assertEqual(verify.call_count, 10)
        self.assertTrue(all(0 < int(result.headers['Retry-After']) <= 900
                            for result in results if result.status_code == 429))
        self.assertEqual(next(iter(buckets.rows.values()))['count'], 20)

    async def test_fresh_window_and_independent_subject_and_action_budgets(self):
        buckets = AtomicBuckets()
        with patch.object(auth, 'db', SimpleNamespace(auth_rate_limits=buckets)), patch.object(auth, 'now', return_value=START) as clock:
            for _ in range(10):
                await auth.charge_auth_attempt('login', 'alice@example.com')
            with self.assertRaises(HTTPException):
                await auth.charge_auth_attempt('login', 'alice@example.com')
            await auth.charge_auth_attempt('login', 'bob@example.com')
            await auth.charge_auth_attempt('password-change', 'alice@example.com')
            clock.return_value = START + timedelta(minutes=15)
            await auth.charge_auth_attempt('login', 'alice@example.com')
        self.assertEqual(len(buckets.rows), 4)
        self.assertTrue(all(row['expires_at'].tzinfo is not None for row in buckets.rows.values()))
        self.assertTrue(all('example.com' not in key for key in buckets.rows))

    async def test_successful_login_does_not_reset_password_check_budget(self):
        buckets = AtomicBuckets()
        db = SimpleNamespace(auth_rate_limits=buckets, users=SimpleNamespace(
            find_one=AsyncMock(return_value={'_id': 'alice', 'password_hash': 'hash'})))
        with patch.object(auth, 'db', db), patch.object(auth, 'now', return_value=START), patch.object(auth, 'verify_password', return_value=True), patch.object(auth, 'establish_session', AsyncMock()) as establish:
            for _ in range(10):
                await auth.login(auth.Credentials(email='alice@example.com', password='valid-password'), Response())
            with self.assertRaises(HTTPException) as limited:
                await auth.login(auth.Credentials(email='alice@example.com', password='valid-password'), Response())
            self.assertEqual(limited.exception.status_code, 429)
            self.assertEqual(establish.await_count, 10)

    async def test_initial_upsert_collision_retries_atomic_increment_without_upsert(self):
        with patch.object(auth, 'db') as db, patch.object(auth, 'now', return_value=START):
            db.auth_rate_limits.find_one_and_update = AsyncMock(side_effect=[DuplicateKeyError('race'), {'count': 11}])
            with self.assertRaises(HTTPException) as limited:
                await auth.charge_auth_attempt('login', 'alice@example.com')
            self.assertEqual(limited.exception.status_code, 429)
            calls = db.auth_rate_limits.find_one_and_update.call_args_list
            self.assertEqual(calls[0].args[0], calls[1].args[0])
            self.assertNotIn('upsert', calls[1].kwargs)
            self.assertEqual(calls[1].args[1], {'$inc': {'count': 1}})
