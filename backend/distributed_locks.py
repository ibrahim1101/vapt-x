"""Mongo-backed leases for short organization-scoped coordination sections."""
import asyncio
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from core import db

LEASE_SECONDS=120
RENEW_SECONDS=20
WAIT_SECONDS=15
logger=logging.getLogger(__name__)


class Lease:
    def __init__(self,key,wait_seconds=WAIT_SECONDS):
        self.key=key
        self.wait_seconds=wait_seconds
        self.owner=str(uuid.uuid4())
        self.heartbeat=None
        self.parent=None

    async def __aenter__(self):
        deadline=time.monotonic()+self.wait_seconds
        while True:
            now=datetime.now(timezone.utc)
            try:
                result=await db.coordination_locks.find_one_and_update(
                    {'_id':self.key,'$or':[{'lease_expires_at':{'$lte':now}},
                        {'owner_id':self.owner}]},
                    {'$set':{'owner_id':self.owner,'lease_expires_at':now+timedelta(seconds=LEASE_SECONDS),
                        'updated_at':now},'$inc':{'fence':1}},upsert=True,
                    return_document=ReturnDocument.AFTER)
            except DuplicateKeyError:
                result=None
            if result and result.get('owner_id')==self.owner:
                self.parent=asyncio.current_task()
                self.heartbeat=asyncio.create_task(self._renew())
                return self
            if time.monotonic()>=deadline:
                raise HTTPException(503,'A concurrent organization update is still in progress. Retry shortly.')
            await asyncio.sleep(0.05)

    async def _renew(self):
        while True:
            await asyncio.sleep(RENEW_SECONDS)
            now=datetime.now(timezone.utc)
            try:
                result=await db.coordination_locks.update_one(
                    {'_id':self.key,'owner_id':self.owner},
                    {'$set':{'lease_expires_at':now+timedelta(seconds=LEASE_SECONDS),
                        'updated_at':now}})
            except Exception:
                result=None
            if not result or result.matched_count!=1:
                # A caller must not continue a protected mutation after losing its lease.
                if self.parent and not self.parent.done():self.parent.cancel()
                return

    async def __aexit__(self,exc_type,exc,tb):
        if self.heartbeat:
            self.heartbeat.cancel()
            await asyncio.gather(self.heartbeat,return_exceptions=True)
        try:
            now=datetime.now(timezone.utc)
            await db.coordination_locks.update_one(
                {'_id':self.key,'owner_id':self.owner},
                {'$set':{'lease_expires_at':now-timedelta(seconds=LEASE_SECONDS+1),
                    'updated_at':now},'$unset':{'owner_id':''}})
        except Exception:
            logger.warning('Could not release a coordination lease; it will expire automatically')
        return False


class LeaseFactory:
    def __init__(self,namespace):
        self.namespace=namespace

    def for_scope(self,scope):
        return Lease(f'{self.namespace}:{scope}')


def distributed_lock(namespace,scope,wait_seconds=WAIT_SECONDS):
    return Lease(f'{namespace}:{scope}',wait_seconds)
