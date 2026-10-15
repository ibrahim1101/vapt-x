from fastapi import HTTPException
from core import db, DomainDocument, iso, audit


class Repository:
    """All domain access injects organization scope, including background jobs."""
    def __init__(self, ctx):
        self.ctx = ctx

    def query(self, filters=None):
        return {**(filters or {}), "org_id": self.ctx.org_id}

    async def list(self, collection, filters=None, limit=1000):
        docs = await db[collection].find(self.query(filters), {"triage_history": 0}).sort("created_at", -1).limit(limit).to_list(limit)
        return [DomainDocument.from_mongo(d).model_dump() for d in docs]

    async def complete_list(self, collection, filters=None, max_rows=5000):
        """Return a bounded complete set or fail; never silently truncate reports."""
        rows = await self.list(collection, filters, limit=max_rows + 1)
        if len(rows) > max_rows:
            raise HTTPException(413, f"Too many {collection} for this operation (maximum {max_rows}); narrow the assessment")
        return rows

    async def get(self, collection, oid):
        doc = await db[collection].find_one(self.query({"_id": oid}))
        if not doc:
            raise HTTPException(404, "Resource not found")
        return DomainDocument.from_mongo(doc).model_dump()

    async def add(self, collection, fields, log=True):
        doc = DomainDocument(**{**fields, "org_id": self.ctx.org_id, "created_by": self.ctx.uid})
        await db[collection].insert_one(doc.to_mongo())
        if log:
            await audit(self.ctx, f"{collection}.created", collection, doc.id)
        return doc.model_dump()

    async def update(self, collection, oid, fields, log=True):
        await self.get(collection, oid)
        safe = {k: v for k, v in fields.items() if k not in {"id", "_id", "org_id", "created_by", "created_at"}}
        await db[collection].update_one(self.query({"_id": oid}), {"$set": {**safe, "updated_at": iso()}})
        if log:
            await audit(self.ctx, f"{collection}.updated", collection, oid, {"fields": list(safe)})
        return await self.get(collection, oid)
