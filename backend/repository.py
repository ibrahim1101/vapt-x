from fastapi import HTTPException
from core import db, DomainDocument, iso, audit
from project_access import ORG_COLLECTIONS,CHILD_COLLECTIONS,require_all_projects


def public_document(doc):
    """Keep queue authority and lease metadata private from API responses."""
    data=DomainDocument.from_mongo(doc).model_dump()
    return {key:value for key,value in data.items()
        if key!='_execution_actor' and not key.startswith('_worker_lease_')}


class Repository:
    """All domain access injects organization scope, including background jobs."""
    def __init__(self, ctx):
        self.ctx = ctx

    def query(self, filters=None, collection=None):
        query={**(filters or {}), "org_id": self.ctx.org_id}
        if self.ctx.project_ids is None or collection in ORG_COLLECTIONS:return query
        field='_id' if collection=='projects' else 'project_id'
        restriction={field:{'$in':self.ctx.project_ids}}
        # Never allow caller filters/$or to replace the admission predicate.
        return {'$and':[query,restriction]}

    async def read_query(self,collection,filters=None):
        if self.ctx.project_ids is not None and collection in CHILD_COLLECTIONS:
            parent,key=CHILD_COLLECTIONS[collection]
            value=(filters or {}).get(key)
            if isinstance(value,str):
                await self.get(parent,value)
                # Legacy blobs lack project_id; their verified parent is authoritative.
                return {**(filters or {}),'org_id':self.ctx.org_id}
        return self.query(filters,collection)

    async def list(self, collection, filters=None, limit=1000):
        docs = await db[collection].find(await self.read_query(collection,filters), {"triage_history": 0, "severity_history": 0}).sort("created_at", -1).limit(limit).to_list(limit)
        return [public_document(d) for d in docs]

    async def page(self, collection, filters=None, offset=0, limit=25, projection=None):
        query = await self.read_query(collection,filters)
        total = await db[collection].count_documents(query)
        docs = await db[collection].find(query, projection if projection is not None else {"triage_history": 0, "severity_history": 0}).sort(
            [("created_at", -1), ("_id", -1)]).skip(offset).limit(limit).to_list(limit)
        return {"items": [public_document(d) for d in docs],
                "total": total, "offset": offset, "limit": limit,
                "has_more": offset + len(docs) < total}

    async def complete_list(self, collection, filters=None, max_rows=5000):
        """Return a bounded complete set or fail; never silently truncate reports."""
        rows = await self.list(collection, filters, limit=max_rows + 1)
        if len(rows) > max_rows:
            raise HTTPException(413, f"Too many {collection} for this operation (maximum {max_rows}); narrow the assessment")
        return rows

    async def get(self, collection, oid):
        doc = await db[collection].find_one(self.query({"_id": oid},collection))
        if self.ctx.project_ids is not None and collection in CHILD_COLLECTIONS:
            if not doc:doc=await db[collection].find_one({'_id':oid,'org_id':self.ctx.org_id})
            if doc:
                parent,key=CHILD_COLLECTIONS[collection]
                await self.get(parent,doc.get(key))
        if not doc:
            raise HTTPException(404, "Resource not found")
        return public_document(doc)

    async def add(self, collection, fields, log=True):
        if self.ctx.project_ids is not None:
            if collection in {'projects','project_templates'}:require_all_projects(self.ctx)
            elif collection not in ORG_COLLECTIONS:
                fields=dict(fields)
                if collection in CHILD_COLLECTIONS:
                    parent,key=CHILD_COLLECTIONS[collection]
                    item=await self.get(parent,fields.get(key))
                    fields['project_id']=item['project_id']
                if fields.get('project_id') not in self.ctx.project_ids:raise HTTPException(404,'Project not found')
                await self.get('projects',fields['project_id'])
        doc = DomainDocument(**{**fields, "org_id": self.ctx.org_id, "created_by": self.ctx.uid})
        await db[collection].insert_one(doc.to_mongo())
        if log:
            await audit(self.ctx, f"{collection}.created", collection, doc.id)
        return public_document(doc.to_mongo())

    async def update(self, collection, oid, fields, log=True):
        if collection=="project_templates":require_all_projects(self.ctx)
        existing=await self.get(collection, oid)
        safe = {k: v for k, v in fields.items() if k not in {"id", "_id", "org_id", "created_by", "created_at", "project_id", "evidence_id", "report_id"}}
        await db[collection].update_one(await self.read_query(collection,{"_id": oid,**({CHILD_COLLECTIONS[collection][1]:existing[CHILD_COLLECTIONS[collection][1]]} if collection in CHILD_COLLECTIONS else {})}), {"$set": {**safe, "updated_at": iso()}})
        if log:
            await audit(self.ctx, f"{collection}.updated", collection, oid, {"fields": list(safe)})
        return await self.get(collection, oid)
