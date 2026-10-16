import base64
import hashlib
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from core import get_ctx, audit
from repository import Repository

router = APIRouter(prefix="/api")
MAX_SIZE = 10 * 1024 * 1024
CHUNK_SIZE = 192 * 1024


class UploadInit(BaseModel):
    finding_id: str
    filename: str = Field(min_length=1, max_length=180)
    size: int = Field(gt=0, le=MAX_SIZE)
    content_type: str = Field(max_length=100)


class ChunkInput(BaseModel):
    data: str = Field(max_length=270000)


@router.post("/evidence")
async def begin_upload(body: UploadInit, ctx=Depends(get_ctx)):
    ctx.require("evidence")
    repo = Repository(ctx)
    finding = await repo.get("findings", body.finding_id)
    suffix = body.filename.rsplit(".", 1)[-1].lower()
    if suffix not in {"txt", "json", "xml", "csv", "pdf", "png", "jpg", "jpeg", "log"}:
        raise HTTPException(415, "Supported evidence: text, JSON, XML, CSV, PDF, PNG and JPEG")
    return await repo.add("evidence", {**body.model_dump(), "filename": body.filename.replace("/", "_").replace("\\", "_"), "project_id": finding["project_id"], "status": "uploading", "chunk_count": (body.size + CHUNK_SIZE - 1) // CHUNK_SIZE})


@router.put("/evidence/{evidence_id}/chunks/{index}")
async def upload_chunk(evidence_id: str, index: int, body: ChunkInput, ctx=Depends(get_ctx)):
    ctx.require("evidence")
    repo = Repository(ctx)
    item = await repo.get("evidence", evidence_id)
    if item["created_by"] != ctx.uid or item["status"] != "uploading":
        raise HTTPException(403, "Only the uploader may write unfinished evidence")
    if index < 0 or index >= item["chunk_count"]:
        raise HTTPException(400, "Chunk index out of range")
    try:
        raw = base64.b64decode(body.data, validate=True)
    except ValueError:
        raise HTTPException(400, "Invalid base64 chunk")
    expected = min(CHUNK_SIZE, item["size"] - index * CHUNK_SIZE)
    if len(raw) != expected:
        raise HTTPException(400, "Chunk size does not match the upload declaration")
    previous = await repo.list("evidence_chunks", {"evidence_id": evidence_id, "index": index})
    if previous:
        await repo.update("evidence_chunks", previous[0]["id"], {"data": body.data}, log=False)
    else:
        await repo.add("evidence_chunks", {"evidence_id": evidence_id, "project_id": item["project_id"], "index": index, "data": body.data}, log=False)
    return {"received": index}


async def read_bytes(repo, item):
    chunks = await repo.list("evidence_chunks", {"evidence_id": item["id"]})
    if len(chunks) != item["chunk_count"]:
        raise HTTPException(409, "Upload is incomplete")
    try:
        ordered = sorted(chunks, key=lambda c: c["index"])
        if [c["index"] for c in ordered] != list(range(item["chunk_count"])):
            raise ValueError("Invalid chunk sequence")
        raw = b"".join(base64.b64decode(c["data"], validate=True) for c in ordered)
    except (KeyError, TypeError, ValueError):
        raise HTTPException(409, "Evidence integrity verification failed") from None
    if len(raw) != item["size"]:
        raise HTTPException(409, "Evidence integrity verification failed")
    return raw


@router.post("/evidence/{evidence_id}/complete")
async def complete(evidence_id: str, ctx=Depends(get_ctx)):
    ctx.require("evidence")
    repo = Repository(ctx)
    item = await repo.get("evidence", evidence_id)
    if item["created_by"] != ctx.uid:
        raise HTTPException(403, "Only the uploader may complete evidence")
    raw = await read_bytes(repo, item)
    if len(raw) != item["size"]:
        raise HTTPException(400, "File size mismatch")
    if item["status"] == "ready":
        if hashlib.sha256(raw).hexdigest() != item.get("sha256"):
            raise HTTPException(409, "Evidence integrity verification failed")
        return item
    if item["status"] != "uploading":
        raise HTTPException(409, "Evidence is not accepting completion")
    extension = item["filename"].rsplit(".", 1)[-1].lower()
    signatures = {"pdf": b"%PDF-", "png": b"\x89PNG\r\n\x1a\n", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff"}
    if extension in signatures and not raw.startswith(signatures[extension]):
        raise HTTPException(415, "File signature does not match its extension")
    digest = hashlib.sha256(raw).hexdigest()
    result = await repo.update("evidence", evidence_id, {"sha256": digest, "status": "ready"})
    await audit(ctx, "evidence.verified", "evidence", evidence_id, {"sha256": digest, "size": len(raw)})
    return result


@router.get("/evidence/{evidence_id}/download")
async def download(evidence_id: str, ctx=Depends(get_ctx)):
    ctx.require("read")
    repo = Repository(ctx)
    item = await repo.get("evidence", evidence_id)
    if item["status"] != "ready":
        raise HTTPException(409, "Evidence upload is not complete")
    raw = await read_bytes(repo, item)
    if hashlib.sha256(raw).hexdigest() != item["sha256"]:
        raise HTTPException(409, "Evidence integrity verification failed")
    await audit(ctx, "evidence.downloaded", "evidence", evidence_id)
    return Response(raw, media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="evidence-{evidence_id}"', "X-Content-Type-Options": "nosniff", "X-Content-SHA256": item["sha256"]})
