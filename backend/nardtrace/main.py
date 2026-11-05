"""NardTrace HTTP API (FastAPI). Serves the built frontend too, when present."""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from . import __version__
from .config import settings
from .db import (Analysis, Case, CustodyEvent, Evidence, Note, case_bundle, get_engine, get_session, log_event,
                 store_evidence, utcnow, verify_evidence)
from .domain_intel import analyze_domain
from .email_analyzer import analyze_email
from .hash_analyzer import analyze_bytes, analyze_hash
from .ip_intel import analyze_ip
from .reports import build_abuse_email, build_markdown, render_pdf
from .url_analyzer import analyze_url

@asynccontextmanager
async def lifespan(_: FastAPI):
    get_engine()
    yield


app = FastAPI(title="NardTrace", version=__version__, lifespan=lifespan,
              description="Email and infrastructure investigation workbench. Read-only lookups; never visits URLs "
                          "or executes attachments.")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])

FIXTURES = Path(__file__).resolve().parent / "demo"


# ------------------------------------------------------------------ helpers

def _attach(session: Session, case_id: int | None, kind: str, label: str, result: dict[str, Any],
            evidence: Evidence | None = None) -> dict[str, Any]:
    if case_id is None:
        return result
    an = Analysis(case_id=case_id, kind=kind, label=label, evidence_id=evidence.id if evidence else None,
                  result_json=json.dumps(result, default=str))
    session.add(an)
    session.flush()
    log_event(session, case_id, "analysis.added", f"{kind} analysis #{an.id}: {label}",
              evidence.sha256 if evidence else None)
    case = session.get(Case, case_id)
    if case:
        case.updated_at = utcnow()
    session.commit()
    result["saved_to_case"] = {"case_id": case_id, "analysis_id": an.id,
                               "evidence_id": evidence.id if evidence else None}
    return result


def _require_case(session: Session, case_id: int | None) -> Case | None:
    if case_id is None:
        return None
    case = session.get(Case, case_id)
    if not case:
        raise HTTPException(404, f"Case {case_id} not found")
    return case


async def _read_upload(f: UploadFile) -> bytes:
    data = await f.read(settings().max_upload_bytes + 1)
    if len(data) > settings().max_upload_bytes:
        raise HTTPException(413, "File too large")
    return data


# ------------------------------------------------------------------ meta

@app.get("/api/health")
def health() -> dict[str, Any]:
    s = settings()
    return {"status": "ok", "version": __version__, "offline": s.offline}


@app.get("/api/config")
def config() -> dict[str, Any]:
    s = settings()
    return {"version": __version__, "offline": s.offline, "integrations": s.integrations(),
            "max_upload_mb": s.max_upload_bytes // (1024 * 1024)}


# ------------------------------------------------------------------ analyzers

@app.post("/api/email/analyze")
async def email_analyze(file: UploadFile | None = File(None), raw: str | None = Form(None),
                        trusted_domain: str | None = Form(None), lookup: bool = Form(True),
                        case_id: int | None = Form(None), session: Session = Depends(get_session)) -> dict[str, Any]:
    case = _require_case(session, case_id)
    if file is not None and file.filename:
        data, name = await _read_upload(file), file.filename
    elif raw and raw.strip():
        data, name = raw.encode("utf-8"), "pasted-headers.txt"
    else:
        raise HTTPException(400, "Upload an .eml file or paste raw headers.")
    trusted = trusted_domain or (case.trusted_domain if case else None) or None
    result = analyze_email(data, trusted_domain=trusted, lookup=lookup)
    if result.get("error"):
        raise HTTPException(422, result["error"])
    result["input_name"] = name
    ev = None
    if case:
        ev = store_evidence(session, case.id, data, name, file.content_type if file and file.filename else "text/plain",
                            "Original message" if file and file.filename else "Pasted raw headers")
        result["evidence_sha256"] = ev.sha256
    label = f"Email: {result['summary'].get('subject') or name}"[:200]
    return _attach(session, case_id, "email", label, result, ev)


class IPReq(BaseModel):
    ip: str
    case_id: int | None = None


@app.post("/api/ip/analyze")
def ip_analyze(req: IPReq, session: Session = Depends(get_session)) -> dict[str, Any]:
    _require_case(session, req.case_id)
    result = analyze_ip(req.ip)
    if not result.get("valid"):
        raise HTTPException(422, result.get("error", "Invalid IP"))
    return _attach(session, req.case_id, "ip", f"IP: {result['input']}", result)


class DomainReq(BaseModel):
    domain: str
    trusted_domain: str | None = None
    case_id: int | None = None


@app.post("/api/domain/analyze")
def domain_analyze(req: DomainReq, session: Session = Depends(get_session)) -> dict[str, Any]:
    case = _require_case(session, req.case_id)
    result = analyze_domain(req.domain, trusted_domain=req.trusted_domain or (case.trusted_domain if case else None))
    if result.get("error"):
        raise HTTPException(422, result["error"])
    return _attach(session, req.case_id, "domain", f"Domain: {result['domain']}", result)


class URLReq(BaseModel):
    url: str
    trusted_domain: str | None = None
    lookup: bool = True
    case_id: int | None = None


@app.post("/api/url/analyze")
def url_analyze(req: URLReq, session: Session = Depends(get_session)) -> dict[str, Any]:
    case = _require_case(session, req.case_id)
    result = analyze_url(req.url, trusted_domain=req.trusted_domain or (case.trusted_domain if case else None),
                         lookup=req.lookup)
    if result.get("error"):
        raise HTTPException(422, result["error"])
    return _attach(session, req.case_id, "url", f"URL: {result['final']['defanged']}"[:200], result)


@app.post("/api/file/analyze")
async def file_analyze(file: UploadFile = File(...), lookup: bool = Form(True), case_id: int | None = Form(None),
                       session: Session = Depends(get_session)) -> dict[str, Any]:
    case = _require_case(session, case_id)
    data = await _read_upload(file)
    result = analyze_bytes(data, file.filename or "upload", lookup=lookup)
    ev = store_evidence(session, case.id, data, file.filename or "upload", file.content_type or
                        "application/octet-stream", "File for hash analysis") if case else None
    return _attach(session, case_id, "file", f"File: {file.filename}", result, ev)


class HashReq(BaseModel):
    hash: str
    case_id: int | None = None


@app.post("/api/hash/analyze")
def hash_analyze(req: HashReq, session: Session = Depends(get_session)) -> dict[str, Any]:
    _require_case(session, req.case_id)
    result = analyze_hash(req.hash)
    if result.get("error"):
        raise HTTPException(422, result["error"])
    return _attach(session, req.case_id, "hash", f"Hash: {result['input'][:16]}…", result)


# ------------------------------------------------------------------ cases

class CaseIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    trusted_domain: str = ""
    redact_terms: str = ""
    status: str = "open"


class CasePatch(BaseModel):
    title: str | None = None
    description: str | None = None
    trusted_domain: str | None = None
    redact_terms: str | None = None
    status: str | None = None


def _case_summary(session: Session, c: Case) -> dict[str, Any]:
    n = len(session.exec(select(Analysis.id).where(Analysis.case_id == c.id)).all())
    return {**c.model_dump(), "analysis_count": n}


@app.get("/api/cases")
def list_cases(session: Session = Depends(get_session)) -> list[dict[str, Any]]:
    return [_case_summary(session, c) for c in session.exec(select(Case).order_by(Case.updated_at.desc())).all()]


@app.post("/api/cases", status_code=201)
def create_case(body: CaseIn, session: Session = Depends(get_session)) -> dict[str, Any]:
    c = Case(**body.model_dump())
    session.add(c)
    session.flush()
    log_event(session, c.id, "case.created", c.title)
    session.commit()
    session.refresh(c)
    return _case_summary(session, c)


@app.get("/api/cases/{case_id}")
def get_case(case_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    b = case_bundle(session, case_id)
    if not b:
        raise HTTPException(404, "Case not found")
    return {
        "case": b["case"].model_dump(),
        "analyses": [{"id": a.id, "kind": a.kind, "label": a.label, "created_at": a.created_at,
                      "evidence_id": a.evidence_id, "result": a.result} for a in b["analyses"]],
        "notes": [n.model_dump() for n in b["notes"]],
        "evidence": [{k: v for k, v in e.model_dump().items() if k != "stored_path"} for e in b["evidence"]],
        "custody": [e.model_dump() for e in b["custody"]],
    }


@app.patch("/api/cases/{case_id}")
def update_case(case_id: int, body: CasePatch, session: Session = Depends(get_session)) -> dict[str, Any]:
    c = _require_case(session, case_id)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(c, k, v)
    c.updated_at = utcnow()
    log_event(session, case_id, "case.updated", ", ".join(sorted(changes)))
    session.commit()
    session.refresh(c)
    return _case_summary(session, c)


@app.delete("/api/cases/{case_id}", status_code=204)
def delete_case(case_id: int, session: Session = Depends(get_session)) -> Response:
    _require_case(session, case_id)
    for model in (CustodyEvent, Note, Analysis, Evidence):
        for row in session.exec(select(model).where(model.case_id == case_id)).all():
            session.delete(row)
    session.flush()
    session.delete(session.get(Case, case_id))
    session.commit()
    return Response(status_code=204)


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=10000)


@app.post("/api/cases/{case_id}/notes", status_code=201)
def add_note(case_id: int, body: NoteIn, session: Session = Depends(get_session)) -> dict[str, Any]:
    _require_case(session, case_id)
    n = Note(case_id=case_id, text=body.text)
    session.add(n)
    session.flush()
    log_event(session, case_id, "note.added", f"note #{n.id}")
    session.commit()
    session.refresh(n)
    return n.model_dump()


@app.delete("/api/cases/{case_id}/notes/{note_id}", status_code=204)
def delete_note(case_id: int, note_id: int, session: Session = Depends(get_session)) -> Response:
    n = session.get(Note, note_id)
    if not n or n.case_id != case_id:
        raise HTTPException(404, "Note not found")
    session.delete(n)
    log_event(session, case_id, "note.deleted", f"note #{note_id}")
    session.commit()
    return Response(status_code=204)


@app.delete("/api/cases/{case_id}/analyses/{analysis_id}", status_code=204)
def delete_analysis(case_id: int, analysis_id: int, session: Session = Depends(get_session)) -> Response:
    a = session.get(Analysis, analysis_id)
    if not a or a.case_id != case_id:
        raise HTTPException(404, "Analysis not found")
    session.delete(a)
    log_event(session, case_id, "analysis.removed", f"analysis #{analysis_id}: {a.label} (evidence retained)")
    session.commit()
    return Response(status_code=204)


@app.get("/api/cases/{case_id}/evidence/{evidence_id}/verify")
def verify(case_id: int, evidence_id: int, session: Session = Depends(get_session)) -> dict[str, Any]:
    ev = session.get(Evidence, evidence_id)
    if not ev or ev.case_id != case_id:
        raise HTTPException(404, "Evidence not found")
    res = verify_evidence(ev)
    log_event(session, case_id, "evidence.verified" if res["ok"] else "evidence.verify_failed",
              f"evidence #{evidence_id}", res["actual"])
    session.commit()
    return res


@app.get("/api/cases/{case_id}/evidence/{evidence_id}/download")
def download_evidence(case_id: int, evidence_id: int, session: Session = Depends(get_session)) -> FileResponse:
    ev = session.get(Evidence, evidence_id)
    if not ev or ev.case_id != case_id:
        raise HTTPException(404, "Evidence not found")
    log_event(session, case_id, "evidence.exported", f"evidence #{evidence_id} downloaded", ev.sha256)
    session.commit()
    # Served as an opaque download, never rendered inline.
    return FileResponse(ev.stored_path, media_type="application/octet-stream", filename=ev.filename)


def _bundle_or_404(session: Session, case_id: int) -> dict[str, Any]:
    b = case_bundle(session, case_id)
    if not b:
        raise HTTPException(404, "Case not found")
    return b


@app.get("/api/cases/{case_id}/report.md")
def report_md(case_id: int, redact: bool = Query(False), session: Session = Depends(get_session)) -> PlainTextResponse:
    b = _bundle_or_404(session, case_id)
    log_event(session, case_id, "report.exported", f"markdown{' (redacted)' if redact else ''}")
    session.commit()
    b = _bundle_or_404(session, case_id)
    text = build_markdown(b, redact=redact)
    return PlainTextResponse(text, media_type="text/markdown; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="nardtrace-case-{case_id}{"-redacted" if redact else ""}.md"'})


@app.get("/api/cases/{case_id}/report.pdf")
def report_pdf(case_id: int, redact: bool = Query(False), session: Session = Depends(get_session)) -> Response:
    _bundle_or_404(session, case_id)
    log_event(session, case_id, "report.exported", f"pdf{' (redacted)' if redact else ''}")
    session.commit()
    b = _bundle_or_404(session, case_id)
    pdf = render_pdf(build_markdown(b, redact=redact))
    return Response(pdf, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="nardtrace-case-{case_id}{"-redacted" if redact else ""}.pdf"'})


@app.get("/api/cases/{case_id}/abuse-email")
def abuse_email(case_id: int, redact: bool = Query(False), session: Session = Depends(get_session)) -> dict[str, Any]:
    return build_abuse_email(_bundle_or_404(session, case_id), redact=redact)


@app.post("/api/demo/seed", status_code=201)
def seed_demo(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Create a demo case from the bundled synthetic phishing email (no real personal data)."""
    data = (FIXTURES / "demo_phish.eml").read_bytes()
    c = Case(title="Demo: 'account limited' PayPal impersonation",
             description="Synthetic demonstration case. A Gmail account impersonating PayPal billing asks the "
                         "recipient to 'confirm identity' via a lookalike domain. All addresses are fictitious.",
             trusted_domain="paypal.com", redact_terms="recipient@example.net")
    session.add(c)
    session.flush()
    log_event(session, c.id, "case.created", c.title)
    result = analyze_email(data, trusted_domain="paypal.com", lookup=True)
    result["input_name"] = "demo_phish.eml"
    ev = store_evidence(session, c.id, data, "demo_phish.eml", "message/rfc822", "Synthetic demo message")
    result["evidence_sha256"] = ev.sha256
    _attach(session, c.id, "email", f"Email: {result['summary']['subject']}", result, ev)
    session.add(Note(case_id=c.id, text="Received in inbox; not clicked. Original saved as .eml before analysis."))
    session.commit()
    return _case_summary(session, session.get(Case, c.id))


# ------------------------------------------------------------------ frontend

def _mount_frontend() -> None:
    dist = settings().frontend_dist or (Path(__file__).resolve().parents[2] / "frontend" / "dist")
    if not (dist / "index.html").exists():
        return
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        if path.startswith("api/"):
            raise HTTPException(404)
        candidate = (dist / path).resolve()
        if path and candidate.is_file() and dist in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")


_mount_frontend()
