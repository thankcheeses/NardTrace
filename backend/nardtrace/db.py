"""Case storage (SQLite via SQLModel) and the evidence store.

Uploaded artifacts are written to NARDTRACE_DATA_DIR/evidence/<sha256> and
never leave the machine. Every action on a case is appended to an immutable
custody log with a UTC timestamp.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import event
from sqlmodel import Field, Session, SQLModel, create_engine, select

from .config import settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class Case(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    title: str
    description: str = ""
    trusted_domain: str = ""
    redact_terms: str = ""   # newline-separated terms masked in public/redacted exports
    status: str = "open"
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class Evidence(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    case_id: int = Field(foreign_key="case.id", index=True)
    filename: str
    content_type: str = "application/octet-stream"
    size: int
    sha256: str = Field(index=True)
    sha1: str
    md5: str
    stored_path: str
    description: str = ""
    received_at: datetime = Field(default_factory=utcnow)


class Analysis(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    case_id: int = Field(foreign_key="case.id", index=True)
    kind: str
    label: str
    evidence_id: int | None = Field(default=None, foreign_key="evidence.id")
    result_json: str
    created_at: datetime = Field(default_factory=utcnow)

    @property
    def result(self) -> dict[str, Any]:
        return json.loads(self.result_json)


class Note(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    case_id: int = Field(foreign_key="case.id", index=True)
    text: str
    created_at: datetime = Field(default_factory=utcnow)


class CustodyEvent(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    case_id: int = Field(foreign_key="case.id", index=True)
    timestamp: datetime = Field(default_factory=utcnow)
    action: str
    detail: str = ""
    sha256: str | None = None


_ENGINES: dict[str, Any] = {}


def get_engine():
    url = settings().database_url
    if url not in _ENGINES:
        if url.startswith("sqlite:///"):
            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
        if url.startswith("sqlite"):
            @event.listens_for(engine, "connect")
            def _fk_on(dbapi_conn, _):  # noqa: ANN001
                dbapi_conn.execute("PRAGMA foreign_keys=ON")
        SQLModel.metadata.create_all(engine)
        _ENGINES[url] = engine
    return _ENGINES[url]


def get_session() -> Iterator[Session]:
    with Session(get_engine()) as session:
        yield session


def evidence_dir() -> Path:
    d = settings().data_dir / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    return d


def log_event(session: Session, case_id: int, action: str, detail: str = "", sha256: str | None = None) -> None:
    session.add(CustodyEvent(case_id=case_id, action=action, detail=detail, sha256=sha256))


def store_evidence(session: Session, case_id: int, data: bytes, filename: str,
                   content_type: str = "application/octet-stream", description: str = "") -> Evidence:
    sha256 = hashlib.sha256(data).hexdigest()
    path = evidence_dir() / sha256
    if not path.exists():
        path.write_bytes(data)
        path.chmod(0o440)
    ev = Evidence(case_id=case_id, filename=filename, content_type=content_type, size=len(data), sha256=sha256,
                  sha1=hashlib.sha1(data).hexdigest(), md5=hashlib.md5(data).hexdigest(),
                  stored_path=str(path), description=description)
    session.add(ev)
    session.flush()
    log_event(session, case_id, "evidence.received", f"{filename} ({len(data)} bytes) stored as evidence #{ev.id}",
              sha256)
    return ev


def verify_evidence(ev: Evidence) -> dict[str, Any]:
    p = Path(ev.stored_path)
    if not p.exists():
        return {"ok": False, "expected": ev.sha256, "actual": None, "error": "Stored file is missing."}
    actual = hashlib.sha256(p.read_bytes()).hexdigest()
    return {"ok": actual == ev.sha256, "expected": ev.sha256, "actual": actual, "error": None}


def case_bundle(session: Session, case_id: int) -> dict[str, Any] | None:
    case = session.get(Case, case_id)
    if not case:
        return None
    analyses = session.exec(select(Analysis).where(Analysis.case_id == case_id).order_by(Analysis.id)).all()
    notes = session.exec(select(Note).where(Note.case_id == case_id).order_by(Note.id)).all()
    evidence = session.exec(select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.id)).all()
    custody = session.exec(select(CustodyEvent).where(CustodyEvent.case_id == case_id)
                           .order_by(CustodyEvent.id)).all()
    return {"case": case, "analyses": analyses, "notes": notes, "evidence": evidence, "custody": custody}
