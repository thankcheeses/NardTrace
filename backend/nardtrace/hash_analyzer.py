"""File & Hash analysis. Files are only read as bytes — never executed, opened, or unpacked."""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .findings import Confidence, Finding, Severity, Status, unknown
from .reputation import virustotal_file

MODULE = "file"

# (magic bytes, offset, type label, expected extensions)
MAGIC: list[tuple[bytes, int, str, set[str]]] = [
    (b"%PDF-", 0, "PDF document", {"pdf"}),
    (b"MZ", 0, "Windows executable (PE/DOS)", {"exe", "dll", "scr", "sys", "com", "cpl", "ocx", "drv", "efi"}),
    (b"\x7fELF", 0, "Linux/Unix executable (ELF)", {"", "so", "bin", "elf", "o"}),
    (b"\xcf\xfa\xed\xfe", 0, "macOS executable (Mach-O)", {"", "dylib", "bundle"}),
    (b"\xca\xfe\xba\xbe", 0, "Mach-O universal binary / Java class", {"", "class", "dylib"}),
    (b"PK\x03\x04", 0, "ZIP archive (also DOCX/XLSX/PPTX/JAR/APK)",
     {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar", "apk", "odt", "ods", "epub", "kmz", "xpi"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "OLE2 compound file (legacy DOC/XLS/PPT/MSG/MSI)",
     {"doc", "xls", "ppt", "msg", "msi", "dot", "xlt", "pub", "vsd"}),
    (b"Rar!\x1a\x07", 0, "RAR archive", {"rar"}),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive", {"7z"}),
    (b"\x1f\x8b", 0, "GZIP archive", {"gz", "tgz"}),
    (b"BZh", 0, "BZIP2 archive", {"bz2"}),
    (b"\xfd7zXZ\x00", 0, "XZ archive", {"xz"}),
    (b"CD001", 0x8001, "ISO 9660 disk image", {"iso", "img"}),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0, "Windows shortcut (LNK)", {"lnk"}),
    (b"{\\rtf", 0, "Rich Text Format", {"rtf", "doc"}),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image", {"png"}),
    (b"\xff\xd8\xff", 0, "JPEG image", {"jpg", "jpeg", "jfif"}),
    (b"GIF8", 0, "GIF image", {"gif"}),
    (b"RIFF", 0, "RIFF container (WAV/AVI/WEBP)", {"wav", "avi", "webp"}),
    (b"MSCF", 0, "Microsoft Cabinet archive", {"cab"}),
    (b"koly", -512, "Apple disk image (DMG)", {"dmg"}),
]

DANGEROUS_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta",
                 "ps1", "msi", "lnk", "iso", "img", "vhd", "vhdx", "jar", "docm", "xlsm", "pptm", "cpl",
                 "reg", "html", "htm", "svg", "one", "xll", "appx", "msix", "dll", "chm"}
EXECUTABLE_TYPES = {"Windows executable (PE/DOS)", "Linux/Unix executable (ELF)", "macOS executable (Mach-O)",
                    "Windows shortcut (LNK)"}


def hashes(data: bytes) -> dict[str, str]:
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def detect_type(data: bytes) -> dict[str, Any]:
    for magic, offset, label, exts in MAGIC:
        if offset >= 0:
            chunk = data[offset:offset + len(magic)]
        else:
            chunk = data[offset:offset + len(magic)] if len(data) >= -offset else b""
        if chunk == magic:
            return {"label": label, "expected_extensions": sorted(exts), "method": "magic bytes"}
    head = data[:512].lstrip()
    if head.startswith(b"#!"):
        return {"label": "Script with interpreter line (#!)", "expected_extensions": ["sh", "py", "pl", ""],
                "method": "shebang"}
    low = head[:200].lower()
    if low.startswith(b"<!doctype html") or low.startswith(b"<html") or b"<script" in low:
        return {"label": "HTML document", "expected_extensions": ["html", "htm"], "method": "content sniff"}
    if low.startswith(b"<svg") or (low.startswith(b"<?xml") and b"<svg" in data[:2048].lower()):
        return {"label": "SVG image (can contain script)", "expected_extensions": ["svg"], "method": "content sniff"}
    try:
        data[:4096].decode("utf-8")
        return {"label": "Plain text (UTF-8/ASCII)", "expected_extensions": [], "method": "content sniff"}
    except UnicodeDecodeError:
        return {"label": "Unknown binary", "expected_extensions": [], "method": "none"}


def extension_of(filename: str) -> str:
    name = (filename or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return name.rsplit(".", 1)[1].lower() if "." in name else ""


def analyze_bytes(data: bytes, filename: str, *, lookup: bool = True, module: str = MODULE) -> dict[str, Any]:
    h = hashes(data)
    ftype = detect_type(data)
    ext = extension_of(filename)
    name_parts = (filename or "").lower().split(".")
    double_ext = len(name_parts) >= 3 and name_parts[-1] in DANGEROUS_EXT and len(name_parts[-2]) <= 4
    mismatch = bool(ftype["expected_extensions"]) and ext not in ftype["expected_extensions"]
    result: dict[str, Any] = {"kind": "file", "filename": filename, "size": len(data), "hashes": h,
                              "detected_type": ftype, "claimed_extension": ext, "extension_mismatch": mismatch,
                              "executed": False}
    findings: list[Finding] = [Finding(
        module, f"File hashes for {filename or 'upload'}", Status.CONFIRMED,
        f"SHA-256 {h['sha256']} · SHA-1 {h['sha1']} · MD5 {h['md5']} · {len(data)} bytes",
        "Computed locally from the file bytes.",
        "A unique fingerprint for this exact file. Share the SHA-256 with investigators instead of the file itself.",
        "Anything about whether the file is malicious.", Confidence.HIGH,
        "Look the SHA-256 up in reputation services, or include it in your report.",
    ), Finding(
        module, f"Detected type: {ftype['label']}", Status.CONFIRMED,
        f"Content signature ({ftype['method']}) indicates {ftype['label']}; file name claims '.{ext or '(none)'}'.",
        "Magic-byte inspection of the first bytes of the file.",
        "What the file actually is, regardless of its name.",
        "What the file does when opened.", Confidence.HIGH if ftype["method"] == "magic bytes" else Confidence.MEDIUM,
        "Do not open the file on your own computer.",
    )]
    if mismatch:
        findings.append(Finding(
            module, "File type does not match its extension", Status.CONFIRMED,
            f"Named '.{ext or '(none)'}' but the content is {ftype['label']}.", "Magic bytes vs. filename.",
            "Disguising a file's real type is a classic malware delivery trick (for example an executable named .pdf).",
            "That the file is malicious — some software mislabels files.", Confidence.HIGH,
            "Treat the file as dangerous; do not open it.",
            severity=Severity.HIGH if ftype["label"] in EXECUTABLE_TYPES else Severity.MEDIUM,
        ))
    if ext in DANGEROUS_EXT or ftype["label"] in EXECUTABLE_TYPES:
        findings.append(Finding(
            module, "High-risk file type", Status.CONFIRMED,
            f"'.{ext}' / {ftype['label']} can run code or scripts when opened.", "Extension and content signature.",
            "Files like this are commonly used to deliver malware by email.",
            "That this particular file is malicious.", Confidence.HIGH,
            "Never open it. Report the sender; share only the hash.", severity=Severity.HIGH,
        ))
    if double_ext:
        findings.append(Finding(
            module, "Double extension in file name", Status.CONFIRMED, filename, "File name",
            "Names like 'invoice.pdf.exe' rely on hidden extensions to disguise the real type.",
            "That the file is malicious.", Confidence.HIGH, "Do not open it.", severity=Severity.HIGH,
        ))
    if lookup:
        vt = virustotal_file(h["sha256"])
        result["reputation"] = vt
        if vt["configured"]:
            findings.append(_vt_finding(vt, h["sha256"], module))
    result["findings"] = [f.to_dict() for f in findings]
    return result


def _vt_finding(vt: dict[str, Any], sha256: str, module: str) -> Finding:
    if vt.get("error"):
        return unknown(module, "VirusTotal lookup failed", sha256, vt["error"], "Retry later.")
    if not vt.get("data"):
        return Finding(module, "Hash unknown to VirusTotal", Status.EXTERNAL_INTEL, sha256, "VirusTotal file lookup",
                       "No one has submitted this exact file to VirusTotal.",
                       "That the file is safe — targeted or new malware is often unknown.", Confidence.MEDIUM,
                       "Do not open it. NardTrace never uploads your files.")
    stats = vt["data"].get("last_analysis_stats") or {}
    mal = (stats.get("malicious") or 0) + (stats.get("suspicious") or 0)
    return Finding(module, f"VirusTotal: {mal} engine(s) flag this file", Status.EXTERNAL_INTEL, str(stats),
                   "VirusTotal file report (existing data only).",
                   "Antivirus engines detect this file as malicious." if mal else "No detections on record.",
                   "A clean result does not mean the file is safe.", Confidence.MEDIUM,
                   "Report the sender and delete the file.",
                   severity=Severity.HIGH if mal >= 3 else Severity.MEDIUM if mal else Severity.INFO,
                   data=vt["data"])


HASH_RE = {"md5": re.compile(r"^[a-f0-9]{32}$"), "sha1": re.compile(r"^[a-f0-9]{40}$"),
           "sha256": re.compile(r"^[a-f0-9]{64}$")}


def analyze_hash(value: str) -> dict[str, Any]:
    v = (value or "").strip().lower()
    algo = next((k for k, r in HASH_RE.items() if r.match(v)), None)
    result: dict[str, Any] = {"kind": "hash", "input": value, "algorithm": algo, "findings": []}
    if not algo:
        result["error"] = "Not a valid MD5, SHA-1 or SHA-256 hex digest."
        return result
    vt = virustotal_file(v)
    result["reputation"] = vt
    if vt["configured"]:
        result["findings"] = [_vt_finding(vt, v, "hash").to_dict()]
    else:
        result["findings"] = [unknown("hash", "No hash reputation source configured", v,
                                      "VIRUSTOTAL_API_KEY is not set", "Set VIRUSTOTAL_API_KEY to enable lookups.")
                              .to_dict()]
    return result
