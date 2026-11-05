"""Build the static GitHub Pages site into _site/.

The demo report is generated here by running the real NardTrace API against the bundled
synthetic demo email (offline, so lookups appear as UNKNOWN with their error). Nothing in
the published report is hand-written.

Usage:  python scripts/build_site.py [output_dir]
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "_site").resolve()

os.environ["NARDTRACE_OFFLINE"] = "1"
os.environ["NARDTRACE_DATA_DIR"] = tempfile.mkdtemp(prefix="nardtrace-site-")
sys.path.insert(0, str(ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from nardtrace.main import app  # noqa: E402
from nardtrace.reports import render_html  # noqa: E402

WEB_CSS = """<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  html { background: #f8fafc; }
  body { max-width: 920px; margin: 0 auto; padding: 24px 16px 64px; background: #fff; }
  .banner { font: 13px/1.5 system-ui, sans-serif; background: #e0f2fe; color: #075985;
            border: 1px solid #bae6fd; border-radius: 8px; padding: 10px 14px; margin-bottom: 20px; }
  .banner a { color: #0369a1; }
  table { display: block; overflow-x: auto; }
</style>"""

BANNER = ('<div class="banner">This is a real NardTrace report, generated automatically from a '
          '<b>synthetic</b> demo email (no real people or addresses). Lookups ran in offline mode, so '
          'registry and DNS checks show as UNKNOWN. That is how NardTrace reports a check it did not perform. '
          '<a href="../">← Back to NardTrace</a> · <a href="report.pdf">PDF</a> · '
          '<a href="report.md">Markdown</a></div>')


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    shutil.copytree(ROOT / "site", OUT)
    shutil.copytree(ROOT / "docs" / "screenshots", OUT / "screenshots")
    shutil.copy(ROOT / "frontend" / "public" / "favicon.svg", OUT / "favicon.svg")
    demo = OUT / "demo"
    demo.mkdir()

    with TestClient(app) as client:
        case = client.post("/api/demo/seed")
        case.raise_for_status()
        cid = case.json()["id"]
        md = client.get(f"/api/cases/{cid}/report.md", params={"redact": "true"})
        pdf = client.get(f"/api/cases/{cid}/report.pdf", params={"redact": "true"})
        mail = client.get(f"/api/cases/{cid}/abuse-email", params={"redact": "true"})
        for r in (md, pdf, mail):
            r.raise_for_status()

    (demo / "report.md").write_text(md.text, encoding="utf-8")
    (demo / "report.pdf").write_bytes(pdf.content)
    html = render_html(md.text).replace("<head>", "<head><title>NardTrace demo report</title>" + WEB_CSS, 1)
    html = html.replace("<body>", "<body>" + BANNER, 1)
    (demo / "index.html").write_text(html, encoding="utf-8")
    m = mail.json()
    (demo / "abuse-email.txt").write_text(
        f"To: {', '.join(m['to']) or '(no abuse contact found in offline mode)'}\nSubject: {m['subject']}\n\n{m['body']}\n",
        encoding="utf-8")
    (OUT / ".nojekyll").write_text("")
    print(f"Site built in {OUT}")


if __name__ == "__main__":
    main()
