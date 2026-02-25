"""Extract text from PDF files into a workspace-friendly format.

Default behavior:
- Writes extracted text to: documentation/_pdf_extract/<pdf-stem>.txt
- Uses `pypdf` (pure-Python) so it works without external tools.

Optional:
- If `pdftotext` (Poppler) is installed, it can be used with --pdftotext.

Examples:
  /Users/erik/Code/Retro/opForge/.venv/bin/python scripts/pdf_extract.py \
    documentation/opForge-reference-manual.pdf

  /Users/erik/Code/Retro/opForge/.venv/bin/python scripts/pdf_extract.py \
    --output-dir documentation/_pdf_extract \
    --pdftotext \
    documentation/opForge-reference-manual.pdf
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def _extract_with_pdftotext(pdf_path: Path, out_path: Path) -> None:
    pdftotext = shutil.which("pdftotext")
    if not pdftotext:
        raise RuntimeError("pdftotext not found on PATH")

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # -layout preserves column-ish formatting for manuals.
    subprocess.run(
        [pdftotext, "-layout", str(pdf_path), str(out_path)],
        check=True,
    )


def _extract_with_pypdf(pdf_path: Path, out_path: Path) -> None:
    try:
        from pypdf import PdfReader  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "Missing dependency: pypdf. Install with: pip install pypdf"
        ) from exc

    reader = PdfReader(str(pdf_path))

    out_path.parent.mkdir(parents=True, exist_ok=True)

    chunks: list[str] = []
    for page_number, page in enumerate(reader.pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception as exc:  # pragma: no cover
            text = f"[extract_text failed: {exc!r}]"

        chunks.append(f"\n\n===== Page {page_number} =====\n\n")
        chunks.append(text)

    out_path.write_text("".join(chunks), encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Extract text from PDF(s) into documentation/_pdf_extract/ for reference.",
    )
    parser.add_argument(
        "pdfs",
        nargs="+",
        type=Path,
        help="One or more PDF paths (relative to repo root or absolute).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("documentation/_pdf_extract"),
        help="Directory to write extracted text files (default: documentation/_pdf_extract).",
    )
    parser.add_argument(
        "--pdftotext",
        action="store_true",
        help="Prefer Poppler's pdftotext if available (fallback to pypdf).",
    )

    args = parser.parse_args(argv)

    output_dir: Path = args.output_dir

    failures: list[str] = []

    for pdf in args.pdfs:
        pdf_path = pdf
        if not pdf_path.is_absolute():
            pdf_path = Path.cwd() / pdf_path

        if not pdf_path.exists():
            failures.append(f"Not found: {pdf}")
            continue

        out_path = output_dir / f"{pdf_path.stem}.txt"

        try:
            if args.pdftotext:
                try:
                    _extract_with_pdftotext(pdf_path, out_path)
                except Exception:
                    _extract_with_pypdf(pdf_path, out_path)
            else:
                _extract_with_pypdf(pdf_path, out_path)

            rel_out = out_path
            if not rel_out.is_absolute():
                rel_out = (Path.cwd() / rel_out).resolve()
            print(f"OK: {pdf} -> {out_path}")
        except Exception as exc:
            failures.append(f"Failed: {pdf} ({exc})")

    if failures:
        for line in failures:
            print(line, file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
