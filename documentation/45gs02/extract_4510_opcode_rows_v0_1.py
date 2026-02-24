#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
from pathlib import Path

ENTRY_BC = re.compile(r"^(\d+)\s+([0-9][0-9a-z]*)$")
ENTRY_MODE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


def is_mnemonic(text: str) -> bool:
    compact = text.replace(" ", "")
    return compact.isalpha() and compact.upper() == compact


def extract_rows(lines: list[str], start: int, end: int) -> list[tuple[int, str, str, str, str]]:
    rows: list[tuple[int, str, str, str, str]] = []
    i = start
    while i + 3 <= end:
        bc = lines[i].strip()
        m = lines[i + 1].strip()
        mode = lines[i + 2].strip()
        match = ENTRY_BC.fullmatch(bc)

        if (
            match is not None
            and is_mnemonic(m)
            and ENTRY_MODE.fullmatch(mode)
        ):
            b, c = match.groups()
            rows.append((i + 1, b, c, m.replace(" ", ""), mode))
            i += 3
            continue

        i += 1

    return rows


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    source = root / "documentation" / "_pdf_extract" / "mega65-book-2.txt"
    output = Path(__file__).with_name("opcode_table_4510_45gs02_raw_v0_1.csv")

    text = source.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    start_line = 25012
    end_line = 27744
    rows = extract_rows(lines, start_line - 1, end_line - 1)

    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source_line", "bytes", "cycles", "mnemonic", "address_mode_key"])
        writer.writerows(rows)

    print(f"{output.relative_to(root)} rows={len(rows)}")


if __name__ == "__main__":
    main()
