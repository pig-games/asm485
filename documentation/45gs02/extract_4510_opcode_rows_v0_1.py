#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
from pathlib import Path

ENTRY_BC = re.compile(r"^(\d+)\s+([0-9][0-9a-z]*)$")
ENTRY_MODE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
ROW_MARKER = re.compile(r"^\$([0-9A-Fa-f])x$")
COLUMN_SET = re.compile(r"^\$x([0-9A-Fa-f])(?:\s+\$x([0-9A-Fa-f]))+")


def is_mnemonic(text: str) -> bool:
    compact = text.replace(" ", "")
    return compact.isalpha() and compact.upper() == compact


def parse_column_line(line: str) -> list[int]:
    tokens = line.split()
    columns: list[int] = []
    for token in tokens:
        if token.startswith("$x") and len(token) == 3:
            columns.append(int(token[2], 16))
    return columns


def extract_rows(lines: list[str], start: int, end: int) -> list[tuple[int, str, str, str, str, str]]:
    rows: list[tuple[int, str, str, str, str, str]] = []
    i = start
    active_columns: list[int] = []
    active_row: int | None = None
    column_index = 0

    while i + 3 <= end:
        line = lines[i].strip()
        if COLUMN_SET.match(line):
            active_columns = parse_column_line(line)
            column_index = 0
            i += 1
            continue

        row_match = ROW_MARKER.fullmatch(line)
        if row_match:
            active_row = int(row_match.group(1), 16)
            column_index = 0
            i += 1
            continue

        bc = lines[i].strip()
        m = lines[i + 1].strip()
        mode = lines[i + 2].strip()
        match = ENTRY_BC.fullmatch(bc)

        if (
            match is not None
            and is_mnemonic(m)
            and ENTRY_MODE.fullmatch(mode)
            and active_row is not None
            and active_columns
            and column_index < len(active_columns)
        ):
            b, c = match.groups()
            opcode = (active_row << 4) | active_columns[column_index]
            rows.append((i + 1, f"{opcode:02X}", b, c, m.replace(" ", ""), mode))
            column_index += 1
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
        writer.writerow(
            [
                "source_line",
                "opcode_hex",
                "bytes",
                "cycles",
                "mnemonic",
                "address_mode_key",
            ]
        )
        writer.writerows(rows)

    print(f"{output.relative_to(root)} rows={len(rows)}")


if __name__ == "__main__":
    main()
