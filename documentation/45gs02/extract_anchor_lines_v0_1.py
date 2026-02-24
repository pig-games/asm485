#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

PATTERNS = {
    "appendix_k": "45GS02 Microprocessor",
    "appendix_l": "45GS02 & 6502 Instruction Sets",
    "instruction_set_4510": "4510 INSTRUCTION SET",
    "opcode_table_4510_45gs02": "Opcode T able 4510/45GS02",
    "compound_instructions": "45GS02 COMPOUND INSTRUCTIONS",
}


def find_first_line_numbers(text: str) -> dict[str, int]:
    result: dict[str, int] = {}
    lines = text.splitlines()
    for key, needle in PATTERNS.items():
        for index, line in enumerate(lines, start=1):
            if needle in line:
                result[key] = index
                break
    return result


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    source = root / "documentation" / "_pdf_extract" / "mega65-book-2.txt"
    output = Path(__file__).with_name("anchor_lines_v0_1.json")

    text = source.read_text(encoding="utf-8", errors="replace")
    anchors = find_first_line_numbers(text)

    payload = {
        "source": str(source.relative_to(root)),
        "patterns": PATTERNS,
        "anchors": anchors,
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(str(output.relative_to(root)))


if __name__ == "__main__":
    main()
