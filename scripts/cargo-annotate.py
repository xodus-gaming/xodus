#!/usr/bin/env python3
"""Turn `cargo <cmd> --message-format=json` output into GitHub Actions
annotations (`::warning file=...,line=...::...`) with file/line attribution.

Usage:
    cargo check --workspace --message-format=json | scripts/cargo-annotate.py [label]

`label`, if given (e.g. a target triple), is prefixed to each annotation's
title so runs from different matrix legs stay distinguishable in the PR UI
instead of looking like unlabeled duplicates of each other.

Exits non-zero if any error-level diagnostics were seen, so it can be used
as the tail of a CI pipeline (with `set -o pipefail`) to still fail the job.
"""
import json
import sys

LEVEL_MAP = {
    "error": "error",
    "error: internal compiler error": "error",
    "warning": "warning",
    "note": "notice",
    "help": "notice",
}


def escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def primary_span(spans):
    for span in spans:
        if span.get("is_primary"):
            return span
    return spans[0] if spans else None


def main() -> int:
    label = sys.argv[1] if len(sys.argv) > 1 else None
    saw_error = False
    seen = set()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if record.get("reason") != "compiler-message":
            continue

        message = record["message"]
        level = message.get("level", "warning")
        gh_level = LEVEL_MAP.get(level)
        if gh_level is None:
            continue

        if level == "error":
            saw_error = True

        span = primary_span(message.get("spans", []))
        code = (message.get("code") or {}).get("code")
        title = code or "cargo"
        if label:
            title = f"{label}: {title}"
        text = (message.get("rendered") or message["message"]).rstrip("\n")

        dedup_key = (span and span.get("file_name"), span and span.get("line_start"), text)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        props = [f"title={escape_property(title)}"]
        if span is not None:
            props.append(f"file={escape_property(span['file_name'])}")
            props.append(f"line={span['line_start']}")
            props.append(f"endLine={span['line_end']}")
            props.append(f"col={span['column_start']}")
            props.append(f"endColumn={span['column_end']}")

        print(f"::{gh_level} {','.join(props)}::{escape_data(text)}")

    return 1 if saw_error else 0


if __name__ == "__main__":
    sys.exit(main())
