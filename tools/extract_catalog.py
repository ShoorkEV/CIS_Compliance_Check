#!/usr/bin/env python3
"""Build catalog/controls.tsv from the benchmark text dump.

usage: pdftotext -enc UTF-8 -layout <benchmark.pdf> bench.txt
       python3 tools/parse.py bench.txt recs.json          (must report 350)
       python3 tools/extract_catalog.py recs.json catalog/controls.tsv

Titles, assessment type and the Server/Workstation levels come from the PDF's
"Profile Applicability" block (never from the section number). The check type,
params, applies_if and slow columns for the Level 1 - Server rows come from
tools/catalog_spec.py; every other row is written as status=todo.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from catalog_spec import S  # noqa: E402

COLS = ["id", "title", "assessment", "srv_level", "ws_level", "check_type",
        "params", "applies_if", "slow", "status"]


def level(profiles, kind):
    for p in profiles:
        m = re.match(r"Level (\d) - " + kind, p)
        if m:
            return m.group(1)
    return "-"


def main(recs_path, out_path):
    recs = json.load(open(recs_path, encoding="utf8"))
    if len(recs) != 350:
        sys.exit("expected 350 recommendations, got %d" % len(recs))
    rows = []
    for r in recs:
        m = re.match(r"^(.*?)\s*\((Automated|Manual)\)\s*$", r["title"])
        title, assess = (m.group(1), m.group(2)) if m else (r["title"], "Automated")
        srv, ws = level(r["profiles"], "Server"), level(r["profiles"], "Workstation")
        i = r["id"]
        if srv == "1":
            if i not in S:
                sys.exit("no spec for Level 1 - Server control %s" % i)
            t, params, applies, slow = S[i]
            if assess == "Manual" and t != "manual":
                sys.exit("%s is Manual in the PDF but spec says %s" % (i, t))
            status = "done"
        else:
            t, params, applies, slow, status = "-", "", "", 0, "todo"
        # "-" marks an empty field: read's tab splitting would collapse empty fields
        rows.append([i, title, assess, srv, ws, t, params or "-", applies or "-", str(slow), status])
    extra = set(S) - {r[0] for r in rows if r[3] == "1"}
    if extra:
        sys.exit("spec has IDs that are not Level 1 - Server: %s" % sorted(extra))

    def key(row):
        return [int(x) for x in row[0].split(".")]
    rows.sort(key=key)
    with open(out_path, "w", encoding="utf8", newline="\n") as f:
        f.write("\t".join(COLS) + "\n")
        for row in rows:
            for c in row:
                if "\t" in c:
                    sys.exit("tab in field: %r" % c)
            f.write("\t".join(row) + "\n")
    l1 = sum(1 for r in rows if r[3] == "1")
    print("wrote %d rows, %d Level 1 - Server" % (len(rows), l1))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
