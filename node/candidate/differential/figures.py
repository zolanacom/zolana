#!/usr/bin/env python3
"""The figures decision 0043 quotes, computed from the logs of differential runs.

usage: figures.py LOG...

Prints, for each log, the counts the record states and a digest of the whole
tally, so that two runs can be compared line for line; then the sums over the
first two logs (the two runs against the pinned candidate) and over all logs.
The output holds no path, time or duration: the same runs give the same text
on any machine, which is what run.sh compares with expected-figures.txt.

Standard library only.
"""
import hashlib
import re
import sys
from pathlib import Path

KIND = re.compile(r"^\s*(\d+)  (NPOOL00[34]|other pool) \| feature (on|off) \| (.+) \| (\S+)$")
SEAL = re.compile(r"^\s*(\d+)  (left unchanged|recorded|refused \(.*\))$")
HEAD = re.compile(r"^(\d+) instructions gave the same result, the same account bytes and the same compute "
                  r"units left in the workspace build and the candidate build; (\d+) of them", re.MULTILINE)
RUN = re.compile(r"^seed (\d+), (\d+) walks of (\d+) steps$", re.MULTILINE)
SUMMED = ("instructions", "registered", "finalizations", "altered", "accepted_unaltered",
          "accepted_unaltered_npool004_on", "refused_npool004_off", "seals", "hardening_only")


def figures(path):
    text = Path(path).read_text()
    head, run = HEAD.search(text), RUN.search(text)
    if not head or not run:
        raise SystemExit(f"figures: {Path(path).name} is not the log of a finished run")
    out = {"run": f"seed {run.group(1)}, {run.group(2)} walks of {run.group(3)} steps",
           "instructions": int(head.group(1)), "registered": int(head.group(2)),
           "finalizations": 0, "altered": 0, "accepted_unaltered": 0,
           "accepted_unaltered_npool004_on": 0, "refused_npool004_off": 0, "seals": 0,
           "hardening_only": int(re.search(r"not compared: (\d+)", text).group(1))}
    tally = []
    for line in text.splitlines():
        kind = KIND.match(line)
        if kind:
            count, pool, gate, label, result = (int(kind.group(1)), kind.group(2), kind.group(3),
                                                kind.group(4), kind.group(5))
            tally.append(line.strip())
            # The harness derives every case below from a finalize instruction;
            # the last label is the inline opcode on the staged account list.
            if (label == "finalize" or label.startswith("finalize, ")
                    or label == "other opcode with the inline account list"):
                out["finalizations"] += count
                if label != "finalize":
                    out["altered"] += count
                elif result == "accepted":
                    out["accepted_unaltered"] += count
                    if pool == "NPOOL004" and gate == "on":
                        out["accepted_unaltered_npool004_on"] += count
                if label == "finalize" and pool == "NPOOL004" and gate == "off" and result == "InvalidAccountData":
                    out["refused_npool004_off"] += count
        seal = SEAL.match(line)
        if seal:
            tally.append(line.strip())
            out["seals"] += int(seal.group(1))
    if sum(int(line.split()[0]) for line in tally if KIND.match(line)) != out["instructions"]:
        raise SystemExit(f"figures: the tally of {Path(path).name} does not add up to its first line")
    out["tally_lines"] = len(tally)
    out["tally_sha256"] = hashlib.sha256("\n".join(tally).encode()).hexdigest()[:16]
    passed = re.search(r"^test result: ok\. 2 passed; 0 failed", text, re.MULTILINE)
    out["both_tests_passed"] = "yes" if passed else "NO"
    return out


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__.strip())
    rows = [(Path(path).name, figures(path)) for path in sys.argv[1:]]
    for name, row in rows:
        print(name)
        for key, value in row.items():
            print(f"    {key}: {value}")
    if len(rows) >= 2:
        print("first two logs together:")
        for key in SUMMED:
            print(f"    {key}: {sum(row[key] for _, row in rows[:2])}")
    print("all logs together:")
    for key in ("instructions", "registered", "seals", "hardening_only"):
        print(f"    {key}: {sum(row[key] for _, row in rows)}")


if __name__ == "__main__":
    main()
