#!/usr/bin/env python3
"""Show that the differential run fails when one build differs.

usage: negative_controls.py SCRATCH

First the unchanged assembly must pass. Then, for each control, the scratch
workspace SCRATCH/controls is assembled afresh, one textual change is made to
one assembled build, and the run (seed 1, 3 walks, and the fixed edge cases)
must compile and fail in the comparison test. The repository's own files are
never changed: only the copies under SCRATCH are.

Standard library only. run.sh calls this as `run.sh controls`.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

# (what the change is, assembled file, text that occurs once, replacement)
CONTROLS = (
    ("the workspace copy asks for the roots of the next slot",
     "workspace-program/src/processor/finalization.rs",
     ".accepted_roots(slot)", ".accepted_roots(slot + 1)"),
    ("the candidate copy answers an inactive feature with another error",
     "candidate-program/src/processor.rs",
     "!differential_gate::slot_anchors() {\n            return Err(Error::InvalidAccountData);",
     "!differential_gate::slot_anchors() {\n            return Err(Error::InvalidInstructionData);"),
    ("the candidate copy has no feature check",
     "candidate-program/src/processor.rs",
     "        if state.uses_slot_anchors() && !differential_gate::slot_anchors() {\n"
     "            return Err(Error::InvalidAccountData);\n        }\n", ""),
    ("the binding file charges one compute unit more",
     "workspace-program/src/processor/runtime_features.rs",
     "    context.consume_checked(units)\n", "    context.consume_checked(units + 1)\n"),
    ("the binding file reports the charge as paid when it was not",
     "workspace-program/src/processor/runtime_features.rs",
     "    context.consume_checked(units)\n", "    let _ = context.consume_checked(units);\n    Ok(())\n"),
    ("the binding file invokes for a marker without the program's signature",
     "workspace-program/src/processor/runtime_features.rs",
     "    context.native_invoke(instruction, &[*marker])\n", "    context.native_invoke(instruction, &[])\n"),
    ("the binding file drops an unsigned invocation",
     "workspace-program/src/processor/runtime_features.rs",
     "    context.native_invoke(instruction, &[])\n", "    let _ = instruction;\n    Ok(())\n"),
)


def assemble(workspace):
    result = subprocess.run(
        [sys.executable, "-B", str(HERE / "assemble.py"), "--out", str(workspace)],
        capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SystemExit("assemble failed: " + result.stdout + result.stderr)


def run(scratch, workspace):
    environment = dict(os.environ, DIFFERENTIAL_SEED="1", DIFFERENTIAL_WALKS="3")
    result = subprocess.run(
        ["sh", str(ROOT / "tools/dev.sh"), "test", "--offline",
         "--manifest-path", str(workspace / "Cargo.toml"), "--target-dir", str(scratch / "build"),
         "-p", "program-differential", "--test", "differential", "--", "--nocapture"],
        capture_output=True, text=True, check=False, env=environment)
    return result.returncode, result.stdout + result.stderr


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__.strip())
    scratch = Path(sys.argv[1]).resolve()
    workspace = scratch / "controls"
    assemble(workspace)
    code, output = run(scratch, workspace)
    summary = re.search(r"test result: [^;]*; [^;]*;", output)
    if code != 0 or "test result: ok. 2 passed; 0 failed;" not in output:
        raise SystemExit("the unchanged assembly does not pass, so the controls would show nothing:\n"
                         + output[-2000:])
    print(f"unchanged assembly: {summary.group(0)}", flush=True)
    survivors = 0
    for label, name, old, new in CONTROLS:
        assemble(workspace)
        path = workspace / name
        text = path.read_text()
        if text.count(old) != 1:
            raise SystemExit(f"control '{label}': the text to change occurs {text.count(old)} times in {name}")
        path.write_text(text.replace(old, new))
        code, output = run(scratch, workspace)
        compiled = "error: could not compile" not in output
        failed = re.search(r"^test every_build_decides_alike \.\.\. FAILED$", output, re.MULTILINE)
        panic = re.search(r"assertion `left == right` failed: ([^\n]*)", output)
        summary = re.search(r"test result: [^;]*; [^;]*;", output)
        caught = code != 0 and compiled and bool(failed)
        survivors += not caught
        state = "detected" if caught else ("DID NOT COMPILE" if not compiled else "NOT DETECTED")
        print(f"{state}: {label}\n    {name}: {old!r} -> {new!r}\n"
              f"    first difference reported: {panic.group(1) if panic else 'none'}\n"
              f"    {summary.group(0) if summary else '(no result line)'}", flush=True)
    # Leave the scratch workspace as assembled, without the last change.
    assemble(workspace)
    print(f"{len(CONTROLS) - survivors} of {len(CONTROLS)} deliberate differences detected")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
