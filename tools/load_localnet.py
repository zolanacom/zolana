#!/usr/bin/env python3
"""Bounded concurrent payment acceptance; owns and stops its loopback validators."""
import argparse
import json
from pathlib import Path
import subprocess
import time

from localnet import PROJECT, LAB, load, port, quiet, rpc, start, stop, wait_rpc
from fault_localnet import durable


def run(root, count, baseline=False):
    children = [None, None]
    result = {"status": "running", "baseline": baseline, "bursts": []}
    try:
        subprocess.run([str(LAB), "init", str(root)], check=True, capture_output=True)
        result["genesis_hash"] = load(root)["genesis_hash"]
        for i in [0, 1]:
            children[i] = start(root, i)
            wait_rpc(root, i)
        quiet(root)
        for kind in (["deposit"] if baseline else ["deposit", "send"]):
            process = subprocess.run([str(LAB), "load", str(root), str(count), kind], capture_output=True, text=True, timeout=600)
            (root / f"load-{kind}.log").write_text(process.stdout + process.stderr)
            if process.returncode:
                raise RuntimeError(process.stderr)
            receipt = json.loads(process.stdout)
            result["bursts"].append(receipt)
            print({key: value for key, value in receipt.items() if key != "outcomes"}, flush=True)
            if not baseline and receipt["accepted"] != count:
                raise RuntimeError("not all distinct payments finalized")
            if baseline and (receipt["accepted"] != 16 or any("invalid instruction data" not in item.get("error", "") for item in receipt["outcomes"] if "error" in item)):
                raise RuntimeError("baseline did not isolate the 16-root anchor bound")
            if durable(root, 0) != durable(root, 1):
                raise RuntimeError("validators disagree on pool/nullifiers")
        if not baseline:
            expected = durable(root, 0)
            tip = max(rpc(port(i), "getSlot", [{"commitment": "processed"}]) for i in [0, 1])
            for i in [1, 0]:
                stop(root, i)
            for i in [0, 1]:
                children[i] = start(root, i, coordinated=True)
                wait_rpc(root, i)
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                roots = [rpc(port(i), "getSlot", [{"commitment": "finalized"}]) for i in [0, 1]]
                if min(roots) > tip + 8 and all(durable(root, i) == expected for i in [0, 1]):
                    result["coordinated_restart"] = {"tip": tip, "finalized_slots": roots, "exact_pool_and_nullifiers": True}
                    break
                time.sleep(0.4)
            else:
                raise RuntimeError("post-load restart did not finalize unchanged native state")
            audit = subprocess.run([str(LAB), "load", str(root), str(count), "audit"], capture_output=True, text=True, timeout=240)
            (root / "load-audit.log").write_text(audit.stdout + audit.stderr)
            if audit.returncode:
                raise RuntimeError(audit.stderr)
            result["multi_wallet_audit"] = json.loads(audit.stdout)
        result["status"] = "passed"
    except Exception as error:
        result.update(status="failed", error=str(error))
        raise
    finally:
        cleanup_errors = []
        for i in [0, 1]:
            if children[i] is not None and children[i].poll() is None:
                try:
                    stop(root, i)
                except Exception as error:
                    cleanup_errors.append(str(error))
        if cleanup_errors:
            result.update(status="failed", cleanup_errors=cleanup_errors)
        if root.exists():
            (root / "load-result.json").write_text(json.dumps(result, indent=2))
        if cleanup_errors:
            raise RuntimeError("owned validator cleanup failed; inspect load-result.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--clients", type=int, default=24)
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if PROJECT / ".data" not in root.parents or root.exists():
        raise SystemExit("use a new directory under .data")
    run(root, args.clients, args.baseline)
