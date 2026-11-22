"""Protocol copy guard: disposable patch chains with real Git apply, then the repository itself."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import protocol_copy_guard as guard
import reconstruct_native_candidate as candidate

# Reviewed on 2026-11-21 against the patch chain through LOCAL-098-r3. Each
# entry is (unmatched candidate lines, unmatched workspace lines, class).
# Entries may be removed and counts may fall as the copies converge. Adding an
# entry, raising a count or raising a class records a new divergence between
# the code the checks test and the code the validator runs: it needs a new
# review of that difference, not only an edit here.
#
# state.rs was (7, 186, "refactor") in that review. It was raised when the
# workspace copy gained two pool-state rules that the plan's copy does not
# have. The proposed patch below carries the same rules for the candidate; with
# it applied the two files differ in 7 and 186 lines again.
#
# The two program files were (10, 7, "behaviour") and (287, 25, "behaviour")
# in that review. They were reviewed again when the workspace program gained
# the slot-anchor rule and its binding file (decision 0043). Their class fell,
# because the rule is now the same in both programs. Three counts rose,
# because the workspace text names the functions of its binding file where the
# candidate copy names its runtime's interfaces. The difference in behaviour
# that remains is in the binding file, which was added below with two test
# files; finalization.rs fell from "behaviour" to "refactor".
REVIEWED_DIFFERENCES = {
    "node/adapter/src/lib.rs": (5, 8, "refactor"),
    "node/adapter/src/nullifiers.rs": (10, 3, "refactor"),
    "node/adapter/src/processor.rs": (293, 45, "refactor"),
    "node/adapter/src/staging.rs": (80, 18, "refactor"),
    "protocol/payments/src/envelope.rs": (0, 1, "refactor"),
    "protocol/payments/src/lib.rs": (0, 1, "refactor"),
    "protocol/payments/src/state.rs": (11, 283, "behaviour"),
    "protocol/payments/src/wire.rs": (5, 11, "refactor"),
}
REVIEWED_WORKSPACE_ONLY = {
    "node/adapter/src/processor/finalization.rs": "refactor",
    "node/adapter/src/processor/runtime_features.rs": "behaviour",
    "node/adapter/src/processor/runtime_features_tests.rs": "refactor",
    "node/adapter/src/processor/slot_anchor_tests.rs": "refactor",
    "protocol/payments/src/native_accounts.rs": "refactor",
}
REVIEWED_CANDIDATE_ONLY = {}
# Patches outside the reconstruction plan that may change a copy, by SHA-256.
# Removing one passes. Adding one, or changing its bytes, fails until it is
# reviewed and this entry is edited as well.
REVIEWED_PROPOSED_PATCHES = {
    "node/candidate/drafts/pool-state-hardening/agave-4.3.2-pool-state-hardening.patch":
        "c9e832dddd3ab1d7d816cac3f6a83433180f09b832fb86a41cf7af6a7344029e",
}
IDENTICAL_TODAY = [
    "node/adapter/src/instructions.rs",
    "protocol/payments/src/anchors.rs",
    "protocol/payments/src/staging.rs",
    "protocol/payments/src/verification.rs",
]
REVIEW = "Reviewed difference used by this fixture only."


def checksum(raw):
    return hashlib.sha256(raw).hexdigest()


def state(raw):
    return None if raw is None else {"bytes": len(raw), "sha256": checksum(raw)}


def added(name, text):
    lines = text.splitlines()
    return (f"diff --git a/{name} b/{name}\nnew file mode 100644\n--- /dev/null\n+++ b/{name}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{line}\n" for line in lines))


def replaced(name, before, after):
    return (f"diff --git a/{name} b/{name}\n--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n"
            f"-{before}\n+{after}\n")


MANIFEST = '[package]\nname = "copy"\n\n[dependencies]\norchard = "=0.16.0"\n'
STATE = "pub fn root() {}\npub fn encode() {}\n"
WIRE_BASE = "const MAGIC: u8 = 1;\n"
WIRE_PATCHED = "const MAGIC: u8 = 2;\n"
WIRE_WORKSPACE = "pub const MAGIC: u8 = 2;\n"
PROCESSOR = "pub fn process() {}\n"
DEEP = "pub fn finalize() {}\n"


class GuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name) / "repository"
        self.artifacts = self.repository / "node/candidate"
        self.artifacts.mkdir(parents=True)
        for module in (guard, candidate):
            replacement = patch.object(module, "ROOT", self.repository)
            replacement.start()
            self.addCleanup(replacement.stop)
        self.workspace("Cargo.toml", '[workspace.dependencies]\norchard = { version = "=0.16.0" }\n')
        self.workspace("protocol/payments/src/state.rs", STATE)
        self.workspace("protocol/payments/src/wire.rs", WIRE_WORKSPACE)
        self.workspace("node/adapter/src/processor.rs", PROCESSOR)
        self.workspace("node/adapter/src/processor/deep.rs", DEEP)
        self.plan_path = self.artifacts / "plan.json"
        self.allowlist_path = self.repository / "allowlist.json"
        self.write_chain()
        self.allowlist = {
            "format": guard.FORMAT,
            "plan_sha256": checksum(self.plan_path.read_bytes()),
            "differences": {"protocol/payments/src/wire.rs": {
                "candidate_sha256": checksum(WIRE_PATCHED.encode()),
                "workspace_sha256": checksum(WIRE_WORKSPACE.encode()),
                "unmatched_lines": {"candidate": 1, "workspace": 1},
                "class": "refactor", "review": REVIEW}},
            "workspace_only": {},
            "candidate_only": {},
            "proposed_patches": {},
        }

    def workspace(self, name, text):
        path = self.repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def artifact(self, name, raw):
        path = self.artifacts / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return {"path": path.relative_to(self.repository).as_posix(), "sha256": checksum(raw)}

    def write_chain(self, wire_after=WIRE_PATCHED, extra_base="", manifest=MANIFEST):
        """A base patch that adds both copies, then one step that edits a copy."""
        base = (added("zolana-native/protocol/Cargo.toml", manifest)
                + added("zolana-native/protocol/src/state.rs", STATE)
                + added("zolana-native/protocol/src/wire.rs", WIRE_BASE)
                + added("zolana-native/adapter/Cargo.toml", manifest)
                + added("zolana-native/adapter/src/processor.rs", PROCESSOR)
                + added("zolana-native/adapter/src/processor/deep.rs", DEEP)
                # Files outside the copies never reach the scratch tree.
                + replaced("runtime/src/bank.rs", "upstream", "patched")
                + extra_base).encode()
        step = (replaced("zolana-native/protocol/src/wire.rs", WIRE_BASE.strip(), wire_after.strip())
                + replaced("runtime/src/bank.rs", "patched", "again")).encode()
        manifest_json = json.dumps({"files": {
            "zolana-native/protocol/src/wire.rs": {
                "before": state(WIRE_BASE.encode()), "after": state(wire_after.encode())},
            "runtime/src/bank.rs": {"before": state(b"patched\n"), "after": state(b"again\n")},
        }}).encode()
        plan = {
            "format": candidate.FORMAT,
            "upstream_commit": candidate.source_tools.UPSTREAM_COMMIT,
            "archive_sha256": "0" * 64,
            "base_patch": self.artifact("base.patch", base),
            "steps": [{"revision": "first",
                       "manifest": self.artifact("first.json", manifest_json),
                       "patch": self.artifact("first.patch", step)}],
        }
        self.plan_path.write_text(json.dumps(plan))
        return checksum(self.plan_path.read_bytes())

    def run_check(self):
        self.allowlist_path.write_text(json.dumps(self.allowlist))
        return guard.check(self.allowlist_path, self.plan_path)

    def problems(self):
        return "\n".join(self.run_check()[1])

    def test_identical_copies_and_a_recorded_difference_pass(self):
        result, problems = self.run_check()
        self.assertEqual(problems, [])
        self.assertEqual(result["identical"], [
            "node/adapter/src/processor.rs", "node/adapter/src/processor/deep.rs",
            "protocol/payments/src/state.rs"])
        self.assertEqual(result["recorded_differences"], ["protocol/payments/src/wire.rs"])
        self.assertEqual(result["behaviour_differences"], [])
        self.assertEqual(result["revisions"], ["first"])

    def test_candidate_copy_is_the_state_after_the_whole_chain(self):
        plan = candidate.load_plan(self.plan_path, self.allowlist["plan_sha256"])
        copies = guard.candidate_copies(plan)
        self.assertEqual(copies["zolana-native/protocol/src/wire.rs"], WIRE_PATCHED.encode())
        self.assertEqual(sorted(copies), [
            "zolana-native/adapter/src/processor.rs", "zolana-native/adapter/src/processor/deep.rs",
            "zolana-native/protocol/src/state.rs", "zolana-native/protocol/src/wire.rs"])

    def test_workspace_edit_to_an_identical_file_fails(self):
        self.workspace("protocol/payments/src/state.rs", STATE + "pub fn complete_slot() {}\n")
        self.assertIn("state.rs: the workspace and the candidate series differ", self.problems())

    def test_workspace_edit_to_a_recorded_difference_fails(self):
        self.workspace("protocol/payments/src/wire.rs", WIRE_WORKSPACE + "pub const EXTRA: u8 = 3;\n")
        problems = self.problems()
        self.assertIn("wire.rs: the workspace copy changed since the difference was reviewed", problems)
        self.assertIn("wire.rs: recorded line counts do not describe the files", problems)

    def test_candidate_edit_to_a_recorded_difference_fails(self):
        self.allowlist["plan_sha256"] = self.write_chain(wire_after="const MAGIC: u8 = 9;\n")
        self.assertIn("wire.rs: the candidate copy changed since the difference was reviewed",
                      self.problems())

    def test_candidate_edit_to_an_identical_file_fails(self):
        self.allowlist["plan_sha256"] = self.write_chain(
            extra_base=added("zolana-native/adapter/src/staging.rs", "pub struct Buffer;\n"))
        self.workspace("node/adapter/src/staging.rs", "pub struct Buffer(u8);\n")
        self.assertIn("staging.rs: the workspace and the candidate series differ", self.problems())

    def test_a_changed_plan_is_refused_until_the_allowlist_names_it(self):
        self.write_chain(wire_after="const MAGIC: u8 = 9;\n")
        with self.assertRaisesRegex(ValueError, "reconstruction plan hash mismatch"):
            self.run_check()

    def test_converged_file_must_leave_the_allowlist(self):
        self.workspace("protocol/payments/src/wire.rs", WIRE_PATCHED)
        self.assertIn("wire.rs: the copies are identical now. Delete its allow-list entry",
                      self.problems())
        del self.allowlist["differences"]["protocol/payments/src/wire.rs"]
        result, problems = self.run_check()
        self.assertEqual(problems, [])
        self.assertIn("protocol/payments/src/wire.rs", result["identical"])

    def test_one_sided_files_need_a_record_pinned_to_their_bytes(self):
        self.workspace("protocol/payments/src/native_accounts.rs", "pub const ID: u8 = 1;\n")
        self.allowlist["plan_sha256"] = self.write_chain(
            extra_base=added("zolana-native/adapter/src/harness.rs", "fn smoke() {}\n"))
        problems = self.problems()
        self.assertIn("native_accounts.rs: exists only in the workspace and is not recorded", problems)
        self.assertIn("harness.rs: exists only in the candidate series and is not recorded", problems)
        self.allowlist["workspace_only"]["protocol/payments/src/native_accounts.rs"] = {
            "workspace_sha256": checksum(b"pub const ID: u8 = 1;\n"),
            "class": "refactor", "review": REVIEW}
        self.allowlist["candidate_only"]["node/adapter/src/harness.rs"] = {
            "candidate_sha256": checksum(b"fn smoke() {}\n"), "class": "refactor", "review": REVIEW}
        result, problems = self.run_check()
        self.assertEqual(problems, [])
        self.assertEqual(result["recorded_workspace_only"], ["protocol/payments/src/native_accounts.rs"])
        self.assertEqual(result["recorded_candidate_only"], ["node/adapter/src/harness.rs"])
        self.workspace("protocol/payments/src/native_accounts.rs", "pub const ID: u8 = 2;\n")
        self.assertIn("native_accounts.rs: workspace-only file changed since it was reviewed",
                      self.problems())

    def test_entries_for_absent_or_two_sided_files_fail(self):
        entry = {"workspace_sha256": checksum(STATE.encode()), "class": "refactor", "review": REVIEW}
        self.allowlist["workspace_only"]["protocol/payments/src/gone.rs"] = entry
        self.allowlist["workspace_only"]["protocol/payments/src/state.rs"] = entry
        problems = self.problems()
        self.assertIn("gone.rs: allow-list entry for a file that no longer exists", problems)
        self.assertIn("state.rs: recorded as workspace-only but the candidate series has it now", problems)

    def test_patch_outside_the_plan_that_touches_a_copy_fails(self):
        self.artifact("drafts/next/unplanned.patch", replaced(
            "zolana-native/protocol/src/state.rs", "pub fn root() {}", "pub fn root() { todo!() }").encode())
        self.artifact("drafts/next/elsewhere.patch", replaced(
            "ledger/src/blockstore_db.rs", "old", "new").encode())
        problems = self.problems()
        self.assertIn("node/candidate/drafts/next/unplanned.patch: a patch outside the "
                      "reconstruction plan changes a protocol copy", problems)
        self.assertNotIn("elsewhere.patch", problems)

    def test_recorded_proposal_passes_until_it_changes_or_stops_being_one(self):
        name = "node/candidate/drafts/next/proposed.patch"
        raw = replaced("zolana-native/protocol/src/state.rs", "pub fn root() {}", "pub fn root() { todo!() }").encode()
        self.artifact("drafts/next/proposed.patch", raw)
        self.allowlist["proposed_patches"][name] = {"sha256": checksum(raw), "review": REVIEW}
        result, problems = self.run_check()
        self.assertEqual(problems, [])
        self.assertEqual(result["recorded_proposed_patches"], [name])
        # A proposal is not applied: the plan's copy is still the one compared.
        self.assertIn("protocol/payments/src/state.rs", result["identical"])
        # A second, unrecorded patch is not covered by the record of the first.
        self.artifact("drafts/next/other.patch", replaced(
            "zolana-native/adapter/src/processor.rs", "pub fn process() {}", "pub fn process() { todo!() }").encode())
        self.assertIn("other.patch: a patch outside the reconstruction plan changes a protocol copy",
                      self.problems())
        (self.artifacts / "drafts/next/other.patch").unlink()
        self.artifact("drafts/next/proposed.patch", raw + b"\n")
        self.assertIn("proposed.patch: the proposed patch changed since it was reviewed", self.problems())
        self.artifact("drafts/next/proposed.patch", replaced("ledger/src/blockstore_db.rs", "old", "new").encode())
        self.assertIn("proposed.patch: allow-list entry for a proposed patch that is gone, has joined the "
                      "plan or no longer changes a copy", self.problems())
        (self.artifacts / "drafts/next/proposed.patch").unlink()
        self.assertIn("proposed.patch: allow-list entry for a proposed patch that is gone", self.problems())

    def test_proof_system_release_must_be_the_same_exact_pin(self):
        self.allowlist["plan_sha256"] = self.write_chain(
            manifest=MANIFEST.replace("=0.16.0", "=0.17.0"))
        problems = self.problems()
        self.assertIn("zolana-native/protocol/Cargo.toml: requires orchard '=0.17.0'; "
                      "the workspace requires '=0.16.0'", problems)
        self.assertIn("zolana-native/adapter/Cargo.toml: requires orchard", problems)
        self.allowlist["plan_sha256"] = self.write_chain()
        self.workspace("Cargo.toml", '[workspace.dependencies]\norchard = "0.16"\n')
        self.assertIn("does not pin orchard to one exact release", self.problems())

    def test_allowlist_shape_is_strict(self):
        entry = self.allowlist["differences"]["protocol/payments/src/wire.rs"]
        for field, value, message in (
                ("class", "harmless", "unknown class"),
                ("review", "ok", "needs a written review"),
                ("workspace_sha256", "abc", "invalid hash"),
                ("unmatched_lines", {"candidate": -1, "workspace": 1}, "invalid line counts")):
            with self.subTest(field=field), patch.dict(entry, {field: value}):
                with self.assertRaisesRegex(ValueError, message):
                    self.run_check()
        with patch.dict(entry, {"note": "extra"}):
            with self.assertRaisesRegex(ValueError, "must have exactly"):
                self.run_check()
        with patch.dict(self.allowlist, {"format": "other"}):
            with self.assertRaisesRegex(ValueError, "invalid protocol copy allow-list"):
                self.run_check()
        name = "node/candidate/drafts/next/proposed.patch"
        for proposal, message in (
                ({"sha256": "abc", "review": REVIEW}, "invalid hash"),
                ({"sha256": "0" * 64, "review": "ok"}, "needs a written review"),
                ({"sha256": "0" * 64, "review": REVIEW, "note": "extra"}, "must have exactly"),
                ({"sha256": "0" * 64}, "must have exactly")):
            with self.subTest(proposal=proposal), patch.dict(self.allowlist["proposed_patches"], {name: proposal}):
                with self.assertRaisesRegex(ValueError, message):
                    self.run_check()
        with patch.dict(self.allowlist, {"proposed_patches": []}):
            with self.assertRaisesRegex(ValueError, "proposed_patches must be an object"):
                self.run_check()

    def test_unmatched_lines_ignore_order_and_count_repeats(self):
        self.assertEqual(guard.unmatched_lines(b"a\nb\nc\n", b"c\na\nb\n"),
                         {"candidate": 0, "workspace": 0})
        self.assertEqual(guard.unmatched_lines(b"a\na\nb\n", b"a\nd\n"),
                         {"candidate": 2, "workspace": 1})


class RepositoryTests(unittest.TestCase):
    """The retained patch chain against the workspace crates of this checkout."""

    def test_repository_copies_match_the_reviewed_allowlist(self):
        result, problems = guard.check()
        self.assertEqual(problems, [])
        self.assertEqual(result["identical"], IDENTICAL_TODAY)
        self.assertEqual(result["recorded_differences"], sorted(REVIEWED_DIFFERENCES))
        self.assertEqual(result["recorded_workspace_only"], sorted(REVIEWED_WORKSPACE_ONLY))
        self.assertEqual(result["recorded_candidate_only"], sorted(REVIEWED_CANDIDATE_ONLY))
        self.assertEqual(result["recorded_proposed_patches"], sorted(REVIEWED_PROPOSED_PATCHES))

    def test_allowlist_stays_within_the_reviewed_ceiling(self):
        allowlist = guard.load_allowlist(guard.DEFAULT_ALLOWLIST)
        rank = guard.CLASSES.index
        self.assertLessEqual(set(allowlist["differences"]), set(REVIEWED_DIFFERENCES))
        for name, entry in allowlist["differences"].items():
            ours, theirs, reviewed_class = REVIEWED_DIFFERENCES[name]
            with self.subTest(name=name):
                self.assertLessEqual(entry["unmatched_lines"]["candidate"], ours)
                self.assertLessEqual(entry["unmatched_lines"]["workspace"], theirs)
                self.assertLessEqual(rank(entry["class"]), rank(reviewed_class))
        for section, reviewed in (("workspace_only", REVIEWED_WORKSPACE_ONLY),
                                  ("candidate_only", REVIEWED_CANDIDATE_ONLY)):
            self.assertLessEqual(set(allowlist[section]), set(reviewed))
            for name, entry in allowlist[section].items():
                with self.subTest(name=name):
                    self.assertLessEqual(rank(entry["class"]), rank(reviewed[name]))
        for name, entry in allowlist["proposed_patches"].items():
            with self.subTest(name=name):
                self.assertEqual(entry["sha256"], REVIEWED_PROPOSED_PATCHES.get(name))

    def test_every_candidate_patch_is_either_planned_or_leaves_the_copies_alone(self):
        allowlist = guard.load_allowlist(guard.DEFAULT_ALLOWLIST)
        plan = candidate.load_plan(candidate.DEFAULT_PLAN, allowlist["plan_sha256"])
        self.assertLessEqual(guard.unplanned_patches(plan).items(), REVIEWED_PROPOSED_PATCHES.items())
        # Only the base patch creates the copies; no later revision edits them.
        touching = [step.revision for step in plan.transitions
                    if any(guard.candidate_root_of(name) for name in step.files)]
        self.assertEqual(touching, [])


if __name__ == "__main__":
    unittest.main()
