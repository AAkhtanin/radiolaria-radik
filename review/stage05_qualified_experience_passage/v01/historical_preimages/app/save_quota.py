"""Persistent single-dispatch grant for the controlled first live exam.

The trusted runner fixes the ledger directory across runs and routes every exam
SAVE through save(). A model has no access to this adapter, ledger, or callbacks.
Native E pending packets do not call this adapter and do not consume its quota.
The existing five-field native effect policy and effect callbacks are unchanged.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

VERSION = "radik.single_save_quota.v01"
MAX_LEDGER_BYTES = 65536
GRANT_KEYS = {"version", "kind", "handoff_path", "handoff_sha256", "caller_id", "root_id", "task_id",
    "result_id", "result_sha256", "content_sha256", "root_decision_id", "root_binding_sha256", "sources",
    "source_scope_sha256", "policy_revision", "consent_ref", "valid_to", "target", "output_directory"}
HASH_KEYS = ("handoff_sha256", "result_sha256", "content_sha256", "root_binding_sha256", "source_scope_sha256")
CONTEXT_KEYS = GRANT_KEYS - {"version", "kind", "target"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if type(value) is bytes else canonical(value)).hexdigest()


def _owned_directory(directory):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink() and directory.absolute() == directory.resolve(strict=True),
        "quota_owned_directory")
    return directory


def _validate_grant(grant):
    require(type(grant) is dict and set(grant) == GRANT_KEYS and grant["version"] == VERSION, "quota_grant_shape")
    require(grant["kind"] in ("NATIVE_DOCUMENT_DELTA", "SIMULATED_QUOTA_ONLY", "TARGETED_NATIVE_EFFECT_SEAM"), "quota_grant_kind")
    require(all(type(grant[k]) is str and re.fullmatch(r"[0-9a-f]{64}", grant[k]) for k in HASH_KEYS), "quota_grant_hash")
    require(all(type(grant[k]) is str and 0 < len(grant[k]) <= 256 for k in
        ("handoff_path", "caller_id", "root_id", "task_id", "result_id", "root_decision_id", "consent_ref")), "quota_grant_identity")
    require(type(grant["policy_revision"]) is int and grant["policy_revision"] >= 1 and type(grant["valid_to"]) is int,
        "quota_grant_policy")
    require(type(grant["sources"]) is list and len(grant["sources"]) == 2 and all(type(v) is dict and
        set(v) == {"source_ref", "revision", "sha256"} and type(v["source_ref"]) is str and type(v["revision"]) is int and
        v["revision"] >= 1 and type(v["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", v["sha256"]) for v in grant["sources"]),
        "quota_grant_sources")
    require(len({v["source_ref"] for v in grant["sources"]}) == 2 and digest(grant["sources"]) == grant["source_scope_sha256"],
        "quota_grant_source_scope")
    require(type(grant["target"]) is str and re.fullmatch(r"accepted_live_[0-9a-f]{12}\.txt", grant["target"]), "quota_exact_target_shape")
    _owned_directory(grant["output_directory"])
    return json.loads(canonical(grant))


def _document_context(console, *, handoff_path, handoff_sha256, caller_id):
    # Lazy import: mechanical quota fixtures do not load the native runtime.
    from .native_document import validate_outcome, descriptors, normalize_sources
    task = console.task
    require(task is not None and console.outcome is task.accepted and task.delta_count == 1, "quota_actual_delta_outcome_required")
    require(_owned_directory(console.output) == _owned_directory(task.workspace), "quota_native_output_directory")
    accepted = validate_outcome(console.outcome, console.intake.read())
    current = task.source.current()
    policy = console.current_policy()
    require(policy == current["policy"] and policy["save_allowed"] and current["now"] < policy["valid_to"], "quota_current_policy")
    require(policy["consent_ref"].startswith("permission:") and policy["consent_ref"].endswith(handoff_sha256), "quota_handoff_consent")
    sources = descriptors(normalize_sources(console.intake.read()))
    require(sources == accepted["sources"] == current["sources"], "quota_current_source_scope")
    handoff_path = Path(handoff_path)
    require(handoff_path.is_file() and not handoff_path.is_symlink() and handoff_path.absolute() == handoff_path.resolve(strict=True)
        and digest(handoff_path.read_bytes()) == handoff_sha256, "quota_handoff_bytes")
    return dict(handoff_path=str(handoff_path), handoff_sha256=handoff_sha256, caller_id=caller_id,
        root_id=task.root_id, task_id=task.task_id, result_id=accepted["result_id"], result_sha256=accepted["result_sha256"],
        content_sha256=digest(accepted["content"].encode()), root_decision_id=accepted["root"]["result"]["decision_id"],
        root_binding_sha256=accepted["root_binding_sha256"], sources=sources, source_scope_sha256=digest(sources),
        policy_revision=policy["revision"], consent_ref=policy["consent_ref"], valid_to=policy["valid_to"],
        output_directory=str(_owned_directory(console.output)))


def prepare_grant(console, *, handoff_path, handoff_sha256, caller_id, run_id, now=None):
    """Prepare reviewable dynamic scope from an actual current accepted delta.

    Call only from the reviewed controlled runner. This grants no model authority
    and does not dispatch, install, or consume a native pending packet.
    """
    require(type(run_id) is str and re.fullmatch(r"[0-9a-f]{12}", run_id), "quota_run_id")
    current = _document_context(console, handoff_path=handoff_path, handoff_sha256=handoff_sha256, caller_id=caller_id)
    now = int(time.time()) if now is None else now
    require(type(now) is int and now < current["valid_to"], "quota_grant_expired")
    return _validate_grant(dict(version=VERSION, kind="NATIVE_DOCUMENT_DELTA", target="accepted_live_" + run_id + ".txt", **current))


def _regular_file(fd):
    value = os.fstat(fd)
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and stat.S_IMODE(value.st_mode) == 0o600,
        "quota_regular_private_file")


class SingleSaveQuota:
    """One irreversible reservation in a fixed owned persistent ledger.

    CLOSED and UNKNOWN never reopen. Constructor grant replacement and a missing
    ledger beside an existing lock both fail closed. Corrupt/truncated records do
    not restore quota. Reservation and closure each fsync before returning.
    """
    def __init__(self, directory, grant, *, clock=lambda: int(time.time())):
        self.directory, self.grant, self.clock = _owned_directory(directory), _validate_grant(grant), clock
        self.directory_identity = self.directory.resolve(strict=True)
        self.path = self.directory / "single_save.jsonl"
        self.lock_path = self.directory / "single_save.lock"
        with self._lock(initial=True) as first:
            if first:
                require(not self.path.exists(), "quota_unexpected_existing_ledger")
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
                self._append([], "GRANTED", dict(grant=self.grant, max_dispatch_attempts=1))
            rows = self._read()
            require(rows[0]["details"]["grant"] == self.grant, "quota_grant_replacement_forbidden")

    @contextmanager
    def _lock(self, *, initial=False):
        require(self.directory.resolve(strict=True) == self.directory_identity and not self.directory.is_symlink(), "quota_directory_changed")
        first = False
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            first = True
            os.fsync(fd)
            self._sync_directory()
        except FileExistsError:
            fd = os.open(self.lock_path, flags)
        try:
            _regular_file(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ValueError("quota_busy") from error
            require(initial or not first, "quota_lock_missing")
            require(first or self.path.is_file(), "quota_missing_ledger_no_reset")
            yield first
        finally:
            os.close(fd)

    def _sync_directory(self):
        fd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read(self):
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            _regular_file(fd)
            raw = os.read(fd, MAX_LEDGER_BYTES + 1)
        finally:
            os.close(fd)
        require(0 < len(raw) <= MAX_LEDGER_BYTES and raw.endswith(b"\n"), "quota_ledger_corrupt_or_truncated")
        try:
            rows = [json.loads(line) for line in raw.splitlines()]
        except (ValueError, UnicodeError) as error:
            raise ValueError("quota_ledger_corrupt_or_truncated") from error
        previous = None
        for index, row in enumerate(rows):
            require(type(row) is dict and set(row) == {"version", "sequence", "previous_sha256", "state", "at", "details", "record_sha256"}
                and row["version"] == VERSION and row["sequence"] == index and row["previous_sha256"] == previous
                and type(row["at"]) is int and type(row["details"]) is dict and
                row["record_sha256"] == digest({k: v for k, v in row.items() if k != "record_sha256"}), "quota_ledger_identity")
            previous = row["record_sha256"]
            require(canonical(row) == raw.splitlines()[index], "quota_ledger_canonical_bytes")
        states = [row["state"] for row in rows]
        require(states in (["GRANTED"], ["GRANTED", "RESERVED"], ["GRANTED", "RESERVED", "CLOSED"],
            ["GRANTED", "RESERVED", "UNKNOWN"]), "quota_ledger_transition")
        require(rows[0]["details"] == dict(grant=self.grant, max_dispatch_attempts=1), "quota_grant_replacement_forbidden")
        return rows

    def _append(self, rows, state, details):
        now = self.clock()
        require(type(now) is int, "quota_clock")
        row = dict(version=VERSION, sequence=len(rows), previous_sha256=rows[-1]["record_sha256"] if rows else None,
            state=state, at=now, details=details)
        row["record_sha256"] = digest(row)
        payload = canonical(row) + b"\n"
        require(self.path.stat().st_size + len(payload) <= MAX_LEDGER_BYTES, "quota_ledger_budget")
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
        try:
            _regular_file(fd)
            written = 0
            while written < len(payload):
                written += os.write(fd, payload[written:])
            os.fsync(fd)
        finally:
            os.close(fd)
        self._sync_directory()
        return row

    def state(self):
        with self._lock():
            return self._read()[-1]["state"]

    def _run(self, context, target, dispatch, verify_receipt):
        """Trusted core; fixture callbacks are separately labelled in the driver."""
        with self._lock():
            rows = self._read()
            require(rows[-1]["state"] == "GRANTED", "quota_consumed_or_unknown")
            require(target == self.grant["target"], "quota_target_not_allowed")
            require(type(context) is dict and set(context) == CONTEXT_KEYS and context ==
                {k: self.grant[k] for k in CONTEXT_KEYS}, "quota_context_changed")
            require(self.clock() < self.grant["valid_to"], "quota_expired")
            output = _owned_directory(self.grant["output_directory"])
            require(not (output / target).exists() and not (output / target).is_symlink(), "quota_target_exists_no_overwrite")
            reservation = self._append(rows, "RESERVED", dict(target=target, context_sha256=digest(context), retry_allowed=False))
            rows.append(reservation)
            # RESERVED is durable before the only callback that can start writer.
            try:
                receipt = dispatch()
                checked = verify_receipt(receipt)
                require(type(checked) is dict and set(checked) == {"packet_id", "receipt_id", "receipt_sha256", "readback_sha256", "executor_starts"}
                    and checked["readback_sha256"] == self.grant["content_sha256"] and checked["executor_starts"] == 1,
                    "quota_receipt_or_executor_binding")
                self._append(rows, "CLOSED", dict(receipt=checked, grant_revoked=True, retry_allowed=False))
            except BaseException as error:
                # A missing receipt, crash, callback refusal or checkpoint error
                # cannot prove the effect did not start. Never restore allowance.
                self._append(rows, "UNKNOWN", dict(error_type=type(error).__name__, retry_allowed=False))
                raise
            return receipt

    def save(self, console, target, *, caller_id):
        require(self.grant["kind"] == "NATIVE_DOCUMENT_DELTA", "quota_live_document_grant_required")
        context = _document_context(console, handoff_path=self.grant["handoff_path"],
            handoff_sha256=self.grant["handoff_sha256"], caller_id=caller_id)
        def checked_receipt(receipt):
            from .native_authority import root_plain
            from hedgehog.kernel import abi_v01 as abi
            pending = console.task.last_save
            require(pending is not None and pending.get("effect_host") is not None, "quota_actual_effect_host")
            host = pending["effect_host"]
            attempts = host.registry.action_packet_fulfillment_attempt_contexts
            require(len(attempts) == 1 and attempts[0].receipt is not None, "quota_actual_native_receipt")
            actual = abi.kernel_artifact_to_plain_dict_v01(attempts[0].receipt)
            require(receipt["packet_id"] == pending["packet_id"] and receipt["receipt"] == actual and
                receipt["root"] == root_plain(pending["review"]) and pending["job"]["inputs"]["result_ref"] == self.grant["result_id"]
                and pending["job"]["inputs"]["source_scope_sha256"] == self.grant["source_scope_sha256"], "quota_actual_native_result_binding")
            raw = (_owned_directory(self.grant["output_directory"]) / target).read_bytes()
            require(raw == console.outcome.content.encode() and receipt["readback"]["target"] == target and
                digest(raw) == receipt["readback"]["sha256"], "quota_actual_output_readback")
            return dict(packet_id=pending["packet_id"], receipt_id=actual["artifact_id"], receipt_sha256=digest(actual),
                readback_sha256=digest(raw), executor_starts=sum(event[0] == "EXECUTOR_STARTED" for event in host.events))
        return self._run(context, target, lambda: console.save(target), checked_receipt)
