"""Candidate bounded Codex stdio adapter. No capability or Root authority.

The trusted caller supplies exact reviewed closure pins and a persistent shared
turn ledger. Metadata, diagnostic inference and admitted runtime are separate.
Empty environments and denied server requests are controls, not a claim that
every built-in/hosted tool is closed. A live boundary witness is still required.
"""
from collections import deque
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

REQUESTED_MODEL = "gpt-6.1-sol"
REQUESTED_EFFORT = "high"
REQUESTED_TIER = "default"
PERMISSION_PROFILE = "radik_model_closed_v01"
DISABLED_FEATURES = (
    "apps", "plugins", "remote_plugin", "hooks", "goals", "shell_tool",
    "shell_snapshot", "unified_exec", "multi_agent", "multi_agent_v2",
    "computer_use", "browser_use", "browser_use_external", "image_generation",
    "view_image", "code_mode", "code_mode_host", "skill_search",
    "skill_mcp_dependency_install", "tool_suggest", "memories", "sleep_tool",
    "request_permissions_tool", "unbounded_connection_retries",
)
SCHEMA_FILES = {
    "initialize": "v1/InitializeParams.json",
    "model/list": "v2/ModelListParams.json",
    "thread/start": "v2/ThreadStartParams.json",
    "mcpServerStatus/list": "v2/ListMcpServerStatusParams.json",
    "turn/start": "v2/TurnStartParams.json",
    "turn/interrupt": "v2/TurnInterruptParams.json",
    "thread/unsubscribe": "v2/ThreadUnsubscribeParams.json",
    "account/read": "v2/GetAccountParams.json",
    "config/read": "v2/ConfigReadParams.json",
    "configRequirements/read": "ClientRequest.json",
    "permissionProfile/list": "v2/PermissionProfileListParams.json",
    "experimentalFeature/list": "v2/ExperimentalFeatureListParams.json",
}
RESPONSE_FILES = {
    "initialize": "v1/InitializeResponse.json",
    "model/list": "v2/ModelListResponse.json",
    "thread/start": "v2/ThreadStartResponse.json",
    "mcpServerStatus/list": "v2/ListMcpServerStatusResponse.json",
    "turn/start": "v2/TurnStartResponse.json",
    "turn/interrupt": "v2/TurnInterruptResponse.json",
    "thread/unsubscribe": "v2/ThreadUnsubscribeResponse.json",
    "account/read": "v2/GetAccountResponse.json",
    "config/read": "v2/ConfigReadResponse.json",
    "configRequirements/read": "v2/ConfigRequirementsReadResponse.json",
    "permissionProfile/list": "v2/PermissionProfileListResponse.json",
    "experimentalFeature/list": "v2/ExperimentalFeatureListResponse.json",
}
NOTIFICATION_FILES = {
    "item/started": "v2/ItemStartedNotification.json",
    "item/completed": "v2/ItemCompletedNotification.json",
    "turn/completed": "v2/TurnCompletedNotification.json",
    "thread/tokenUsage/updated": "v2/ThreadTokenUsageUpdatedNotification.json",
}
PROTOCOL_FILES = tuple(dict.fromkeys((*SCHEMA_FILES.values(), *RESPONSE_FILES.values(),
                                     *NOTIFICATION_FILES.values())))
ALLOWED_ITEMS = frozenset(("userMessage", "agentMessage", "reasoning"))


class TransportGap(RuntimeError):
    """A concrete unsupported, unverified or violated transport boundary."""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def sanitize(value):
    text = str(value)
    text = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{10,}|eyJ[A-Za-z0-9_.-]{20,})", "[REDACTED]", text)
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9_.-]+", r"\1[REDACTED]", text)
    return re.sub(r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization)\s*[=:]\s*)[^\s,;]+", r"\1[REDACTED]", text)


def safe_message(value):
    return sanitize(str(value)[:2048])


def toml_value(value):
    """CLI -c parses TOML; JSON object syntax would become an invalid string."""
    if isinstance(value, dict):
        return "{" + ", ".join(json.dumps(k) + " = " + toml_value(v)
                               for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    if value is None:
        raise TransportGap("toml_null_not_supported")
    return json.dumps(value)


def owned_path(project, value):
    project = Path(project).resolve(strict=True)
    path = Path(value)
    if not path.is_absolute():
        path = project / path
    if not path.resolve().is_relative_to(project):
        raise TransportGap("transport_path_outside_owned_project")
    for parent in (path, *path.parents):
        if parent == project:
            break
        if parent.is_symlink():
            raise TransportGap("transport_symlink_path")
    return path


def verify_review(project, review, required, scope, status="ACCEPTED_FOR_RESEARCH"):
    """Check exact local review binding, not independence by a self-asserted hash.

    Producing an independent review record and accepting it are trusted launcher
    responsibilities. The adapter never writes its own positive review record.
    """
    if not isinstance(review, dict) or review.get("scope") != scope:
        raise TransportGap("independent_transport_review_scope_required")
    if review.get("status") != status or not review.get("reviewer"):
        raise TransportGap("independent_transport_review_required")
    pins = review.get("pins", {})
    if not isinstance(pins, dict) or not pins or not set(required).issubset(pins):
        raise TransportGap("transport_review_closure_incomplete")
    for relative, expected in pins.items():
        path = owned_path(project, relative)
        if not path.is_file() or sha256(path.read_bytes()) != expected:
            raise TransportGap("transport_review_pin_mismatch:" + relative)


def permission_config():
    return {
        "permissions": {PERMISSION_PROFILE: {
            "description": "No filesystem or network access for model tools.",
            "filesystem": {"/": "deny"},
            "network": {"enabled": False},
        }},
        "default_permissions": PERMISSION_PROFILE,
        "approval_policy": {"granular": {
            "sandbox_approval": False, "rules": False, "mcp_elicitations": False,
            "skill_approval": False, "request_permissions": False,
        }},
        "approvals_reviewer": "user",
        "model_reasoning_effort": REQUESTED_EFFORT,
        "agents": {"enabled": False}, "web_search": "disabled",
        "mcp_servers": {},
        "features": {name: False for name in DISABLED_FEATURES},
        "memories": {"generate_memories": False, "use_memories": False},
    }


def thread_params(cwd, role_instructions):
    return {
        "cwd": str(cwd), "model": REQUESTED_MODEL, "serviceTier": REQUESTED_TIER,
        "permissions": PERMISSION_PROFILE, "approvalPolicy": permission_config()["approval_policy"],
        "approvalsReviewer": "user", "ephemeral": True,
        "allowProviderModelFallback": False, "environments": [], "dynamicTools": [],
        "selectedCapabilityRoots": [], "runtimeWorkspaceRoots": [],
        "experimentalRawEvents": False, "baseInstructions": role_instructions,
        "developerInstructions": "Return a closed proposal only. All authority belongs to the local application.",
        "config": permission_config(),
    }


def turn_params(thread_id, context, output_schema):
    return {
        "threadId": thread_id, "input": [{"type": "text", "text": context}],
        "model": REQUESTED_MODEL, "effort": REQUESTED_EFFORT,
        "serviceTierForTurn": REQUESTED_TIER, "permissions": PERMISSION_PROFILE,
        "approvalPolicy": permission_config()["approval_policy"],
        "approvalsReviewer": "user", "environments": [], "runtimeWorkspaceRoots": [],
        "outputSchema": output_schema,
    }


@dataclass(frozen=True)
class ProposalObservation:
    value: object
    context_sha256: str
    thread_id: str
    turn_id: str
    requested_model: str
    resolved_model: str
    served_model: str
    requested_effort: str
    resolved_effort: str
    speed_tier: str
    outcome: str
    usage: object
    wall_seconds: float
    requested_service_tier: str = REQUESTED_TIER
    service_tier_basis: str = "RETURNED_THREAD_SETTING_NOT_SERVED_TURN_TELEMETRY"
    provider_output_token_cap: str = "UNKNOWN_NOT_SUPPORTED_BY_TURN_SCHEMA"


class CodexTransport:
    """Own finite process; a caller cannot pass arbitrary RPC/tool callbacks."""

    def __init__(self, *, project, attempt_directory, binary, binary_sha256,
                 schema_directory, schema_pins, review, budget=None, state_home=None,
                 credential_store=None):
        self.project = Path(project).resolve(strict=True)
        self.attempt = owned_path(self.project, attempt_directory)
        self.schemas = owned_path(self.project, schema_directory)
        self.binary = Path(binary).resolve(strict=True)
        if sha256(self.binary.read_bytes()) != binary_sha256:
            raise TransportGap("codex_binary_identity_changed")
        self.binary_sha256 = binary_sha256
        self.schema_pins = dict(schema_pins)
        self.review = review
        self.budget = budget
        self.state_home = None if state_home is None else owned_path(self.project, state_home)
        if credential_store not in (None, 'file', 'keyring'):
            raise TransportGap('unsupported_credential_store_reuse')
        self.credential_store = credential_store
        self.reserved_turn_attempts = 0
        self.proc = None
        self.selector = None
        self.buffer = bytearray()
        self.stderr = bytearray()
        self.notifications = deque()
        self.denied_requests = []
        self.item_types = []
        self.next_id = 1
        self.thread_id = None
        self.resolved_model = "UNKNOWN"
        self.resolved_effort = "UNKNOWN"
        self.resolved_tier = "UNKNOWN"
        self.model_verified = False
        self.metadata_boundary_checked = False
        self.closed_witness = None
        self.runtime_review = None
        self.events = []
        self._active_turn = False
        self._thread_used = False
        self._turn_start_written = False
        self._stderr_truncated = False
        self._stderr_bytes_seen = 0
        self._stderr_hash = hashlib.sha256()
        self._stderr_eof = False
        self._stdout_bytes_seen = 0
        self._stdout_hash = hashlib.sha256()
        self._stdout_eof = False

    def _required_closure(self):
        return ("app/codex_transport.py", "review/transport/boundary_probe.py", *(
            str((self.schemas / name).relative_to(self.project)) for name in PROTOCOL_FILES))

    def _check_closure(self):
        scope = self.review.get('scope')
        if scope not in ('TRANSPORT_DIAGNOSTIC_RESEARCH_ONLY', 'NON_MODEL_CONTROL_INSPECTION_ONLY',
                         'RUNTIME_MODEL_PROPOSALS_ONLY'):
            raise TransportGap('transport_review_scope_not_admitted')
        status = ('ACCEPTED_FOR_RUNTIME_MODEL_PROPOSALS' if scope == 'RUNTIME_MODEL_PROPOSALS_ONLY'
                  else 'ACCEPTED_FOR_RESEARCH')
        verify_review(self.project, self.review, self._required_closure(), scope, status=status)
        for name in PROTOCOL_FILES:
            relative = str((self.schemas / name).relative_to(self.project))
            expected = self.schema_pins.get(relative)
            if expected is None or sha256((self.schemas / name).read_bytes()) != expected:
                raise TransportGap("installed_protocol_schema_pin_mismatch:" + name)

    def _validate(self, method, params):
        import jsonschema
        path = self.schemas / SCHEMA_FILES[method]
        value = {'id': 0, 'method': method, 'params': params} if method == 'configRequirements/read' else params
        jsonschema.validate(value, json.loads(path.read_text()))

    def _validate_result(self, method, result):
        import jsonschema
        jsonschema.validate(result, json.loads((self.schemas / RESPONSE_FILES[method]).read_text()))

    def _validate_notification(self, method, params):
        import jsonschema
        if method in NOTIFICATION_FILES:
            jsonschema.validate(params, json.loads((self.schemas / NOTIFICATION_FILES[method]).read_text()))

    def start_metadata(self):
        self._check_closure()
        if self.proc is not None:
            raise TransportGap("transport_process_already_started")
        self.attempt.mkdir(parents=True, exist_ok=False)
        home = self.state_home or self.attempt / 'codex-home'
        if not home.exists(): home.mkdir(mode=0o700)
        if home.is_symlink() or home.stat().st_mode & 0o777 != 0o700:
            raise TransportGap('owned_state_home_mode_or_symlink')
        process_tmp = home.parent / ('process-tmp-' + sha256(str(self.attempt).encode())[:12])
        process_tmp.mkdir(mode=0o700, exist_ok=False)
        if process_tmp.stat().st_mode & 0o777 != 0o700:
            raise TransportGap('owned_process_tmp_mode')
        config = permission_config()
        config.update(sqlite_home=str(self.attempt / "sqlite"), log_dir=str(self.attempt / "log"),
                      **{"analytics.enabled": False, "check_for_update_on_startup": False})
        if self.credential_store is not None:
            config['cli_auth_credentials_store'] = self.credential_store
        argv = [str(self.binary), "app-server", "--stdio"]
        for key, value in config.items():
            argv.extend(("-c", key + "=" + toml_value(value)))
        child_environment = dict(os.environ)
        child_environment.update({'CODEX_HOME': str(home), 'TMPDIR': str(process_tmp),
            'CODEX_SQLITE_HOME': str(self.attempt / 'sqlite'), 'RUST_BACKTRACE': 'full'})
        self.proc = subprocess.Popen(argv, cwd=self.attempt, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            env=child_environment)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.proc.stdout, selectors.EVENT_READ, "stdout")
        self.selector.register(self.proc.stderr, selectors.EVENT_READ, "stderr")
        self.events.append({"stage": "own_process_started", "argv": argv, 'pid': self.proc.pid,
            'cwd': str(self.attempt), 'child_locations': {'codex_home': str(home), 'process_tmp': str(process_tmp)},
            'credential_store_requested': self.credential_store or 'DEFAULT', 'parent_environment_changed': False})
        initial = self.request("initialize", {"clientInfo": {"name": "radik_bounded_transport", "version": "0.2.0"},
                                    "capabilities": {"experimentalApi": True}}, timeout=15)
        self.events.append({'stage': 'initialize_returned_bindings', 'bindings': {
            k: initial[k] for k in ('codexHome','platformFamily','platformOs')}})
        if Path(initial['codexHome']).resolve() != home.resolve():
            raise TransportGap('returned_isolated_home_mismatch')
        self.events.append({"stage": "initialize_response_obtained"})
        self._notify("initialized", {})
        self._verify_catalog()

    def _verify_catalog(self):
        cursor = None
        for _ in range(5):
            params = {"limit": 100, "includeHidden": False}
            if cursor is not None:
                params["cursor"] = cursor
            page = self.request("model/list", params, timeout=15)
            rows = page.get("data", [])
            matching = [r for r in rows if r.get("model") == REQUESTED_MODEL]
            if matching:
                efforts = [x.get("reasoningEffort") for x in matching[0].get("supportedReasoningEfforts", [])]
                if REQUESTED_EFFORT not in efforts:
                    raise TransportGap("requested_reasoning_effort_unavailable")
                self.model_verified = True
                self.events.append({"stage": "actual_requested_model_catalog_obtained",
                                    "model": REQUESTED_MODEL, "supported_efforts": efforts})
                return
            cursor = page.get("nextCursor")
            if cursor is None:
                break
        raise TransportGap("requested_model_not_available_no_fallback")

    def _wire(self, message):
        if self.proc is None or self.proc.poll() is not None:
            raise TransportGap("own_transport_not_running")
        self.proc.stdin.write(canonical(message) + b"\n")
        self.proc.stdin.flush()

    def _notify(self, method, params):
        if method != "initialized":
            raise TransportGap("notification_method_not_allowed")
        self._wire({"method": method, "params": params})

    def _receive(self, deadline):
        while time.monotonic() < deadline:
            if b"\n" in self.buffer:
                line, _, rest = self.buffer.partition(b"\n")
                self.buffer[:] = rest
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise TransportGap("non_object_protocol_message")
                if "method" in message and "id" in message:
                    method = str(message["method"])[:200]
                    self.denied_requests.append(method)
                    self._wire({"id": message["id"], "error": {"code": -32601,
                        "message": "All server requests denied by closed Radik client."}})
                    continue
                return message
            for key, _ in self.selector.select(min(.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    if key.data == "stderr":
                        self._stderr_eof = True
                    else:
                        self._stdout_eof = True
                    self.selector.unregister(key.fileobj)
                elif key.data == "stderr":
                    self._capture_stderr(chunk)
                    if self._stderr_truncated:
                        raise TransportGap("stderr_size_limit")
                else:
                    self._stdout_bytes_seen += len(chunk)
                    self._stdout_hash.update(chunk)
                    self.buffer.extend(chunk)
                    if len(self.buffer) > 2_097_152:
                        raise TransportGap("protocol_message_size_limit")
            if self.proc.poll() is not None and not self.selector.get_map():
                raise TransportGap("own_transport_exited_before_response")
        raise TransportGap("transport_timeout_outcome_unknown")

    def _capture_stderr(self, chunk):
        self._stderr_bytes_seen += len(chunk)
        self._stderr_hash.update(chunk)
        remaining = max(0, 2_097_152 - len(self.stderr))
        self.stderr.extend(chunk[:remaining])
        self._stderr_truncated |= len(chunk) > remaining

    def request(self, method, params, *, timeout=30):
        if method not in SCHEMA_FILES:
            raise TransportGap("request_method_not_allowed")
        if method == 'account/read' and params != {'refreshToken': False}:
            raise TransportGap('forced_refresh_or_account_dump_not_allowed')
        if method == "turn/start" and not self._active_turn:
            raise TransportGap("turn_requires_review_and_shared_ledger")
        self._validate(method, params)
        request_id = self.next_id
        self.next_id += 1
        self._wire({"id": request_id, "method": method, "params": params})
        if method == "turn/start":
            self._turn_start_written = True
        self.events.append({"stage": "request_sent", "method": method, "id": request_id})
        deadline = time.monotonic() + timeout
        while True:
            message = self._receive(deadline)
            if "method" in message:
                if len(self.notifications) >= 1024:
                    raise TransportGap("notification_queue_limit")
                self.notifications.append(message)
                continue
            if message.get("id") != request_id:
                self.events.append({"stage": "unmatched_response_omitted"})
                continue
            if "error" in message:
                error = message["error"]
                raise TransportGap("rpc_error:" + str(error.get("code", "UNKNOWN")) + ":" + safe_message(error.get("message", "")))
            if not isinstance(message.get("result"), dict):
                raise TransportGap("non_object_protocol_result")
            self._validate_result(method, message["result"])
            return message["result"]

    def _feature_bindings(self, thread_id=None):
        bindings = {}
        cursor = None
        for _ in range(5):
            params = {'limit': 100}
            if thread_id is not None:
                params['threadId'] = thread_id
            if cursor is not None:
                params['cursor'] = cursor
            page = self.request('experimentalFeature/list', params, timeout=15)
            for row in page['data']:
                if row['name'] in bindings:
                    raise TransportGap('duplicate_feature_inventory_name')
                bindings[row['name']] = row['enabled']
            cursor = page.get('nextCursor')
            if cursor is None:
                return {name: bindings.get(name, 'UNKNOWN') for name in DISABLED_FEATURES}
        raise TransportGap('feature_inventory_pagination_incomplete')

    def _check_current_process_controls(self):
        """Recheck actual controls before a role thread with any inference budget.

        These guards can refuse known gaps. They do not replace the independent
        complete inventory and pre-execution enforcement witness.
        """
        account = self.request('account/read', {'refreshToken': False}, timeout=15)
        account_type = None if account['account'] is None else account['account']['type']
        self.events.append({'stage': 'current_account_type', 'account_type': account_type,
                            'requiresOpenaiAuth': account['requiresOpenaiAuth']})
        if account_type is None:
            raise TransportGap('current_native_authentication_not_observed')
        if account_type != 'chatgpt':
            raise TransportGap('current_authentication_mode_not_chatgpt')
        config = self.request('config/read', {'cwd': str(self.attempt), 'includeLayers': False}, timeout=15)['config']
        wanted = permission_config()
        if config.get('cli_auth_credentials_store') != 'file':
            raise TransportGap('current_native_credential_store_not_file')
        if config.get('model_provider') not in (None, 'openai'):
            raise TransportGap('current_provider_mode_not_openai')
        for key in ('default_permissions', 'approval_policy', 'approvals_reviewer', 'web_search'):
            if config.get(key) != wanted[key]:
                raise TransportGap('current_effective_config_mismatch:' + key)
        if config.get('sandbox_mode') is not None:
            raise TransportGap('legacy_sandbox_override_not_admitted')
        profile = config.get('permissions', {}).get(PERMISSION_PROFILE) or {}
        if (profile.get('filesystem', {}).get('/') != 'deny'
                or profile.get('network', {}).get('enabled') is not False):
            raise TransportGap('current_named_permission_config_mismatch')
        feature_config = config.get('features') or {}
        if any(feature_config.get(name) is not False for name in DISABLED_FEATURES):
            raise TransportGap('current_requested_feature_disable_not_confirmed')
        requirements = self.request('configRequirements/read', None, timeout=15)['requirements']
        forced = {} if requirements is None else requirements.get('featureRequirements') or {}
        if any(forced.get(name) is True for name in DISABLED_FEATURES):
            raise TransportGap('managed_required_feature_conflicts_with_closed_scope')
        bindings = self._feature_bindings()
        self.events.append({'stage': 'current_process_feature_bindings', 'bindings': bindings,
                            'managed_requirements_present': requirements is not None,
                            'effective_named_profile_sha256': sha256(profile)})
        if any(value is not False for value in bindings.values()):
            raise TransportGap('effective_process_feature_disable_not_confirmed')

    def create_role_thread(self, role_instructions):
        self._check_closure()
        if not self.model_verified or self._active_turn:
            raise TransportGap("thread_requires_actual_catalog_and_fresh_context")
        if not isinstance(role_instructions, str) or len(role_instructions.encode()) > 8192:
            raise TransportGap("role_instruction_limit")
        if self.budget is not None:
            self._check_current_process_controls()
        if self.thread_id is not None:
            self.request("thread/unsubscribe", {"threadId": self.thread_id})
            self.thread_id = None
            self.notifications.clear()
        self.metadata_boundary_checked = False
        self._thread_used = False
        result = self.request("thread/start", thread_params(self.attempt, role_instructions), timeout=30)
        self.events.append({'stage': 'thread_start_returned_bindings', 'bindings': {
            **{k: result.get(k, 'UNKNOWN') for k in ('activePermissionProfile','approvalPolicy','approvalsReviewer',
                 'cwd','disabledPluginIds','model','modelProvider','multiAgentMode','reasoningEffort',
                 'runtimeWorkspaceRoots','sandbox','serviceTier')},
            'instruction_sources_field_present': 'instructionSources' in result,
            'instruction_sources_count': len(result['instructionSources']) if isinstance(result.get('instructionSources'), list) else 'UNKNOWN',
            'instruction_sources_sha256': sha256(result['instructionSources']) if 'instructionSources' in result else 'UNKNOWN'}})
        self.thread_id = result["thread"]["id"]
        self.resolved_model = result.get("model", "UNKNOWN")
        self.resolved_effort = result.get("reasoningEffort", "UNKNOWN")
        self.resolved_tier = result.get('serviceTier') or 'UNKNOWN'
        if self.resolved_model != REQUESTED_MODEL:
            raise TransportGap("model_fallback_or_substitution_refused")
        if self.budget is not None and result.get('modelProvider') != 'openai':
            raise TransportGap('current_thread_provider_not_openai')
        if result.get("activePermissionProfile", {}).get("id") != PERMISSION_PROFILE:
            raise TransportGap("named_closed_permission_profile_not_confirmed")
        sandbox = result.get("sandbox", {})
        if sandbox.get("networkAccess") is not False:
            raise TransportGap("sandbox_network_deny_not_confirmed")
        if result.get("runtimeWorkspaceRoots", []) != []:
            raise TransportGap("unexpected_runtime_workspace_roots")
        if self.budget is not None:
            if self.resolved_effort != REQUESTED_EFFORT or self.resolved_tier != REQUESTED_TIER:
                raise TransportGap('current_thread_effort_or_tier_not_confirmed')
            if (result.get('approvalPolicy') != permission_config()['approval_policy']
                    or result.get('approvalsReviewer') != 'user'
                    or result.get('cwd') != str(self.attempt)
                    or result.get('instructionSources') != []
                    or result.get('disabledPluginIds') != []
                    or result.get('activePermissionProfile', {}).get('extends') is not None):
                raise TransportGap('current_thread_closed_bindings_not_confirmed')
            bindings = self._feature_bindings(self.thread_id)
            self.events.append({'stage': 'current_thread_feature_bindings', 'bindings': bindings})
            if any(value is not False for value in bindings.values()):
                raise TransportGap('effective_thread_feature_disable_not_confirmed')
        cursor = None
        for _ in range(5):
            params = {"threadId": self.thread_id, "limit": 100, "detail": "toolsAndAuthOnly"}
            if cursor is not None:
                params["cursor"] = cursor
            page = self.request("mcpServerStatus/list", params, timeout=30)
            for server in page.get("data", []):
                if server.get("tools") or server.get("resources") or server.get("resourceTemplates") or server.get("runtimeStatus") not in ("disabled", "cancelled"):
                    raise TransportGap("inherited_or_unverified_mcp_runtime_not_closed")
            cursor = page.get("nextCursor")
            if cursor is None:
                self.metadata_boundary_checked = True
                return {"thread_id": self.thread_id, "resolved_model": self.resolved_model,
                        "permission_profile": PERMISSION_PROFILE, "mcp_tools": 0,
                        "effective_closed_boundary": "UNPROVEN_REQUIRES_DIAGNOSTIC_WITNESS"}
        raise TransportGap("mcp_catalog_pagination_incomplete")

    def install_runtime_review(self, review):
        """Independent model-proposal gate; this conveys no native effect authority."""
        required = (*self._required_closure(), "app/__init__.py", "app/budget.py",
                    "app/contracts.py", "app/controller.py", "config/model_policy.json")
        verify_review(self.project, review, required, "RUNTIME_MODEL_PROPOSALS_ONLY",
                      status="ACCEPTED_FOR_RUNTIME_MODEL_PROPOSALS")
        self.runtime_review = review

    def install_closed_boundary_witness(self, witness):
        self._check_closure()
        if not isinstance(witness, dict) or witness.get("binary_sha256") != self.binary_sha256:
            raise TransportGap("closed_boundary_witness_missing")
        verify_review(self.project, witness, self._required_closure(),
                      "EFFECTIVE_CLOSED_TRANSPORT_BOUNDARY", status="PASS_RESEARCH_BOUNDARY")
        if witness.get("configuration_sha256") != sha256(permission_config()):
            raise TransportGap("closed_boundary_witness_configuration_mismatch")
        evidence_pins = witness.get("evidence_pins", {})
        if not isinstance(evidence_pins, dict) or not evidence_pins:
            raise TransportGap("closed_boundary_witness_evidence_missing")
        for path, expected in evidence_pins.items():
            if sha256(owned_path(self.project, path).read_bytes()) != expected:
                raise TransportGap("closed_boundary_witness_pin_mismatch")
        if not {"file_read", "shell_write", "hosted_tools"}.issubset(witness.get("verified_controls", [])):
            raise TransportGap("closed_boundary_witness_controls_incomplete")
        self.closed_witness = witness

    def propose(self, *, role, context, output_schema, diagnostic=False, max_output_bytes=16384):
        self._check_closure()
        if diagnostic and self.review.get('diagnostic_turns_allowed') is not True:
            raise TransportGap('diagnostic_turns_not_accepted_by_independent_review')
        if not self.metadata_boundary_checked or self.thread_id is None or self.budget is None:
            raise TransportGap("proposal_metadata_or_shared_ledger_missing")
        if diagnostic:
            if role != "boundary_probe":
                raise TransportGap("diagnostic_role_required")
            verify_review(self.project, self.review, (*self._required_closure(),
                "app/__init__.py", "app/budget.py", "app/contracts.py", "config/model_policy.json"),
                "TRANSPORT_DIAGNOSTIC_RESEARCH_ONLY")
        else:
            if self.closed_witness is None or self.runtime_review is None:
                raise TransportGap("closed_boundary_and_independent_runtime_review_required")
            self.install_runtime_review(self.runtime_review)
            self.install_closed_boundary_witness(self.closed_witness)
        if self._active_turn:
            raise TransportGap("single_concurrency_required")
        if self._thread_used:
            raise TransportGap("fresh_role_thread_required_for_each_call")
        if not isinstance(context, str) or len(context.encode()) > 98304:
            raise TransportGap("proposal_input_byte_limit")
        if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 16384:
            raise TransportGap("proposal_output_limit_invalid")
        params = turn_params(self.thread_id, context, output_schema)
        self._validate("turn/start", params)
        context_hash = sha256(context.encode("utf-8"))
        # The caller's ledger persists BEFORE the wire write, including failures.
        attempt_id = self.budget.reserve(role=role, context_sha256=context_hash,
            purpose="diagnostic_boundary" if diagnostic else "semantic_role")
        self.reserved_turn_attempts += 1
        started = time.monotonic()
        outcome, usage, turn_id, value = "UNKNOWN", "UNKNOWN", "UNKNOWN", None
        terminal_observed = False
        provider_outcome = "UNKNOWN"
        self._active_turn = True
        self._thread_used = True
        self._turn_start_written = False
        try:
            reply = self.request("turn/start", params, timeout=30)
            turn_id = reply["turn"]["id"]
            self.resolved_effort = REQUESTED_EFFORT if self.resolved_effort == REQUESTED_EFFORT else "UNKNOWN"
            completed = False
            texts = []
            deadline = time.monotonic() + 180
            while not completed:
                message = self.notifications.popleft() if self.notifications else self._receive(deadline)
                method = message.get("method")
                if not method:
                    continue
                params = message.get("params", {})
                self._validate_notification(method, params)
                if params.get("threadId") not in (None, self.thread_id):
                    raise TransportGap("foreign_thread_notification")
                if params.get("turnId") not in (None, turn_id):
                    raise TransportGap("foreign_turn_notification")
                if method in ("item/started", "item/completed"):
                    item = params.get("item", {})
                    kind = item.get("type", "UNKNOWN")
                    self.item_types.append(kind)
                    if len(self.item_types) > 1024:
                        raise TransportGap("observed_item_count_limit")
                    if kind not in ALLOWED_ITEMS:
                        self._wire({"id": self.next_id, "method": "turn/interrupt", "params": {
                            "threadId": self.thread_id, "turnId": turn_id}})
                        self.next_id += 1
                        raise TransportGap("model_tool_or_unexpected_item:" + kind)
                    if method == "item/completed" and kind == "agentMessage":
                        text = item.get("text", "")
                        if len(text.encode()) > max_output_bytes:
                            raise TransportGap("proposal_output_byte_limit")
                        texts.append(text)
                if method == "thread/tokenUsage/updated":
                    usage = params.get("tokenUsage", "UNKNOWN")
                if method == "turn/completed" and params.get("turn", {}).get("id") == turn_id:
                    completed = True
                    terminal_observed = True
                    provider_outcome = params["turn"].get("status", "UNKNOWN")
                    outcome = {"completed": "COMPLETED", "failed": "FAILED",
                               "interrupted": "CANCELLED"}.get(provider_outcome, "UNKNOWN")
                    if outcome != "COMPLETED":
                        raise TransportGap("semantic_turn_did_not_complete:" + provider_outcome)
            if self.denied_requests:
                raise TransportGap("server_tool_request_seen_and_denied")
            if not texts:
                raise TransportGap("structured_proposal_missing")
            value = json.loads(texts[-1])
            import jsonschema
            jsonschema.validate(value, output_schema)
            return ProposalObservation(value, context_hash, self.thread_id, turn_id, REQUESTED_MODEL,
                self.resolved_model, "UNKNOWN", REQUESTED_EFFORT, self.resolved_effort,
                self.resolved_tier, outcome, usage, round(time.monotonic() - started, 6))
        except Exception:
            if outcome == "COMPLETED":
                outcome = "FAILED"
            raise
        finally:
            self._active_turn = False
            self.budget.finish(attempt_id, outcome=outcome, usage=usage, telemetry={
                "wall_seconds": round(time.monotonic() - started, 6),
                "thread_id": self.thread_id, "turn_id": turn_id,
                "requested_model": REQUESTED_MODEL, "resolved_model": self.resolved_model,
                "served_model": "UNKNOWN", "requested_effort": REQUESTED_EFFORT,
                "resolved_effort": self.resolved_effort, "requested_service_tier": REQUESTED_TIER,
                "speed_tier": self.resolved_tier,
                "service_tier_basis": "RETURNED_THREAD_SETTING_NOT_SERVED_TURN_TELEMETRY",
                "provider_outcome": provider_outcome, "terminal_observed": terminal_observed,
                "own_process_finished": self.proc is not None and self.proc.poll() is not None,
                "turn_not_started": not self._turn_start_written,
            })

    def close(self):
        """Release only this adapter's own process; no retry or foreign lifecycle."""
        if self.proc is None:
            return
        if self.proc.stdin and not self.proc.stdin.closed:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        if self.selector:
            # Drain only this process's finite remaining pipe bytes. A descendant
            # keeping a pipe open cannot block cleanup or make a complete claim.
            deadline = time.monotonic() + 1
            while self.selector.get_map() and time.monotonic() < deadline:
                for key, _ in self.selector.select(.05):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        if key.data == "stderr":
                            self._stderr_eof = True
                        else:
                            self._stdout_eof = True
                        self.selector.unregister(key.fileobj)
                    elif key.data == "stderr":
                        self._capture_stderr(chunk)
                    else:
                        self._stdout_bytes_seen += len(chunk)
                        self._stdout_hash.update(chunk)
            self.selector.close()
        if self.attempt.is_dir():
            safe_stderr = sanitize(self.stderr.decode(errors="replace")).encode()
            (self.attempt / "stderr.txt").write_bytes(safe_stderr)
            (self.attempt / "transport_observation.json").write_bytes(canonical({
                "events": self.events, "denied_server_requests": self.denied_requests,
                "item_types": self.item_types, "own_process_exit_code": self.proc.returncode,
                "stderr_original_sha256": self._stderr_hash.hexdigest(),
                'stdout_original_sha256': self._stdout_hash.hexdigest(),
                'stdout_original_bytes_received': self._stdout_bytes_seen,
                'stdout_capture_complete': self._stdout_eof,
                "stderr_original_bytes_received": self._stderr_bytes_seen,
                "stderr_capture_complete": self._stderr_eof and not self._stderr_truncated,
                "stderr_capture_truncated": self._stderr_truncated,
                "stderr_sanitized": safe_stderr != bytes(self.stderr),
                "stderr_sanitized_sha256": sha256(safe_stderr),
                "stderr_excerpt": safe_message(self.stderr.decode(errors="replace")),
                "effective_closed_boundary": "UNPROVEN" if self.closed_witness is None else "WITNESS_BOUND",
            }) + b"\n")
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream and not stream.closed:
                stream.close()
