"""Owned SIWC grant management. Import and construction perform no I/O."""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import fcntl
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import threading
import time
from typing import Any, Callable, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit
import uuid

ISSUER = "https://auth.openai.com"
AUTHORIZE_ENDPOINT = ISSUER + "/api/accounts/authorize"
TOKEN_ENDPOINT = ISSUER + "/api/accounts/oauth/token"
DISCOVERY_ENDPOINT = ISSUER + "/.well-known/openid-configuration"
JWKS_ENDPOINT = ISSUER + "/.well-known/jwks.json"
RESOURCE = "https://api.openai.com/v1"
IDENTITY_SCOPES = frozenset({"openid", "profile", "email"})
PLAN_SCOPES = frozenset({"offline_access", "resource.invoke", "chatgpt.tokens.use.direct"})
REQUESTED_SCOPES = IDENTITY_SCOPES | PLAN_SCOPES
PRIVATE_RELATIVE = Path("state/private/chatgpt_plan")
_MAX_JSON = 128 * 1024
_MAX_TOKEN = 32 * 1024
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,80}\Z")
_RECORD_FIELDS = frozenset({
    "schema", "connection_id", "host_id", "issuer", "client_id", "subject",
    "access_token", "refresh_token", "id_token", "id_nonce", "scopes",
    "expires_at", "earliest_refresh_at", "saved_at", "grant_status",
})
_REGISTRATION_FIELDS = frozenset({
    "schema", "host_id", "issuer", "client_id", "registration_status",
    "identity_status", "subject", "connection_id", "created_at", "updated_at",
})
_PRIVATE_FILENAMES = frozenset({"host.json", "connection.json", "registration.json"})


class PlanAuthError(RuntimeError):
    """Only curated codes and phases may cross into public evidence."""

    def __init__(self, code: str, operation: str, *, http_status: int | None = None):
        self.code = code
        self.operation = operation
        self.http_status = http_status
        super().__init__(code)

    def public(self) -> dict[str, Any]:
        return {"code": self.code, "operation": self.operation, "http_status": self.http_status}


@dataclasses.dataclass(frozen=True)
class PlanGrant:
    access_token: str = dataclasses.field(repr=False)
    connection_id: str
    scopes: tuple[str, ...]
    expires_at: int

    def public_receipt(self) -> dict[str, Any]:
        return {
            "schema": "radik.plan_connection_receipt.v01",
            "status": "OWN_PLAN_GRANT_VERIFIED",
            "connection_id": self.connection_id,
            "scopes": list(self.scopes),
            "expires_at": self.expires_at,
            "issuer_verified": True,
            "issued_client_identity_binding_verified": True,
            "workspace_binding_basis": "ISSUED_CLIENT_REGISTRATION_NOT_EMAIL_OR_SUBJECT",
        }


@dataclasses.dataclass(frozen=True, repr=False)
class AuthReply:
    status: int
    data: dict[str, Any]
    request_started_at: int | None = None


class AuthHttp(Protocol):
    """Trusted offline injections expose operations, never arbitrary destinations."""

    def discovery(self) -> AuthReply: ...
    def jwks(self) -> AuthReply: ...
    def exchange(self, body: bytes) -> AuthReply: ...
    def refresh(self, body: bytes) -> AuthReply: ...


class FixedAuthHttp:
    """Fixed-origin TLS with no redirect or bearer/API-key fallback."""

    def __init__(self):
        self._observations: list[dict[str, Any]] = []
        self._observation_lock = threading.Lock()
        self._dropped = 0
        self._totals = {name: 0 for name in ("discovery", "jwks", "exchange", "refresh")}

    def public_observations(self) -> dict[str, Any]:
        with self._observation_lock:
            return {"schema": "radik.plan_auth_http_observations.v01",
                    "basis": "OWN_FIXED_AUTH_HTTP_OPERATIONS_NOT_INFERENCE",
                    "requests": [dict(row) for row in self._observations],
                    "operation_totals": dict(self._totals), "dropped_rows": self._dropped}

    def _observe(self, operation: str) -> dict[str, Any]:
        row = {"operation": operation, "attempted_http_dispatch": False,
               "returned_status": None, "curated_error": None,
               "duration_seconds": None, "cleanup": "PENDING",
               "caller_total_deadline": False, "worker_finished": False}
        with self._observation_lock:
            self._totals[operation] += 1
            if len(self._observations) >= 128:
                self._observations.pop(0)
                self._dropped += 1
            self._observations.append(row)
        return row

    def _update_observation(self, row: dict[str, Any], **values: Any) -> None:
        with self._observation_lock:
            row.update(values)

    def _request(self, operation: str, path: str, body: bytes | None = None) -> AuthReply:
        permitted = {
            "discovery": ("GET", "/.well-known/openid-configuration"),
            "jwks": ("GET", "/.well-known/jwks.json"),
            "exchange": ("POST", "/api/accounts/oauth/token"),
            "refresh": ("POST", "/api/accounts/oauth/token"),
        }
        if operation not in permitted or permitted[operation][1] != path:
            raise PlanAuthError("AUTH_DESTINATION_REFUSED", operation)
        observation = self._observe(operation)
        started_monotonic = time.monotonic()
        method = permitted[operation][0]
        conn = http.client.HTTPSConnection("auth.openai.com", timeout=20, context=ssl.create_default_context())
        started_at = int(time.time())
        cancelled = threading.Event()
        completed = threading.Event()
        result: list[AuthReply | PlanAuthError] = []
        owned_socket = None
        def close_socket() -> bool:
            cleanup_ok = True
            sock = owned_socket if owned_socket is not None else conn.sock
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                except Exception:
                    cleanup_ok = False
            try:
                conn.close()
            except Exception:
                cleanup_ok = False
            return cleanup_ok
        def worker() -> None:
            nonlocal owned_socket
            response = None
            try:
                headers = {"Accept": "application/json"}
                if body is not None:
                    if len(body) > _MAX_JSON:
                        raise PlanAuthError("AUTH_REQUEST_BOUND", operation)
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                conn.connect()
                owned_socket = conn.sock
                # DNS can outlive a socket timeout. Never send after its caller expired.
                if cancelled.is_set():
                    raise PlanAuthError("AUTH_TOTAL_DEADLINE", operation)
                self._update_observation(observation, attempted_http_dispatch=True)
                conn.request(method, path, body=body, headers=headers)
                # getresponse may detach conn.sock when the response owns its file.
                owned_socket = conn.sock
                response = conn.getresponse()
                self._update_observation(observation, returned_status=response.status)
                if 300 <= response.status < 400:
                    raise PlanAuthError("AUTH_REDIRECT_REFUSED", operation, http_status=response.status)
                raw = response.read(_MAX_JSON + 1)
                if len(raw) > _MAX_JSON:
                    raise PlanAuthError("AUTH_RESPONSE_BOUND", operation, http_status=response.status)
                data = _object_json(raw, operation)
                result.append(AuthReply(response.status, data, started_at))
            except PlanAuthError as error:
                result.append(error)
                self._update_observation(observation, curated_error=error.code)
            except Exception:
                result.append(PlanAuthError("AUTH_NETWORK_FAILURE", operation))
                self._update_observation(observation, curated_error="AUTH_NETWORK_FAILURE")
            finally:
                cleanup_ok = True
                try:
                    if response is not None:
                        try:
                            response.close()
                        except Exception:
                            cleanup_ok = False
                    cleanup_ok = close_socket() and cleanup_ok
                    if not cleanup_ok:
                        result.clear()
                        result.append(PlanAuthError("AUTH_CLEANUP_UNCERTAIN", operation))
                except Exception:
                    cleanup_ok = False
                    result.clear()
                    result.append(PlanAuthError("AUTH_CLEANUP_UNCERTAIN", operation))
                finally:
                    try:
                        error = result[0] if result and isinstance(result[0], PlanAuthError) else None
                        self._update_observation(observation,
                            curated_error="AUTH_TOTAL_DEADLINE" if cancelled.is_set() else error.code if error else None,
                            duration_seconds=max(0.0, time.monotonic() - started_monotonic),
                            cleanup="COMPLETE" if cleanup_ok else "UNCERTAIN", worker_finished=True)
                    finally:
                        completed.set()
        thread = threading.Thread(target=worker, name="Radik-auth-HTTP", daemon=True)
        thread.start()
        if not completed.wait(30):
            cancelled.set()
            cleanup_ok = close_socket()
            self._update_observation(observation, curated_error="AUTH_TOTAL_DEADLINE",
                caller_total_deadline=True,
                duration_seconds=max(0.0, time.monotonic() - started_monotonic),
                cleanup="STOP_REQUESTED_NOT_COMPLETION" if cleanup_ok else "UNCERTAIN")
            raise PlanAuthError("AUTH_TOTAL_DEADLINE", operation)
        if not result or isinstance(result[0], PlanAuthError):
            raise result[0] if result else PlanAuthError("AUTH_NETWORK_FAILURE", operation)
        return result[0]

    def discovery(self) -> AuthReply:
        return self._request("discovery", "/.well-known/openid-configuration")

    def jwks(self) -> AuthReply:
        return self._request("jwks", "/.well-known/jwks.json")

    def exchange(self, body: bytes) -> AuthReply:
        return self._request("exchange", "/api/accounts/oauth/token", body)

    def refresh(self, body: bytes) -> AuthReply:
        return self._request("refresh", "/api/accounts/oauth/token", body)


def _object_json(raw: bytes, operation: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate")
            out[key] = value
        return out
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        if not isinstance(data, dict):
            raise ValueError("object")
        return data
    except Exception:
        raise PlanAuthError("AUTH_JSON_INVALID", operation) from None


def _text(value: Any, *, limit: int = _MAX_TOKEN, operation: str = "grant") -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise PlanAuthError("AUTH_FIELD_INVALID", operation)
    return value


def _client(value: Any) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or value == "dynamic_agent_client" or not value.isascii()
            or any(not 33 <= ord(c) <= 126 for c in value)):
        raise PlanAuthError("ISSUED_CLIENT_INVALID", "grant")
    return value


def _scopes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or len(value) > 1024:
        raise PlanAuthError("GRANTED_SCOPES_INVALID", "grant")
    scopes = value.split()
    if len(scopes) != len(set(scopes)) or not set(scopes) <= REQUESTED_SCOPES:
        raise PlanAuthError("GRANTED_SCOPES_INVALID", "grant")
    return tuple(sorted(scopes))


def _jwt_refusal(code: str, stage: str) -> PlanAuthError:
    """Fixed local stages only; never expose exception text or token material."""
    error = PlanAuthError(code, "jwt")
    error.verification_stage = stage
    return error


class JwtVerifier:
    """Select one fixed RS256 public key; PyJWT verifies signed claims."""

    def verify(self, token: str, jwks: dict[str, Any], *, audience: str,
               nonce: str | None = None, subject: str | None = None) -> dict[str, Any]:
        token = _text(token, operation="jwt")
        stage = "DEPENDENCY"
        try:
            import jwt
            from jwt.algorithms import RSAAlgorithm
            if jwt.__version__ != "2.14.0":
                raise _jwt_refusal("JWT_DEPENDENCY_MISMATCH", stage)
            stage = "HEADER"
            header = jwt.get_unverified_header(token)
            if not isinstance(header, dict) or header.get("alg") != "RS256":
                raise _jwt_refusal("JWT_HEADER_PROFILE_REFUSED", stage)
            if set(header) - {"alg", "kid", "typ"}:
                raise _jwt_refusal("JWT_HEADER_PROFILE_REFUSED", stage)
            kid = _text(header.get("kid"), limit=256, operation="jwt")
            stage = "KEY_SET"
            keys = jwks.get("keys")
            if not isinstance(keys, list) or len(keys) > 32:
                raise _jwt_refusal("JWT_KEY_SET_INVALID", stage)
            stage = "KEY_IDENTITY"
            selected = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
            if len(selected) != 1:
                raise _jwt_refusal("JWT_KEY_IDENTITY_REFUSED", stage)
            key = selected[0]
            stage = "KEY_PROFILE"
            if key.get("kty") != "RSA" or key.get("alg") != "RS256" or key.get("use") != "sig":
                raise _jwt_refusal("JWT_KEY_PROFILE_REFUSED", stage)
            if set(key) & {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}:
                raise _jwt_refusal("JWT_PRIVATE_KEY_REFUSED", stage)
            stage = "KEY_MATERIAL"
            public = RSAAlgorithm.from_jwk(json.dumps({"kty": "RSA", "n": key["n"], "e": key["e"]}))
            stage = "SIGNED_CLAIMS"
            try:
                claims = jwt.decode(token, public, algorithms=["RS256"], audience=audience,
                                    issuer=ISSUER, leeway=5,
                                    options={"require": ["iss", "aud", "exp", "iat", "sub"], "strict_aud": False})
            except jwt.exceptions.InvalidTokenError as error:
                categories = (
                    (jwt.exceptions.InvalidSignatureError, "JWT_SIGNATURE_INVALID"),
                    (jwt.exceptions.ExpiredSignatureError, "JWT_EXPIRED"),
                    (jwt.exceptions.InvalidIssuerError, "JWT_ISSUER_MISMATCH"),
                    (jwt.exceptions.ImmatureSignatureError, "JWT_NOT_YET_VALID"),
                    (jwt.exceptions.MissingRequiredClaimError, "JWT_REQUIRED_CLAIM_MISSING"),
                    (jwt.exceptions.InvalidIssuedAtError, "JWT_ISSUED_AT_INVALID"),
                    (jwt.exceptions.InvalidSubjectError, "JWT_SUBJECT_INVALID"),
                    (jwt.exceptions.InvalidJTIError, "JWT_TOKEN_ID_INVALID"),
                    (jwt.exceptions.DecodeError, "JWT_ENCODING_INVALID"),
                )
                code = next((value for kind, value in categories if isinstance(error, kind)),
                            "JWT_VERIFICATION_FAILED")
                if isinstance(error, jwt.exceptions.InvalidAudienceError):
                    # Exact fixed messages from the pinned PyJWT; never publish their text.
                    code = {"Invalid claim format in token": "JWT_AUDIENCE_MALFORMED",
                            "Audience doesn't match": "JWT_AUDIENCE_MISMATCH"}.get(
                                str(error), "JWT_AUDIENCE_REFUSAL_UNKNOWN")
                raise _jwt_refusal(code, stage) from None
            # Only the issued client is trusted; signed array membership is insufficient.
            signed_audience = claims.get("aud")
            if isinstance(signed_audience, str):
                if signed_audience != audience:
                    raise _jwt_refusal("JWT_AUDIENCE_MISMATCH", stage)
            elif isinstance(signed_audience, list) and signed_audience and all(
                    isinstance(value, str) for value in signed_audience):
                if len(signed_audience) != 1:
                    raise _jwt_refusal("JWT_AUDIENCE_ADDITIONAL_REFUSED", stage)
                if signed_audience[0] != audience:
                    raise _jwt_refusal("JWT_AUDIENCE_MISMATCH", stage)
            else:
                raise _jwt_refusal("JWT_AUDIENCE_MALFORMED", stage)
            stage = "SUBJECT"
            verified_subject = _text(claims.get("sub"), limit=4096, operation="jwt")
            if subject is not None and not hmac.compare_digest(verified_subject, subject):
                raise _jwt_refusal("JWT_SUBJECT_MISMATCH", stage)
            if nonce is not None:
                stage = "NONCE"
                returned = claims.get("nonce")
                if not isinstance(returned, str) or not hmac.compare_digest(returned, nonce):
                    raise _jwt_refusal("JWT_NONCE_MISMATCH", stage)
            return claims
        except PlanAuthError as error:
            error.verification_stage = stage
            raise
        except Exception:
            # Unclassified exceptions remain unknown, with a nonprivate stage.
            raise _jwt_refusal("JWT_VERIFICATION_FAILED", stage) from None


@dataclasses.dataclass(repr=False)
class CallbackAttempt:
    state: str
    nonce: str
    verifier: str
    redirect_uri: str
    deadline: float
    client_id: str | None = None
    used: bool = False

    def consume(self, target: str, *, host: str, peer: str, now: float) -> tuple[str, str]:
        if self.used or now >= self.deadline:
            raise PlanAuthError("CALLBACK_EXPIRED_OR_REUSED", "callback")
        try:
            uri = urlsplit(target)
            expected = urlsplit(self.redirect_uri)
        except Exception:
            raise PlanAuthError("CALLBACK_INVALID", "callback") from None
        if (len(target) > 16 * 1024 or peer != "127.0.0.1" or uri.scheme or uri.netloc
                or uri.path != "/auth/callback" or uri.fragment or host != expected.netloc):
            raise PlanAuthError("FOREIGN_CALLBACK", "callback")
        try:
            pairs = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True, max_num_fields=12)
            data = dict(pairs)
            if len(data) != len(pairs):
                raise ValueError("duplicate")
            if set(data) - {"code", "state", "client_id", "scope", "error", "error_description", "error_uri", "iss"}:
                raise ValueError("fields")
        except Exception:
            raise PlanAuthError("CALLBACK_INVALID", "callback") from None
        returned_state = data.get("state")
        if (not isinstance(returned_state, str) or len(returned_state) > 256
                or not returned_state.isascii() or not hmac.compare_digest(returned_state, self.state)):
            raise PlanAuthError("CALLBACK_STATE_MISMATCH", "callback")
        self.used = True
        if "error" in data:
            raise PlanAuthError("OWNER_AUTHORIZATION_DENIED", "callback")
        if "iss" in data and data["iss"] != ISSUER:
            raise PlanAuthError("CALLBACK_ISSUER_MISMATCH", "callback")
        issued = self.client_id
        if issued is None:
            issued = _client(data.get("client_id"))
        elif "client_id" in data and data["client_id"] != issued:
            raise PlanAuthError("CALLBACK_CLIENT_MISMATCH", "callback")
        return _text(data.get("code"), limit=8192, operation="callback"), issued


class _PrivateStore:
    def __init__(self, project_root: Path):
        self.root = project_root

    @contextlib.contextmanager
    def locked(self, *, create: bool = False):
        if not self.root.is_absolute() or ".." in self.root.parts:
            raise PlanAuthError("PRIVATE_PATH_REFUSED", "store")
        # Inspect ancestors without resolving away symlinks.
        current = Path(self.root.anchor)
        for part in self.root.parts[1:]:
            current /= part
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise PlanAuthError("PRIVATE_PATH_REFUSED", "store")
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        lock_fd = None
        try:
            for name in PRIVATE_RELATIVE.parts:
                try:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise PlanAuthError("AUTHORIZATION_REQUIRED", "store") from None
                    os.mkdir(name, 0o700, dir_fd=fd)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                info = os.fstat(child)
                if info.st_uid != os.getuid() or (name != "state" and stat.S_IMODE(info.st_mode) != 0o700):
                    os.close(child)
                    raise PlanAuthError("PRIVATE_DIRECTORY_PERMISSIONS", "store")
                os.close(fd)
                fd = child
            lock_fd = os.open("grant.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
            self._file(lock_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PlanAuthError("CONNECTION_BUSY", "store") from None
            yield fd
        except PlanAuthError:
            raise
        except Exception:
            raise PlanAuthError("PRIVATE_STORE_FAILURE", "store") from None
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(fd)

    @staticmethod
    def _file(fd: int) -> None:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise PlanAuthError("PRIVATE_FILE_PERMISSIONS", "store")

    def read(self, fd: int, name: str) -> dict[str, Any] | None:
        if name not in _PRIVATE_FILENAMES:
            raise PlanAuthError("PRIVATE_FILENAME_REFUSED", "store")
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            return None
        try:
            self._file(file_fd)
            with os.fdopen(file_fd, "rb", closefd=False) as stream:
                raw = stream.read(_MAX_JSON + 1)
            if len(raw) > _MAX_JSON:
                raise PlanAuthError("PRIVATE_RECORD_BOUND", "store")
            return _object_json(raw, "store")
        finally:
            os.close(file_fd)

    def write(self, fd: int, name: str, data: dict[str, Any]) -> None:
        if name not in _PRIVATE_FILENAMES:
            raise PlanAuthError("PRIVATE_FILENAME_REFUSED", "store")
        self.read(fd, name)  # Refuse an existing symlink, hardlink, or permissive target.
        raw = (json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if len(raw) > _MAX_JSON:
            raise PlanAuthError("PRIVATE_RECORD_BOUND", "store")
        temporary = ".new-" + secrets.token_hex(16)
        file_fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(file_fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
            os.fsync(file_fd)
            os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(file_fd)
            try:
                os.unlink(temporary, dir_fd=fd)
            except FileNotFoundError:
                pass


class PlanAuth:
    """One owned account/workspace registration; no native Codex credential access."""

    def __init__(self, project_root: Path | str, *, http: AuthHttp | None = None,
                 jwt_verifier: JwtVerifier | None = None, clock: Callable[[], float] | None = None):
        from config.application_profile_gate import require_external_owner
        require_external_owner(project_root,'AUTH')
        self.store = _PrivateStore(Path(project_root))
        self.http = http if http is not None else FixedAuthHttp()
        self.verifier = jwt_verifier if jwt_verifier is not None else JwtVerifier()
        self.clock = clock if clock is not None else time.time
        self._jwks: dict[str, Any] | None = None
        self._jwks_at = 0.0

    def public_observations(self) -> dict[str, Any]:
        """Snapshot only; it does not read credentials, refresh, or start I/O."""
        if isinstance(self.http, FixedAuthHttp):
            return self.http.public_observations()
        return {"schema": "radik.plan_auth_http_observations.v01",
                "basis": "INJECTED_OFFLINE_HTTP_NOT_OWNER_NETWORK_WITNESS",
                "requests": [], "operation_totals": {}, "dropped_rows": 0}

    def _keys(self) -> dict[str, Any]:
        now = self.clock()
        if self._jwks is not None and now - self._jwks_at < 300:
            return self._jwks
        discovery = self.http.discovery()
        if discovery.status != 200 or any(discovery.data.get(key) != value for key, value in {
            "issuer": ISSUER, "authorization_endpoint": AUTHORIZE_ENDPOINT,
            "token_endpoint": TOKEN_ENDPOINT, "jwks_uri": JWKS_ENDPOINT,
        }.items()) or discovery.data.get("id_token_signing_alg_values_supported") != ["RS256"]:
            raise PlanAuthError("DISCOVERY_PROFILE_MISMATCH", "discovery", http_status=discovery.status)
        reply = self.http.jwks()
        if reply.status != 200 or not isinstance(reply.data.get("keys"), list):
            raise PlanAuthError("JWKS_UNAVAILABLE", "jwks", http_status=reply.status)
        self._jwks = reply.data
        self._jwks_at = now
        return self._jwks

    def _record(self, raw: dict[str, Any] | None) -> dict[str, Any]:
        if raw is None:
            raise PlanAuthError("AUTHORIZATION_REQUIRED", "grant")
        if set(raw) != _RECORD_FIELDS or raw.get("schema") != "radik.private_plan_grant.v01" or raw.get("issuer") != ISSUER:
            raise PlanAuthError("PRIVATE_GRANT_INVALID", "grant")
        _client(raw.get("client_id"))
        _text(raw.get("subject"), limit=4096)
        for key in ("access_token", "id_token", "id_nonce", "host_id"):
            _text(raw.get(key))
        connection = raw.get("connection_id")
        try:
            if not isinstance(connection, str) or connection != "radik-plan:" + str(uuid.UUID(connection.removeprefix("radik-plan:"))):
                raise ValueError("connection")
        except Exception:
            raise PlanAuthError("PRIVATE_GRANT_INVALID", "grant") from None
        if not isinstance(raw.get("refresh_token"), str) or len(raw["refresh_token"]) > _MAX_TOKEN:
            raise PlanAuthError("PRIVATE_GRANT_INVALID", "grant")
        for key in ("expires_at", "earliest_refresh_at", "saved_at"):
            if type(raw.get(key)) is not int or raw[key] < 0:
                raise PlanAuthError("PRIVATE_GRANT_INVALID", "grant")
        if not isinstance(raw.get("scopes"), list) or tuple(raw["scopes"]) != _scopes(" ".join(raw["scopes"])):
            raise PlanAuthError("PRIVATE_GRANT_INVALID", "grant")
        if raw.get("grant_status") not in {"ACTIVE", "PLAN_SCOPE_MISSING", "REFRESH_IN_PROGRESS", "REFRESH_UNCERTAIN", "OWNER_REAUTHORIZATION_REQUIRED"}:
            raise PlanAuthError("PRIVATE_GRANT_INVALID", "grant")
        return raw

    @staticmethod
    def _host_record(raw: dict[str, Any] | None) -> str:
        if raw is None:
            raise PlanAuthError("PRIVATE_HOST_INVALID", "store")
        if set(raw) != {"schema", "host_id"} or raw["schema"] != "radik.private_plan_host.v01":
            raise PlanAuthError("PRIVATE_HOST_INVALID", "store")
        value = _text(raw["host_id"], limit=64)
        try:
            if value != "urn:uuid:" + str(uuid.UUID(value.removeprefix("urn:uuid:"))):
                raise ValueError("host")
        except Exception:
            raise PlanAuthError("PRIVATE_HOST_INVALID", "store") from None
        return value

    def _host(self, fd: int) -> str:
        raw = self.store.read(fd, "host.json")
        if raw is None:
            raw = {"schema": "radik.private_plan_host.v01", "host_id": "urn:uuid:" + str(uuid.uuid4())}
            self.store.write(fd, "host.json", raw)
        return self._host_record(raw)

    @staticmethod
    def _registration(raw: dict[str, Any] | None) -> dict[str, Any] | None:
        if raw is None:
            return None
        if (set(raw) != _REGISTRATION_FIELDS or raw.get("schema") != "radik.private_plan_registration.v01"
                or raw.get("issuer") != ISSUER):
            raise PlanAuthError("PRIVATE_REGISTRATION_INVALID", "registration")
        PlanAuth._host_record({"schema": "radik.private_plan_host.v01", "host_id": raw.get("host_id")})
        _client(raw.get("client_id"))
        for field in ("created_at", "updated_at"):
            if type(raw.get(field)) is not int or raw[field] < 0:
                raise PlanAuthError("PRIVATE_REGISTRATION_INVALID", "registration")
        if (raw["updated_at"] < raw["created_at"]
                or raw.get("registration_status") not in {"PENDING_EXCHANGE", "BOUND"}
                or raw.get("identity_status") not in {"UNVERIFIED", "VERIFIED"}):
            raise PlanAuthError("PRIVATE_REGISTRATION_INVALID", "registration")
        if raw["identity_status"] == "UNVERIFIED":
            if raw["subject"] is not None or raw["connection_id"] is not None or raw["registration_status"] == "BOUND":
                raise PlanAuthError("PRIVATE_REGISTRATION_INVALID", "registration")
        else:
            _text(raw["subject"], limit=4096, operation="registration")
            connection = raw["connection_id"]
            try:
                if not isinstance(connection, str) or connection != "radik-plan:" + str(uuid.UUID(connection.removeprefix("radik-plan:"))):
                    raise ValueError("connection")
            except Exception:
                raise PlanAuthError("PRIVATE_REGISTRATION_INVALID", "registration") from None
        return raw

    @staticmethod
    def _check_registration(raw: dict[str, Any], host_id: str, prior: dict[str, Any] | None) -> None:
        if raw["host_id"] != host_id or (prior is not None and (
                prior["host_id"] != host_id or raw["client_id"] != prior["client_id"])):
            raise PlanAuthError("REGISTRATION_BINDING_MISMATCH", "registration")
        if raw["identity_status"] == "VERIFIED" and (prior is None or (
                raw["subject"] != prior["subject"] or raw["connection_id"] != prior["connection_id"])):
            raise PlanAuthError("REGISTRATION_BINDING_MISMATCH", "registration")

    def pending_registration_status(self) -> dict[str, Any]:
        """Read protected registration state without HTTP, refresh, or grant authority."""
        base = {"schema": "radik.plan_pending_registration_status.v01", "registration_present": False,
                "identity_status": "UNVERIFIED", "explicit_recovery_required": False,
                "recovery_available": False}
        try:
            with self.store.locked() as fd:
                registration = self._registration(self.store.read(fd, "registration.json"))
                if registration is None:
                    return dict(base, status="REGISTRATION_ABSENT")
                host_id = self._host_record(self.store.read(fd, "host.json"))
                prior_raw = self.store.read(fd, "connection.json")
                prior = self._record(prior_raw) if prior_raw is not None else None
                self._check_registration(registration, host_id, prior)
                pending = registration["registration_status"] == "PENDING_EXCHANGE"
                return dict(base, status="EXPLICIT_OWNER_RECOVERY_REQUIRED" if pending else "REGISTRATION_BOUND",
                            registration_present=True, identity_status=registration["identity_status"],
                            explicit_recovery_required=pending, recovery_available=True)
        except PlanAuthError as error:
            if error.code == "AUTHORIZATION_REQUIRED" and error.operation == "store":
                return dict(base, status="REGISTRATION_ABSENT")
            return dict(base, status=error.code, registration_present=None, identity_status="UNKNOWN",
                        explicit_recovery_required=True, operation=error.operation)

    def _authorization_context(self, fd: int, *, recovery: bool) -> tuple[str, dict[str, Any] | None, str | None, str | None]:
        host_id = self._host(fd)
        prior_raw = self.store.read(fd, "connection.json")
        prior = self._record(prior_raw) if prior_raw is not None else None
        registration = self._registration(self.store.read(fd, "registration.json"))
        if prior is not None and prior["host_id"] != host_id:
            raise PlanAuthError("HOST_BINDING_MISMATCH", "authorize")
        if registration is not None:
            self._check_registration(registration, host_id, prior)
        if (prior is not None or registration is not None) and not recovery:
            raise PlanAuthError("EXPLICIT_OWNER_RECOVERY_REQUIRED", "authorize")
        if recovery and prior is None and registration is None:
            raise PlanAuthError("OWNER_RECOVERY_UNAVAILABLE", "authorize")
        client_id = registration["client_id"] if registration else prior["client_id"] if prior else None
        # A retained issued registration is not a verified identity hint.
        hint = prior["id_token"] if prior is not None and (
            registration is None or registration["identity_status"] == "VERIFIED") else None
        return host_id, prior, client_id, hint

    @staticmethod
    def _authorization_attempt(*, redirect_uri: str, timeout_seconds: int, host_id: str,
                               client_id: str | None, id_token_hint: str | None) -> tuple[CallbackAttempt, dict[str, str]]:
        if type(timeout_seconds) is not int or not 30 <= timeout_seconds <= 900:
            raise PlanAuthError("AUTHORIZATION_TIMEOUT_INVALID", "authorize")
        try:
            target = urlsplit(redirect_uri)
            if (target.scheme != "http" or target.hostname != "127.0.0.1" or target.username is not None
                    or target.password is not None or target.port is None or not 1 <= target.port <= 65535
                    or target.path != "/auth/callback" or target.query or target.fragment):
                raise ValueError("redirect")
        except Exception:
            raise PlanAuthError("CALLBACK_URI_INVALID", "authorize") from None
        if client_id is not None:
            _client(client_id)
        verifier = secrets.token_urlsafe(64)
        nonce = secrets.token_urlsafe(32)
        attempt = CallbackAttempt(secrets.token_urlsafe(32), nonce, verifier, redirect_uri,
                                  time.monotonic() + timeout_seconds, client_id)
        query = {"client_id": client_id or "dynamic_agent_client", "ext_agent_host_id": host_id,
                 "response_type": "code", "redirect_uri": redirect_uri, "scope": " ".join(sorted(REQUESTED_SCOPES)),
                 "resource": RESOURCE, "state": attempt.state, "nonce": nonce, "code_challenge_method": "S256",
                 "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")}
        if client_id is None:
            query["agent_name_hint"] = "Radik"
        elif id_token_hint is not None:
            query["id_token_hint"] = id_token_hint
        return attempt, query

    def _exchange_callback(self, fd: int, attempt: CallbackAttempt, value: tuple[str, str], *,
                           host_id: str, prior: dict[str, Any] | None) -> dict[str, Any]:
        """Persist the validated callback's issued registration before any exchange dispatch."""
        if not attempt.used:
            raise PlanAuthError("CALLBACK_NOT_CONSUMED", "exchange")
        code, issued = value
        _text(code, limit=8192, operation="callback")
        _client(issued)
        registration = self._registration(self.store.read(fd, "registration.json"))
        if registration is not None:
            self._check_registration(registration, host_id, prior)
        selected = registration["client_id"] if registration else prior["client_id"] if prior else attempt.client_id
        if ((selected is not None and selected != issued)
                or (attempt.client_id is not None and attempt.client_id != issued)):
            raise PlanAuthError("CALLBACK_CLIENT_MISMATCH", "callback")
        now = int(self.clock())
        retained = {"schema": "radik.private_plan_registration.v01", "host_id": host_id, "issuer": ISSUER,
                    "client_id": issued, "registration_status": "PENDING_EXCHANGE",
                    "identity_status": "VERIFIED" if prior is not None else "UNVERIFIED",
                    "subject": prior["subject"] if prior else None, "connection_id": prior["connection_id"] if prior else None,
                    "created_at": registration["created_at"] if registration else now, "updated_at": now}
        self._registration(retained)
        self.store.write(fd, "registration.json", retained)
        body = urlencode({"grant_type": "authorization_code", "client_id": issued, "code": code,
                          "code_verifier": attempt.verifier, "redirect_uri": attempt.redirect_uri,
                          "resource": RESOURCE}).encode("ascii")
        reply = self.http.exchange(body)
        updated = self._replacement(reply, client_id=issued, nonce=attempt.nonce, host_id=host_id, prior=prior)
        self.store.write(fd, "connection.json", updated)
        bound = dict(retained, identity_status="VERIFIED", subject=updated["subject"],
                     connection_id=updated["connection_id"], updated_at=int(self.clock()),
                     registration_status="BOUND" if updated["grant_status"] == "ACTIVE" else "PENDING_EXCHANGE")
        self._registration(bound)
        self.store.write(fd, "registration.json", bound)
        if updated["grant_status"] != "ACTIVE":
            raise PlanAuthError("AUTHORIZATION_REQUIRED", "scopes")
        return PlanGrant(updated["access_token"], updated["connection_id"], tuple(updated["scopes"]), updated["expires_at"]).public_receipt()

    def _replacement(self, reply: AuthReply, *, client_id: str, nonce: str,
                     host_id: str, prior: dict[str, Any] | None, refresh: bool = False) -> dict[str, Any]:
        if reply.status != 200:
            error = reply.data.get("error")
            code = "OWNER_REAUTHORIZATION_REQUIRED" if error in {"invalid_grant", "access_denied", "invalid_client"} else "AUTH_SERVER_REFUSAL"
            raise PlanAuthError(code, "refresh" if refresh else "exchange", http_status=reply.status)
        data = reply.data
        if data.get("token_type") != "Bearer":
            raise PlanAuthError("TOKEN_TYPE_INVALID", "grant")
        scopes = (tuple(prior["scopes"]) if refresh and prior is not None and "scope" not in data
                  else _scopes(data.get("scope")))
        if not IDENTITY_SCOPES <= set(scopes):
            raise PlanAuthError("IDENTITY_SCOPES_MISSING", "grant")
        token = data.get("id_token")
        if token is None and refresh and prior is not None:
            token = prior["id_token"]
            subject = prior["subject"]
        else:
            claims = self.verifier.verify(_text(token), self._keys(), audience=client_id,
                                          nonce=None if refresh else nonce,
                                          subject=prior["subject"] if prior else None)
            if refresh and "nonce" in claims:
                returned_nonce = claims["nonce"]
                if (not isinstance(returned_nonce, str) or not returned_nonce.isascii()
                        or not hmac.compare_digest(returned_nonce, nonce)):
                    raise PlanAuthError("JWT_VERIFICATION_FAILED", "jwt")
            subject = claims["sub"]
        expires_in = data.get("expires_in")
        earliest = data.get("earliest_refresh_at", 0)
        if type(expires_in) is not int or not 1 <= expires_in <= 86400 or type(earliest) is not int or earliest < 0:
            raise PlanAuthError("TOKEN_EXPIRY_INVALID", "grant")
        now = int(self.clock())
        issued_at_bound = reply.request_started_at if reply.request_started_at is not None else now
        if type(issued_at_bound) is not int or issued_at_bound > now or issued_at_bound < now - 120:
            raise PlanAuthError("TOKEN_RESPONSE_TIME_INVALID", "grant")
        renewable = _text(data.get("refresh_token")) if "offline_access" in scopes else ""
        raw = {
            "schema": "radik.private_plan_grant.v01",
            "connection_id": prior["connection_id"] if prior else "radik-plan:" + str(uuid.uuid4()),
            "host_id": host_id, "issuer": ISSUER, "client_id": client_id, "subject": subject,
            "access_token": _text(data.get("access_token")), "refresh_token": renewable,
            "id_token": token, "id_nonce": nonce, "scopes": list(scopes),
            "expires_at": issued_at_bound + expires_in, "earliest_refresh_at": earliest, "saved_at": now,
            "grant_status": "ACTIVE" if REQUESTED_SCOPES <= set(scopes) else "PLAN_SCOPE_MISSING",
        }
        return raw

    def _refresh_locked(self, fd: int, raw: dict[str, Any]) -> dict[str, Any]:
        if not raw["refresh_token"]:
            raise PlanAuthError("OWNER_REAUTHORIZATION_REQUIRED", "refresh")
        if int(self.clock()) < raw["earliest_refresh_at"]:
            raise PlanAuthError("REFRESH_NOT_YET_ALLOWED", "refresh")
        pending = dict(raw, grant_status="REFRESH_IN_PROGRESS")
        self.store.write(fd, "connection.json", pending)
        body = urlencode({"grant_type": "refresh_token", "client_id": raw["client_id"],
                          "refresh_token": raw["refresh_token"], "resource": RESOURCE}).encode("ascii")
        try:
            reply = self.http.refresh(body)
            updated = self._replacement(reply, client_id=raw["client_id"], nonce=raw["id_nonce"],
                                        host_id=raw["host_id"], prior=raw, refresh=True)
            self.store.write(fd, "connection.json", updated)
            return updated
        except Exception as error:
            terminal = isinstance(error, PlanAuthError) and error.code == "OWNER_REAUTHORIZATION_REQUIRED"
            self.store.write(fd, "connection.json", dict(raw, grant_status="OWNER_REAUTHORIZATION_REQUIRED" if terminal else "REFRESH_UNCERTAIN"))
            if terminal:
                raise error
            raise PlanAuthError("REFRESH_UNCERTAIN", "refresh") from None

    def access_for_plan(self) -> PlanGrant:
        with self.store.locked() as fd:
            registration = self._registration(self.store.read(fd, "registration.json"))
            prior_raw = self.store.read(fd, "connection.json")
            raw = self._record(prior_raw) if prior_raw is not None else None
            host_id = self._host_record(self.store.read(fd, "host.json"))
            if registration is not None:
                self._check_registration(registration, host_id, raw)
                # A crash after the connection write still requires explicit owner recovery.
                if registration["registration_status"] != "BOUND":
                    raise PlanAuthError("EXPLICIT_OWNER_RECOVERY_REQUIRED", "grant")
                # A visible binding whose writer failed after replace is confirmed under this lock.
                try:
                    os.fsync(fd)
                except Exception:
                    raise PlanAuthError("REGISTRATION_BINDING_UNCERTAIN", "registration") from None
            raw = self._record(raw)
            if raw["host_id"] != host_id:
                raise PlanAuthError("HOST_BINDING_MISMATCH", "grant")
            if raw["grant_status"] in {"REFRESH_IN_PROGRESS", "REFRESH_UNCERTAIN"}:
                raise PlanAuthError("REFRESH_UNCERTAIN", "refresh")
            if raw["grant_status"] == "OWNER_REAUTHORIZATION_REQUIRED":
                raise PlanAuthError("OWNER_REAUTHORIZATION_REQUIRED", "grant")
            if not REQUESTED_SCOPES <= set(raw["scopes"]):
                raise PlanAuthError("AUTHORIZATION_REQUIRED", "scopes")
            if raw["expires_at"] <= int(self.clock()) + 120:
                raw = self._refresh_locked(fd, raw)
            if raw["expires_at"] <= int(self.clock()) + 15 or not REQUESTED_SCOPES <= set(raw["scopes"]):
                raise PlanAuthError("AUTHORIZATION_REQUIRED", "grant")
            return PlanGrant(raw["access_token"], raw["connection_id"], tuple(raw["scopes"]), raw["expires_at"])

    def connection_receipt(self) -> dict[str, Any]:
        try:
            return self.access_for_plan().public_receipt()
        except PlanAuthError as error:
            return {"schema": "radik.plan_connection_receipt.v01", "status": error.code,
                    "operation": error.operation, "http_status": error.http_status}

    def authorize_owner(self, *, recovery: bool = False,
                        browser_open: Callable[[str], bool] | None = None,
                        progress: Callable[[str], None] | None = None,
                        timeout_seconds: int = 600) -> dict[str, Any]:
        """Only the reviewed owner-started entry calls this explicit browser operation."""
        if type(timeout_seconds) is not int or not 30 <= timeout_seconds <= 900:
            raise PlanAuthError("AUTHORIZATION_TIMEOUT_INVALID", "authorize")
        with self.store.locked(create=True) as fd:
            host_id, prior, client_id, hint = self._authorization_context(fd, recovery=recovery)
            result: list[tuple[str, str] | PlanAuthError] = []
            attempt: CallbackAttempt | None = None
            class QuietServer(http.server.HTTPServer):
                def handle_error(server_self, _request, _client_address):
                    result.append(PlanAuthError("CALLBACK_TRANSPORT_FAILURE", "callback"))
            class Handler(http.server.BaseHTTPRequestHandler):
                def setup(handler):
                    super().setup()
                    handler.connection.settimeout(5)
                    lifetime = min(5.0, max(0.01, attempt.deadline - time.monotonic())) if attempt else 0.01
                    def close_callback_socket():
                        try:
                            handler.connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    handler.callback_timer = threading.Timer(lifetime, close_callback_socket)
                    handler.callback_timer.daemon = True
                    handler.callback_timer.start()
                def finish(handler):
                    try:
                        super().finish()
                    finally:
                        handler.callback_timer.cancel()
                def log_message(handler, *_args):
                    pass
                def do_GET(handler):
                    nonlocal attempt
                    try:
                        if attempt is None:
                            raise PlanAuthError("CALLBACK_NOT_READY", "callback")
                        value = attempt.consume(handler.path, host=handler.headers.get("Host", ""),
                                                peer=handler.client_address[0], now=time.monotonic())
                        result.append(value)
                        status = 200
                    except PlanAuthError as error:
                        if attempt is not None and attempt.used:
                            result.append(error)
                        status = 400
                    handler.send_response(status)
                    handler.send_header("Content-Type", "text/plain; charset=utf-8")
                    handler.send_header("Cache-Control", "no-store")
                    handler.end_headers()
                    handler.wfile.write("Вернитесь в консоль Radik.".encode("utf-8"))
            server = None
            try:
                server = QuietServer(("127.0.0.1", 0), Handler)
                server.timeout = 1
                redirect = "http://127.0.0.1:" + str(server.server_port) + "/auth/callback"
                attempt, query = self._authorization_attempt(redirect_uri=redirect, timeout_seconds=timeout_seconds,
                                                              host_id=host_id, client_id=client_id, id_token_hint=hint)
                if progress is not None:
                    progress("SEPARATE_RADIK_OWNER_AUTHORIZATION_REQUIRED")
                if browser_open is None:
                    import webbrowser
                    browser_open = webbrowser.open_new_tab
                if not browser_open(AUTHORIZE_ENDPOINT + "?" + urlencode(query)):
                    raise PlanAuthError("SYSTEM_BROWSER_OPEN_FAILED", "authorize")
                if progress is not None:
                    progress("OWNER_BROWSER_LOGIN_PENDING")
                while not result and time.monotonic() < attempt.deadline:
                    server.handle_request()
                if not result:
                    raise PlanAuthError("OWNER_AUTHORIZATION_TIMED_OUT", "authorize")
                value = result[0]
                if isinstance(value, PlanAuthError):
                    raise value
                return self._exchange_callback(fd, attempt, value, host_id=host_id, prior=prior)
            except PlanAuthError:
                raise
            except Exception:
                raise PlanAuthError("OWNER_AUTHORIZATION_FAILED", "authorize") from None
            finally:
                if server is not None:
                    try:
                        server.server_close()
                    except Exception:
                        raise PlanAuthError("CALLBACK_CLEANUP_UNCERTAIN", "authorize") from None
