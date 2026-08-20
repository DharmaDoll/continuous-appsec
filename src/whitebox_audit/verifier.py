"""Strict verifier policy, runtime adapter, and HTTP case validation."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, cast
from urllib.parse import unquote, urlsplit

from whitebox_audit.models import SCHEMA_VERSION, VerificationCase

_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_IMAGE_DIGEST: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._/:+-]{0,500}@sha256:[0-9a-f]{64}\Z"
)
_JSON_PATH: Final[re.Pattern[str]] = re.compile(
    r"\$(?:(?:\.[A-Za-z_][A-Za-z0-9_-]{0,63})|(?:\[[0-9]{1,4}\])){1,16}\Z"
)
_INVALID_PERCENT_ESCAPE: Final[re.Pattern[str]] = re.compile(r"%(?![0-9A-Fa-f]{2})")
_HARD_HTTP_METHODS: Final[frozenset[str]] = frozenset(
    {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
)
_HARD_HTTP_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "accept",
        "authorization",
        "content-type",
        "if-match",
        "x-csrf-token",
        "x-requested-with",
    }
)
_MAX_TIMEOUT_SECONDS: Final[int] = 300
_MAX_MEMORY_BYTES: Final[int] = 8 * 1024 * 1024 * 1024
_MAX_CPU_COUNT: Final[float] = 8.0
_MAX_PIDS: Final[int] = 1024
_MAX_REQUEST_BODY_BYTES: Final[int] = 1024 * 1024
_MAX_RESPONSE_BODY_BYTES: Final[int] = 4 * 1024 * 1024
_MAX_JSON_ASSERTIONS: Final[int] = 32


def _strict_keys(
    value: Mapping[str, object],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    label: str,
) -> None:
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        missing = sorted(required - keys)
        unknown = sorted(keys - required - optional)
        raise ValueError(f"{label} fields are invalid (missing={missing}, unknown={unknown})")


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return {cast(str, key): item for key, item in value.items()}


def _string(value: object, label: str, *, maximum: int = 2_048) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{label} must be a bounded non-empty string")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def _integer(value: object, label: str, *, minimum: int = 1, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _number(value: object, label: str, *, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or not minimum <= float(value) <= maximum
    ):
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return float(value)


def _identifier(value: object, label: str) -> str:
    result = _string(value, label, maximum=64)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ValueError(f"{label} must be a lowercase identifier")
    return result


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty string array")
    result = tuple(_identifier(item, label) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must not contain duplicates")
    return result


def _json_copy(value: object, label: str) -> object:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} must contain strict JSON data") from error
    return decoded


def _fingerprint(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_digest_image(value: str, label: str = "image") -> str:
    """Require an immutable OCI/Docker image reference without resolving it."""

    if _IMAGE_DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must use an immutable sha256 digest")
    return value


@dataclass(frozen=True, slots=True)
class VerifierPolicy:
    schema_version: int
    network_default: str
    internal_network_allowed: bool
    external_egress_allowed: bool
    root_read_only: bool
    target_read_only: bool
    case_read_only: bool
    output_only_writable: bool
    docker_socket_allowed: bool
    host_home_allowed: bool
    drop_all_capabilities: bool
    no_new_privileges: bool
    max_timeout_seconds: int
    max_memory_bytes: int
    max_cpu_count: float
    max_pids: int
    max_request_body_bytes: int
    max_response_body_bytes: int
    max_json_assertions: int
    allowed_http_methods: tuple[str, ...]
    allowed_http_headers: tuple[str, ...]
    require_image_digest: bool

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported verifier policy schema version")
        if self.network_default != "none" or self.external_egress_allowed:
            raise ValueError("verifier policy must deny external network by default")
        if not all(
            (
                self.root_read_only,
                self.target_read_only,
                self.case_read_only,
                self.output_only_writable,
                self.drop_all_capabilities,
                self.no_new_privileges,
                self.require_image_digest,
            )
        ):
            raise ValueError("verifier policy cannot weaken mandatory isolation")
        if self.docker_socket_allowed or self.host_home_allowed:
            raise ValueError("verifier policy cannot expose host authority")
        _integer(
            self.max_timeout_seconds,
            "limits.timeout_seconds",
            maximum=_MAX_TIMEOUT_SECONDS,
        )
        _integer(self.max_memory_bytes, "limits.memory_bytes", maximum=_MAX_MEMORY_BYTES)
        _number(self.max_cpu_count, "limits.cpu_count", minimum=0.1, maximum=_MAX_CPU_COUNT)
        _integer(self.max_pids, "limits.pids", maximum=_MAX_PIDS)
        _integer(
            self.max_request_body_bytes,
            "limits.request_body_bytes",
            maximum=_MAX_REQUEST_BODY_BYTES,
        )
        _integer(
            self.max_response_body_bytes,
            "limits.response_body_bytes",
            maximum=_MAX_RESPONSE_BODY_BYTES,
        )
        _integer(
            self.max_json_assertions,
            "limits.json_assertions",
            maximum=_MAX_JSON_ASSERTIONS,
        )
        if not self.allowed_http_methods or not set(self.allowed_http_methods).issubset(
            _HARD_HTTP_METHODS
        ):
            raise ValueError("policy contains an unsupported HTTP method")
        if len(set(self.allowed_http_methods)) != len(self.allowed_http_methods):
            raise ValueError("policy HTTP methods must be unique")
        if not self.allowed_http_headers or not set(self.allowed_http_headers).issubset(
            _HARD_HTTP_HEADERS
        ):
            raise ValueError("policy contains an unsupported HTTP header")
        if len(set(self.allowed_http_headers)) != len(self.allowed_http_headers):
            raise ValueError("policy HTTP headers must be unique")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "network": {
                "default": self.network_default,
                "internal_allowed": self.internal_network_allowed,
                "external_egress": self.external_egress_allowed,
            },
            "filesystem": {
                "root_read_only": self.root_read_only,
                "target_read_only": self.target_read_only,
                "case_read_only": self.case_read_only,
                "output_only_writable": self.output_only_writable,
                "docker_socket": self.docker_socket_allowed,
                "host_home": self.host_home_allowed,
            },
            "capabilities": {
                "drop_all": self.drop_all_capabilities,
                "no_new_privileges": self.no_new_privileges,
            },
            "limits": {
                "timeout_seconds": self.max_timeout_seconds,
                "memory_bytes": self.max_memory_bytes,
                "cpu_count": self.max_cpu_count,
                "pids": self.max_pids,
                "request_body_bytes": self.max_request_body_bytes,
                "response_body_bytes": self.max_response_body_bytes,
                "json_assertions": self.max_json_assertions,
            },
            "http": {
                "methods": list(self.allowed_http_methods),
                "headers": list(self.allowed_http_headers),
            },
            "image": {"require_digest": self.require_image_digest},
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.to_dict())


def parse_verifier_policy(document: Mapping[str, object]) -> VerifierPolicy:
    _strict_keys(
        document,
        required=frozenset(
            {"schema_version", "network", "filesystem", "capabilities", "limits", "http", "image"}
        ),
        label="verifier policy",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported verifier policy schema version")
    network = _object(document["network"], "network")
    filesystem = _object(document["filesystem"], "filesystem")
    capabilities = _object(document["capabilities"], "capabilities")
    limits = _object(document["limits"], "limits")
    http = _object(document["http"], "http")
    image = _object(document["image"], "image")
    _strict_keys(
        network,
        required=frozenset({"default", "internal_allowed", "external_egress"}),
        label="network",
    )
    _strict_keys(
        filesystem,
        required=frozenset(
            {
                "root_read_only",
                "target_read_only",
                "case_read_only",
                "output_only_writable",
                "docker_socket",
                "host_home",
            }
        ),
        label="filesystem",
    )
    _strict_keys(
        capabilities,
        required=frozenset({"drop_all", "no_new_privileges"}),
        label="capabilities",
    )
    _strict_keys(
        limits,
        required=frozenset(
            {
                "timeout_seconds",
                "memory_bytes",
                "cpu_count",
                "pids",
                "request_body_bytes",
                "response_body_bytes",
                "json_assertions",
            }
        ),
        label="limits",
    )
    _strict_keys(http, required=frozenset({"methods", "headers"}), label="http")
    _strict_keys(image, required=frozenset({"require_digest"}), label="image")
    method_values = http["methods"]
    header_values = http["headers"]
    if not isinstance(method_values, list) or any(
        not isinstance(item, str) for item in method_values
    ):
        raise ValueError("http.methods must be a string array")
    if not isinstance(header_values, list) or any(
        not isinstance(item, str) for item in header_values
    ):
        raise ValueError("http.headers must be a string array")
    methods = tuple(cast(str, item).upper() for item in method_values)
    headers = tuple(cast(str, item).lower() for item in header_values)
    return VerifierPolicy(
        schema_version=SCHEMA_VERSION,
        network_default=_string(network["default"], "network.default", maximum=20),
        internal_network_allowed=_bool(network["internal_allowed"], "network.internal_allowed"),
        external_egress_allowed=_bool(network["external_egress"], "network.external_egress"),
        root_read_only=_bool(filesystem["root_read_only"], "filesystem.root_read_only"),
        target_read_only=_bool(filesystem["target_read_only"], "filesystem.target_read_only"),
        case_read_only=_bool(filesystem["case_read_only"], "filesystem.case_read_only"),
        output_only_writable=_bool(
            filesystem["output_only_writable"], "filesystem.output_only_writable"
        ),
        docker_socket_allowed=_bool(filesystem["docker_socket"], "filesystem.docker_socket"),
        host_home_allowed=_bool(filesystem["host_home"], "filesystem.host_home"),
        drop_all_capabilities=_bool(capabilities["drop_all"], "capabilities.drop_all"),
        no_new_privileges=_bool(
            capabilities["no_new_privileges"], "capabilities.no_new_privileges"
        ),
        max_timeout_seconds=_integer(
            limits["timeout_seconds"], "limits.timeout_seconds", maximum=_MAX_TIMEOUT_SECONDS
        ),
        max_memory_bytes=_integer(
            limits["memory_bytes"], "limits.memory_bytes", maximum=_MAX_MEMORY_BYTES
        ),
        max_cpu_count=_number(
            limits["cpu_count"], "limits.cpu_count", minimum=0.1, maximum=_MAX_CPU_COUNT
        ),
        max_pids=_integer(limits["pids"], "limits.pids", maximum=_MAX_PIDS),
        max_request_body_bytes=_integer(
            limits["request_body_bytes"],
            "limits.request_body_bytes",
            maximum=_MAX_REQUEST_BODY_BYTES,
        ),
        max_response_body_bytes=_integer(
            limits["response_body_bytes"],
            "limits.response_body_bytes",
            maximum=_MAX_RESPONSE_BODY_BYTES,
        ),
        max_json_assertions=_integer(
            limits["json_assertions"],
            "limits.json_assertions",
            maximum=_MAX_JSON_ASSERTIONS,
        ),
        allowed_http_methods=methods,
        allowed_http_headers=headers,
        require_image_digest=_bool(image["require_digest"], "image.require_digest"),
    )


@dataclass(frozen=True, slots=True)
class RuntimeAdapter:
    schema_version: int
    name: str
    image: str
    command_id: str
    service_host: str
    service_port: int
    health_path: str
    health_timeout_seconds: int
    fixtures: tuple[str, ...]
    identities: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported runtime adapter schema version")
        _identifier(self.name, "adapter.name")
        validate_digest_image(self.image, "adapter image")
        _identifier(self.command_id, "adapter.command_id")
        _identifier(self.service_host, "adapter.service.host")
        _integer(self.service_port, "adapter.service.port", maximum=65_535)
        _safe_http_path(self.health_path, "adapter.health.path")
        _integer(
            self.health_timeout_seconds,
            "adapter.health.timeout_seconds",
            maximum=_MAX_TIMEOUT_SECONDS,
        )
        if not self.fixtures or not self.identities:
            raise ValueError("adapter fixtures and identities are required")
        if len(set(self.fixtures)) != len(self.fixtures) or len(set(self.identities)) != len(
            self.identities
        ):
            raise ValueError("adapter fixtures and identities must be unique")
        for item in (*self.fixtures, *self.identities):
            _identifier(item, "adapter allowlist item")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "image": self.image,
            "command_id": self.command_id,
            "service": {"host": self.service_host, "port": self.service_port},
            "health": {
                "path": self.health_path,
                "timeout_seconds": self.health_timeout_seconds,
            },
            "fixtures": list(self.fixtures),
            "identities": list(self.identities),
        }

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.to_dict())


def parse_runtime_adapter(document: Mapping[str, object], policy: VerifierPolicy) -> RuntimeAdapter:
    _strict_keys(
        document,
        required=frozenset(
            {
                "schema_version",
                "name",
                "image",
                "command_id",
                "service",
                "health",
                "fixtures",
                "identities",
            }
        ),
        label="runtime adapter",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported runtime adapter schema version")
    service = _object(document["service"], "service")
    health = _object(document["health"], "health")
    _strict_keys(service, required=frozenset({"host", "port"}), label="service")
    _strict_keys(health, required=frozenset({"path", "timeout_seconds"}), label="health")
    timeout = _integer(
        health["timeout_seconds"],
        "health.timeout_seconds",
        maximum=policy.max_timeout_seconds,
    )
    return RuntimeAdapter(
        schema_version=SCHEMA_VERSION,
        name=_identifier(document["name"], "adapter.name"),
        image=_string(document["image"], "adapter.image", maximum=600),
        command_id=_identifier(document["command_id"], "adapter.command_id"),
        service_host=_identifier(service["host"], "service.host"),
        service_port=_integer(service["port"], "service.port", maximum=65_535),
        health_path=_safe_http_path(_string(health["path"], "health.path"), "health.path"),
        health_timeout_seconds=timeout,
        fixtures=_strings(document["fixtures"], "fixtures"),
        identities=_strings(document["identities"], "identities"),
    )


def _safe_http_path(value: str, label: str) -> str:
    if (
        len(value) > 2_048
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or "${" in value
        or _INVALID_PERCENT_ESCAPE.search(value) is not None
        or any(ord(character) < 0x20 or character.isspace() for character in value)
    ):
        raise ValueError(f"{label} must be a bounded local absolute-path reference")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise ValueError(f"{label} cannot contain a scheme, host, or fragment")
    decoded_segments = unquote(parsed.path).split("/")
    if any(segment in {".", ".."} for segment in decoded_segments):
        raise ValueError(f"{label} cannot contain traversal segments")
    return value


def _reject_templates(value: object, label: str) -> None:
    if isinstance(value, str):
        if "${" in value:
            raise ValueError(f"{label} cannot contain environment/template references")
        return
    if isinstance(value, list):
        for item in value:
            _reject_templates(item, label)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and "${" in key:
                raise ValueError(f"{label} cannot contain environment/template references")
            _reject_templates(item, label)


def _normalize_headers(
    value: object, *, policy: VerifierPolicy, identity: str
) -> dict[str, object]:
    headers = _object(value, "action.headers")
    normalized: dict[str, object] = {}
    for raw_name, raw_value in headers.items():
        name = raw_name.lower()
        if name in normalized:
            raise ValueError("action.headers contains a case-insensitive duplicate")
        if name not in policy.allowed_http_headers:
            raise ValueError(f"HTTP header is not allowed by policy: {raw_name}")
        header_value = _string(raw_value, f"action.headers.{raw_name}", maximum=2_048)
        if "\r" in header_value or "\n" in header_value:
            raise ValueError("HTTP header values cannot contain line breaks")
        if name == "authorization":
            expected = f"${{fixture.token.{identity}}}"
            if header_value != expected:
                raise ValueError("Authorization must use the selected fixture identity token")
        elif "${" in header_value:
            raise ValueError("templates are not allowed in this HTTP header")
        normalized[name] = header_value
    return normalized


def _normalize_json_assertions(value: object, policy: VerifierPolicy) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("oracle.json_assertions must be an array")
    if len(value) > policy.max_json_assertions:
        raise ValueError("oracle.json_assertions exceeds the verifier policy")
    result: list[object] = []
    for index, raw_assertion in enumerate(value):
        assertion = _object(raw_assertion, f"oracle.json_assertions[{index}]")
        _strict_keys(
            assertion,
            required=frozenset({"path", "equals"}),
            label=f"oracle.json_assertions[{index}]",
        )
        path = _string(assertion["path"], "oracle assertion path", maximum=1_024)
        if _JSON_PATH.fullmatch(path) is None:
            raise ValueError("oracle assertion path is outside the supported JSON path subset")
        equals = _json_copy(assertion["equals"], "oracle assertion value")
        _reject_templates(equals, "oracle assertion value")
        if isinstance(equals, dict | list):
            raise ValueError("oracle assertion equality is limited to JSON scalar values")
        if isinstance(equals, str) and len(equals) > 4_096:
            raise ValueError("oracle assertion string exceeds its limit")
        result.append({"path": path, "equals": equals})
    return result


def create_http_verification_case(
    document: Mapping[str, object],
    *,
    target_id: str,
    target_tree_hash: str,
    policy: VerifierPolicy,
    adapter: RuntimeAdapter,
) -> VerificationCase:
    _strict_keys(
        document,
        required=frozenset(
            {
                "schema_version",
                "hypothesis_id",
                "runtime_profile",
                "setup",
                "actor",
                "action",
                "oracle",
                "limits",
            }
        ),
        optional=frozenset({"verification_id", "target_id", "target_tree_hash"}),
        label="verification case",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported verification case schema version")
    if document.get("target_id", target_id) != target_id:
        raise ValueError("verification case target ID does not match the run")
    if document.get("target_tree_hash", target_tree_hash) != target_tree_hash:
        raise ValueError("verification case target fingerprint does not match the run")
    runtime_profile = _identifier(document["runtime_profile"], "runtime_profile")
    if runtime_profile != adapter.name:
        raise ValueError("runtime profile does not match the reviewed adapter")
    if not policy.internal_network_allowed:
        raise ValueError("HTTP verification requires a policy-approved internal network")

    setup = _object(document["setup"], "setup")
    actor = _object(document["actor"], "actor")
    action = _object(document["action"], "action")
    oracle = _object(document["oracle"], "oracle")
    limits = _object(document["limits"], "limits")
    _strict_keys(setup, required=frozenset({"fixture"}), label="setup")
    _strict_keys(actor, required=frozenset({"identity"}), label="actor")
    _strict_keys(
        action,
        required=frozenset({"protocol", "method", "path", "headers"}),
        optional=frozenset({"body"}),
        label="action",
    )
    _strict_keys(
        oracle,
        required=frozenset(),
        optional=frozenset({"forbidden_status", "json_assertions"}),
        label="oracle",
    )
    _strict_keys(
        limits,
        required=frozenset({"timeout_seconds", "max_response_body_bytes"}),
        label="limits",
    )

    fixture = _identifier(setup["fixture"], "setup.fixture")
    identity = _identifier(actor["identity"], "actor.identity")
    if fixture not in adapter.fixtures:
        raise ValueError("setup fixture is not allowed by the runtime adapter")
    if identity not in adapter.identities:
        raise ValueError("actor identity is not allowed by the runtime adapter")
    if _string(action["protocol"], "action.protocol", maximum=20) != "http":
        raise ValueError("v1 verification cases support only HTTP actions")
    method = _string(action["method"], "action.method", maximum=20).upper()
    if method not in policy.allowed_http_methods:
        raise ValueError("HTTP method is not allowed by the verifier policy")
    path = _safe_http_path(_string(action["path"], "action.path"), "action.path")
    headers = _normalize_headers(action["headers"], policy=policy, identity=identity)
    body = _json_copy(action.get("body"), "action.body")
    _reject_templates(body, "action.body")
    if body is not None and method in {"GET", "HEAD"}:
        raise ValueError("GET and HEAD verification actions cannot contain a body")
    body_size = (
        0
        if body is None
        else len(
            json.dumps(body, allow_nan=False, ensure_ascii=False, separators=(",", ":")).encode()
        )
    )
    if body_size > policy.max_request_body_bytes:
        raise ValueError("HTTP request body exceeds the verifier policy")

    forbidden_status_raw = oracle.get("forbidden_status")
    forbidden_status: int | None = None
    if forbidden_status_raw is not None:
        forbidden_status = _integer(
            forbidden_status_raw,
            "oracle.forbidden_status",
            minimum=100,
            maximum=599,
        )
    assertions = _normalize_json_assertions(oracle.get("json_assertions", []), policy)
    if forbidden_status is None and not assertions:
        raise ValueError("verification oracle requires a status or JSON assertion")
    timeout_seconds = _integer(
        limits["timeout_seconds"],
        "limits.timeout_seconds",
        maximum=policy.max_timeout_seconds,
    )
    response_body_bytes = _integer(
        limits["max_response_body_bytes"],
        "limits.max_response_body_bytes",
        maximum=policy.max_response_body_bytes,
    )
    case = VerificationCase.create(
        target_id=target_id,
        target_tree_hash=target_tree_hash,
        hypothesis_id=_string(document["hypothesis_id"], "hypothesis_id", maximum=64),
        policy_fingerprint=policy.fingerprint,
        adapter_fingerprint=adapter.fingerprint,
        runtime_profile=runtime_profile,
        runtime_image=adapter.image,
        setup={"fixture": fixture},
        actor={"identity": identity},
        action={
            "protocol": "http",
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
        },
        oracle={"forbidden_status": forbidden_status, "json_assertions": assertions},
        limits={
            "timeout_seconds": timeout_seconds,
            "max_response_body_bytes": response_body_bytes,
        },
    )
    supplied_id = document.get("verification_id")
    if supplied_id is not None and supplied_id != case.verification_id:
        raise ValueError("supplied verification ID does not match normalized content")
    return case


def verification_case_references(value: Mapping[str, object]) -> tuple[str, str]:
    policy_fingerprint = _string(value.get("policy_fingerprint"), "policy_fingerprint", maximum=64)
    adapter_fingerprint = _string(
        value.get("adapter_fingerprint"), "adapter_fingerprint", maximum=64
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", policy_fingerprint) is None
        or re.fullmatch(r"[0-9a-f]{64}", adapter_fingerprint) is None
    ):
        raise ValueError("verification case contains invalid policy/adapter fingerprints")
    return policy_fingerprint, adapter_fingerprint


def parse_stored_verification_case(
    value: Mapping[str, object],
    *,
    policy: VerifierPolicy,
    adapter: RuntimeAdapter,
) -> VerificationCase:
    _strict_keys(
        value,
        required=frozenset(
            {
                "schema_version",
                "verification_id",
                "target_id",
                "target_tree_hash",
                "hypothesis_id",
                "policy_fingerprint",
                "adapter_fingerprint",
                "runtime_profile",
                "runtime_image",
                "setup",
                "actor",
                "action",
                "oracle",
                "limits",
            }
        ),
        label="stored verification case",
    )
    policy_ref, adapter_ref = verification_case_references(value)
    if policy_ref != policy.fingerprint or adapter_ref != adapter.fingerprint:
        raise ValueError("verification case policy/adapter fingerprint mismatch")
    if value["runtime_image"] != adapter.image:
        raise ValueError("verification case runtime image does not match its adapter")
    case = create_http_verification_case(
        {
            "schema_version": value["schema_version"],
            "verification_id": value["verification_id"],
            "target_id": value["target_id"],
            "target_tree_hash": value["target_tree_hash"],
            "hypothesis_id": value["hypothesis_id"],
            "runtime_profile": value["runtime_profile"],
            "setup": value["setup"],
            "actor": value["actor"],
            "action": value["action"],
            "oracle": value["oracle"],
            "limits": value["limits"],
        },
        target_id=_string(value["target_id"], "target_id", maximum=64),
        target_tree_hash=_string(value["target_tree_hash"], "target_tree_hash", maximum=64),
        policy=policy,
        adapter=adapter,
    )
    if case.to_dict() != dict(value):
        raise ValueError("stored verification case is not canonical")
    return case
