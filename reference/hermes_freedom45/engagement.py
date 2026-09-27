"""Engagement authz — fail-closed before sensors."""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class AuthzStatus(str, Enum):
    draft = "draft"
    pending = "pending"
    authorized = "authorized"
    revoked = "revoked"
    expired = "expired"


class Scope(BaseModel):
    ip_cidrs: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    ports_allowed: list[int] = Field(
        default_factory=lambda: [22, 80, 443, 8080, 8443, 25, 587, 993, 995, 3389, 445, 3306, 5432, 6379, 27017, 9200, 11211, 5900, 23]
    )
    notes: str = ""

    @field_validator("ip_cidrs")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        for c in v:
            ipaddress.ip_network(c, strict=False)
        return v


class Authorization(BaseModel):
    status: AuthzStatus = AuthzStatus.draft
    signed_by: str = ""
    signed_at: str | None = None
    expires_at: str | None = None
    scope_confirmed: bool = False
    method_limits: str = (
        "non-destructive TCP connect, HTTP(S) header/TLS probe only — "
        "no exploit, brute force, credential spray, or unscoped scan"
    )
    evidence_ref: str = ""


class Engagement(BaseModel):
    id: str = Field(default_factory=lambda: f"eng-{uuid4().hex[:12]}")
    client_name: str = "client"
    classification: str = "confidential"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scope: Scope = Field(default_factory=Scope)
    authorization: Authorization = Field(default_factory=Authorization)
    assessor: str = "evergreen"

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def is_live_ready(self) -> tuple[bool, str]:
        a = self.authorization
        if a.status == AuthzStatus.revoked:
            return False, "revoked"
        if a.status != AuthzStatus.authorized:
            return False, f"status={a.status.value}"
        if not a.scope_confirmed:
            return False, "scope_confirmed=false"
        if not a.signed_by.strip():
            return False, "signed_by empty"
        if a.expires_at:
            try:
                exp = datetime.fromisoformat(a.expires_at.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > exp:
                    return False, "expired"
            except ValueError:
                return False, "bad expires_at"
        if not (self.scope.ip_cidrs or self.scope.hosts or self.scope.urls):
            return False, "empty scope"
        return True, "ok"

    def host_in_scope(self, host: str) -> bool:
        host = host.strip().lower().rstrip(".")
        if host in {h.lower().rstrip(".") for h in self.scope.hosts}:
            return True
        try:
            ip = ipaddress.ip_address(host)
            for c in self.scope.ip_cidrs:
                if ip in ipaddress.ip_network(c, strict=False):
                    return True
        except ValueError:
            pass
        for url in self.scope.urls:
            if host in url.lower():
                return True
        return False

    def port_allowed(self, port: int) -> bool:
        return port in self.scope.ports_allowed


def load_engagement(path: str | Path) -> Engagement:
    return Engagement.model_validate_json(Path(path).read_text(encoding="utf-8"))


def save_engagement(eng: Engagement, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    eng.touch()
    p.write_text(eng.model_dump_json(indent=2) + "\n", encoding="utf-8")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return p


def lab_engagement() -> Engagement:
    return Engagement(
        id="eng-lab-client-sim",
        client_name="Evergreen Lab Acme client-sim",
        classification="internal-lab",
        scope=Scope(
            ip_cidrs=["192.168.10.140/32", "192.168.10.0/24"],
            hosts=["192.168.10.140"],
            urls=["http://192.168.10.140/"],
            notes="Lab LAN only",
        ),
        authorization=Authorization(
            status=AuthzStatus.authorized,
            signed_by="reid-lab@evergreen.local",
            signed_at=datetime.now(timezone.utc).isoformat(),
            scope_confirmed=True,
            evidence_ref="lab-client-sim-pve2",
        ),
        assessor="freedom45bot",
    )


def require_authz(eng: Engagement, target: str, ports: list[int]) -> None:
    ok, reason = eng.is_live_ready()
    if not ok:
        raise PermissionError(f"authz blocked: {reason}")
    if not eng.host_in_scope(target):
        raise PermissionError(f"target {target!r} out of scope")
    for p in ports:
        if not eng.port_allowed(p):
            raise PermissionError(f"port {p} not allowed")
