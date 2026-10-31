"""Registro de auditoría inmutable y saneado (Hito 3, etapa 3).

- Cada evento se encadena: ``hash = HMAC(audit_key, prev_hash || evento)``.
  Modificar, borrar o reordenar un registro rompe la verificación.
- Triggers de SQLite impiden UPDATE y DELETE dentro del plazo de conservación.
- Las conexiones de rol no tienen permiso de escritura sobre ``audit_log``;
  solo esta clase, con la conexión de sistema, inserta eventos.
- ``sanitize`` elimina claves prohibidas (contraseñas, tokens, códigos, llaves)
  y enmascara cualquier valor con forma de correo, RUT, teléfono o tarjeta.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import threading
import uuid
from typing import Any

from .crypto import GENESIS, chain_mac
from .db import now_iso

RETENTION_DAYS = 730

# Claves que nunca se registran, aunque un desarrollador las pase por error.
FORBIDDEN_KEYS = re.compile(
    r"pass|contrase|token|secret|clave|key|codigo|code|cvv|(^|_)pan($|_)|tarjeta|cookie|authorization",
    re.IGNORECASE,
)
# Valores con forma de dato personal: se enmascaran.
_MASKS = [
    (re.compile(r"[^@\s\"']+@[^@\s\"']+\.[A-Za-z]{2,}"), "[correo]"),
    (re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b"), "[rut]"),
    (re.compile(r"(?:\d[ -]?){13,19}"), "[numero]"),
    (re.compile(r"\+?56\s?9\s?\d{4}\s?\d{4}"), "[telefono]"),
]

AUDITED_ACTIONS = {
    "auth.login", "auth.logout", "auth.bloqueo", "auth.registro",
    "datos.lectura_sensible", "datos.lectura_enmascarada", "datos.modificacion", "datos.exportacion",
    "datos.supresion", "consentimiento.otorgado", "consentimiento.revocado", "consentimiento.consulta",
    "derechos.solicitud", "derechos.verificacion", "derechos.evaluacion", "derechos.ejecucion",
    "derechos.rechazo", "derechos.cierre", "derechos.prorroga", "acceso.denegado",
    "admin.cambio_rol", "admin.estado_pedido", "seudonimo.reversion", "reporte.anonimizado",
    "auditoria.consulta", "auditoria.verificacion", "auditoria.purga",
    "seguridad.alerta", "incidente.apertura", "incidente.contencion", "incidente.recuperacion",
    "incidente.cierre", "incidente.evidencia", "sistema.rotacion_llaves", "menores.reporte",
    "pedido.creacion", "despacho.estado", "error.interno",
}


def sanitize(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "[omitido]"
    if isinstance(value, dict):
        return {k: ("[omitido]" if FORBIDDEN_KEYS.search(str(k)) else sanitize(v, depth + 1))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v, depth + 1) for v in list(value)[:50]]
    if isinstance(value, str):
        for pattern, replacement in _MASKS:
            value = pattern.sub(replacement, value)
        return value[:300]
    return value


def ip_prefix(ip: str | None) -> str | None:
    """Guarda solo la red /24 (IPv4) o /48 (IPv6): útil para investigar, no identifica un hogar."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


class AuditLog:
    def __init__(self, conn: sqlite3.Connection, key: bytes) -> None:
        self._conn = conn
        self._key = key
        self._lock = threading.Lock()

    def record(self, *, action: str, actor_type: str, actor_ref: str, actor_role: str,
               resource_type: str, resource_ref: str | None = None, result: str = "ok",
               request_id: str | None = None, ip: str | None = None,
               details: dict | None = None) -> str:
        if action not in AUDITED_ACTIONS:
            raise ValueError(f"Acción de auditoría no catalogada: {action}")
        event = {
            "event_id": str(uuid.uuid4()),
            "occurred_at": now_iso(),
            "actor_type": actor_type,
            "actor_ref": actor_ref,
            "actor_role": actor_role,
            "action": action,
            "resource_type": resource_type,
            "resource_ref": resource_ref,
            "result": result,
            "request_id": request_id,
            "ip_prefix": ip_prefix(ip),
            "details": json.dumps(sanitize(details or {}), ensure_ascii=False, sort_keys=True),
        }
        with self._lock:
            own = not self._conn.in_transaction
            if own:
                self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
                if row is None:
                    anchor = self._conn.execute(
                        "SELECT last_hash FROM audit_anchor ORDER BY id DESC LIMIT 1").fetchone()
                    prev = anchor["last_hash"] if anchor else GENESIS
                else:
                    prev = row["hash"]
                event["prev_hash"] = prev
                event["hash"] = chain_mac(self._key, prev, event)
                cols = ", ".join(event)
                self._conn.execute(f"INSERT INTO audit_log ({cols}) VALUES ({', '.join('?' * len(event))})",
                                   list(event.values()))
                if own:
                    self._conn.execute("COMMIT")
            except Exception:
                if own:
                    self._conn.execute("ROLLBACK")
                raise
        return event["event_id"]

    def verify(self) -> dict:
        """Recalcula la cadena completa desde el ancla (o el génesis)."""
        anchor = self._conn.execute("SELECT last_id, last_hash FROM audit_anchor ORDER BY id DESC LIMIT 1").fetchone()
        prev = anchor["last_hash"] if anchor else GENESIS
        checked = 0
        for row in self._conn.execute("SELECT * FROM audit_log ORDER BY id"):
            event = {k: row[k] for k in row.keys() if k not in ("id", "hash")}
            if row["prev_hash"] != prev or chain_mac(self._key, prev, event) != row["hash"]:
                return {"valida": False, "registros_verificados": checked, "falla_en_id": row["id"]}
            prev = row["hash"]
            checked += 1
        return {"valida": True, "registros_verificados": checked, "cabeza": prev}

    def purge_expired(self) -> int:
        """Borra registros con más de RETENTION_DAYS y deja un ancla para seguir verificando."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                last = self._conn.execute(
                    "SELECT id, hash FROM audit_log WHERE occurred_at < strftime('%Y-%m-%dT%H:%M:%S','now',?)"
                    " ORDER BY id DESC LIMIT 1", (f"-{RETENTION_DAYS} days",)).fetchone()
                if last is None:
                    self._conn.execute("COMMIT")
                    return 0
                self._conn.execute("INSERT INTO audit_anchor (created_at, last_id, last_hash) VALUES (?,?,?)",
                                   (now_iso(), last["id"], last["hash"]))
                cur = self._conn.execute("DELETE FROM audit_log WHERE id <= ?", (last["id"],))
                self._conn.execute("COMMIT")
                return cur.rowcount
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def query(self, conn: sqlite3.Connection | None = None, *, action: str | None = None,
              actor_ref: str | None = None, resource_ref: str | None = None, limit: int = 100) -> list[dict]:
        """Consulta sobre la conexión del rol (el authorizer decide si puede leer audit_log)."""
        conn = conn or self._conn
        sql, args = "SELECT * FROM audit_log WHERE 1=1", []
        for col, val in (("action", action), ("actor_ref", actor_ref), ("resource_ref", resource_ref)):
            if val:
                sql += f" AND {col} = ?"
                args.append(val)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(min(max(limit, 1), 500))
        out = []
        for row in conn.execute(sql, args):
            item = dict(row)
            item["details"] = json.loads(item["details"])
            out.append(item)
        return out
