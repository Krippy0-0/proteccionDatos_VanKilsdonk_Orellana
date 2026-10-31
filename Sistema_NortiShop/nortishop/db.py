"""Acceso a SQLite con restricciones por rol en el propio motor.

``connect_for_role`` devuelve una conexión con un *authorizer* que consulta
``rbac.DB_POLICY``: cualquier SELECT/INSERT/UPDATE/DELETE sobre una tabla no
permitida para el rol se rechaza con ``sqlite3.DatabaseError`` antes de
ejecutarse. ``connect_system`` es la conexión de servicios internos
(auditoría, alertas, seudónimos, motor de derechos), que igualmente queda
sujeta a los triggers de inmutabilidad.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import rbac

SCHEMA = Path(__file__).with_name("schema.sql")

_READ_ACTIONS = {sqlite3.SQLITE_READ}
_WRITE_ACTIONS = {sqlite3.SQLITE_INSERT: "insert", sqlite3.SQLITE_UPDATE: "update", sqlite3.SQLITE_DELETE: "delete"}
_INTERNAL_TABLES = {"sqlite_master", "sqlite_schema", "sqlite_sequence", "sqlite_temp_master"}
# Las vistas heredan el permiso de la tabla de origen.
VIEW_SOURCES = {"consent_state": "consent_events"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def now_iso() -> str:
    return iso(utcnow())


def plus(days: float = 0, minutes: float = 0) -> str:
    return iso(utcnow() + timedelta(days=days, minutes=minutes))


def _base_connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db(path: str) -> None:
    conn = _base_connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    finally:
        conn.close()


class RoleAuthorizer:
    """Callback de ``set_authorizer`` basado en la política del rol."""

    def __init__(self, role: str) -> None:
        policy = rbac.DB_POLICY.get(role)
        if policy is None:
            raise PermissionError(f"Rol sin política de datos: {role}")
        self.role = role
        self.readable = policy[rbac.R]
        self.writable = policy[rbac.W]
        self.denied: list[tuple[str, str]] = []

    def __call__(self, action, arg1, arg2, dbname, source):  # noqa: ANN001
        if action in _READ_ACTIONS:
            table, column = VIEW_SOURCES.get(arg1, arg1), arg2
            if table in _INTERNAL_TABLES:
                return sqlite3.SQLITE_OK
            if table not in self.readable:
                self.denied.append(("read", table))
                return sqlite3.SQLITE_DENY
            if (table == "customers" and self.role in rbac.CUSTOMER_STATUS_ROLES
                    and column and column not in rbac.CUSTOMER_STATUS_COLUMNS):
                self.denied.append(("read", f"customers.{column}"))
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        if action in _WRITE_ACTIONS:
            table = arg1
            if table in _INTERNAL_TABLES:
                return sqlite3.SQLITE_OK
            if table not in self.writable:
                self.denied.append((_WRITE_ACTIONS[action], table))
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_PRAGMA) and source is None:
            # Impide adjuntar otras bases o cambiar pragmas desde una conexión de rol.
            if action == sqlite3.SQLITE_PRAGMA and arg1 in ("foreign_keys", "busy_timeout"):
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK


def connect_for_role(path: str, role: str) -> sqlite3.Connection:
    conn = _base_connect(path)
    conn.set_authorizer(RoleAuthorizer(role))
    return conn


def connect_system(path: str) -> sqlite3.Connection:
    return _base_connect(path)
