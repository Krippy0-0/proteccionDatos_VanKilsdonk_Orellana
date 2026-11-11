"""Entrega ordenada de altas y bajas al proveedor de mailing.

El proveedor recibe una referencia seudónima estable. Debe tratar las acciones
``subscribe`` y ``suppress`` de forma idempotente: si ocurre un corte después
del envío y antes de marcar ``sent_at``, la misma orden se reintentará.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable

from .db import now_iso


def dispatch_pending(system: sqlite3.Connection, deliver: Callable[[str, str], None]) -> int:
    """Confirma solo las órdenes aceptadas por el proveedor."""
    delivered = 0
    for row in system.execute("SELECT id, customer_ref, action FROM marketing_outbox"
                              " WHERE sent_at IS NULL ORDER BY id").fetchall():
        deliver(row["action"], row["customer_ref"])
        system.execute("UPDATE marketing_outbox SET sent_at=? WHERE id=? AND sent_at IS NULL",
                       (now_iso(), row["id"]))
        delivered += 1
    return delivered
