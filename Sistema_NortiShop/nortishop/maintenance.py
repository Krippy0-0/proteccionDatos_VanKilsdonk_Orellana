"""Procedimientos técnicos de recuperación y mantenimiento.

- ``rotate_keys``: recifra todos los campos ``*_enc`` con la versión de llave activa
  (erradicación tras exposición de una llave; rotación periódica).
- ``reapply_erasures``: tras restaurar un respaldo, vuelve a suprimir a los titulares
  registrados en ``erasure_tombstones`` para que una restauración no "resucite" datos.
"""

from __future__ import annotations

import sqlite3
from typing import Callable

from .consent import ConsentService
from .crypto import FieldProtector, Pseudonymizer
from .rights import erase_customer

# tabla → [(columna, función que arma el contexto a partir de la fila)]
ENCRYPTED_COLUMNS: dict[str, list[tuple[str, Callable[[sqlite3.Row], str]]]] = {
    "customers": [("full_name_enc", lambda r: "customer:name"), ("email_enc", lambda r: "customer:email"),
                  ("phone_enc", lambda r: "customer:phone")],
    "addresses": [("street_enc", lambda r: "customer:street")],
    "billing_profiles": [("rut_enc", lambda r: "billing:rut"), ("business_name_enc", lambda r: "billing:name"),
                         ("billing_address_enc", lambda r: "billing:address")],
    "orders": [("recipient_name_enc", lambda r: f"order:{r['public_id']}:recipient"),
               ("recipient_phone_enc", lambda r: f"order:{r['public_id']}:phone"),
               ("shipping_street_enc", lambda r: f"order:{r['public_id']}:street")],
    "payments": [("auth_code_enc", lambda r: "payment:authorization")],
    "saved_payment_methods": [("gateway_token_enc", lambda r: "payment:token")],
    "support_tickets": [("body_enc", lambda r: "ticket:body")],
    "rights_requests": [("payload_enc", lambda r: "rights:payload")],
}


def rotate_keys(system: sqlite3.Connection, fields: FieldProtector) -> dict[str, int]:
    counts: dict[str, int] = {}
    system.execute("BEGIN IMMEDIATE")
    try:
        for table, columns in ENCRYPTED_COLUMNS.items():
            n = 0
            for row in system.execute(f"SELECT * FROM {table}").fetchall():  # noqa: S608 - nombres fijos
                updates = {}
                for column, ctx in columns:
                    if fields.needs_rotation(row[column]):
                        updates[column] = fields.rotate(row[column], context=ctx(row))
                if updates:
                    sets = ", ".join(f"{c}=?" for c in updates)
                    system.execute(f"UPDATE {table} SET {sets} WHERE id=?", (*updates.values(), row["id"]))
                    n += 1
            counts[table] = n
        system.execute("COMMIT")
    except Exception:
        system.execute("ROLLBACK")
        raise
    return counts


def reapply_erasures(system: sqlite3.Connection, consent: ConsentService, pseudo: Pseudonymizer) -> list[str]:
    reapplied = []
    for t in system.execute("SELECT customer_public_id FROM erasure_tombstones").fetchall():
        row = system.execute("SELECT id, status FROM customers WHERE public_id=?", (t[0],)).fetchone()
        if row and row["status"] != "erased":
            erase_customer(system, consent, pseudo, row["id"], t[0])
            reapplied.append(t[0])
    return reapplied
