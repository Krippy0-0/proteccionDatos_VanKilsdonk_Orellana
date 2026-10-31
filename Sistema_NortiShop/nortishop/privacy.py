"""Seudonimización, anonimización y enmascaramiento (Hito 2, parte 2).

Seudonimización (reversible solo con información adicional separada):
- ``analytics_events`` y ``marketing_outbox`` usan ``customer_ref`` = HMAC(pseudo_key, dominio||id).
- ``consent_events`` usa un seudónimo propio del dominio ``consentimiento``.
- La tabla ``pseudonym_vault`` (y la llave ``pseudo_key``) es la información
  adicional: solo el rol ``dpo`` puede leerla (authorizer de SQLite + RBAC).

Anonimización (irreversible):
- ``sales_report``: agregación por región y mes con supresión de celdas con
  menos de K_ANONYMITY clientes distintos y montos en tramos.
- ``anonymize_dataset_for_dev``: copia de datos para desarrollo y pruebas sin
  identificadores directos, con atributos generalizados y valores sintéticos.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict

from .crypto import Pseudonymizer
from .db import now_iso

K_ANONYMITY = 5
DOMAINS = ("consentimiento", "analitica", "marketing")


def ensure_pseudonym(system: sqlite3.Connection, pseudo: Pseudonymizer, customer_id: int, domain: str) -> str:
    if domain not in DOMAINS:
        raise ValueError("Dominio de seudónimo desconocido")
    ref = pseudo.pseudonym(customer_id, domain=domain)
    system.execute("INSERT OR IGNORE INTO pseudonym_vault (pseudonym, domain, customer_id, created_at)"
                   " VALUES (?,?,?,?)", (ref, domain, customer_id, now_iso()))
    return ref


def resolve_pseudonym(dpo_conn: sqlite3.Connection, pseudonym: str) -> dict | None:
    """Reversión controlada: requiere la conexión del rol dpo (otras conexiones fallan en el motor)."""
    row = dpo_conn.execute(
        "SELECT v.domain, c.public_id FROM pseudonym_vault v JOIN customers c ON c.id = v.customer_id"
        " WHERE v.pseudonym = ?", (pseudonym,)).fetchone()
    return {"dominio": row["domain"], "cliente": row["public_id"]} if row else None


# ---------- Enmascaramiento para vistas de personal ----------
def mask_name(name: str | None) -> str | None:
    if not name:
        return name
    parts = name.split()
    return " ".join(p[0] + "." if i else p for i, p in enumerate(parts))  # "Camila R. G."


def mask_email(email: str | None) -> str | None:
    if not email or "@" not in email:
        return email
    user, domain = email.split("@", 1)
    return user[0] + "***@" + domain


def mask_phone(phone: str | None) -> str | None:
    return None if not phone else "+569****" + phone[-4:]


def mask_rut(rut: str | None) -> str | None:
    return None if not rut else "**.***." + rut[-5:]


# ---------- Anonimización ----------
def amount_bucket(clp: int) -> str:
    for limit, label in ((20_000, "< $20.000"), (50_000, "$20.000–49.999"), (100_000, "$50.000–99.999"),
                         (300_000, "$100.000–299.999")):
        if clp < limit:
            return label
    return "≥ $300.000"


def sales_report(conn: sqlite3.Connection) -> dict:
    """Ventas por región y mes. Celdas con < K clientes distintos se suprimen."""
    cells: dict[tuple[str, str], dict] = defaultdict(lambda: {"clientes": set(), "pedidos": 0, "total": 0,
                                                              "tramos": defaultdict(int)})
    rows = conn.execute("SELECT id, customer_id, shipping_region, substr(created_at,1,7) AS mes, total_clp"
                        " FROM orders WHERE status <> 'anulado'")
    for row in rows:
        cell = cells[(row["shipping_region"], row["mes"])]
        cell["clientes"].add(row["customer_id"] if row["customer_id"] is not None else f"invitado-{row['id']}")
        cell["pedidos"] += 1
        cell["total"] += row["total_clp"]
        cell["tramos"][amount_bucket(row["total_clp"])] += 1
    published, suppressed = [], 0
    for (region, month), cell in sorted(cells.items()):
        if len(cell["clientes"]) < K_ANONYMITY:
            suppressed += 1
            continue
        published.append({"region": region, "mes": month, "clientes_distintos": len(cell["clientes"]),
                          "pedidos": cell["pedidos"], "venta_total_clp": round(cell["total"], -3),
                          "distribucion_montos": dict(cell["tramos"])})
    return {"k_anonimato": K_ANONYMITY, "celdas_publicadas": published, "celdas_suprimidas": suppressed}


def anonymize_dataset_for_dev(conn: sqlite3.Connection) -> list[dict]:
    """Extrae pedidos para un ambiente de desarrollo sin datos personales.

    - Se eliminan nombre, contacto, dirección, RUT, tokens y códigos.
    - El cliente se reemplaza por un número secuencial sin relación con el id real
      (no se guarda la tabla de correspondencia: es anonimización, no seudonimización).
    - Fecha → mes; comuna → región; monto → tramo.
    """
    out, mapping = [], {}
    for row in conn.execute("SELECT id, customer_id, shipping_region, substr(created_at,1,7) AS mes,"
                            " total_clp, status FROM orders ORDER BY random()"):
        key = row["customer_id"] if row["customer_id"] is not None else f"invitado-{row['id']}"
        mapping.setdefault(key, len(mapping) + 1)
        out.append({"cliente_dev": f"DEV-{mapping[key]:05d}", "region": row["shipping_region"],
                    "mes": row["mes"], "tramo_monto": amount_bucket(row["total_clp"]), "estado": row["status"]})
    mapping.clear()  # la correspondencia se descarta
    return out
