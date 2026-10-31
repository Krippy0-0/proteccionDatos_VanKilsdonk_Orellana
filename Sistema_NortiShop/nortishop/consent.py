"""Módulo de gestión del consentimiento (Hito 3, etapa 1).

Principios implementados:
- Una decisión independiente por finalidad: no existe "aceptar todo"; cada
  ``grant`` recibe un único ``purpose_code`` y ``has_consent`` consulta solo esa
  finalidad.
- Por defecto no hay consentimiento (sin casillas premarcadas): la ausencia de
  evento equivale a "no otorgado".
- Se registra la versión exacta del texto informado; si el cliente envía una
  versión distinta de la vigente, la operación se rechaza (consentimiento informado).
- Historial append-only con HMAC encadenado; la revocación es un evento nuevo,
  nunca la edición del anterior.
- No se guarda IP ni dispositivo: basta canal, fecha, finalidad y versión.
- La revocación se propaga a los procesos dependientes (``REVOCATION_EFFECTS``).
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3

from .crypto import GENESIS, chain_mac
from .db import now_iso
from .privacy import ensure_pseudonym

PURPOSES = {
    "marketing_email": {
        "name": "Ofertas por correo electrónico",
        "description": "Envío de boletín y promociones de NortiShop al correo registrado.",
        "retention": "Mientras esté vigente; la prueba de otorgamiento/revocación se conserva 3 años.",
        "text": "Autorizo a NortiShop a enviarme ofertas y novedades por correo electrónico. "
                "Puedo retirar esta autorización en cualquier momento desde mi cuenta.",
    },
    "personalizacion": {
        "name": "Recomendaciones personalizadas",
        "description": "Uso del historial de compras para sugerir productos en la tienda.",
        "retention": "Mientras esté vigente.",
        "text": "Autorizo a NortiShop a usar mi historial de compras para mostrarme recomendaciones "
                "personalizadas dentro del sitio.",
    },
    "analitica": {
        "name": "Analítica de navegación",
        "description": "Registro seudonimizado de productos vistos y búsquedas para mejorar el sitio.",
        "retention": "13 meses; luego solo datos agregados.",
        "text": "Autorizo el registro seudonimizado de mi navegación (productos vistos, carrito y búsquedas) "
                "con fines de analítica. No se registra mi dirección IP.",
    },
    "guardar_medio_pago": {
        "name": "Guardar medio de pago",
        "description": "Conservar el token emitido por la pasarela para compras futuras.",
        "retention": "Hasta revocación o 12 meses sin uso.",
        "text": "Autorizo a NortiShop a conservar el token de mi medio de pago emitido por la pasarela "
                "(no el número de la tarjeta) para agilizar compras futuras.",
    },
}

CURRENT_VERSION = "2026-10"

# Finalidades que NO dependen del consentimiento (no aparecen en este módulo):
# ejecución del contrato de compraventa (pedido, pago, despacho) y obligaciones
# legales (facturación). Ver informe del Hito 3, sección 1.


class ConsentError(ValueError):
    pass


def seed_purposes(system: sqlite3.Connection) -> None:
    for code, p in PURPOSES.items():
        system.execute("INSERT OR IGNORE INTO consent_purposes (code, name, description, retention)"
                       " VALUES (?,?,?,?)", (code, p["name"], p["description"], p["retention"]))
        system.execute(
            "INSERT OR IGNORE INTO consent_texts (purpose_code, version, body, body_sha256, published_at)"
            " VALUES (?,?,?,?,?)",
            (code, CURRENT_VERSION, p["text"], hashlib.sha256(p["text"].encode()).hexdigest(), now_iso()))


class ConsentService:
    def __init__(self, system: sqlite3.Connection, key: bytes, pseudo) -> None:  # noqa: ANN001
        self._db = system
        self._key = hmac.new(key, b"nortishop:consent:v1", hashlib.sha256).digest()
        self._pseudo = pseudo

    def subject_ref(self, customer_id: int) -> str:
        return ensure_pseudonym(self._db, self._pseudo, customer_id, "consentimiento")

    def current_text(self, purpose: str) -> sqlite3.Row:
        row = self._db.execute("SELECT * FROM consent_texts WHERE purpose_code=? AND is_current=1"
                               " ORDER BY id DESC LIMIT 1", (purpose,)).fetchone()
        if row is None:
            raise ConsentError("Finalidad desconocida")
        return row

    def append_event(self, customer_id: int, purpose: str, version: str, action: str, channel: str) -> dict:
        ref = self.subject_ref(customer_id)
        own = not self._db.in_transaction
        if own:
            self._db.execute("BEGIN IMMEDIATE")
        try:
            last = self._db.execute("SELECT mac FROM consent_events ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["mac"] if last else GENESIS
            record = {"subject_ref": ref, "purpose_code": purpose, "text_version": version,
                      "action": action, "channel": channel, "occurred_at": now_iso()}
            mac = chain_mac(self._key, prev, record)
            self._db.execute(
                "INSERT INTO consent_events (customer_id, subject_ref, purpose_code, text_version, action,"
                " channel, occurred_at, prev_mac, mac) VALUES (?,?,?,?,?,?,?,?,?)",
                (customer_id, ref, purpose, version, action, channel, record["occurred_at"], prev, mac))
            if own:
                self._db.execute("COMMIT")
        except Exception:
            if own:
                self._db.execute("ROLLBACK")
            raise
        return record

    def grant(self, customer_id: int, purpose: str, text_version: str, channel: str = "web") -> dict:
        current = self.current_text(purpose)
        if text_version != current["version"]:
            raise ConsentError("La versión del texto informado no es la vigente; vuelva a leerlo")
        if self.has_consent(customer_id, purpose):
            raise ConsentError("El consentimiento ya está otorgado para esta finalidad")
        record = self.append_event(customer_id, purpose, text_version, "otorgado", channel)
        if purpose == "marketing_email":
            ref = ensure_pseudonym(self._db, self._pseudo, customer_id, "marketing")
            self._db.execute("INSERT INTO marketing_outbox (customer_ref, action, created_at) VALUES (?,?,?)",
                             (ref, "subscribe", now_iso()))
        return record

    def revoke(self, customer_id: int, purpose: str, channel: str = "web") -> dict:
        state = self.state(customer_id).get(purpose)
        if not state or state["estado"] != "otorgado":
            raise ConsentError("No hay un consentimiento vigente que revocar para esta finalidad")
        record = self.append_event(customer_id, purpose, state["version_texto"], "revocado", channel)
        effects = apply_revocation(self._db, self._pseudo, customer_id, purpose)
        record["efectos"] = effects
        return record

    def has_consent(self, customer_id: int, purpose: str) -> bool:
        """Consulta SOLO la finalidad indicada; nunca infiere otras."""
        ref = self._pseudo.pseudonym(customer_id, domain="consentimiento")
        row = self._db.execute("SELECT state FROM consent_state WHERE subject_ref=? AND purpose_code=?",
                               (ref, purpose)).fetchone()
        return bool(row and row["state"] == "otorgado")

    def state(self, customer_id: int) -> dict:
        ref = self._pseudo.pseudonym(customer_id, domain="consentimiento")
        out = {code: {"finalidad": p["name"], "estado": "no_otorgado", "version_texto": None, "desde": None}
               for code, p in PURPOSES.items()}
        for row in self._db.execute("SELECT * FROM consent_state WHERE subject_ref=?", (ref,)):
            out[row["purpose_code"]].update(estado=row["state"], version_texto=row["text_version"],
                                            desde=row["occurred_at"])
        return out

    def history(self, customer_id: int) -> list[dict]:
        ref = self._pseudo.pseudonym(customer_id, domain="consentimiento")
        return [{"finalidad": r["purpose_code"], "accion": r["action"], "version_texto": r["text_version"],
                 "canal": r["channel"], "fecha_hora_utc": r["occurred_at"]}
                for r in self._db.execute("SELECT * FROM consent_events WHERE subject_ref=? ORDER BY id", (ref,))]

    def verify_chain(self) -> bool:
        prev = GENESIS
        for r in self._db.execute("SELECT * FROM consent_events ORDER BY id"):
            record = {k: r[k] for k in ("subject_ref", "purpose_code", "text_version", "action", "channel",
                                        "occurred_at")}
            if r["prev_mac"] != prev or chain_mac(self._key, prev, record) != r["mac"]:
                return False
            prev = r["mac"]
        return True


def apply_revocation(system: sqlite3.Connection, pseudo, customer_id: int, purpose: str) -> list[str]:  # noqa: ANN001
    """Efectos de la revocación en los procesos que dependían del consentimiento."""
    effects = []
    if purpose == "marketing_email":
        ref = ensure_pseudonym(system, pseudo, customer_id, "marketing")
        system.execute("INSERT INTO marketing_outbox (customer_ref, action, created_at) VALUES (?,?,?)",
                       (ref, "suppress", now_iso()))
        effects.append("Se excluye de la audiencia y se envía la baja al proveedor de mailing")
    elif purpose == "analitica":
        ref = pseudo.pseudonym(customer_id, domain="analitica")
        n = system.execute("DELETE FROM analytics_events WHERE customer_ref=?", (ref,)).rowcount
        effects.append(f"Se detiene el registro de navegación y se eliminan {n} eventos seudonimizados")
    elif purpose == "guardar_medio_pago":
        n = system.execute("DELETE FROM saved_payment_methods WHERE customer_id=?", (customer_id,)).rowcount
        effects.append(f"Se eliminan {n} tokens de pago guardados")
    elif purpose == "personalizacion":
        effects.append("Las recomendaciones pasan a ser genéricas (no se usa el historial)")
    return effects
