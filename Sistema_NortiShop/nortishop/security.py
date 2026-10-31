"""Detección de eventos sospechosos e incidentes (Hito 3, etapas 4 y 5).

Niveles:
- ``alerta``: una señal aislada que se registra y se revisa en lote.
- ``sospechoso``: una regla superó su umbral; el oficial de seguridad debe analizarlo.
- ``incidente``: confirmado por el oficial (o automático si falla la integridad de la
  auditoría); abre un caso en ``incidents`` y habilita la contención.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path

from .audit import AuditLog
from .db import now_iso

# Reglas de detección: (nombre, acción auditada, resultado, umbral, ventana en minutos, nivel)
RULES = [
    ("fuerza_bruta_login", "auth.login", "denegado", 5, 10, "sospechoso"),
    ("accesos_denegados_reiterados", "acceso.denegado", "denegado", 5, 10, "sospechoso"),
    ("exportacion_anomala", "datos.exportacion", "ok", 3, 24 * 60, "sospechoso"),
    ("lectura_masiva_clientes", "datos.lectura_enmascarada", "ok", 50, 10, "sospechoso"),
]

SEVERITY_FOR_RULE = {
    "fuerza_bruta_login": "media",
    "accesos_denegados_reiterados": "media",
    "exportacion_anomala": "alta",
    "lectura_masiva_clientes": "alta",
    "integridad_auditoria": "critica",
    "credencial_expuesta": "critica",
}


class Detector:
    def __init__(self, conn: sqlite3.Connection, audit: AuditLog) -> None:
        self._conn = conn
        self._audit = audit

    def evaluate(self, *, action: str, result: str, subject_ref: str) -> list[str]:
        """Se invoca después de cada evento auditado relevante."""
        raised = []
        for name, rule_action, rule_result, threshold, window, level in RULES:
            if action != rule_action or result != rule_result:
                continue
            count = self._conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE action=? AND result=? AND "
                "(actor_ref=? OR resource_ref=?) AND occurred_at >= strftime('%Y-%m-%dT%H:%M:%S','now',?)",
                (rule_action, rule_result, subject_ref, subject_ref, f"-{window} minutes"),
            ).fetchone()[0]
            if count < threshold:
                continue
            already = self._conn.execute(
                "SELECT 1 FROM security_alerts WHERE rule=? AND subject_ref=? AND status IN ('abierta','en_analisis')"
                " AND created_at >= strftime('%Y-%m-%dT%H:%M:%S','now',?)",
                (name, subject_ref, f"-{window} minutes")).fetchone()
            if already:
                continue
            self.raise_alert(name, level, subject_ref, {"eventos": count, "ventana_min": window})
            raised.append(name)
        return raised

    def raise_alert(self, rule: str, level: str, subject_ref: str | None, details: dict) -> int:
        cur = self._conn.execute(
            "INSERT INTO security_alerts (created_at, rule, level, subject_ref, details) VALUES (?,?,?,?,?)",
            (now_iso(), rule, level, subject_ref, json.dumps(details)))
        self._audit.record(action="seguridad.alerta", actor_type="sistema", actor_ref="detector",
                           actor_role="sistema", resource_type="alerta", resource_ref=str(cur.lastrowid),
                           details={"regla": rule, "nivel": level, "sujeto": subject_ref})
        return cur.lastrowid

    def check_audit_integrity(self) -> dict:
        status = self._audit.verify()
        if not status["valida"]:
            alert_id = self.raise_alert("integridad_auditoria", "incidente", None, status)
            open_incident(self._conn, self._audit, actor_ref="detector", severity="critica",
                          summary="Falla de integridad en la cadena del registro de auditoría",
                          alert_ids=[alert_id])
        return status


def open_incident(conn: sqlite3.Connection, audit: AuditLog, *, actor_ref: str, severity: str,
                  summary: str, alert_ids: list[int] | None = None,
                  data_categories: list[str] | None = None, request_id: str | None = None,
                  ip: str | None = None) -> str:
    public_id = "INC-" + uuid.uuid4().hex[:8].upper()
    cur = conn.execute(
        "INSERT INTO incidents (public_id, opened_at, severity, phase, summary, data_categories)"
        " VALUES (?,?,?,?,?,?)",
        (public_id, now_iso(), severity, "analisis", summary, json.dumps(data_categories or [])))
    for alert_id in alert_ids or []:
        conn.execute("UPDATE security_alerts SET status='escalada', incident_id=? WHERE id=?",
                     (cur.lastrowid, alert_id))
    audit.record(action="incidente.apertura", actor_type="staff" if actor_ref != "detector" else "sistema",
                 actor_ref=actor_ref, actor_role="oficial_seguridad" if actor_ref != "detector" else "sistema",
                 resource_type="incidente", resource_ref=public_id, request_id=request_id, ip=ip,
                 details={"severidad": severity, "alertas": alert_ids or []})
    return public_id


def preserve_evidence(conn: sqlite3.Connection, audit: AuditLog, evidence_dir: Path, incident_id: str) -> str:
    """Copia el registro de auditoría y el estado de alertas ANTES de contener.

    Se guarda un JSON con su SHA-256 en ``incident_actions`` para demostrar
    que la evidencia no cambió después (cadena de custodia).
    """
    evidence_dir.mkdir(parents=True, exist_ok=True)
    snapshot = {
        "incidente": incident_id,
        "capturado_en": now_iso(),
        "verificacion_auditoria": audit.verify(),
        "auditoria": [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")],
        "alertas": [dict(r) for r in conn.execute("SELECT * FROM security_alerts ORDER BY id")],
        "sesiones_activas": conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL").fetchone()[0],
    }
    raw = json.dumps(snapshot, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    path = evidence_dir / f"{incident_id}_{snapshot['capturado_en'].replace(':', '')}_{digest[:12]}.json"
    path.write_bytes(raw)
    return digest


# Criterios de notificación según Ley 19.628 modificada por Ley 21.719, art. 14 sexies.
SUBJECT_NOTICE_CATEGORIES = {"sensibles", "menores_14", "financieros_comerciales"}


def notification_assessment(data_categories: list[str], reasonable_risk: bool) -> dict:
    """Determina si corresponde reportar a la Agencia y comunicar a los titulares."""
    agency = bool(reasonable_risk)
    subjects = agency and bool(SUBJECT_NOTICE_CATEGORIES & set(data_categories))
    return {
        "reportar_agencia": agency,
        "comunicar_titulares": subjects,
        "plazo": "por los medios más expeditos posibles y sin dilaciones indebidas (art. 14 sexies)"
                 if agency else "no aplica; se documenta la evaluación",
        "fundamento": "Ley 19.628 modificada por Ley 21.719, art. 14 sexies (vigente desde 01-12-2026)",
    }
