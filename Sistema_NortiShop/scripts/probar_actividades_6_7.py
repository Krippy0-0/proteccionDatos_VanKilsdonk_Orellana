"""Pruebas directas de derechos y auditoría sin iniciar el servidor HTTP."""

from __future__ import annotations

import importlib
import json
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path


# Cargamos los servicios sin ejecutar nortishop.__init__, que inicializa Flask.
ROOT = Path(__file__).resolve().parents[1]
package = types.ModuleType("nortishop")
package.__path__ = [str(ROOT / "nortishop")]
sys.modules["nortishop"] = package

audit_mod = importlib.import_module("nortishop.audit")
consent_mod = importlib.import_module("nortishop.consent")
crypto_mod = importlib.import_module("nortishop.crypto")
db_mod = importlib.import_module("nortishop.db")
privacy_mod = importlib.import_module("nortishop.privacy")
marketing_mod = importlib.import_module("nortishop.marketing")
rights_mod = importlib.import_module("nortishop.rights")
security_mod = importlib.import_module("nortishop.security")


class ActividadesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(db_mod.SCHEMA.read_text(encoding="utf-8"))
        keys = crypto_mod.Keyring.ephemeral()
        self.fields = crypto_mod.FieldProtector(keys)
        self.hasher = crypto_mod.PasswordHasher(2**10)
        self.pseudo = crypto_mod.Pseudonymizer(keys)
        self.audit = audit_mod.AuditLog(self.db, keys.audit_key)
        self.consent = consent_mod.ConsentService(self.db, keys.index_key, self.pseudo)
        consent_mod.seed_purposes(self.db)
        self.mail = []
        self.rights = rights_mod.RightsService(
            self.db, self.fields, self.hasher, self.consent, self.pseudo, self.mail,
            lambda action, ref, result, details: self.audit.record(
                action=action, actor_type="customer", actor_ref="CLI-1", actor_role="cliente",
                resource_type="solicitud_derechos", resource_ref=ref, result=result, details=details),
        )
        self._customer(1, "CLI-1", "ana@nortishop.test", "Ana Demo")
        self._customer(2, "CLI-2", "bea@nortishop.test", "Bea Demo")

    def _customer(self, cid: int, public_id: str, email: str, name: str) -> None:
        now = db_mod.now_iso()
        self.db.execute(
            "INSERT INTO customers (id,public_id,full_name_enc,email_enc,email_idx,phone_enc,"
            "adult_declared,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (cid, public_id, self.fields.encrypt(name, context="customer:name"),
             self.fields.encrypt(email, context="customer:email"),
             self.fields.blind_index(email, context="customer:email-index"),
             self.fields.encrypt("+56912345678", context="customer:phone"),
             1, "active", now, now),
        )
        self.db.execute(
            "INSERT INTO credentials (customer_id,password_hash,password_changed_at) VALUES (?,?,?)",
            (cid, self.hasher.hash("Clave-2026!"), now),
        )

    def _row(self, cid: int = 1) -> sqlite3.Row:
        return self.db.execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone()

    def _request(self, kind: str, changes: dict | None = None) -> str:
        payload = {"tipo": kind}
        if changes is not None:
            payload["cambios"] = changes
        return self.rights.create(self._row(), payload)["solicitud"]

    def _verify(self, rid: str, code: bool = False) -> dict:
        payload = {"password": "Clave-2026!"}
        if code:
            payload["codigo"] = self.mail[-1]["codigo"]
        return self.rights.verify(self._row(), self.db.execute(
            "SELECT password_hash FROM credentials WHERE customer_id=1").fetchone()[0], rid, payload)

    def test_solicitante_no_verificado(self) -> None:
        rid = self._request("acceso")
        with self.assertRaises(rights_mod.RightsError):
            self.rights.export(self._row(), rid)
        with self.assertRaises(rights_mod.RightsError):
            self.rights.verify(self._row(), self.db.execute(
                "SELECT password_hash FROM credentials WHERE customer_id=1").fetchone()[0],
                rid, {"password": "incorrecta", "codigo": self.mail[-1]["codigo"]})
        self.assertEqual(self.db.execute(
            "SELECT status FROM rights_requests WHERE public_id=?", (rid,)).fetchone()[0], "verificacion")

    def test_acceso_portabilidad_y_aislamiento(self) -> None:
        now = db_mod.now_iso()
        self.db.execute("INSERT INTO support_tickets (customer_id,subject,body_enc,status,created_at)"
                        " VALUES (?,?,?,?,?)", (1, "Garantía", self.fields.encrypt("Consulta de garantía",
                        context="ticket:body"), "abierto", now))
        self.db.execute("INSERT INTO billing_profiles (customer_id,rut_enc,rut_idx,business_name_enc,"
                        "billing_address_enc,created_at) VALUES (?,?,?,?,?,?)",
                        (1, self.fields.encrypt("12.345.678-5", context="billing:rut"), "indice-rut",
                         self.fields.encrypt("Ana Demo", context="billing:name"),
                         self.fields.encrypt("Calle Uno 123", context="billing:address"), now))
        self.db.execute("INSERT INTO analytics_events (customer_ref,event,sku,occurred_on) VALUES (?,?,?,?)",
                        (self.pseudo.pseudonym(1, domain="analitica"), "vista_producto", "SKU-1", now[:10]))
        self.db.execute("INSERT INTO orders (public_id,customer_id,status,document_type,billing_profile_id,"
                        "recipient_name_enc,recipient_phone_enc,shipping_street_enc,shipping_comuna,"
                        "shipping_region,total_clp,created_at,retention_until)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        ("PED-1", 1, "entregado", "factura", 1,
                         self.fields.encrypt("Ana Demo", context="order:PED-1:recipient"),
                         self.fields.encrypt("+56912345678", context="order:PED-1:phone"),
                         self.fields.encrypt("Calle Uno 123", context="order:PED-1:street"),
                         "Santiago", "Metropolitana", 15000, now, db_mod.plus(days=365)))
        self.db.execute("INSERT INTO shipments (order_id,carrier,tracking_code,status,delivered_at,"
                        "access_expires_at) VALUES (?,?,?,?,?,?)",
                        (1, "Transportista demo", "SEG-1", "entregado", now, now))
        for kind in ("acceso", "portabilidad"):
            rid = self._request(kind)
            self._verify(rid, code=True)
            data = self.rights.export(self._row(), rid)
            self.assertEqual(data["titular"]["email"], "ana@nortishop.test")
            self.assertEqual(data["facturacion"][0]["rut"], "12.345.678-5")
            self.assertEqual(data["soporte"][0]["mensaje"], "Consulta de garantía")
            self.assertEqual(data["analitica"][0]["sku"], "SKU-1")
            self.assertEqual(data["pedidos"][0]["despacho"]["tracking_code"], "SEG-1")
            self.assertEqual(data["pedidos"][0]["telefono_destinatario"], "+56912345678")
            self.assertNotIn("bea@nortishop.test", json.dumps(data))

    def test_rectificacion_registra_campo_sin_valor(self) -> None:
        rid = self._request("rectificacion", {"telefono": "+56987654321"})
        self._verify(rid)
        self.assertEqual(self.fields.decrypt(self._row()["phone_enc"], context="customer:phone"), "+56987654321")
        changes = self.audit.query(action="datos.modificacion")
        self.assertEqual(changes[0]["details"]["campos"], ["telefono"])
        self.assertNotIn("87654321", json.dumps(changes))

    def test_oposicion_detiene_marketing_y_propaga(self) -> None:
        self.consent.grant(1, "marketing_email", "2026-10")
        audience = set()
        def provider(action: str, ref: str) -> None:
            if action == "subscribe":
                audience.add(ref)
            else:
                audience.discard(ref)
        self.assertEqual(marketing_mod.dispatch_pending(self.db, provider), 1)
        self.assertEqual(len(audience), 1)
        rid = self._request("oposicion")
        self._verify(rid)
        self.assertFalse(self.consent.has_consent(1, "marketing_email"))
        self.assertEqual(marketing_mod.dispatch_pending(self.db, provider), 1)
        self.assertEqual(len(audience), 0)
        self.assertEqual(self.db.execute("SELECT action FROM marketing_outbox ORDER BY id DESC LIMIT 1")
                         .fetchone()[0], "suppress")
        self.assertIn("datos.oposicion", [r["action"] for r in self.audit.query()])

    def test_supresion_bloquea_facturacion_y_propaga(self) -> None:
        now = db_mod.now_iso()
        self.db.execute("INSERT INTO billing_profiles (customer_id,rut_enc,rut_idx,business_name_enc,"
                        "billing_address_enc,created_at) VALUES (?,?,?,?,?,?)",
                        (1, self.fields.encrypt("12.345.678-5", context="billing:rut"), "indice-rut",
                         self.fields.encrypt("Ana", context="billing:name"),
                         self.fields.encrypt("Calle Uno 123", context="billing:address"), now))
        rid = self._request("supresion")
        self._verify(rid, code=True)
        self.assertEqual(self._row()["status"], "erased")
        self.assertIsNone(self._row()["email_enc"])
        self.assertEqual(self.db.execute("SELECT blocked FROM billing_profiles WHERE customer_id=1")
                         .fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT action FROM marketing_outbox ORDER BY id DESC LIMIT 1")
                         .fetchone()[0], "suppress")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM erasure_tombstones").fetchone()[0], 1)

    def test_alerta_incidente_y_reconstruccion(self) -> None:
        detector = security_mod.Detector(self.db, self.audit)
        for _ in range(5):
            self.audit.record(action="acceso.denegado", actor_type="staff", actor_ref="EMP-1",
                              actor_role="soporte", resource_type="clientes", result="denegado")
            detector.evaluate(action="acceso.denegado", result="denegado", subject_ref="EMP-1")
        alert = self.db.execute("SELECT * FROM security_alerts WHERE rule='accesos_denegados_reiterados'").fetchone()
        self.assertIsNotNone(alert)
        incident = security_mod.open_incident(self.db, self.audit, actor_ref="EMP-SEG", severity="alta",
                                              summary="Intentos de consulta no autorizados", alert_ids=[alert["id"]])
        digest = security_mod.preserve_evidence(self.db, self.audit, Path(self.tmp.name), incident)
        self.assertEqual(len(digest), 64)
        self.assertTrue(self.audit.verify()["valida"])
        self.assertEqual(len(self.audit.query(action="acceso.denegado", actor_ref="EMP-1")), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
